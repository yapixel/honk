use async_trait::async_trait;
use honk_config::node::Node;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

use super::protocol::{Snell, UDP_REQUEST, connect_request, write_header, write_udp_header};
use super::udp::SnellUdpTransport;
use super::v6::{SnellV6Mode, V6Codec};
use crate::proxy::{
    MultiTargetTransport, PacketOutbound, PacketTransport, PreparedUdpTransport, ProbeableOutbound,
    ProxyStream, SharedSourceOutbound, TcpOutbound,
};

/// What Snell version label the handler uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnellVersion {
    V3,
    V4,
    V5,
    V6,
}

impl SnellVersion {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            5 => Some(Self::V5),
            6 => Some(Self::V6),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::V3 => "v3",
            Self::V4 => "v4",
            Self::V5 => "v5",
            Self::V6 => "v6",
        }
    }
}

/// Local half-close progress. It ends at the flushed zero chunk: every
/// Snell server version aborts the whole session on transport EOF, dropping
/// any reply the upstream has yet to send, so the write side stays open until
/// the connection is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalHalfClose {
    Open,
    WritingZero,
    FlushingZero,
    Sent,
    Failed,
}

/// Stream wrapping `Snell<S>` with half-close zero-chunk emission on `poll_shutdown`.
pub struct SnellStream<S> {
    inner: Snell<S>,
    local_half_close: LocalHalfClose,
}

impl<S: std::fmt::Debug> std::fmt::Debug for SnellStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellStream")
            .field("inner", &self.inner)
            .field("local_half_close", &self.local_half_close)
            .finish()
    }
}

impl<S> SnellStream<S> {
    pub fn new(inner: Snell<S>) -> Self {
        Self {
            inner,
            local_half_close: LocalHalfClose::Open,
        }
    }

    pub fn inner_mut(&mut self) -> &mut Snell<S> {
        &mut self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SnellStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SnellStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match this.local_half_close {
                LocalHalfClose::Open => {
                    this.local_half_close = LocalHalfClose::WritingZero;
                }
                LocalHalfClose::WritingZero => {
                    match Pin::new(&mut this.inner).poll_write(cx, &[]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            this.local_half_close = LocalHalfClose::Failed;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(n)) if n > 0 => continue,
                        Poll::Ready(Ok(_)) => {
                            this.local_half_close = LocalHalfClose::FlushingZero;
                        }
                    }
                }
                LocalHalfClose::FlushingZero => match Pin::new(&mut this.inner).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        this.local_half_close = LocalHalfClose::Failed;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(())) => {
                        this.local_half_close = LocalHalfClose::Sent;
                    }
                },
                LocalHalfClose::Sent => return Poll::Ready(Ok(())),
                LocalHalfClose::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "snell: previous shutdown attempt failed",
                    )));
                }
            }
        }
    }
}

#[derive(Default)]
pub struct SnellHandler;

impl SnellHandler {
    pub fn new() -> Self {
        Self
    }

    pub(crate) fn build_snell<S: AsyncRead + AsyncWrite + Unpin>(
        node: &Node,
        stream: S,
    ) -> anyhow::Result<(Snell<S>, SnellVersion)> {
        let config = node
            .snell()
            .ok_or_else(|| anyhow::anyhow!("missing snell config"))?;
        let psk = config
            .psk
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("snell: psk is required"))?;
        if psk.is_empty() {
            anyhow::bail!("snell: psk must not be empty");
        }

        let version = config.version.unwrap_or(4);
        let version = SnellVersion::from_u8(version)
            .ok_or_else(|| anyhow::anyhow!("snell: unsupported version {version}"))?;

        let mode = match config.mode.as_deref() {
            Some(m) => SnellV6Mode::parse(m)
                .ok_or_else(|| anyhow::anyhow!("snell: invalid v6 mode '{m}'"))?,
            None => SnellV6Mode::Default,
        };
        if version != SnellVersion::V6 && config.mode.is_some() {
            anyhow::bail!("snell: mode is only supported with version 6");
        }

        let psk_bytes: Arc<[u8]> = Arc::from(psk.as_bytes());
        let snell = match version {
            SnellVersion::V3 => Snell::new_v3(stream, psk_bytes),
            SnellVersion::V4 | SnellVersion::V5 => Snell::new(stream, psk_bytes),
            SnellVersion::V6 => {
                Snell::new_v6(stream, psk_bytes, V6Codec::new(mode, psk.as_bytes()))
            }
        };
        Ok((snell, version))
    }

    async fn dial_udp_stream(
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::prepare_udp_stream(node, target, target_domain, connect_timeout)
            .await?
            .commit()
            .await
    }

    async fn prepare_udp_stream(
        node: &Node,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let transport = Self::open_udp_stream(node, target, domain, timeout).await?;
        Ok(PreparedUdpTransport::ready(
            transport as Arc<dyn PacketTransport>,
        ))
    }

    pub(crate) async fn prepare_udp_source(
        node: &Node,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let transport = Self::open_udp_stream(node, target, domain, timeout).await?;
        Ok(PreparedUdpTransport::ready(
            transport as Arc<dyn MultiTargetTransport>,
        ))
    }

    pub(crate) async fn open_udp_stream(
        node: &Node,
        target: SocketAddr,
        domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<SnellUdpTransport>> {
        if !crate::descriptor::network_allows_udp(node) {
            anyhow::bail!(
                "Snell UDP: node network {:?} does not include \"udp\"",
                node.network()
            );
        }
        let addr = format!("{}:{}", node.host(), node.port);
        debug!("Snell UDP: connecting to {} for target {}", addr, target);
        let stream = crate::util::connect_outbound(&addr, connect_timeout).await?;
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        let boxed: Box<dyn crate::proxy::AsyncReadWrite> = Box::new(stream);
        let (mut snell, version) = Self::build_snell(node, boxed)?;

        if version == SnellVersion::V6 {
            snell.defer_request(UDP_REQUEST.to_vec())?;
            snell.flush().await?;
        } else {
            write_udp_header(&mut snell).await?;
        }
        if version != SnellVersion::V3 {
            snell.read_reply().await?;
        }

        Ok(Arc::new(SnellUdpTransport::new(snell, target, domain)))
    }
}

#[async_trait]
impl TcpOutbound for SnellHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = format!("{}:{}", node.host(), node.port);
        debug!("Snell: connecting to {} for target {}", addr, target);
        let stream = crate::util::connect_outbound(&addr, connect_timeout).await?;
        self.dial_with_tcp(node, target, target_domain, stream, connect_timeout)
            .await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        stream: TcpStream,
        _connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );

        let (mut snell, version) = Self::build_snell(node, stream)?;

        let (host, port) = if let Some(domain) = target_domain {
            (domain.to_string(), target.port())
        } else {
            (target.ip().to_string(), target.port())
        };

        if version == SnellVersion::V6 {
            let req = connect_request(&host, port, true)?;
            snell.defer_request(req)?;
        } else {
            write_header(&mut snell, &host, port, false).await?;
        }

        let wrapped = SnellStream::new(snell);
        Ok(ProxyStream {
            stream: Box::new(wrapped),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[async_trait]
impl PacketOutbound for SnellHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::dial_udp_stream(node, target, target_domain, connect_timeout).await
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::dial_udp_stream(&runtime.node, target, target_domain, connect_timeout).await
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        Self::prepare_udp_stream(&runtime.node, target, target_domain, connect_timeout).await
    }
}

#[async_trait]
impl SharedSourceOutbound for SnellHandler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let _ = speculative;
        Self::prepare_udp_source(&runtime.node, target, target_domain, connect_timeout).await
    }
}

#[async_trait]
impl ProbeableOutbound for SnellHandler {}
