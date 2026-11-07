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

use super::obfs::{HttpObfs, TlsObfs};
use super::protocol::{Snell, UDP_REQUEST, connect_request, write_header, write_udp_header};
use super::udp::SnellUdpTransport;
use super::v6::{SnellV6Mode, V6Codec};
use crate::proxy::{
    AsyncReadWrite, MultiTargetTransport, PacketOutbound, PacketTransport, PreparedUdpTransport,
    ProbeableOutbound, ProxyStream, SharedSourceOutbound, TcpOutbound, WarmRequirement,
    WarmableOutbound,
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

/// Stream wrapping `Snell<Box<dyn AsyncReadWrite>>` with half-close zero-chunk emission on `poll_shutdown`
/// and connection reuse pool return on `Drop`.
pub struct SnellStream {
    inner: Option<Snell<Box<dyn AsyncReadWrite>>>,
    local_half_close: LocalHalfClose,
    pool: Option<Arc<super::pool::SnellPool>>,
    reuse_failed: bool,
}

impl std::fmt::Debug for SnellStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellStream")
            .field("inner", &self.inner)
            .field("local_half_close", &self.local_half_close)
            .field("pool", &self.pool.is_some())
            .field("reuse_failed", &self.reuse_failed)
            .finish()
    }
}

impl SnellStream {
    pub fn new(inner: Snell<Box<dyn AsyncReadWrite>>) -> Self {
        Self {
            inner: Some(inner),
            local_half_close: LocalHalfClose::Open,
            pool: None,
            reuse_failed: false,
        }
    }

    pub fn pooled(
        inner: Snell<Box<dyn AsyncReadWrite>>,
        pool: Arc<super::pool::SnellPool>,
    ) -> Self {
        Self {
            inner: Some(inner),
            local_half_close: LocalHalfClose::Open,
            pool: Some(pool),
            reuse_failed: false,
        }
    }

    pub fn inner_mut(&mut self) -> Option<&mut Snell<Box<dyn AsyncReadWrite>>> {
        self.inner.as_mut()
    }
}

impl AsyncRead for SnellStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "snell stream closed",
            )));
        };
        let result = Pin::new(inner).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.reuse_failed = true;
        }
        result
    }
}

impl AsyncWrite for SnellStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "snell stream closed",
            )));
        };
        let result = Pin::new(inner).poll_write(cx, buf);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.reuse_failed = true;
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "snell stream closed",
            )));
        };
        let result = Pin::new(inner).poll_flush(cx);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.reuse_failed = true;
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match this.local_half_close {
                LocalHalfClose::Open => {
                    this.local_half_close = LocalHalfClose::WritingZero;
                }
                LocalHalfClose::WritingZero => {
                    let Some(inner) = this.inner.as_mut() else {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "snell stream closed",
                        )));
                    };
                    match Pin::new(inner).poll_write(cx, &[]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            this.local_half_close = LocalHalfClose::Failed;
                            this.reuse_failed = true;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(n)) if n > 0 => continue,
                        Poll::Ready(Ok(_)) => {
                            this.local_half_close = LocalHalfClose::FlushingZero;
                        }
                    }
                }
                LocalHalfClose::FlushingZero => {
                    let Some(inner) = this.inner.as_mut() else {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "snell stream closed",
                        )));
                    };
                    match Pin::new(inner).poll_flush(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            this.local_half_close = LocalHalfClose::Failed;
                            this.reuse_failed = true;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            this.local_half_close = LocalHalfClose::Sent;
                        }
                    }
                }
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

impl Drop for SnellStream {
    fn drop(&mut self) {
        let (Some(mut snell), Some(pool)) = (self.inner.take(), self.pool.take()) else {
            return;
        };
        if !self.reuse_failed
            && snell.peer_half_closed()
            && matches!(self.local_half_close, LocalHalfClose::Sent)
        {
            snell.reset_reply_state();
            pool.put(snell);
        }
    }
}

#[derive(Default)]
pub struct SnellHandler;

impl SnellHandler {
    pub fn new() -> Self {
        Self
    }

    pub(crate) fn build_snell(
        node: &Node,
        stream: Box<dyn AsyncReadWrite>,
    ) -> anyhow::Result<(Snell<Box<dyn AsyncReadWrite>>, SnellVersion)> {
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

        let host = || {
            config
                .obfs_host
                .clone()
                .unwrap_or_else(|| node.host().to_string())
        };
        let stream: Box<dyn AsyncReadWrite> = match config.obfs.as_deref() {
            None => stream,
            Some(_) if version == SnellVersion::V6 => {
                anyhow::bail!("snell: obfs is not supported by snell v6")
            }
            Some("http") => Box::new(HttpObfs::new(stream, host(), node.port)?),
            Some("tls") => Box::new(TlsObfs::new(stream, host())?),
            Some(other) => anyhow::bail!("snell: unsupported obfs mode '{other}'"),
        };

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

        let boxed: Box<dyn AsyncReadWrite> = Box::new(stream);
        let (mut snell, version) = Self::build_snell(node, boxed)?;

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

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let node = &runtime.node;
        let config = node.snell();
        let pool = runtime
            .snell_pool()
            .filter(|_| config.is_some_and(|c| c.reuse == Some(true) && c.version != Some(3)));
        let Some(pool) = pool else {
            return self
                .dial(node, target, target_domain, connect_timeout)
                .await;
        };
        let host = target_domain.map_or_else(|| target.ip().to_string(), str::to_string);
        let port = target.port();
        let v6_request = config
            .is_some_and(|c| c.version == Some(6))
            .then(|| connect_request(&host, port, true))
            .transpose()?;
        let into_stream = |snell| ProxyStream {
            stream: Box::new(SnellStream::pooled(snell, Arc::clone(&pool))),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        };

        while let Some(mut snell) = pool.take_idle() {
            snell.reset_reply_state();
            if let Err(e) = start_session(&mut snell, v6_request.as_deref(), &host, port).await {
                debug!("snell: pooled connection unusable: {e}");
                continue;
            }
            if let Some(observer) = crate::runtime::flow_observation::current() {
                observer.publish(
                    crate::runtime::flow_observation::FlowEvent::TransportAttached {
                        server_addr: None,
                        resolution_location:
                            crate::runtime::flow_observation::ResolutionLocation::Reused,
                    },
                );
            }
            return Ok(into_stream(snell));
        }

        let addr = format!("{}:{}", node.host(), node.port);
        debug!("Snell: connecting to {} for target {}", addr, target);
        let stream = crate::util::connect_outbound(&addr, connect_timeout).await?;
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        let boxed: Box<dyn AsyncReadWrite> = Box::new(stream);
        let (mut snell, _) = Self::build_snell(node, boxed)?;
        start_session(&mut snell, v6_request.as_deref(), &host, port).await?;
        Ok(into_stream(snell))
    }
}

/// Opens a `CommandConnectV2` session. v6 carries the request in the session's
/// first record, so a stale pooled conn surfaces on first use rather than here.
async fn start_session(
    snell: &mut super::pool::PoolStream,
    v6_request: Option<&[u8]>,
    host: &str,
    port: u16,
) -> io::Result<()> {
    match v6_request {
        Some(request) => snell.defer_request(request.to_vec()),
        None => write_header(snell, host, port, true).await,
    }
}

#[async_trait]
impl WarmableOutbound for SnellHandler {
    async fn warm(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _connect_timeout: std::time::Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        Ok(())
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
