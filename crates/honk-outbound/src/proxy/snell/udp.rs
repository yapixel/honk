use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use async_trait::async_trait;
use tokio::io::{AsyncRead, ReadBuf};

use super::protocol::{COMMAND_UDP_FORWARD, PacketFrameProgress, Snell};
use crate::proxy::{AsyncReadWrite, FramePoison, MultiTargetTransport, PacketTransport};

pub(crate) fn build_request_frame(addr: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 1 + 16 + 2 + payload.len());
    buf.push(COMMAND_UDP_FORWARD);
    buf.push(0);
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(0x04);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(0x06);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub(crate) fn build_request_frame_domain(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut buf = Vec::with_capacity(1 + 1 + host_bytes.len() + 2 + payload.len());
    buf.push(COMMAND_UDP_FORWARD);
    buf.push(host_bytes.len() as u8);
    buf.extend_from_slice(host_bytes);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub(crate) fn parse_response_frame(
    frame: &[u8],
    out: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    if frame.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell udp: empty response frame",
        ));
    }

    let (addr, payload_start) = match frame[0] {
        0x04 => {
            const HEAD_LEN: usize = 1 + 4 + 2;
            if frame.len() < HEAD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp: short IPv4 response frame",
                ));
            }
            let ip = [frame[1], frame[2], frame[3], frame[4]];
            let port = [frame[5], frame[6]];
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port)),
                HEAD_LEN,
            )
        }
        0x06 => {
            const HEAD_LEN: usize = 1 + 16 + 2;
            if frame.len() < HEAD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp: short IPv6 response frame",
                ));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&frame[1..17]);
            let port = [frame[17], frame[18]];
            let ip6 = Ipv6Addr::from(ip);
            let canonical_ip = match ip6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(ip6),
            };
            (
                SocketAddr::new(canonical_ip, u16::from_be_bytes(port)),
                HEAD_LEN,
            )
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("snell udp: unknown address family 0x{other:x}"),
            ));
        }
    };

    let payload = &frame[payload_start..];
    if payload.len() > out.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snell udp frame exceeds buffer",
        ));
    }
    out[..payload.len()].copy_from_slice(payload);
    Ok((payload.len(), addr))
}

pub struct SnellUdpTransport {
    stream: Arc<parking_lot::Mutex<Snell<Box<dyn AsyncReadWrite>>>>,
    writer: tokio::sync::Mutex<()>,
    poison: FramePoison,
    reader: tokio::sync::Mutex<Vec<u8>>,
    max_frame: usize,
    domain: Option<Box<str>>,
    relay_addr: SocketAddr,
}

impl std::fmt::Debug for SnellUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellUdpTransport")
            .field("relay_addr", &self.relay_addr)
            .finish()
    }
}

impl SnellUdpTransport {
    pub(crate) fn new(
        snell: Snell<Box<dyn AsyncReadWrite>>,
        relay_addr: SocketAddr,
        domain: Option<&str>,
    ) -> Self {
        Self {
            max_frame: snell.max_packet_frame_len(),
            stream: Arc::new(parking_lot::Mutex::new(snell)),
            writer: tokio::sync::Mutex::new(()),
            poison: FramePoison::default(),
            reader: tokio::sync::Mutex::new(Vec::new()),
            domain: domain.map(Box::from),
            relay_addr,
        }
    }

    async fn send_frame(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        admitted: Option<&std::sync::atomic::AtomicBool>,
    ) -> io::Result<()> {
        let domain = crate::proxy::addr::dialed_name(self.domain.as_deref(), domain);
        if domain.is_some_and(|name| name.len() > 255) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: domain name too long",
            ));
        }
        let frame = match domain {
            Some(name) => build_request_frame_domain(name, target.port(), data),
            None => build_request_frame(&target, data),
        };
        if frame.len() > self.max_frame {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            ));
        }

        let Ok(_writer_guard) = self.writer.try_lock() else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "snell UDP writer is busy",
            ));
        };

        let write = self.poison.begin(admitted)?;
        let mut progress = PacketFrameProgress::default();
        std::future::poll_fn(|cx| {
            let mut stream = self.stream.lock();
            stream.poll_write_packet_frame(cx, &frame, &mut progress)
        })
        .await?;
        write.complete();
        Ok(())
    }
}

#[async_trait]
impl PacketTransport for SnellUdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    fn allows_full_cone_replies(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.send_frame(self.relay_addr, self.domain.as_deref(), data, None)
            .await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut frame = self.reader.lock().await;
        if frame.len() < self.max_frame {
            frame.resize(self.max_frame, 0);
        }
        let n = std::future::poll_fn(|cx| {
            let mut stream = self.stream.lock();
            let mut rb = ReadBuf::new(frame.as_mut_slice());
            match Pin::new(&mut *stream).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "snell udp: unexpected EOF reading response frame",
            ));
        }
        parse_response_frame(&frame[..n], buf)
    }
}

#[async_trait]
impl MultiTargetTransport for SnellUdpTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        _confirmed: bool,
        admitted: Option<&std::sync::atomic::AtomicBool>,
    ) -> io::Result<()> {
        self.send_frame(target, domain, data, admitted).await
    }

    fn frame_stream_torn(&self) -> bool {
        self.poison.is_set()
    }
}
