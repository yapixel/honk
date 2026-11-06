//! Snell protocol constants and the high-level `Snell` stream wrapper.
//!
//! Bridges the version-specific AEAD codec to the snell request/response
//! semantics:
//!
//! * The client writes a 5-byte `[ver | cmd | client-id-len=0 | host-len |
//!   host... | port:u16 BE]` connect request after the salt is in flight.
//! * The server replies with a status byte (Tunnel/Pong/Error). Error
//!   responses carry `[code, msg-len, msg...]`.
//! * Either side may send a zero-payload frame to signal half-close.
//! * v6 always uses the reuse-capable request and defers it into the
//!   session's first record (see [`Snell::defer_request`]).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::v3::{V3Conn, is_zero_chunk as is_v3_zero_chunk};
use super::v4::{V4Conn, is_zero_chunk as is_v4_zero_chunk};
use super::v6::{V6Codec, V6Conn};

/// First byte of every Snell request — `0x01` since v1.
pub const HEADER_VERSION: u8 = 1;

pub const COMMAND_CONNECT: u8 = 1;
/// Reuse-capable TCP connect; used when the client maintains a pool or for v6.
pub const COMMAND_CONNECT_V2: u8 = 5;

pub const RESPONSE_TUNNEL: u8 = 0;
pub const RESPONSE_PONG: u8 = 1;
pub const RESPONSE_ERROR: u8 = 2;

/// True iff an error is a version-specific Snell zero-chunk half-close
/// (v6 reuses v4's).
pub fn is_zero_chunk(err: &io::Error) -> bool {
    is_v3_zero_chunk(err) || is_v4_zero_chunk(err)
}

/// Application-layer error returned by the snell peer.
#[derive(Debug, Clone)]
pub struct AppError {
    pub code: u8,
    pub message: String,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "snell server error code={} msg={}",
            self.code, self.message
        )
    }
}

impl std::error::Error for AppError {}

/// Encode a TCP CONNECT request. The host is sent as text, IP literals
/// included.
pub fn connect_request(host: &str, port: u16, reuse: bool) -> io::Result<Vec<u8>> {
    if host.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snell: host name too long",
        ));
    }
    let mut buf = Vec::with_capacity(5 + host.len() + 2);
    buf.push(HEADER_VERSION);
    buf.push(if reuse {
        COMMAND_CONNECT_V2
    } else {
        COMMAND_CONNECT
    });
    buf.push(0); // empty client ID
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    Ok(buf)
}

/// Write a TCP CONNECT request through the caller's encrypted stream.
pub async fn write_header<W: AsyncWrite + Unpin>(
    stream: &mut W,
    host: &str,
    port: u16,
    reuse: bool,
) -> io::Result<()> {
    stream.write_all(&connect_request(host, port, reuse)?).await
}

/// Emit a zero-chunk (`payload_len == 0 && padding_len == 0`) — the
/// half-close signal recognized by the peer. The Snell codecs turn a
/// zero-byte `poll_write` into a zero-chunk frame, so this is a thin wrapper.
pub async fn write_zero_chunk<W: AsyncWrite + Unpin>(stream: &mut W) -> io::Result<()> {
    // A codec may first finish an in-flight payload write and report that
    // payload's consumed length. Keep polling until the empty input itself
    // completes, which is reported as zero bytes consumed.
    loop {
        if std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_write(cx, &[])).await? == 0 {
            break;
        }
    }
    stream.flush().await
}

// ─── Snell stream wrapper ────────────────────────────────────────────────────

enum SnellInner<S> {
    V3(V3Conn<S>),
    V4(V4Conn<S>),
    V6(V6Conn<S>),
}

impl<S: std::fmt::Debug> std::fmt::Debug for SnellInner<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnellInner::V3(_) => f.debug_tuple("SnellInner::V3").finish(),
            SnellInner::V4(_) => f.debug_tuple("SnellInner::V4").finish(),
            SnellInner::V6(_) => f.debug_tuple("SnellInner::V6").finish(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SnellInner<S> {
    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_read(cx, out),
            SnellInner::V4(conn) => Pin::new(conn).poll_read(cx, out),
            SnellInner::V6(conn) => Pin::new(conn).poll_read(cx, out),
        }
    }

    fn poll_write_inner(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_write(cx, buf),
            SnellInner::V4(conn) => Pin::new(conn).poll_write(cx, buf),
            SnellInner::V6(conn) => Pin::new(conn).poll_write(cx, buf),
        }
    }

    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_flush(cx),
            SnellInner::V4(conn) => Pin::new(conn).poll_flush(cx),
            SnellInner::V6(conn) => Pin::new(conn).poll_flush(cx),
        }
    }

    fn poll_shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_shutdown(cx),
            SnellInner::V4(conn) => Pin::new(conn).poll_shutdown(cx),
            SnellInner::V6(conn) => Pin::new(conn).poll_shutdown(cx),
        }
    }
}

/// AEAD-wrapped stream with snell request/response semantics.
///
/// On the first `poll_read`, the wrapper consumes the server's status byte
/// before yielding any relay bytes (`read_reply`). Subsequent reads pass
/// through directly.
pub struct Snell<S> {
    inner: SnellInner<S>,
    /// Set to `true` after the reply byte has been consumed once. Reset to
    /// `false` by [`Snell::reset_reply_state`] if re-used.
    reply_consumed: bool,
    /// The current session ended with the peer's zero-chunk. Unlike a raw TCP
    /// EOF, this makes a connection recognize protocol-level half-close.
    peer_half_closed: bool,
}

impl<S: std::fmt::Debug> std::fmt::Debug for Snell<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snell")
            .field("inner", &self.inner)
            .field("reply_consumed", &self.reply_consumed)
            .field("peer_half_closed", &self.peer_half_closed)
            .finish()
    }
}

impl<S> Snell<S> {
    pub fn from_v4(inner: V4Conn<S>) -> Self {
        Self {
            inner: SnellInner::V4(inner),
            reply_consumed: false,
            peer_half_closed: false,
        }
    }

    pub fn from_v3(inner: V3Conn<S>) -> Self {
        Self {
            inner: SnellInner::V3(inner),
            reply_consumed: false,
            peer_half_closed: false,
        }
    }

    pub fn new(inner: S, psk: Arc<[u8]>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            inner: SnellInner::V4(V4Conn::new(inner, psk)),
            reply_consumed: false,
            peer_half_closed: false,
        }
    }

    pub fn new_v3(inner: S, psk: Arc<[u8]>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            inner: SnellInner::V3(V3Conn::new(inner, psk)),
            reply_consumed: false,
            peer_half_closed: false,
        }
    }

    pub fn new_v6(inner: S, psk: Arc<[u8]>, codec: V6Codec) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            inner: SnellInner::V6(V6Conn::new(inner, psk, codec)),
            reply_consumed: false,
            peer_half_closed: false,
        }
    }

    /// v6: queue `request` to lead the next record, so it shares a record
    /// with the session's first payload bytes. Earlier versions write their
    /// request eagerly and reject this.
    pub fn defer_request(&mut self, request: Vec<u8>) -> io::Result<()> {
        match &mut self.inner {
            SnellInner::V6(conn) => {
                conn.defer_request(request);
                Ok(())
            }
            SnellInner::V3(_) | SnellInner::V4(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "snell: deferred requests are v6-only",
            )),
        }
    }

    /// Reset the reply-consumed flag so the next `read` consumes a new status byte.
    pub fn reset_reply_state(&mut self) {
        self.reply_consumed = false;
        self.peer_half_closed = false;
    }

    pub fn peer_half_closed(&self) -> bool {
        self.peer_half_closed
    }

    /// Whether an idle connection still looks usable: one read poll
    /// (with a no-op waker) must find nothing — no data, EOF or error.
    pub fn idle_conn_alive(&mut self) -> bool
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut cx = Context::from_waker(Waker::noop());
        let mut byte = [0u8; 1];
        let mut rb = ReadBuf::new(&mut byte);
        self.inner.poll_read_inner(&mut cx, &mut rb).is_pending()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Snell<S> {
    /// Consume the server's status byte. Idempotent — calls after the first
    /// successful invocation are no-ops until [`Snell::reset_reply_state`].
    pub async fn read_reply(&mut self) -> io::Result<()> {
        if self.reply_consumed {
            return Ok(());
        }
        let mut byte = [0u8; 1];
        self.read_exact_underlying(&mut byte).await?;
        self.reply_consumed = true;
        match byte[0] {
            RESPONSE_TUNNEL | RESPONSE_PONG => Ok(()),
            RESPONSE_ERROR => {
                let mut buf = [0u8; 1];
                self.read_exact_underlying(&mut buf).await?;
                let code = buf[0];
                self.read_exact_underlying(&mut buf).await?;
                let len = buf[0] as usize;
                let mut msg = vec![0u8; len];
                if len > 0 {
                    self.read_exact_underlying(&mut msg).await?;
                }
                let message = String::from_utf8_lossy(&msg).into_owned();
                Err(io::Error::other(AppError { code, message }))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("snell: unknown response code 0x{other:x}"),
            )),
        }
    }

    async fn read_exact_underlying(&mut self, buf: &mut [u8]) -> io::Result<()> {
        // Read directly from the AEAD-decoded stream, bypassing the reply
        // guard (otherwise we'd recurse).
        let mut filled = 0;
        while filled < buf.len() {
            let mut rb = ReadBuf::new(&mut buf[filled..]);
            std::future::poll_fn(|cx| self.inner.poll_read_inner(cx, &mut rb)).await?;
            let n = rb.filled().len();
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell: unexpected EOF reading reply",
                ));
            }
            filled += n;
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Snell<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.peer_half_closed {
            return Poll::Ready(Ok(()));
        }
        if !this.reply_consumed {
            let mut buf = [0u8; 1];
            let mut rb = ReadBuf::new(&mut buf);
            match this.inner.poll_read_inner(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if rb.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell: EOF before reply byte",
                )));
            }
            this.reply_consumed = true;
            match buf[0] {
                RESPONSE_TUNNEL | RESPONSE_PONG => {}
                RESPONSE_ERROR => {
                    return Poll::Ready(Err(io::Error::other(
                        "snell: server returned error response (use read_reply for details)",
                    )));
                }
                other => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("snell: unknown response code 0x{other:x}"),
                    )));
                }
            }
        }
        // Map the zero-chunk into a clean EOF for the caller.
        match this.inner.poll_read_inner(cx, out) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if is_zero_chunk(&e) => {
                this.peer_half_closed = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Snell<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_write_inner(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_flush_inner(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_shutdown_inner(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, DuplexStream};

    /// Wrap an await that could hang so a failure is an assertion instead of
    /// a test-runner timeout.
    async fn within<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("test future timed out")
    }

    /// Client `Snell` wrapper on one duplex half, mock-server `V4Conn` on the
    /// other. The v4 codec is symmetric (each direction sends its own salt),
    /// so a bare `V4Conn` works as the server side.
    fn rig() -> (Snell<DuplexStream>, V4Conn<DuplexStream>) {
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        (Snell::new(a, Arc::clone(&psk)), V4Conn::new(b, psk))
    }

    #[tokio::test]
    async fn write_header_connect_layout() {
        let (mut client, mut peer) = rig();
        within(write_header(&mut client, "example.com", 443, false))
            .await
            .unwrap();
        within(client.flush()).await.unwrap();

        let mut got = [0u8; 17];
        within(peer.read_exact(&mut got)).await.unwrap();
        let mut expected = vec![HEADER_VERSION, COMMAND_CONNECT, 0, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&[0x01, 0xBB]); // 443 BE
        assert_eq!(&got[..], &expected[..]);
    }

    #[tokio::test]
    async fn write_header_reuse_uses_connect_v2() {
        let (mut client, mut peer) = rig();
        within(write_header(&mut client, "example.com", 443, true))
            .await
            .unwrap();
        within(client.flush()).await.unwrap();

        let mut got = [0u8; 17];
        within(peer.read_exact(&mut got)).await.unwrap();
        assert_eq!(got[0], HEADER_VERSION);
        assert_eq!(got[1], COMMAND_CONNECT_V2);
    }

    #[tokio::test]
    async fn write_header_rejects_long_host() {
        let host = "h".repeat(256);
        let mut sink = tokio::io::sink();
        let err = write_header(&mut sink, &host, 80, false).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn read_reply_accepts_tunnel_and_pong() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.flush()).await.unwrap();
        within(client.read_reply()).await.unwrap();

        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_PONG])).await.unwrap();
        within(peer.flush()).await.unwrap();
        within(client.read_reply()).await.unwrap();
    }

    #[tokio::test]
    async fn read_reply_parses_error_code_and_message() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_ERROR, 42, 5, b'o', b'o', b'p', b's', b'!']))
            .await
            .unwrap();
        within(peer.flush()).await.unwrap();

        let err = within(client.read_reply()).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("42"), "missing error code in: {msg}");
        assert!(msg.contains("oops!"), "missing error message in: {msg}");
    }

    #[tokio::test]
    async fn read_reply_rejects_unknown_code() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[0x7F])).await.unwrap();
        within(peer.flush()).await.unwrap();

        let err = within(client.read_reply()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("unknown response code"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn first_read_consumes_reply_then_yields_data() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"hello")).await.unwrap();
        within(peer.flush()).await.unwrap();

        let mut buf = [0u8; 16];
        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Reply already consumed by the first read — explicit call is a no-op.
        within(client.read_reply()).await.unwrap();
    }

    #[tokio::test]
    async fn zero_chunk_maps_to_clean_eof() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.flush()).await.unwrap();
        within(write_zero_chunk(&mut peer)).await.unwrap();

        let mut buf = [0u8; 8];
        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(n, 0, "zero chunk should surface as clean EOF");
    }

    #[tokio::test]
    async fn reset_reply_state_consumes_next_status_byte() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"hello")).await.unwrap();
        within(peer.flush()).await.unwrap();

        let mut buf = [0u8; 16];
        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        client.reset_reply_state();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"again")).await.unwrap();
        within(peer.flush()).await.unwrap();

        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"again");
    }
}
