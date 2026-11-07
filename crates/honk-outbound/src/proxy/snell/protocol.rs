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
use super::v4::{MAX_PAYLOAD_LENGTH, V4Conn, is_zero_chunk as is_v4_zero_chunk};
use super::v6::{MAX_RECORD_PAYLOAD as V6_MAX_RECORD_PAYLOAD, V6Codec, V6Conn};

/// First byte of every Snell request — `0x01` since v1.
pub const HEADER_VERSION: u8 = 1;

pub const COMMAND_CONNECT: u8 = 1;
/// Reuse-capable TCP connect; used when the client maintains a pool or for v6.
pub const COMMAND_CONNECT_V2: u8 = 5;
pub const COMMAND_UDP: u8 = 6;
/// First byte of each UDP-over-TCP request frame.
pub const COMMAND_UDP_FORWARD: u8 = 1;

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

/// UDP-ASSOCIATE request (empty client ID).
pub const UDP_REQUEST: [u8; 3] = [HEADER_VERSION, COMMAND_UDP, 0x00];

/// Write a UDP-ASSOCIATE request header.
pub async fn write_udp_header<W: AsyncWrite + Unpin>(stream: &mut W) -> io::Result<()> {
    stream.write_all(&UDP_REQUEST).await
}

/// Cross-poll state for [`Snell::poll_write_packet_frame`]. One instance per
/// datagram write; caller keeps it alive across `Poll::Pending` returns.
#[derive(Default)]
pub struct PacketFrameProgress {
    staged: bool,
    written: usize,
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
    /// Armed when a packet-frame write starts; cleared only when it runs to
    /// completion. A dropped mid-write future leaves a torn stream.
    frame_write_torn: bool,
}

impl<S: std::fmt::Debug> std::fmt::Debug for Snell<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snell")
            .field("inner", &self.inner)
            .field("reply_consumed", &self.reply_consumed)
            .field("peer_half_closed", &self.peer_half_closed)
            .field("frame_write_torn", &self.frame_write_torn)
            .finish()
    }
}

impl<S> Snell<S> {
    pub fn from_v4(inner: V4Conn<S>) -> Self {
        Self {
            inner: SnellInner::V4(inner),
            reply_consumed: false,
            peer_half_closed: false,
            frame_write_torn: false,
        }
    }

    pub fn from_v3(inner: V3Conn<S>) -> Self {
        Self {
            inner: SnellInner::V3(inner),
            reply_consumed: false,
            peer_half_closed: false,
            frame_write_torn: false,
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
            frame_write_torn: false,
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
            frame_write_torn: false,
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
            frame_write_torn: false,
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

    /// Largest datagram frame the codec carries in one record.
    pub fn max_packet_frame_len(&self) -> usize {
        match &self.inner {
            SnellInner::V3(_) | SnellInner::V4(_) => MAX_PAYLOAD_LENGTH,
            SnellInner::V6(_) => V6_MAX_RECORD_PAYLOAD,
        }
    }

    /// Stage a single frame carrying `buf` verbatim as a UDP datagram payload.
    pub async fn write_packet_frame(&mut self, buf: &[u8]) -> io::Result<usize>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if buf.len() > self.max_packet_frame_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            ));
        }
        self.begin_fresh_frame_write()?;
        let result = self.write_packet_frame_inner(buf).await;
        if result.is_ok() {
            self.frame_write_torn = false;
        }
        result
    }

    fn begin_fresh_frame_write(&mut self) -> io::Result<()> {
        let pending_leftover = match &self.inner {
            SnellInner::V3(conn) => conn.has_pending_write(),
            SnellInner::V4(conn) => conn.has_pending_write(),
            SnellInner::V6(conn) => conn.has_pending_write(),
        };
        if self.frame_write_torn || pending_leftover {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snell: packet conn desynced by an earlier incomplete frame write",
            ));
        }
        self.frame_write_torn = true;
        Ok(())
    }

    async fn write_packet_frame_inner(&mut self, buf: &[u8]) -> io::Result<usize>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if buf.len() > self.max_packet_frame_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            ));
        }
        match &mut self.inner {
            SnellInner::V3(conn) => {
                conn.write_all(buf).await?;
                conn.flush().await?;
            }
            SnellInner::V4(conn) => {
                conn.stage_packet_frame(buf)?;
                std::future::poll_fn(|cx| Pin::new(&mut *conn).poll_flush(cx)).await?;
            }
            SnellInner::V6(conn) => {
                conn.stage_packet_frame(buf)?;
                std::future::poll_fn(|cx| Pin::new(&mut *conn).poll_flush(cx)).await?;
            }
        }
        Ok(buf.len())
    }

    /// Poll-based equivalent of [`Snell::write_packet_frame`] for callers
    /// that release the lock between polls.
    pub fn poll_write_packet_frame(
        &mut self,
        cx: &mut Context<'_>,
        frame: &[u8],
        progress: &mut PacketFrameProgress,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if frame.len() > self.max_packet_frame_len() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            )));
        }
        let resuming = progress.staged || progress.written > 0;
        if !resuming {
            match self.begin_fresh_frame_write() {
                Ok(()) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        match &mut self.inner {
            SnellInner::V3(conn) => {
                progress.staged = true;
                while progress.written < frame.len() {
                    match Pin::new(&mut *conn).poll_write(cx, &frame[progress.written..]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "snell v3: packet frame write returned 0",
                            )));
                        }
                        Poll::Ready(Ok(n)) => progress.written += n,
                    }
                }
                match Pin::new(conn).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        self.frame_write_torn = false;
                        *progress = PacketFrameProgress::default();
                        Poll::Ready(Ok(()))
                    }
                    other => other,
                }
            }
            SnellInner::V4(conn) => {
                if !progress.staged {
                    match conn.stage_packet_frame(frame) {
                        Ok(()) => progress.staged = true,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                match Pin::new(&mut *conn).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
                self.frame_write_torn = false;
                *progress = PacketFrameProgress::default();
                Poll::Ready(Ok(()))
            }
            SnellInner::V6(conn) => {
                if !progress.staged {
                    match conn.stage_packet_frame(frame) {
                        Ok(()) => progress.staged = true,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                match Pin::new(&mut *conn).poll_flush(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
                self.frame_write_torn = false;
                *progress = PacketFrameProgress::default();
                Poll::Ready(Ok(()))
            }
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

    struct FlushGate<S> {
        inner: S,
        blocked: Arc<std::sync::atomic::AtomicBool>,
        flushes: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<S> FlushGate<S> {
        fn new(
            inner: S,
        ) -> (
            Self,
            Arc<std::sync::atomic::AtomicBool>,
            Arc<std::sync::atomic::AtomicUsize>,
        ) {
            let blocked = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let flushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            (
                Self {
                    inner,
                    blocked: Arc::clone(&blocked),
                    flushes: Arc::clone(&flushes),
                },
                blocked,
                flushes,
            )
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for FlushGate<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for FlushGate<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.blocked.load(std::sync::atomic::Ordering::Relaxed) {
                Poll::Pending
            } else {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
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

    #[tokio::test]
    async fn write_udp_header_layout() {
        let (mut client, mut peer) = rig();
        within(write_udp_header(&mut client)).await.unwrap();
        within(client.flush()).await.unwrap();

        let mut got = [0u8; 3];
        within(peer.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, [HEADER_VERSION, COMMAND_UDP, 0x00]);
    }

    #[tokio::test]
    async fn cancelled_packet_frame_write_tears_conn_v4() {
        let (a, _b) = tokio::io::duplex(1 << 10);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let mut client = Snell::new(a, psk);

        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            client.write_packet_frame(&[0xAA; 4096]),
        )
        .await;
        assert!(cancelled.is_err(), "write must have timed out mid-frame");

        let err = within(client.write_packet_frame(b"x")).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(
            err.to_string().contains("desynced"),
            "write after a cancelled write must fail fast, got {err:?}"
        );
    }

    #[tokio::test]
    async fn cancelled_packet_frame_write_tears_conn_v3() {
        let (a, _b) = tokio::io::duplex(1 << 10);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let mut client = Snell::new_v3(a, psk);

        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            client.write_packet_frame(&[0xAA; 4096]),
        )
        .await;
        assert!(cancelled.is_err(), "write must have timed out mid-frame");

        let err = within(client.write_packet_frame(b"x")).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(
            err.to_string().contains("desynced"),
            "write after a cancelled write must fail fast, got {err:?}"
        );
    }

    #[test]
    fn poll_packet_frame_refuses_fresh_progress_on_torn_stream() {
        for versioned in [false, true] {
            let (a, _b) = tokio::io::duplex(1 << 10);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let mut client = if versioned {
                Snell::new_v3(a, psk)
            } else {
                Snell::new(a, psk)
            };
            let mut cx = Context::from_waker(std::task::Waker::noop());

            let frame = vec![0xAA; 4096];
            let mut progress = PacketFrameProgress::default();
            let poll = client.poll_write_packet_frame(&mut cx, &frame, &mut progress);
            assert!(
                matches!(poll, Poll::Pending),
                "v{}: write must park mid-frame on the tiny pipe, got {poll:?}",
                if versioned { 3 } else { 4 }
            );

            let mut fresh = PacketFrameProgress::default();
            match client.poll_write_packet_frame(&mut cx, &frame, &mut fresh) {
                Poll::Ready(Err(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
                    assert!(
                        e.to_string().contains("desynced"),
                        "v{}: expected desync error, got {e}",
                        if versioned { 3 } else { 4 }
                    );
                }
                other => panic!(
                    "v{}: expected desynced error on torn stream, got {other:?}",
                    if versioned { 3 } else { 4 }
                ),
            }

            let poll = client.poll_write_packet_frame(&mut cx, &frame, &mut progress);
            assert!(
                matches!(poll, Poll::Pending),
                "v{}: resume on the undrained pipe must stay Pending, got {poll:?}",
                if versioned { 3 } else { 4 }
            );
        }
    }

    #[test]
    fn torn_flag_alone_refuses_fresh_write_and_resume_retries_flush() {
        use std::sync::atomic::Ordering;
        for versioned in [false, true] {
            let (a, _b) = tokio::io::duplex(1 << 16);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let (gate, blocked, flushes) = FlushGate::new(a);
            let mut client = if versioned {
                Snell::new_v3(gate, psk)
            } else {
                Snell::new(gate, psk)
            };
            let mut cx = Context::from_waker(std::task::Waker::noop());

            let frame = vec![0xAA; 4096];
            let mut progress = PacketFrameProgress::default();
            let poll = client.poll_write_packet_frame(&mut cx, &frame, &mut progress);
            assert!(
                matches!(poll, Poll::Pending),
                "v{}: blocked transport flush must park the write, got {poll:?}",
                if versioned { 3 } else { 4 }
            );

            let mut fresh = PacketFrameProgress::default();
            match client.poll_write_packet_frame(&mut cx, &frame, &mut fresh) {
                Poll::Ready(Err(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
                    assert!(
                        e.to_string().contains("desynced"),
                        "v{}: expected desync error, got {e}",
                        if versioned { 3 } else { 4 }
                    );
                }
                other => panic!(
                    "v{}: torn flag must refuse fresh progress even with empty codec pending, got {other:?}",
                    if versioned { 3 } else { 4 }
                ),
            }

            blocked.store(false, Ordering::Relaxed);
            let poll = client.poll_write_packet_frame(&mut cx, &frame, &mut progress);
            assert!(
                matches!(poll, Poll::Ready(Ok(()))),
                "v{}: resume after flush unblocked must complete, got {poll:?}",
                if versioned { 3 } else { 4 }
            );
            assert!(
                flushes.load(Ordering::Relaxed) >= 2,
                "v{}: resume must retry the transport flush",
                if versioned { 3 } else { 4 }
            );
        }
    }

    #[test]
    fn leftover_codec_pending_refuses_fresh_frame_write() {
        for versioned in [false, true] {
            let (a, _b) = tokio::io::duplex(1 << 10);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let mut client = if versioned {
                Snell::new_v3(a, psk)
            } else {
                Snell::new(a, psk)
            };
            let mut cx = Context::from_waker(std::task::Waker::noop());

            let raw = vec![0xAA; 4096];
            let _ = Pin::new(&mut client).poll_write(&mut cx, &raw);

            let mut fresh = PacketFrameProgress::default();
            match client.poll_write_packet_frame(&mut cx, b"x", &mut fresh) {
                Poll::Ready(Err(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
                    assert!(
                        e.to_string().contains("desynced"),
                        "v{}: expected desync error, got {e}",
                        if versioned { 3 } else { 4 }
                    );
                }
                other => panic!(
                    "v{}: leftover codec pending must refuse fresh progress, got {other:?}",
                    if versioned { 3 } else { 4 }
                ),
            }
        }
    }

    #[test]
    fn resumed_packet_frame_write_completes_with_intact_frame() {
        for versioned in [false, true] {
            let (a, b) = tokio::io::duplex(1 << 10);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let mut client = if versioned {
                Snell::new_v3(a, Arc::clone(&psk))
            } else {
                Snell::new(a, Arc::clone(&psk))
            };
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let frame = vec![0xAB; 4096];
            let mut progress = PacketFrameProgress::default();
            assert!(
                client
                    .poll_write_packet_frame(&mut cx, &frame, &mut progress)
                    .is_pending(),
                "v{}: frame must park on the tiny pipe",
                if versioned { 3 } else { 4 }
            );

            let mut plain = Vec::new();
            let mut scratch = [0u8; 1 << 14];
            let mut completed = false;
            macro_rules! pump {
                ($peer:expr) => {
                    for _ in 0..512 {
                        if !completed {
                            match client.poll_write_packet_frame(&mut cx, &frame, &mut progress) {
                                Poll::Ready(Ok(())) => completed = true,
                                Poll::Ready(Err(e)) => panic!("resume: {e}"),
                                Poll::Pending => {}
                            }
                        }
                        loop {
                            let mut rb = ReadBuf::new(&mut scratch);
                            match Pin::new(&mut $peer).poll_read(&mut cx, &mut rb) {
                                Poll::Ready(Ok(())) => {
                                    if rb.filled().is_empty() {
                                        break;
                                    }
                                    plain.extend_from_slice(rb.filled());
                                }
                                Poll::Ready(Err(e)) => panic!("peer read: {e}"),
                                Poll::Pending => break,
                            }
                        }
                        if completed && plain.len() >= frame.len() {
                            break;
                        }
                    }
                };
            }
            if versioned {
                let mut peer = V3Conn::new(b, psk);
                pump!(peer);
            } else {
                let mut peer = V4Conn::new(b, psk);
                pump!(peer);
            }
            assert!(
                completed,
                "v{}: resumed write never completed",
                if versioned { 3 } else { 4 }
            );
            assert_eq!(
                plain,
                frame,
                "v{}: peer decoded corrupted frame",
                if versioned { 3 } else { 4 }
            );
        }
    }

    #[tokio::test]
    async fn completed_packet_frame_write_leaves_conn_usable() {
        let (mut client, mut peer) = rig();
        within(client.write_packet_frame(b"datagram"))
            .await
            .unwrap();
        within(client.write_packet_frame(b"second")).await.unwrap();

        let mut got = [0u8; 64];
        let n = within(peer.read(&mut got)).await.unwrap();
        assert!(n >= b"datagram".len(), "peer saw {n} bytes");
    }

    #[tokio::test]
    async fn completed_packet_frame_write_leaves_conn_usable_v3() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let mut client = Snell::new_v3(a, Arc::clone(&psk));
        let mut peer = V3Conn::new(b, psk);

        within(client.write_packet_frame(b"datagram"))
            .await
            .unwrap();
        within(client.write_packet_frame(b"second")).await.unwrap();

        let mut got = [0u8; 64];
        let n = within(peer.read(&mut got)).await.unwrap();
        assert!(n >= b"datagram".len(), "peer saw {n} bytes");
    }

    #[tokio::test]
    async fn write_packet_frame_rejects_oversize() {
        let (mut client, _peer) = rig();
        let oversize = vec![0u8; MAX_PAYLOAD_LENGTH + 1];
        let err = within(client.write_packet_frame(&oversize))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        within(client.write_packet_frame(b"after")).await.unwrap();
    }

    #[tokio::test]
    async fn write_packet_frame_roundtrips() {
        let (mut client, mut peer) = rig();
        let n = within(client.write_packet_frame(b"datagram"))
            .await
            .unwrap();
        assert_eq!(n, b"datagram".len());

        let mut buf = [0u8; 64];
        let m = within(peer.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..m], b"datagram");
    }

    #[tokio::test]
    async fn write_packet_frame_v6_larger_frame_limit() {
        let (a, _b) = tokio::io::duplex(1 << 18);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let codec = V6Codec::new(super::super::v6::SnellV6Mode::Default, &psk);
        let mut client = Snell::new_v6(a, Arc::clone(&psk), codec);

        assert_eq!(client.max_packet_frame_len(), V6_MAX_RECORD_PAYLOAD);
        const { assert!(V6_MAX_RECORD_PAYLOAD > MAX_PAYLOAD_LENGTH) };

        let oversize = vec![0u8; V6_MAX_RECORD_PAYLOAD + 1];
        let err = client.write_packet_frame(&oversize).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
