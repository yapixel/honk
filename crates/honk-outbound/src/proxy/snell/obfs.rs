use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const TLS_CHUNK_SIZE: usize = 1 << 14;
const TLS_FIRST_RESPONSE_DISCARD: usize = 105;
const TLS_RECORD_HEADER_DISCARD: usize = 3;

#[derive(Debug)]
pub struct HttpObfs<S> {
    inner: S,
    host: String,
    port: u16,

    first_request: bool,
    write_buf: Vec<u8>,
    write_buf_off: usize,
    pending_input: usize,

    first_response: bool,
    response_scratch: Vec<u8>,
    leftover: Vec<u8>,
    leftover_off: usize,
}

impl<S> HttpObfs<S> {
    pub fn new(inner: S, host: String, port: u16) -> io::Result<Self> {
        if !honk_config::node::is_valid_obfs_host(&host) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "simple-obfs: invalid host (empty, over 253 bytes, or contains whitespace/control bytes)",
            ));
        }
        Ok(Self {
            inner,
            host,
            port,
            first_request: true,
            write_buf: Vec::new(),
            write_buf_off: 0,
            pending_input: 0,
            first_response: true,
            response_scratch: Vec::new(),
            leftover: Vec::new(),
            leftover_off: 0,
        })
    }

    fn build_request(&self, body: &[u8]) -> Vec<u8> {
        build_http_request(&self.host, self.port, body)
    }
}

fn build_http_request(host: &str, port: u16, body: &[u8]) -> Vec<u8> {
    let mut rand_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut rand_bytes);
    let key = base64::engine::general_purpose::URL_SAFE.encode(rand_bytes);

    let host_header = if !host.bytes().all(is_go_valid_host_byte) {
        String::new()
    } else if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    let mut rng = rand::rng();
    let ua_maj = rng.next_u32() % 54;
    let ua_min = rng.next_u32() % 2;

    use std::io::Write;
    let mut req = Vec::with_capacity(256 + body.len());
    let _ = write!(
        req,
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: curl/7.{}.{}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Content-Length: {}\r\n\
         \r\n",
        host_header,
        ua_maj,
        ua_min,
        key,
        body.len()
    );
    req.extend_from_slice(body);
    req
}

fn is_go_valid_host_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!$%&'()*+,-.:;=[]_~".contains(&b) || !b.is_ascii()
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpObfs<S> {
    fn poll_drain_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_buf_off < self.write_buf.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_buf_off..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs: write zero",
                )));
            }
            self.write_buf_off += n;
        }
        self.write_buf.clear();
        self.write_buf_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpObfs<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.leftover_off < this.leftover.len() {
            let avail = &this.leftover[this.leftover_off..];
            let take = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..take]);
            this.leftover_off += take;
            if this.leftover_off >= this.leftover.len() {
                this.leftover.clear();
                this.leftover_off = 0;
            }
            return Poll::Ready(Ok(()));
        }

        if this.first_response {
            const MAX_HEADER: usize = 16 * 1024;
            loop {
                let mut tmp = [0u8; 1024];
                let mut rb = ReadBuf::new(&mut tmp);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                let n = rb.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                this.response_scratch.extend_from_slice(&tmp[..n]);
                if let Some(idx) = find_double_crlf(&this.response_scratch) {
                    this.first_response = false;
                    let body_start = idx + 4;
                    let body = &this.response_scratch[body_start..];
                    let take = body.len().min(buf.remaining());
                    buf.put_slice(&body[..take]);
                    if take < body.len() {
                        this.leftover.extend_from_slice(&body[take..]);
                        this.leftover_off = 0;
                    }
                    this.response_scratch.clear();
                    this.response_scratch.shrink_to_fit();
                    return Poll::Ready(Ok(()));
                }
                if this.response_scratch.len() > MAX_HEADER {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "obfs http: response header exceeds limit",
                    )));
                }
            }
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpObfs<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
            let consumed = this.pending_input;
            this.pending_input = 0;
            return Poll::Ready(Ok(consumed));
        }

        if this.first_request {
            this.first_request = false;
            let req = this.build_request(buf);
            this.write_buf = req;
            this.write_buf_off = 0;
            this.pending_input = buf.len();
            match this.poll_drain_write_buf(cx) {
                Poll::Ready(Ok(())) => {
                    let consumed = this.pending_input;
                    this.pending_input = 0;
                    Poll::Ready(Ok(consumed))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn find_double_crlf(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    for i in 0..=data.len() - 4 {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum TlsReadPhase {
    Discard(usize),
    Length,
    Payload(usize),
}

#[derive(Debug)]
pub struct TlsObfs<S> {
    inner: S,
    server: String,

    first_response: bool,
    read_phase: TlsReadPhase,
    len_buf: [u8; 2],
    len_progress: usize,

    first_request: bool,
    write_buf: Vec<u8>,
    write_buf_off: usize,
    pending_input: usize,
}

impl<S> TlsObfs<S> {
    pub fn new(inner: S, server: String) -> io::Result<Self> {
        if !honk_config::node::is_valid_obfs_host(&server) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tls-obfs: invalid server (empty, over 253 bytes, or contains whitespace/control bytes)",
            ));
        }
        Ok(Self {
            inner,
            server,
            first_response: true,
            read_phase: TlsReadPhase::Discard(TLS_FIRST_RESPONSE_DISCARD),
            len_buf: [0u8; 2],
            len_progress: 0,
            first_request: true,
            write_buf: Vec::new(),
            write_buf_off: 0,
            pending_input: 0,
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsObfs<S> {
    fn poll_drain_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_buf_off < self.write_buf.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_buf_off..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs: write zero",
                )));
            }
            self.write_buf_off += n;
        }
        self.write_buf.clear();
        self.write_buf_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsObfs<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_phase {
                TlsReadPhase::Discard(0) => {
                    this.read_phase = TlsReadPhase::Length;
                    this.len_progress = 0;
                }
                TlsReadPhase::Discard(remaining) => {
                    let mut tmp = [0u8; 256];
                    let take = remaining.min(tmp.len());
                    let mut rb = ReadBuf::new(&mut tmp[..take]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.read_phase = TlsReadPhase::Discard(remaining - n);
                }
                TlsReadPhase::Length => {
                    if this.len_progress >= 2 {
                        let length =
                            u16::from_be_bytes([this.len_buf[0], this.len_buf[1]]) as usize;
                        this.read_phase = TlsReadPhase::Payload(length);
                        continue;
                    }
                    let mut tmp = [0u8; 2];
                    let need = 2 - this.len_progress;
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.len_buf[this.len_progress..this.len_progress + n]
                        .copy_from_slice(&tmp[..n]);
                    this.len_progress += n;
                }
                TlsReadPhase::Payload(0) => {
                    this.read_phase = TlsReadPhase::Discard(TLS_RECORD_HEADER_DISCARD);
                    this.first_response = false;
                }
                TlsReadPhase::Payload(remaining) => {
                    let space = buf.remaining().min(remaining);
                    if space == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let added = {
                        let unfilled = buf.initialize_unfilled();
                        let mut rb = ReadBuf::new(&mut unfilled[..space]);
                        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                        rb.filled().len()
                    };
                    if added == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    buf.advance(added);
                    this.read_phase = TlsReadPhase::Payload(remaining - added);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsObfs<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
            let consumed = this.pending_input;
            this.pending_input = 0;
            return Poll::Ready(Ok(consumed));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(TLS_CHUNK_SIZE);
        let chunk = &buf[..take];

        if this.first_request {
            this.first_request = false;
            this.write_buf = build_client_hello(chunk, &this.server);
        } else {
            let mut framed = Vec::with_capacity(5 + chunk.len());
            framed.extend_from_slice(&[0x17, 0x03, 0x03]);
            framed.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            framed.extend_from_slice(chunk);
            this.write_buf = framed;
        }
        this.write_buf_off = 0;
        this.pending_input = take;

        match this.poll_drain_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                let consumed = this.pending_input;
                this.pending_input = 0;
                Poll::Ready(Ok(consumed))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            ready!(this.poll_drain_write_buf(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn build_client_hello(data: &[u8], server: &str) -> Vec<u8> {
    debug_assert!(server.len() <= 253, "SNI host exceeds u16-safe length");
    let mut random = [0u8; 28];
    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    rand::rng().fill_bytes(&mut session_id);

    let server_bytes = server.as_bytes();
    let data_len = data.len();
    let server_len = server_bytes.len();

    let mut buf = Vec::with_capacity(256 + data_len + server_len);

    buf.push(0x16);
    buf.extend_from_slice(&[0x03, 0x01]);
    let record_len = 212u16 + data_len as u16 + server_len as u16;
    buf.extend_from_slice(&record_len.to_be_bytes());

    buf.push(0x01);
    buf.push(0x00);
    let handshake_len = 208u16 + data_len as u16 + server_len as u16;
    buf.extend_from_slice(&handshake_len.to_be_bytes());

    buf.extend_from_slice(&[0x03, 0x03]);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32);
    buf.extend_from_slice(&now.to_be_bytes());
    buf.extend_from_slice(&random);

    buf.push(32);
    buf.extend_from_slice(&session_id);

    buf.extend_from_slice(&[0x00, 0x38]);
    buf.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);

    buf.extend_from_slice(&[0x01, 0x00]);

    let ext_len = 79u16 + data_len as u16 + server_len as u16;
    buf.extend_from_slice(&ext_len.to_be_bytes());

    buf.extend_from_slice(&[0x00, 0x23]);
    buf.extend_from_slice(&(data_len as u16).to_be_bytes());
    buf.extend_from_slice(data);

    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&((server_len as u16) + 5).to_be_bytes());
    buf.extend_from_slice(&((server_len as u16) + 3).to_be_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&(server_len as u16).to_be_bytes());
    buf.extend_from_slice(server_bytes);

    buf.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);

    buf.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);

    buf.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);

    buf.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn http_request_contains_body_and_headers() {
        let body = b"hello world";
        let req = build_http_request("example.com", 80, body);
        let s = std::str::from_utf8(&req[..req.len() - body.len()]).unwrap();
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(!s.contains("Host: example.com:80\r\n"));
        assert!(s.contains("Upgrade: websocket\r\n"));
        assert!(s.contains("Connection: Upgrade\r\n"));
        assert!(s.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(s.contains("Sec-WebSocket-Key: "));
        assert!(s.ends_with("\r\n\r\n"));
        assert_eq!(&req[req.len() - body.len()..], body);
    }

    #[test]
    fn http_request_uses_host_port_when_not_80() {
        let req = build_http_request("example.com", 8080, b"x");
        let s = std::str::from_utf8(&req).unwrap();
        assert!(s.contains("Host: example.com:8080\r\n"));
    }

    #[test]
    fn http_request_blanks_host_go_would_reject() {
        for (host, port) in [
            ("/", 8443),
            ("/", 80),
            ("a/b", 443),
            ("a?b", 80),
            ("a@b", 80),
        ] {
            let req = build_http_request(host, port, b"x");
            let s = std::str::from_utf8(&req).unwrap();
            assert!(
                s.contains("\r\nHost: \r\nUser-Agent: "),
                "{host:?}:{port}: {s:?}"
            );
        }
        for (host, want) in [
            ("[::1]", "Host: [::1]:8443\r\n"),
            ("例え.jp", "Host: 例え.jp:8443\r\n"),
            ("a_b-c.example", "Host: a_b-c.example:8443\r\n"),
        ] {
            let req = build_http_request(host, 8443, b"x");
            let s = std::str::from_utf8(&req).unwrap();
            assert!(s.contains(want), "{host:?}: {s:?}");
        }
    }

    #[test]
    fn tls_client_hello_layout_matches_reference() {
        let data = b"the secret payload";
        let server = "example.com";
        let hello = build_client_hello(data, server);

        assert_eq!(hello[0], 0x16);
        assert_eq!(&hello[1..3], &[0x03, 0x01]);
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5);
        assert_eq!(record_len, 212 + data.len() + server.len());

        assert_eq!(hello[5], 0x01);
        assert_eq!(hello[6], 0x00);
        let handshake_len = u16::from_be_bytes([hello[7], hello[8]]) as usize;
        assert_eq!(handshake_len, 208 + data.len() + server.len());

        assert_eq!(&hello[9..11], &[0x03, 0x03]);
        assert_eq!(hello[43], 32);

        assert!(hello.windows(data.len()).any(|w| w == data));
        assert!(hello.windows(server.len()).any(|w| w == server.as_bytes()));
    }

    #[test]
    fn obfs_host_predicate_rejects_injectable_and_oversized() {
        assert!(honk_config::node::is_valid_obfs_host("example.com"));
        assert!(honk_config::node::is_valid_obfs_host(&"a".repeat(253)));
        for bad in [
            "", "a b", "a\tb", "a\rb", "a\nb", "a\0b", "a\x7fb", "a\u{1f}b",
        ] {
            assert!(
                !honk_config::node::is_valid_obfs_host(bad),
                "{bad:?} must be rejected"
            );
        }
        assert!(!honk_config::node::is_valid_obfs_host(&"a".repeat(254)));
        assert!(honk_config::node::is_valid_obfs_host("例え.jp"));

        let (s, _p) = tokio::io::duplex(64);
        assert!(HttpObfs::new(s, "a\rb".to_string(), 80).is_err());
    }

    #[tokio::test]
    async fn http_obfs_first_write_then_passthrough() {
        let (client, mut server) = tokio::io::duplex(8192);
        let mut obfs = HttpObfs::new(client, "example.com".to_string(), 80).unwrap();

        obfs.write_all(b"PAYLOAD1").await.unwrap();
        obfs.write_all(b"PAYLOAD2").await.unwrap();
        obfs.flush().await.unwrap();

        let mut received = vec![0u8; 4096];
        let mut total = 0;
        while total < 16 {
            let n = server.read(&mut received[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        let received = &received[..total];
        let s = std::str::from_utf8(received).unwrap_or("");
        assert!(s.starts_with("GET / HTTP/1.1\r\n"), "got: {s:?}");
        let idx = received
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header terminator");
        let after = &received[idx + 4..];
        assert!(after.starts_with(b"PAYLOAD1"));
        assert!(after.ends_with(b"PAYLOAD2"));
    }

    #[tokio::test]
    async fn http_obfs_strips_first_response_headers() {
        let (client, mut server) = tokio::io::duplex(8192);
        let mut obfs = HttpObfs::new(client, "example.com".to_string(), 80).unwrap();

        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                        Server: nginx\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\
                        \r\nHELLO_BODY_BYTES";
        server.write_all(response).await.unwrap();
        server.write_all(b"_AND_MORE").await.unwrap();
        drop(server);

        let mut got = Vec::new();
        obfs.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"HELLO_BODY_BYTES_AND_MORE");
    }

    #[tokio::test]
    async fn tls_obfs_write_first_then_chunks() {
        let (client, mut server) = tokio::io::duplex(65536);
        let mut obfs = TlsObfs::new(client, "example.com".to_string()).unwrap();

        obfs.write_all(b"FIRST").await.unwrap();
        obfs.write_all(b"SECOND").await.unwrap();
        obfs.flush().await.unwrap();

        let mut buf = vec![0u8; 4096];
        let mut total = 0;
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                server.read(&mut buf[total..]),
            )
            .await
            .unwrap()
            .unwrap();
            if n == 0 {
                break;
            }
            total += n;
            if total >= 5 + 11 {
                break;
            }
        }
        let received = &buf[..total];

        assert_eq!(received[0], 0x16);
        assert_eq!(&received[1..3], &[0x03, 0x01]);
        let rec_len = u16::from_be_bytes([received[3], received[4]]) as usize;
        let hello_end = 5 + rec_len;

        assert!(
            received[..hello_end]
                .windows(b"FIRST".len())
                .any(|w| w == b"FIRST")
        );

        let after = &received[hello_end..];
        assert_eq!(after[0], 0x17);
        assert_eq!(&after[1..3], &[0x03, 0x03]);
        let len = u16::from_be_bytes([after[3], after[4]]) as usize;
        assert_eq!(len, b"SECOND".len());
        assert_eq!(&after[5..5 + len], b"SECOND");
    }

    #[tokio::test]
    async fn tls_obfs_read_strips_framing() {
        let (client, mut server) = tokio::io::duplex(65536);
        let mut obfs = TlsObfs::new(client, "example.com".to_string()).unwrap();

        let mut server_msg = vec![0xAAu8; TLS_FIRST_RESPONSE_DISCARD];
        let payload1 = b"hello-from-server";
        server_msg.extend_from_slice(&(payload1.len() as u16).to_be_bytes());
        server_msg.extend_from_slice(payload1);

        let payload2 = b"second-frame";
        server_msg.extend_from_slice(&[0x17, 0x03, 0x03]);
        server_msg.extend_from_slice(&(payload2.len() as u16).to_be_bytes());
        server_msg.extend_from_slice(payload2);

        server.write_all(&server_msg).await.unwrap();
        drop(server);

        let mut got = Vec::new();
        obfs.read_to_end(&mut got).await.unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(payload1);
        expected.extend_from_slice(payload2);
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn tls_obfs_round_trip_through_two_wrappers() {
        let (a, mut b) = tokio::io::duplex(65536);
        let mut a_obfs = TlsObfs::new(a, "example.com".to_string()).unwrap();

        a_obfs.write_all(b"first-msg").await.unwrap();
        a_obfs.write_all(b"second-msg").await.unwrap();
        a_obfs.shutdown().await.unwrap();
        drop(a_obfs);

        let mut wire = Vec::new();
        b.read_to_end(&mut wire).await.unwrap();
        let wire = wire.as_slice();

        assert_eq!(wire[0], 0x16);
        let rec_len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        let handshake = &wire[5..5 + rec_len];
        assert!(handshake.windows(9).any(|w| w == b"first-msg"));

        let app = &wire[5 + rec_len..];
        assert_eq!(app[0], 0x17);
        let len = u16::from_be_bytes([app[3], app[4]]) as usize;
        assert_eq!(&app[5..5 + len], b"second-msg");
    }
}
