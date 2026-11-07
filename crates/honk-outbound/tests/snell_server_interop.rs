//! End-to-end integration tests for Snell outbound (v3, v4, v5, v6) against official
//! snell-server Docker containers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use honk_config::node::{Node, OutboundConfig, SnellConfig};
use honk_outbound::proxy::snell::SnellHandler;
use honk_outbound::proxy::{PacketOutbound, PacketTransport, TcpOutbound};
use honk_outbound::runtime::NodeRuntime;

// tag 3.0.1
const IMAGE_SNELL_V3: &str =
    "geekdada/snell-server@sha256:d7368c7d145b370255827c8f22a5ebc4a649b56426c6c36a9914a1bca0d409f0";
// tag 4.1.1
const IMAGE_SNELL_V4: &str =
    "geekdada/snell-server@sha256:d893d1f22a308d39975252543dc5ec214a9618e266bb70cae785a673c0db3210";
// tag 5.0.1
const IMAGE_SNELL_V5: &str =
    "geekdada/snell-server@sha256:d79bd3405c58c3122c28e0f7533f1cdc0f3cebfe5b7fc80f08ad04070ca5ff6a";
// tag 6.0.0
const IMAGE_SNELL_V6: &str =
    "geekdada/snell-server@sha256:37ebe56a46b7509e2bcd32a6b80b76aab77fa69663bc56b9f5d2c6dc9a30570f";

const PSK: &str = "honk-snell-docker-psk";
const T: Duration = Duration::from_secs(30);

fn ensure_docker() {
    let available = std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !available {
        panic!("docker is unavailable: docker info failed or docker not installed");
    }
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct SnellContainer {
    name: String,
    _port: u16,
    _temp_dir: TempDir,
}

impl SnellContainer {
    fn start(port: u16, image: &str, extra_config: &str) -> Self {
        ensure_docker();

        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let container_name = format!("honk-snell-{}-{}-{}", std::process::id(), id, port);

        let temp_dir = TempDir::new(&container_name);
        let config_path = temp_dir.path().join("snell-server.conf");
        let mut conf =
            format!("[snell-server]\nlisten = 127.0.0.1:{port}\npsk = {PSK}\nipv6 = false\n");
        if !extra_config.is_empty() {
            conf.push_str(extra_config);
            if !extra_config.ends_with('\n') {
                conf.push('\n');
            }
        }
        std::fs::write(&config_path, conf).expect("write snell-server.conf");

        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &container_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        let config_str = config_path.canonicalize().unwrap_or(config_path);
        let status = std::process::Command::new("docker")
            .args([
                "run",
                "-d",
                "--network",
                "host",
                "--name",
                &container_name,
                // The image's /start.sh writes its own config from env vars; run the binary on ours.
                "--entrypoint",
                "/usr/bin/snell-server",
                "-v",
                &format!("{}:/etc/snell-server.conf:ro", config_str.display()),
                image,
                "-c",
                "/etc/snell-server.conf",
            ])
            .status();
        if !status.as_ref().is_ok_and(|s| s.success()) {
            panic!("docker run failed for container {container_name}: {status:?}");
        }

        Self {
            name: container_name,
            _port: port,
            _temp_dir: temp_dir,
        }
    }

    fn logs(&self) -> String {
        let out = std::process::Command::new("docker")
            .args(["logs", &self.name])
            .output();
        match out {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                format!(
                    "snell container logs ({})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
                    self.name
                )
            }
            Err(e) => format!("failed to read logs for {}: {e}", self.name),
        }
    }
}

impl Drop for SnellContainer {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("{}", self.logs());
        }
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

async fn wait_until_listening(server: &SnellContainer, port: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !tokio::time::timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map(|res| res.is_ok())
    .unwrap_or(false)
    {
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "snell-server never listened on port {port}\n{}",
                server.logs()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn start_tcp_echo_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let Ok((mut stream, _)) = res else { break; };
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });
    (addr, shutdown_tx)
}

async fn start_reply_after_eof_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let Ok((mut stream, _)) = res else { break; };
                    tokio::spawn(async move {
                        let mut request = Vec::new();
                        if stream.read_to_end(&mut request).await.is_ok() {
                            let _ = stream.write_all(&request).await;
                            let _ = stream.shutdown().await;
                        }
                    });
                }
            }
        }
    });
    (addr, shutdown_tx)
}

async fn start_udp_echo_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let s = Arc::clone(&socket);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = s.recv_from(&mut buf) => {
                    let Ok((n, peer)) = res else { break; };
                    let _ = s.send_to(&buf[..n], peer).await;
                }
            }
        }
    });
    (addr, shutdown_tx)
}

struct CountingForwarder {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl CountingForwarder {
    async fn start(target_port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

        let accepts_clone = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    res = listener.accept() => {
                        let Ok((mut client, _)) = res else { break; };
                        accepts_clone.fetch_add(1, Ordering::SeqCst);
                        tokio::spawn(async move {
                            if let Ok(mut server) =
                                tokio::net::TcpStream::connect(("127.0.0.1", target_port)).await
                            {
                                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                            }
                        });
                    }
                }
            }
        });

        Self {
            addr,
            accepts,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    fn accept_count(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for CountingForwarder {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

fn patterned(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251) as u8 ^ seed.wrapping_mul(31))
        .collect()
}

async fn bulk_echo<S>(stream: &mut S, payload: &[u8], server: &SnellContainer)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(&mut *stream);
    let write = async {
        wr.write_all(payload).await?;
        wr.flush().await
    };
    let read = async {
        let mut echoed = vec![0u8; payload.len()];
        rd.read_exact(&mut echoed).await.map(|_| echoed)
    };
    let (written, echoed) = tokio::time::timeout(T, async { tokio::join!(write, read) })
        .await
        .unwrap_or_else(|_| panic!("bulk echo timed out\n{}", server.logs()));
    written.unwrap_or_else(|e| panic!("bulk write failed: {e}\n{}", server.logs()));
    let echoed = echoed.unwrap_or_else(|e| panic!("bulk read failed: {e}\n{}", server.logs()));
    assert_eq!(&echoed, payload, "bulk echo corrupted the payload");

    tokio::time::timeout(T, stream.shutdown())
        .await
        .expect("shutdown timed out")
        .unwrap_or_else(|e| panic!("shutdown failed: {e}\n{}", server.logs()));
    let mut tail = Vec::new();
    tokio::time::timeout(T, stream.read_to_end(&mut tail))
        .await
        .unwrap_or_else(|_| panic!("EOF after half-close timed out\n{}", server.logs()))
        .unwrap_or_else(|e| panic!("EOF read failed: {e}\n{}", server.logs()));
    assert!(tail.is_empty(), "unexpected bytes after the echo");
}

async fn reply_after_eof<S>(stream: &mut S, payload: &[u8], server: &SnellContainer)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(T, stream.write_all(payload))
        .await
        .expect("write timed out")
        .unwrap_or_else(|e| panic!("write failed: {e}\n{}", server.logs()));
    tokio::time::timeout(T, stream.flush())
        .await
        .expect("flush timed out")
        .unwrap_or_else(|e| panic!("flush failed: {e}\n{}", server.logs()));
    tokio::time::timeout(T, stream.shutdown())
        .await
        .expect("shutdown timed out")
        .unwrap_or_else(|e| panic!("shutdown failed: {e}\n{}", server.logs()));
    let mut reply = Vec::new();
    tokio::time::timeout(T, stream.read_to_end(&mut reply))
        .await
        .unwrap_or_else(|_| panic!("reply after half-close timed out\n{}", server.logs()))
        .unwrap_or_else(|e| panic!("reply read failed: {e}\n{}", server.logs()));
    assert_eq!(reply.len(), payload.len(), "short reply after half-close");
    assert_eq!(&reply, payload, "reply after half-close corrupted");
}

async fn udp_echo_round_trips(
    packets: &dyn PacketTransport,
    echo: SocketAddr,
    lens: &[usize],
    server: &SnellContainer,
) {
    const ATTEMPTS: u8 = 3;
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
    let mut buf = vec![0u8; 64 * 1024];
    let mut unanswered = Vec::new();
    'datagrams: for (i, &len) in (0u8..).zip(lens) {
        for attempt in 0..ATTEMPTS {
            let datagram = patterned(len, 3 + i * ATTEMPTS + attempt);
            tokio::time::timeout(T, packets.send_packet(&datagram))
                .await
                .expect("udp write timed out")
                .unwrap_or_else(|e| panic!("udp write failed: {e}\n{}", server.logs()));
            let deadline = tokio::time::Instant::now() + ATTEMPT_TIMEOUT;
            while let Ok(read) =
                tokio::time::timeout_at(deadline, packets.recv_packet(&mut buf)).await
            {
                let (n, src) =
                    read.unwrap_or_else(|e| panic!("udp read failed: {e}\n{}", server.logs()));
                assert_eq!(src, echo);
                if buf[..n] == datagram[..] {
                    continue 'datagrams;
                }
                assert!(
                    unanswered.iter().any(|sent: &Vec<u8>| buf[..n] == sent[..]),
                    "udp datagram of {len} B changed"
                );
            }
            unanswered.push(datagram);
        }
        panic!(
            "udp echo of {len} B timed out after {ATTEMPTS} attempts\n{}",
            server.logs()
        );
    }
}

fn make_node(
    server_port: u16,
    version: u8,
    mode: Option<&str>,
    reuse: bool,
    obfs: Option<&str>,
) -> Node {
    let mut node = Node {
        name: format!("snell-v{version}-{server_port}"),
        address: format!("127.0.0.1:{server_port}"),
        host: "127.0.0.1".to_string(),
        port: server_port,
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(version),
            mode: mode.map(str::to_string),
            network: Some("tcp,udp".to_string()),
            reuse: Some(reuse),
            obfs: obfs.map(str::to_string),
            obfs_host: None,
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

async fn verify_reuse(
    server_port: u16,
    version: u8,
    mode: Option<&str>,
    server: &SnellContainer,
    check_no_reuse: bool,
) {
    let handler = SnellHandler::new();
    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;

    // Sequential sessions with snell_reuse = true -> accept count 1
    let forwarder = CountingForwarder::start(server_port).await;
    let node_reused = make_node(forwarder.port(), version, mode, true, None);
    let runtime_reused = NodeRuntime::try_ephemeral(&node_reused).unwrap();

    // Session 1
    {
        let mut stream1 = tokio::time::timeout(
            T,
            handler.dial_runtime(
                Arc::clone(&runtime_reused),
                tcp_echo,
                None,
                Duration::from_secs(5),
            ),
        )
        .await
        .expect("dial reuse session 1 timed out")
        .unwrap_or_else(|e| panic!("dial reuse session 1 failed: {e}\n{}", server.logs()));

        bulk_echo(&mut stream1.stream, &patterned(20 * 1024, 11), server).await;
    }

    // Session 2 over the reused connection
    {
        let mut stream2 = tokio::time::timeout(
            T,
            handler.dial_runtime(
                Arc::clone(&runtime_reused),
                tcp_echo,
                None,
                Duration::from_secs(5),
            ),
        )
        .await
        .expect("dial reuse session 2 timed out")
        .unwrap_or_else(|e| panic!("dial reuse session 2 failed: {e}\n{}", server.logs()));

        bulk_echo(&mut stream2.stream, &patterned(20 * 1024, 12), server).await;
    }

    assert_eq!(
        forwarder.accept_count(),
        1,
        "two sequential sessions with snell_reuse=true must share one connection (accept count 1)\n{}",
        server.logs()
    );

    if check_no_reuse {
        // Sequential sessions with snell_reuse = false -> accept count 2
        let forwarder_no_reuse = CountingForwarder::start(server_port).await;
        let node_no_reuse = make_node(forwarder_no_reuse.port(), version, mode, false, None);
        let runtime_no_reuse = NodeRuntime::try_ephemeral(&node_no_reuse).unwrap();

        // Session 1
        {
            let mut stream1 = tokio::time::timeout(
                T,
                handler.dial_runtime(
                    Arc::clone(&runtime_no_reuse),
                    tcp_echo,
                    None,
                    Duration::from_secs(5),
                ),
            )
            .await
            .expect("dial no-reuse session 1 timed out")
            .unwrap_or_else(|e| panic!("dial no-reuse session 1 failed: {e}\n{}", server.logs()));

            bulk_echo(&mut stream1.stream, &patterned(20 * 1024, 21), server).await;
        }

        // Session 2
        {
            let mut stream2 = tokio::time::timeout(
                T,
                handler.dial_runtime(
                    Arc::clone(&runtime_no_reuse),
                    tcp_echo,
                    None,
                    Duration::from_secs(5),
                ),
            )
            .await
            .expect("dial no-reuse session 2 timed out")
            .unwrap_or_else(|e| panic!("dial no-reuse session 2 failed: {e}\n{}", server.logs()));

            bulk_echo(&mut stream2.stream, &patterned(20 * 1024, 22), server).await;
        }

        assert_eq!(
            forwarder_no_reuse.accept_count(),
            2,
            "two sequential sessions with snell_reuse=false must open two connections (accept count 2)\n{}",
            server.logs()
        );
    }
}

async fn v6_round_trips(mode: &str) {
    let port = free_tcp_port();
    let server = SnellContainer::start(port, IMAGE_SNELL_V6, &format!("mode = {mode}\n"));
    wait_until_listening(&server, port).await;

    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
    let (eof_reply, _eof_h) = start_reply_after_eof_server().await;
    let (udp_echo, _udp_h) = start_udp_echo_server().await;

    let handler = SnellHandler::new();
    let node = make_node(port, 6, Some(mode), false, None);
    let runtime = NodeRuntime::try_ephemeral(&node).unwrap();

    let mut stream = tokio::time::timeout(
        T,
        handler.dial_runtime(Arc::clone(&runtime), tcp_echo, None, Duration::from_secs(5)),
    )
    .await
    .expect("dial tcp echo timed out")
    .unwrap_or_else(|e| panic!("dial tcp echo failed: {e}\n{}", server.logs()));
    bulk_echo(&mut stream.stream, &patterned(20 * 1024, 1), &server).await;

    let mut stream = tokio::time::timeout(
        T,
        handler.dial_runtime(
            Arc::clone(&runtime),
            eof_reply,
            None,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("dial reply-after-eof timed out")
    .unwrap_or_else(|e| panic!("dial reply-after-eof failed: {e}\n{}", server.logs()));
    reply_after_eof(&mut stream.stream, &patterned(20 * 1024, 2), &server).await;

    let packets = tokio::time::timeout(
        T,
        handler.dial_udp_transport_runtime(
            Arc::clone(&runtime),
            udp_echo,
            None,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("udp dial timed out")
    .unwrap_or_else(|e| panic!("udp dial failed: {e}\n{}", server.logs()));
    udp_echo_round_trips(&*packets, udp_echo, &[21, 1400, 20_000], &server).await;

    verify_reuse(port, 6, Some(mode), &server, false).await;
}

#[tokio::test]
#[ignore = "needs docker and snell-server images; run by .github/workflows/snell-interop.yml"]
async fn snell_v3_docker_interop() {
    let port = free_tcp_port();
    let server = SnellContainer::start(port, IMAGE_SNELL_V3, "obfs = off\n");
    wait_until_listening(&server, port).await;

    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
    let (eof_reply, _eof_h) = start_reply_after_eof_server().await;
    let (udp_echo, _udp_h) = start_udp_echo_server().await;

    let handler = SnellHandler::new();
    let node = make_node(port, 3, None, false, None);
    let runtime = NodeRuntime::try_ephemeral(&node).unwrap();

    let mut stream = tokio::time::timeout(
        T,
        handler.dial_runtime(Arc::clone(&runtime), tcp_echo, None, Duration::from_secs(5)),
    )
    .await
    .expect("dial tcp echo timed out")
    .unwrap_or_else(|e| panic!("dial tcp echo failed: {e}\n{}", server.logs()));
    bulk_echo(&mut stream.stream, &patterned(20 * 1024, 1), &server).await;

    let mut stream = tokio::time::timeout(
        T,
        handler.dial_runtime(
            Arc::clone(&runtime),
            eof_reply,
            None,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("dial reply-after-eof timed out")
    .unwrap_or_else(|e| panic!("dial reply-after-eof failed: {e}\n{}", server.logs()));
    reply_after_eof(&mut stream.stream, &patterned(20 * 1024, 2), &server).await;

    let packets = tokio::time::timeout(
        T,
        handler.dial_udp_transport_runtime(
            Arc::clone(&runtime),
            udp_echo,
            None,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("udp dial timed out")
    .unwrap_or_else(|e| panic!("udp dial failed: {e}\n{}", server.logs()));
    udp_echo_round_trips(&*packets, udp_echo, &[21, 1400], &server).await;
}

#[tokio::test]
#[ignore = "needs docker and snell-server images; run by .github/workflows/snell-interop.yml"]
async fn snell_v4_docker_interop() {
    let port = free_tcp_port();
    let server = SnellContainer::start(port, IMAGE_SNELL_V4, "obfs = off\n");
    wait_until_listening(&server, port).await;

    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
    let (eof_reply, _eof_h) = start_reply_after_eof_server().await;
    let (udp_echo, _udp_h) = start_udp_echo_server().await;

    let handler = SnellHandler::new();
    let node = make_node(port, 4, None, false, None);
    let runtime = NodeRuntime::try_ephemeral(&node).unwrap();

    let mut stream = tokio::time::timeout(
        T,
        handler.dial_runtime(Arc::clone(&runtime), tcp_echo, None, Duration::from_secs(5)),
    )
    .await
    .expect("dial tcp echo timed out")
    .unwrap_or_else(|e| panic!("dial tcp echo failed: {e}\n{}", server.logs()));
    bulk_echo(&mut stream.stream, &patterned(20 * 1024, 1), &server).await;

    let mut stream = tokio::time::timeout(
        T,
        handler.dial_runtime(
            Arc::clone(&runtime),
            eof_reply,
            None,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("dial reply-after-eof timed out")
    .unwrap_or_else(|e| panic!("dial reply-after-eof failed: {e}\n{}", server.logs()));
    reply_after_eof(&mut stream.stream, &patterned(20 * 1024, 2), &server).await;

    let packets = tokio::time::timeout(
        T,
        handler.dial_udp_transport_runtime(
            Arc::clone(&runtime),
            udp_echo,
            None,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("udp dial timed out")
    .unwrap_or_else(|e| panic!("udp dial failed: {e}\n{}", server.logs()));
    udp_echo_round_trips(&*packets, udp_echo, &[21, 1400, 16_000], &server).await;

    verify_reuse(port, 4, None, &server, true).await;
}

#[tokio::test]
#[ignore = "needs docker and snell-server images; run by .github/workflows/snell-interop.yml"]
async fn snell_v4_obfs_http_docker_interop() {
    let port = free_tcp_port();
    let server = SnellContainer::start(port, IMAGE_SNELL_V4, "obfs = http\n");
    wait_until_listening(&server, port).await;

    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
    let (udp_echo, _udp_h) = start_udp_echo_server().await;

    let handler = SnellHandler::new();
    let node = make_node(port, 4, None, false, Some("http"));
    let runtime = NodeRuntime::try_ephemeral(&node).unwrap();

    let mut stream = tokio::time::timeout(
        T,
        handler.dial_runtime(Arc::clone(&runtime), tcp_echo, None, Duration::from_secs(5)),
    )
    .await
    .expect("dial tcp echo timed out")
    .unwrap_or_else(|e| panic!("dial tcp echo failed: {e}\n{}", server.logs()));
    bulk_echo(&mut stream.stream, &patterned(20 * 1024, 1), &server).await;

    let packets = tokio::time::timeout(
        T,
        handler.dial_udp_transport_runtime(
            Arc::clone(&runtime),
            udp_echo,
            None,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("udp dial timed out")
    .unwrap_or_else(|e| panic!("udp dial failed: {e}\n{}", server.logs()));
    udp_echo_round_trips(&*packets, udp_echo, &[21, 1400], &server).await;
}

#[tokio::test]
#[ignore = "needs docker and snell-server images; run by .github/workflows/snell-interop.yml"]
async fn snell_v5_docker_interop() {
    let port = free_tcp_port();
    let server = SnellContainer::start(port, IMAGE_SNELL_V5, "obfs = off\n");
    wait_until_listening(&server, port).await;

    let (tcp_echo, _tcp_h) = start_tcp_echo_server().await;
    let (eof_reply, _eof_h) = start_reply_after_eof_server().await;
    let (udp_echo, _udp_h) = start_udp_echo_server().await;

    let handler = SnellHandler::new();
    let node = make_node(port, 5, None, false, None);
    let runtime = NodeRuntime::try_ephemeral(&node).unwrap();

    let mut stream = tokio::time::timeout(
        T,
        handler.dial_runtime(Arc::clone(&runtime), tcp_echo, None, Duration::from_secs(5)),
    )
    .await
    .expect("dial tcp echo timed out")
    .unwrap_or_else(|e| panic!("dial tcp echo failed: {e}\n{}", server.logs()));
    bulk_echo(&mut stream.stream, &patterned(20 * 1024, 1), &server).await;

    let mut stream = tokio::time::timeout(
        T,
        handler.dial_runtime(
            Arc::clone(&runtime),
            eof_reply,
            None,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("dial reply-after-eof timed out")
    .unwrap_or_else(|e| panic!("dial reply-after-eof failed: {e}\n{}", server.logs()));
    reply_after_eof(&mut stream.stream, &patterned(20 * 1024, 2), &server).await;

    // v5 datagrams stay below ~5 KB record splitting ceiling
    let packets = tokio::time::timeout(
        T,
        handler.dial_udp_transport_runtime(
            Arc::clone(&runtime),
            udp_echo,
            None,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("udp dial timed out")
    .unwrap_or_else(|e| panic!("udp dial failed: {e}\n{}", server.logs()));
    udp_echo_round_trips(&*packets, udp_echo, &[21, 1400, 4_000], &server).await;

    verify_reuse(port, 5, None, &server, true).await;
}

#[tokio::test]
#[ignore = "needs docker and snell-server images; run by .github/workflows/snell-interop.yml"]
async fn snell_v6_default_mode_docker_interop() {
    v6_round_trips("default").await;
}

#[tokio::test]
#[ignore = "needs docker and snell-server images; run by .github/workflows/snell-interop.yml"]
async fn snell_v6_unshaped_mode_docker_interop() {
    v6_round_trips("unshaped").await;
}

#[tokio::test]
#[ignore = "needs docker and snell-server images; run by .github/workflows/snell-interop.yml"]
async fn snell_v6_unsafe_raw_mode_docker_interop() {
    v6_round_trips("unsafe-raw").await;
}
