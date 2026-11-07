use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::handler::SnellHandler;
use super::protocol::{
    COMMAND_CONNECT, COMMAND_CONNECT_V2, HEADER_VERSION, RESPONSE_TUNNEL, write_zero_chunk,
};
use super::v4::{V4Conn, is_zero_chunk};
use super::v6::{SnellV6Mode, V6Codec, V6Conn};
use crate::proxy::TcpOutbound;
use honk_config::node::{Node, OutboundConfig, SnellConfig};

async fn start_v4_echo_server(
    psk: &'static str,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        tokio::select! {
            _ = &mut shutdown_rx => {}
            res = listener.accept() => {
                let Ok((stream, _)) = res else { return; };
                let mut conn = V4Conn::new(stream, Arc::from(psk.as_bytes()));

                // Read request header: [ver, cmd, client_id_len, host_len, host..., port_be]
                let mut prefix = [0u8; 3];
                if conn.read_exact(&mut prefix).await.is_err() {
                    return;
                }
                assert_eq!(prefix[0], HEADER_VERSION);
                assert_eq!(prefix[1], COMMAND_CONNECT);
                assert_eq!(prefix[2], 0);

                let mut len = [0u8; 1];
                if conn.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut host_buf = vec![0u8; len[0] as usize];
                if conn.read_exact(&mut host_buf).await.is_err() {
                    return;
                }
                let mut port_buf = [0u8; 2];
                if conn.read_exact(&mut port_buf).await.is_err() {
                    return;
                }

                // Reply RESPONSE_TUNNEL
                if conn.write_all(&[RESPONSE_TUNNEL]).await.is_err() || conn.flush().await.is_err() {
                    return;
                }

                // Echo payload until EOF or zero-chunk
                let mut buf = vec![0u8; 4096];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() || conn.flush().await.is_err() {
                                break;
                            }
                        }
                        Err(e) if is_zero_chunk(&e) => {
                            let _ = write_zero_chunk(&mut conn).await;
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    (addr, shutdown_tx)
}

#[tokio::test]
async fn snell_v4_round_trip() {
    const PSK: &str = "test-snell-roundtrip-psk";
    let (server_addr, _shutdown) = start_v4_echo_server(PSK).await;

    let node = Node {
        name: "snell-v4-test".to_string(),
        address: server_addr.to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(4),
            mode: None,
            network: None,
            reuse: None,
            obfs: None,
            obfs_host: None,
        }),
        ..Default::default()
    };

    let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let handler = SnellHandler::new();
    let target_addr = "1.1.1.1:80".parse().unwrap();
    let target_domain = Some("example.com");

    let mut proxy_stream = handler
        .dial_with_tcp(
            &node,
            target_addr,
            target_domain,
            tcp_stream,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg = b"hello snell echo!";
    proxy_stream.stream.write_all(msg).await.unwrap();
    proxy_stream.stream.flush().await.unwrap();

    let mut response = vec![0u8; msg.len()];
    proxy_stream.stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..], msg);

    // Test clean shutdown / half-close
    proxy_stream.stream.shutdown().await.unwrap();
}

async fn start_v4_http_obfs_echo_server(
    psk: &'static str,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        tokio::select! {
            _ = &mut shutdown_rx => {}
            res = listener.accept() => {
                let Ok((stream, _)) = res else { return; };
                let obfs_server = super::obfs_server::HttpObfsServer::new(stream);
                let mut conn = V4Conn::new(obfs_server, Arc::from(psk.as_bytes()));

                let mut prefix = [0u8; 3];
                if conn.read_exact(&mut prefix).await.is_err() {
                    return;
                }
                assert_eq!(prefix[0], HEADER_VERSION);
                assert_eq!(prefix[1], COMMAND_CONNECT);
                assert_eq!(prefix[2], 0);

                let mut len = [0u8; 1];
                if conn.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut host_buf = vec![0u8; len[0] as usize];
                if conn.read_exact(&mut host_buf).await.is_err() {
                    return;
                }
                let mut port_buf = [0u8; 2];
                if conn.read_exact(&mut port_buf).await.is_err() {
                    return;
                }

                if conn.write_all(&[RESPONSE_TUNNEL]).await.is_err() || conn.flush().await.is_err() {
                    return;
                }

                let mut buf = vec![0u8; 4096];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() || conn.flush().await.is_err() {
                                break;
                            }
                        }
                        Err(e) if is_zero_chunk(&e) => {
                            let _ = write_zero_chunk(&mut conn).await;
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    (addr, shutdown_tx)
}

async fn start_v4_tls_obfs_echo_server(
    psk: &'static str,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        tokio::select! {
            _ = &mut shutdown_rx => {}
            res = listener.accept() => {
                let Ok((stream, _)) = res else { return; };
                let obfs_server = super::obfs_server::TlsObfsServer::new(stream);
                let mut conn = V4Conn::new(obfs_server, Arc::from(psk.as_bytes()));

                let mut prefix = [0u8; 3];
                if conn.read_exact(&mut prefix).await.is_err() {
                    return;
                }
                assert_eq!(prefix[0], HEADER_VERSION);
                assert_eq!(prefix[1], COMMAND_CONNECT);
                assert_eq!(prefix[2], 0);

                let mut len = [0u8; 1];
                if conn.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut host_buf = vec![0u8; len[0] as usize];
                if conn.read_exact(&mut host_buf).await.is_err() {
                    return;
                }
                let mut port_buf = [0u8; 2];
                if conn.read_exact(&mut port_buf).await.is_err() {
                    return;
                }

                if conn.write_all(&[RESPONSE_TUNNEL]).await.is_err() || conn.flush().await.is_err() {
                    return;
                }

                let mut buf = vec![0u8; 4096];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() || conn.flush().await.is_err() {
                                break;
                            }
                        }
                        Err(e) if is_zero_chunk(&e) => {
                            let _ = write_zero_chunk(&mut conn).await;
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    (addr, shutdown_tx)
}

#[tokio::test]
async fn snell_v4_http_obfs_round_trip() {
    const PSK: &str = "test-snell-http-obfs-psk";
    let (server_addr, _shutdown) = start_v4_http_obfs_echo_server(PSK).await;

    let node = Node {
        name: "snell-v4-http-obfs".to_string(),
        address: server_addr.to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(4),
            mode: None,
            network: None,
            reuse: None,
            obfs: Some("http".to_string()),
            obfs_host: Some("example.com".to_string()),
        }),
        ..Default::default()
    };

    let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let handler = SnellHandler::new();
    let target_addr = "1.1.1.1:80".parse().unwrap();
    let target_domain = Some("example.com");

    let mut proxy_stream = handler
        .dial_with_tcp(
            &node,
            target_addr,
            target_domain,
            tcp_stream,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg = b"hello snell http obfs echo!";
    proxy_stream.stream.write_all(msg).await.unwrap();
    proxy_stream.stream.flush().await.unwrap();

    let mut response = vec![0u8; msg.len()];
    proxy_stream.stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..], msg);

    proxy_stream.stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn snell_v4_tls_obfs_round_trip() {
    const PSK: &str = "test-snell-tls-obfs-psk";
    let (server_addr, _shutdown) = start_v4_tls_obfs_echo_server(PSK).await;

    let node = Node {
        name: "snell-v4-tls-obfs".to_string(),
        address: server_addr.to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(4),
            mode: None,
            network: None,
            reuse: None,
            obfs: Some("tls".to_string()),
            obfs_host: Some("bing.com".to_string()),
        }),
        ..Default::default()
    };

    let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let handler = SnellHandler::new();
    let target_addr = "1.1.1.1:80".parse().unwrap();
    let target_domain = Some("example.com");

    let mut proxy_stream = handler
        .dial_with_tcp(
            &node,
            target_addr,
            target_domain,
            tcp_stream,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg = b"hello snell tls obfs echo!";
    proxy_stream.stream.write_all(msg).await.unwrap();
    proxy_stream.stream.flush().await.unwrap();

    let mut response = vec![0u8; msg.len()];
    proxy_stream.stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..], msg);

    proxy_stream.stream.shutdown().await.unwrap();
}

async fn start_v4_reuse_tls_obfs_server(
    psk: &'static str,
) -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let accept_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&accept_count);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let Ok((stream, _)) = res else { break; };
                    count_clone.fetch_add(1, Ordering::SeqCst);
                    let psk_bytes = Arc::from(psk.as_bytes());
                    tokio::spawn(async move {
                        let obfs_server = super::obfs_server::TlsObfsServer::new(stream);
                        let mut conn = V4Conn::new(obfs_server, psk_bytes);
                        loop {
                            let mut prefix = [0u8; 3];
                            if conn.read_exact(&mut prefix).await.is_err() {
                                break;
                            }
                            if prefix[0] != HEADER_VERSION || prefix[2] != 0 {
                                break;
                            }
                            let is_v2 = prefix[1] == COMMAND_CONNECT_V2;
                            if !is_v2 && prefix[1] != COMMAND_CONNECT {
                                break;
                            }

                            let mut len = [0u8; 1];
                            if conn.read_exact(&mut len).await.is_err() {
                                break;
                            }
                            let mut host_buf = vec![0u8; len[0] as usize];
                            if conn.read_exact(&mut host_buf).await.is_err() {
                                break;
                            }
                            let mut port_buf = [0u8; 2];
                            if conn.read_exact(&mut port_buf).await.is_err() {
                                break;
                            }

                            if conn.write_all(&[RESPONSE_TUNNEL]).await.is_err() || conn.flush().await.is_err() {
                                break;
                            }

                            let mut buf = vec![0u8; 4096];
                            let mut saw_zero = false;
                            loop {
                                match conn.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if conn.write_all(&buf[..n]).await.is_err() || conn.flush().await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) if is_zero_chunk(&e) => {
                                        let _ = write_zero_chunk(&mut conn).await;
                                        saw_zero = true;
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }
                            if !is_v2 || !saw_zero {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (addr, accept_count, shutdown_tx)
}

#[tokio::test]
async fn snell_v4_reuse_tls_obfs() {
    const PSK: &str = "test-snell-v4-reuse-tls-obfs-psk";
    let (server_addr, accept_count, _shutdown) = start_v4_reuse_tls_obfs_server(PSK).await;

    let mut node = Node {
        name: "snell-v4-reuse-tls-obfs".to_string(),
        address: server_addr.to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(4),
            mode: None,
            network: None,
            reuse: Some(true),
            obfs: Some("tls".to_string()),
            obfs_host: Some("bing.com".to_string()),
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();

    let handler = SnellHandler::new();
    let target_addr = "1.1.1.1:80".parse().unwrap();
    let target_domain = Some("example.com");

    let mut flow1 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg1 = b"echo message 1 through tls obfs reuse";
    flow1.stream.write_all(msg1).await.unwrap();
    flow1.stream.flush().await.unwrap();

    let mut response1 = vec![0u8; msg1.len()];
    flow1.stream.read_exact(&mut response1).await.unwrap();
    assert_eq!(&response1[..], msg1);

    flow1.stream.shutdown().await.unwrap();
    let mut eof_buf = [0u8; 1];
    let n = flow1.stream.read(&mut eof_buf).await.unwrap();
    assert_eq!(n, 0);
    drop(flow1);

    let mut flow2 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg2 = b"echo message 2 through tls obfs reuse";
    flow2.stream.write_all(msg2).await.unwrap();
    flow2.stream.flush().await.unwrap();

    let mut response2 = vec![0u8; msg2.len()];
    flow2.stream.read_exact(&mut response2).await.unwrap();
    assert_eq!(&response2[..], msg2);

    flow2.stream.shutdown().await.unwrap();
    assert_eq!(flow2.stream.read(&mut eof_buf).await.unwrap(), 0);
    drop(flow2);

    assert_eq!(accept_count.load(Ordering::SeqCst), 1);
}

async fn start_v4_reuse_server(
    psk: &'static str,
) -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let accept_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&accept_count);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let Ok((stream, _)) = res else { break; };
                    count_clone.fetch_add(1, Ordering::SeqCst);
                    let psk_bytes = Arc::from(psk.as_bytes());
                    tokio::spawn(async move {
                        let mut conn = V4Conn::new(stream, psk_bytes);
                        loop {
                            let mut prefix = [0u8; 3];
                            if conn.read_exact(&mut prefix).await.is_err() {
                                break;
                            }
                            if prefix[0] != HEADER_VERSION || prefix[2] != 0 {
                                break;
                            }
                            let is_v2 = prefix[1] == COMMAND_CONNECT_V2;
                            if !is_v2 && prefix[1] != COMMAND_CONNECT {
                                break;
                            }

                            let mut len = [0u8; 1];
                            if conn.read_exact(&mut len).await.is_err() {
                                break;
                            }
                            let mut host_buf = vec![0u8; len[0] as usize];
                            if conn.read_exact(&mut host_buf).await.is_err() {
                                break;
                            }
                            let mut port_buf = [0u8; 2];
                            if conn.read_exact(&mut port_buf).await.is_err() {
                                break;
                            }

                            if conn.write_all(&[RESPONSE_TUNNEL]).await.is_err() || conn.flush().await.is_err() {
                                break;
                            }

                            let mut buf = vec![0u8; 4096];
                            let mut saw_zero = false;
                            loop {
                                match conn.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if conn.write_all(&buf[..n]).await.is_err() || conn.flush().await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) if is_zero_chunk(&e) => {
                                        let _ = write_zero_chunk(&mut conn).await;
                                        saw_zero = true;
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }
                            if !is_v2 || !saw_zero {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (addr, accept_count, shutdown_tx)
}

async fn start_v6_reuse_server(
    psk: &'static str,
) -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let accept_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&accept_count);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let Ok((stream, _)) = res else { break; };
                    count_clone.fetch_add(1, Ordering::SeqCst);
                    let psk_bytes = Arc::from(psk.as_bytes());
                    tokio::spawn(async move {
                        let codec = V6Codec::new(SnellV6Mode::Default, &psk_bytes);
                        let mut conn = V6Conn::new(stream, psk_bytes, codec);
                        loop {
                            let mut buf = vec![0u8; 4096];
                            let n = match conn.read(&mut buf).await {
                                Ok(n) if n > 0 => n,
                                _ => break,
                            };
                            if n < 4 || buf[0] != HEADER_VERSION || buf[1] != COMMAND_CONNECT_V2 || buf[2] != 0 {
                                break;
                            }
                            let host_len = buf[3] as usize;
                            let req_len = 4 + host_len + 2;
                            if n < req_len {
                                break;
                            }

                            if conn.write_all(&[RESPONSE_TUNNEL]).await.is_err() || conn.flush().await.is_err() {
                                break;
                            }

                            let initial_payload = &buf[req_len..n];
                            if !initial_payload.is_empty()
                                && (conn.write_all(initial_payload).await.is_err() || conn.flush().await.is_err())
                            {
                                break;
                            }

                            let mut saw_zero = false;
                            loop {
                                match conn.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if conn.write_all(&buf[..n]).await.is_err() || conn.flush().await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) if is_zero_chunk(&e) => {
                                        let _ = write_zero_chunk(&mut conn).await;
                                        saw_zero = true;
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }
                            if !saw_zero {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (addr, accept_count, shutdown_tx)
}

#[tokio::test]
async fn test_a_pool_unit_lifo_expiry_retire_full() {
    use super::pool::SnellPool;
    use super::protocol::Snell;
    use crate::proxy::AsyncReadWrite;

    let pool = SnellPool::new(2, Duration::from_millis(50));
    let (s1, _p1) = {
        let (a, b) = tokio::io::duplex(1024);
        (
            Snell::new(
                Box::new(a) as Box<dyn AsyncReadWrite>,
                Arc::from(b"k".as_slice()),
            ),
            b,
        )
    };
    let (s2, _p2) = {
        let (a, b) = tokio::io::duplex(1024);
        (
            Snell::new(
                Box::new(a) as Box<dyn AsyncReadWrite>,
                Arc::from(b"k".as_slice()),
            ),
            b,
        )
    };
    pool.put(s1);
    pool.put(s2);
    assert_eq!(pool.idle_len(), 2);

    let (s3, _p3) = {
        let (a, b) = tokio::io::duplex(1024);
        (
            Snell::new(
                Box::new(a) as Box<dyn AsyncReadWrite>,
                Arc::from(b"k".as_slice()),
            ),
            b,
        )
    };
    pool.put(s3);
    assert_eq!(pool.idle_len(), 2, "full pool dropped oldest");

    assert!(pool.take_idle().is_some());
    assert_eq!(pool.idle_len(), 1);

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(pool.reap_expired(), 1, "reaped expired");
    assert_eq!(pool.idle_len(), 0);

    let (s4, _p4) = {
        let (a, b) = tokio::io::duplex(1024);
        (
            Snell::new(
                Box::new(a) as Box<dyn AsyncReadWrite>,
                Arc::from(b"k".as_slice()),
            ),
            b,
        )
    };
    pool.put(s4);
    assert_eq!(pool.idle_len(), 1);
    pool.retire();
    assert_eq!(pool.idle_len(), 0);
    assert!(pool.take_idle().is_none());
}

#[tokio::test]
async fn test_b_v4_reuse_sequential_sessions_on_one_connection() {
    const PSK: &str = "test-snell-v4-reuse-psk";
    let (server_addr, accept_count, _shutdown) = start_v4_reuse_server(PSK).await;

    let mut node = Node {
        name: "snell-v4-reuse-test".to_string(),
        address: server_addr.to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(4),
            mode: None,
            network: None,
            reuse: Some(true),
            obfs: None,
            obfs_host: None,
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();

    let handler = SnellHandler::new();
    let target_addr = "1.1.1.1:80".parse().unwrap();
    let target_domain = Some("example.com");

    let mut flow1 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg1 = b"echo message 1";
    flow1.stream.write_all(msg1).await.unwrap();
    flow1.stream.flush().await.unwrap();

    let mut response1 = vec![0u8; msg1.len()];
    flow1.stream.read_exact(&mut response1).await.unwrap();
    assert_eq!(&response1[..], msg1);

    flow1.stream.shutdown().await.unwrap();
    let mut eof_buf = [0u8; 1];
    let n = flow1.stream.read(&mut eof_buf).await.unwrap();
    assert_eq!(n, 0);
    drop(flow1);

    let mut flow2 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg2 = b"echo message 2";
    flow2.stream.write_all(msg2).await.unwrap();
    flow2.stream.flush().await.unwrap();

    let mut response2 = vec![0u8; msg2.len()];
    flow2.stream.read_exact(&mut response2).await.unwrap();
    assert_eq!(&response2[..], msg2);

    flow2.stream.shutdown().await.unwrap();
    let n = flow2.stream.read(&mut eof_buf).await.unwrap();
    assert_eq!(n, 0);
    drop(flow2);

    assert_eq!(accept_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_c_v4_reuse_client_drop_before_shutdown_opens_new_connection() {
    const PSK: &str = "test-snell-v4-drop-psk";
    let (server_addr, accept_count, _shutdown) = start_v4_reuse_server(PSK).await;

    let mut node = Node {
        name: "snell-v4-drop-test".to_string(),
        address: server_addr.to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(4),
            mode: None,
            network: None,
            reuse: Some(true),
            obfs: None,
            obfs_host: None,
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();

    let handler = SnellHandler::new();
    let target_addr = "1.1.1.1:80".parse().unwrap();
    let target_domain = Some("example.com");

    let mut flow1 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg1 = b"flow1 unfinished";
    flow1.stream.write_all(msg1).await.unwrap();
    flow1.stream.flush().await.unwrap();
    let mut response1 = vec![0u8; msg1.len()];
    flow1.stream.read_exact(&mut response1).await.unwrap();
    assert_eq!(&response1[..], msg1);

    drop(flow1);

    let mut flow2 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg2 = b"flow2 on fresh connection";
    flow2.stream.write_all(msg2).await.unwrap();
    flow2.stream.flush().await.unwrap();
    let mut response2 = vec![0u8; msg2.len()];
    flow2.stream.read_exact(&mut response2).await.unwrap();
    assert_eq!(&response2[..], msg2);

    flow2.stream.shutdown().await.unwrap();
    let mut eof_buf = [0u8; 1];
    assert_eq!(flow2.stream.read(&mut eof_buf).await.unwrap(), 0);
    drop(flow2);

    assert_eq!(accept_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_d_v4_reuse_disabled_opens_new_connections() {
    const PSK: &str = "test-snell-v4-disabled-psk";
    let (server_addr, accept_count, _shutdown) = start_v4_reuse_server(PSK).await;

    let mut node = Node {
        name: "snell-v4-noreuse-test".to_string(),
        address: server_addr.to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(4),
            mode: None,
            network: None,
            reuse: Some(false),
            obfs: None,
            obfs_host: None,
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();

    let handler = SnellHandler::new();
    let target_addr = "1.1.1.1:80".parse().unwrap();
    let target_domain = Some("example.com");

    let mut flow1 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let msg1 = b"no reuse 1";
    flow1.stream.write_all(msg1).await.unwrap();
    flow1.stream.flush().await.unwrap();
    let mut resp1 = vec![0u8; msg1.len()];
    flow1.stream.read_exact(&mut resp1).await.unwrap();
    assert_eq!(&resp1[..], msg1);
    flow1.stream.shutdown().await.unwrap();
    let mut eof_buf = [0u8; 1];
    assert_eq!(flow1.stream.read(&mut eof_buf).await.unwrap(), 0);
    drop(flow1);

    let mut flow2 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let msg2 = b"no reuse 2";
    flow2.stream.write_all(msg2).await.unwrap();
    flow2.stream.flush().await.unwrap();
    let mut resp2 = vec![0u8; msg2.len()];
    flow2.stream.read_exact(&mut resp2).await.unwrap();
    assert_eq!(&resp2[..], msg2);
    flow2.stream.shutdown().await.unwrap();
    assert_eq!(flow2.stream.read(&mut eof_buf).await.unwrap(), 0);
    drop(flow2);

    assert_eq!(accept_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_e_v4_reuse_retired_pool_does_not_repool() {
    const PSK: &str = "test-snell-v4-retire-psk";
    let (server_addr, accept_count, _shutdown) = start_v4_reuse_server(PSK).await;

    let mut node = Node {
        name: "snell-v4-retire-test".to_string(),
        address: server_addr.to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(4),
            mode: None,
            network: None,
            reuse: Some(true),
            obfs: None,
            obfs_host: None,
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();

    let handler = SnellHandler::new();
    let target_addr = "1.1.1.1:80".parse().unwrap();
    let target_domain = Some("example.com");

    let mut flow1 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    runtime.snell_pool().unwrap().retire();

    let msg1 = b"retire 1";
    flow1.stream.write_all(msg1).await.unwrap();
    flow1.stream.flush().await.unwrap();
    let mut resp1 = vec![0u8; msg1.len()];
    flow1.stream.read_exact(&mut resp1).await.unwrap();
    assert_eq!(&resp1[..], msg1);
    flow1.stream.shutdown().await.unwrap();
    let mut eof_buf = [0u8; 1];
    assert_eq!(flow1.stream.read(&mut eof_buf).await.unwrap(), 0);
    drop(flow1);

    assert_eq!(runtime.snell_pool().unwrap().idle_len(), 0);

    let mut flow2 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let msg2 = b"retire 2";
    flow2.stream.write_all(msg2).await.unwrap();
    flow2.stream.flush().await.unwrap();
    let mut resp2 = vec![0u8; msg2.len()];
    flow2.stream.read_exact(&mut resp2).await.unwrap();
    assert_eq!(&resp2[..], msg2);
    flow2.stream.shutdown().await.unwrap();
    assert_eq!(flow2.stream.read(&mut eof_buf).await.unwrap(), 0);
    drop(flow2);

    assert_eq!(accept_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_f_v6_reuse_sequential_sessions_on_one_connection() {
    const PSK: &str = "test-snell-v6-reuse-psk";
    let (server_addr, accept_count, _shutdown) = start_v6_reuse_server(PSK).await;

    let mut node = Node {
        name: "snell-v6-reuse-test".to_string(),
        address: server_addr.to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(PSK.to_string()),
            version: Some(6),
            mode: Some("default".to_string()),
            network: None,
            reuse: Some(true),
            obfs: None,
            obfs_host: None,
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();

    let handler = SnellHandler::new();
    let target_addr = "1.1.1.1:80".parse().unwrap();
    let target_domain = Some("example.com");

    // First session
    let mut flow1 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg1 = b"v6 message 1";
    flow1.stream.write_all(msg1).await.unwrap();
    flow1.stream.flush().await.unwrap();

    let mut response1 = vec![0u8; msg1.len()];
    flow1.stream.read_exact(&mut response1).await.unwrap();
    assert_eq!(&response1[..], msg1);

    flow1.stream.shutdown().await.unwrap();
    let mut eof_buf = [0u8; 1];
    let n = flow1.stream.read(&mut eof_buf).await.unwrap();
    assert_eq!(n, 0);
    drop(flow1);

    // Second session on reused connection
    let mut flow2 = handler
        .dial_runtime(
            Arc::clone(&runtime),
            target_addr,
            target_domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let msg2 = b"v6 message 2";
    flow2.stream.write_all(msg2).await.unwrap();
    flow2.stream.flush().await.unwrap();

    let mut response2 = vec![0u8; msg2.len()];
    flow2.stream.read_exact(&mut response2).await.unwrap();
    assert_eq!(&response2[..], msg2);

    flow2.stream.shutdown().await.unwrap();
    let n = flow2.stream.read(&mut eof_buf).await.unwrap();
    assert_eq!(n, 0);
    drop(flow2);

    assert_eq!(accept_count.load(Ordering::SeqCst), 1);
}
