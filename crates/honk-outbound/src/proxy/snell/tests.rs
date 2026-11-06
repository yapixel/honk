use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::handler::SnellHandler;
use super::protocol::{COMMAND_CONNECT, HEADER_VERSION, RESPONSE_TUNNEL, write_zero_chunk};
use super::v4::{V4Conn, is_zero_chunk};
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
