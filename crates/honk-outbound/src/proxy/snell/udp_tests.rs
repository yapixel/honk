use super::*;
use crate::proxy::snell::SnellHandler;
use crate::proxy::snell::protocol::{
    COMMAND_UDP, COMMAND_UDP_FORWARD, HEADER_VERSION, RESPONSE_TUNNEL, Snell,
};
use crate::proxy::snell::v4::V4Conn;
use crate::proxy::snell::v6::{SnellV6Mode, V6Codec, V6Conn};
use crate::proxy::{AsyncReadWrite, MultiTargetTransport, PacketOutbound, PacketTransport};
use honk_config::node::{Node, OutboundConfig, SnellConfig};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn transport_over<S: AsyncReadWrite + 'static>(
    stream: S,
    target: SocketAddr,
    domain: Option<&str>,
) -> SnellUdpTransport {
    let boxed = Box::new(stream) as Box<dyn AsyncReadWrite>;
    let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
    let snell = Snell::new(boxed, psk);
    SnellUdpTransport::new(snell, target, domain)
}

fn parse_server_request(buf: &[u8]) -> (SocketAddr, Option<String>, Vec<u8>) {
    assert_eq!(buf[0], COMMAND_UDP_FORWARD);
    let host_len = buf[1] as usize;
    if host_len == 0 {
        let family = buf[2];
        match family {
            0x04 => {
                let ip = [buf[3], buf[4], buf[5], buf[6]];
                let port = u16::from_be_bytes([buf[7], buf[8]]);
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port),
                    None,
                    buf[9..].to_vec(),
                )
            }
            0x06 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[3..19]);
                let port = u16::from_be_bytes([buf[19], buf[20]]);
                (
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port),
                    None,
                    buf[21..].to_vec(),
                )
            }
            other => panic!("unknown family {other}"),
        }
    } else {
        let host = String::from_utf8(buf[2..2 + host_len].to_vec()).unwrap();
        let port = u16::from_be_bytes([buf[2 + host_len], buf[3 + host_len]]);
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            Some(host),
            buf[4 + host_len..].to_vec(),
        )
    }
}

fn make_response_v4(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    match addr.ip() {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => panic!("not v4"),
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn make_response_v6(ip6_bytes: [u8; 16], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x06];
    out.extend_from_slice(&ip6_bytes);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
async fn snell_udp_v4_roundtrip_two_destinations() {
    let (client, server) = tokio::io::duplex(1 << 16);
    let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
    let mut peer = V4Conn::new(server, psk);

    let a: SocketAddr = "1.2.3.4:53".parse().unwrap();
    let b: SocketAddr = "5.6.7.8:80".parse().unwrap();
    let transport = transport_over(client, a, None);

    transport
        .send_to(a, None, b"packet-a", false, None)
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let n = peer.read(&mut req_buf).await.unwrap();
    let (target, domain, payload) = parse_server_request(&req_buf[..n]);
    assert_eq!(target, a);
    assert_eq!(domain, None);
    assert_eq!(payload, b"packet-a");

    transport
        .send_to(b, None, b"packet-b", false, None)
        .await
        .unwrap();
    let n = peer.read(&mut req_buf).await.unwrap();
    let (target, domain, payload) = parse_server_request(&req_buf[..n]);
    assert_eq!(target, b);
    assert_eq!(domain, None);
    assert_eq!(payload, b"packet-b");

    peer.write_all(&[RESPONSE_TUNNEL]).await.unwrap();
    peer.stage_packet_frame(&make_response_v4(b, b"reply-b"))
        .unwrap();
    peer.flush().await.unwrap();
    let mut buf = [0u8; 64];
    let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"reply-b");
    assert_eq!(src, b);

    peer.stage_packet_frame(&make_response_v4(a, b"reply-a"))
        .unwrap();
    peer.flush().await.unwrap();
    let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"reply-a");
    assert_eq!(src, a);
}

#[tokio::test]
async fn snell_udp_ipv6_dest_and_ipv4_mapped_reply_unmaps() {
    let (client, server) = tokio::io::duplex(1 << 16);
    let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
    let mut peer = V4Conn::new(server, psk);

    let dst6: SocketAddr = "[2001:db8::1]:5353".parse().unwrap();
    let transport = transport_over(client, dst6, None);

    transport
        .send_to(dst6, None, b"hello-v6", false, None)
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let n = peer.read(&mut req_buf).await.unwrap();
    let (target, domain, payload) = parse_server_request(&req_buf[..n]);
    assert_eq!(target, dst6);
    assert_eq!(domain, None);
    assert_eq!(payload, b"hello-v6");

    let mapped = Ipv4Addr::new(192, 0, 2, 33).to_ipv6_mapped();
    peer.write_all(&[RESPONSE_TUNNEL]).await.unwrap();
    peer.stage_packet_frame(&make_response_v6(mapped.octets(), 5353, b"v4-mapped-reply"))
        .unwrap();
    peer.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"v4-mapped-reply");
    assert_eq!(src, "192.0.2.33:5353".parse::<SocketAddr>().unwrap());
}

#[tokio::test]
async fn snell_udp_per_packet_domain_only_dialed_name() {
    let (client, server) = tokio::io::duplex(1 << 16);
    let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
    let mut peer = V4Conn::new(server, psk);

    let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let transport = transport_over(client, a, Some("example.com"));

    transport
        .send_to(a, Some("example.com"), b"match", false, None)
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let n = peer.read(&mut req_buf).await.unwrap();
    let (_, domain, payload) = parse_server_request(&req_buf[..n]);
    assert_eq!(domain.as_deref(), Some("example.com"));
    assert_eq!(payload, b"match");

    transport
        .send_to(a, Some("other.org"), b"mismatch", false, None)
        .await
        .unwrap();
    let n = peer.read(&mut req_buf).await.unwrap();
    let (target, domain, payload) = parse_server_request(&req_buf[..n]);
    assert_eq!(domain, None);
    assert_eq!(target, a);
    assert_eq!(payload, b"mismatch");

    transport
        .send_to(a, None, b"numeric", false, None)
        .await
        .unwrap();
    let n = peer.read(&mut req_buf).await.unwrap();
    let (target, domain, payload) = parse_server_request(&req_buf[..n]);
    assert_eq!(domain, None);
    assert_eq!(target, a);
    assert_eq!(payload, b"numeric");
}

#[tokio::test]
async fn snell_udp_unknown_reply_address_type_is_terminal() {
    let (client, server) = tokio::io::duplex(1 << 16);
    let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
    let mut peer = V4Conn::new(server, psk);

    let a: SocketAddr = "1.2.3.4:53".parse().unwrap();
    let transport = transport_over(client, a, None);

    peer.write_all(&[RESPONSE_TUNNEL]).await.unwrap();
    peer.stage_packet_frame(&[0x09, 1, 2, 3, 4, 0, 53, b'x'])
        .unwrap();
    peer.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let err = transport.recv_packet(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("unknown address family"));
}

#[tokio::test]
async fn snell_udp_cancelled_partial_write_poisons_the_shared_stream() {
    let (client, mut server) = tokio::io::duplex(16);
    let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let b: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
    let transport = transport_over(client, a, None);
    let payload = vec![7u8; 4096];
    let stalled = tokio::time::timeout(
        Duration::from_millis(50),
        transport.send_to(a, None, &payload, false, None),
    )
    .await;
    assert!(stalled.is_err(), "the unread stream must stall the write");
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut server, &mut tokio::io::sink()).await;
    });
    let error = transport
        .send_to(b, None, b"b", false, None)
        .await
        .unwrap_err();
    assert!(crate::proxy::is_frame_interrupted(&error));
    assert!(transport.frame_stream_torn());
}

#[tokio::test]
async fn snell_udp_concurrent_sender_gets_would_block() {
    let (client, server) = tokio::io::duplex(16);
    let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let b: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
    let transport = transport_over(client, a, None);

    let payload = vec![7u8; 4096];
    let mut first = std::pin::pin!(transport.send_to(a, None, &payload, false, None));
    assert!(
        futures_util::poll!(first.as_mut()).is_pending(),
        "writer must be pending on the full stream"
    );
    let busy_admitted = AtomicBool::new(false);
    let error = transport
        .send_to(b, None, b"b", false, Some(&busy_admitted))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(!busy_admitted.load(Ordering::Acquire));
    drop(server);
}

#[tokio::test]
async fn snell_udp_oversize_datagram_rejected_without_poisoning() {
    let (client, server) = tokio::io::duplex(1 << 16);
    let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
    let mut peer = V4Conn::new(server, psk);

    let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let transport = transport_over(client, a, None);

    let oversize = vec![0xAA; transport.max_frame + 1];
    let error = transport
        .send_to(a, None, &oversize, false, None)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(!transport.frame_stream_torn());

    transport
        .send_to(a, None, b"normal", false, None)
        .await
        .unwrap();
    let mut req_buf = [0u8; 1024];
    let n = peer.read(&mut req_buf).await.unwrap();
    let (_, _, payload) = parse_server_request(&req_buf[..n]);
    assert_eq!(payload, b"normal");
}

#[tokio::test]
async fn snell_udp_v6_roundtrip_through_handler() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let target: SocketAddr = "1.1.1.1:53".parse().unwrap();
    let psk_str = "secret-v6-psk";

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let psk: Arc<[u8]> = Arc::from(psk_str.as_bytes());
        let codec = V6Codec::new(SnellV6Mode::Default, &psk);
        let mut server_conn = V6Conn::new(tcp, psk, codec);

        let mut req = [0u8; 3];
        server_conn.read_exact(&mut req).await.unwrap();
        assert_eq!(req, [HEADER_VERSION, COMMAND_UDP, 0x00]);

        server_conn.write_all(&[RESPONSE_TUNNEL]).await.unwrap();
        server_conn.flush().await.unwrap();

        let mut frame_buf = [0u8; 1024];
        let n = server_conn.read(&mut frame_buf).await.unwrap();
        let (req_target, _, req_payload) = parse_server_request(&frame_buf[..n]);
        assert_eq!(req_target, target);
        assert_eq!(req_payload, b"ping");

        let mut reply = vec![0x04, 1, 1, 1, 1];
        reply.extend_from_slice(&53u16.to_be_bytes());
        reply.extend_from_slice(b"pong");
        server_conn.stage_packet_frame(&reply).unwrap();
        server_conn.flush().await.unwrap();
    });

    let node = Node {
        name: "snell-v6-node".into(),
        address: server_addr.ip().to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some(psk_str.into()),
            version: Some(6),
            mode: Some("default".into()),
            network: Some("tcp,udp".into()),
        }),
        ..Default::default()
    };

    let handler = SnellHandler::new();
    let transport = handler
        .dial_udp_transport(&node, target, None, Duration::from_secs(5))
        .await
        .unwrap();

    transport.send_packet(b"ping").await.unwrap();

    let mut buf = [0u8; 64];
    let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pong");
    assert_eq!(peer, target);

    server_task.await.unwrap();
}

#[tokio::test]
async fn snell_udp_node_network_tcp_refuses_dial_udp_transport() {
    let target: SocketAddr = "1.1.1.1:53".parse().unwrap();
    let node = Node {
        name: "snell-tcp-only".into(),
        address: "127.0.0.1".into(),
        host: "127.0.0.1".into(),
        port: 8388,
        outbound: OutboundConfig::Snell(SnellConfig {
            psk: Some("secret".into()),
            version: Some(4),
            network: Some("tcp".into()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let handler = SnellHandler::new();
    let err = handler
        .dial_udp_transport(&node, target, None, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("does not include \"udp\""),
        "error was: {err}"
    );
}
