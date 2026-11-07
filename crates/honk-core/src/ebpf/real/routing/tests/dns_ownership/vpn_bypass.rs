use super::*;
use honk_ebpf_common::{DATAPATH_FLAG_VPN_GATE, DATAPATH_FLAG_VPN_READY};

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn vpn_bypass_gate_wan_egress_semantics() {
    isolated(|| {
        let rules = [rule(
            "proxy-all",
            RoutingCondition {
                ip: vec!["198.51.100.0/24".into(), "203.0.113.0/24".into()],
                ..Default::default()
            },
            "proxy",
            USER_MARK,
            false,
        )];
        let (mut backend, _, _listeners) = publish(&rules);

        let mut config = honk_config::Config::default();
        config.global.vpn_server_ip = vec!["198.51.100.0/24".to_string()];
        config.global.vpn_server_port = vec!["4500".to_string()];
        config.global.vpn_server_l4proto = vec!["tcp".to_string(), "udp".to_string()];
        config.global.wan_interface = vec!["eth0".to_string()];
        backend
            .populate_vpn_gate(&config.global.vpn_server_bypass().unwrap().unwrap())
            .unwrap();

        let local_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let vpn_ip: IpAddr = "198.51.100.7".parse().unwrap();
        let other_ip: IpAddr = "203.0.113.7".parse().unwrap();

        // a. VPN_READY off: TCP SYN to 198.51.100.7:4500 -> TC_ACT_REDIRECT (normal routing).
        backend.set_datapath_flags(DATAPATH_FLAG_VPN_GATE).unwrap();
        let syn_off = packet(local_ip, vpn_ip, IPPROTO_TCP, 41000, 4500, 0, 0x02);
        let res_syn_off = run(&backend, "wan_egress_l2", &syn_off, SkbInput::default());
        assert_eq!(
            res_syn_off.verdict, TC_ACT_REDIRECT,
            "TCP SYN to VPN server while VPN_READY is off should follow normal routing"
        );

        // b. VPN_READY on: TCP SYN to 198.51.100.7:4500 -> TC_ACT_OK; a following ACK -> passes
        backend
            .set_datapath_flags(DATAPATH_FLAG_VPN_GATE | DATAPATH_FLAG_VPN_READY)
            .unwrap();
        let syn_on = packet(local_ip, vpn_ip, IPPROTO_TCP, 41001, 4500, 0, 0x02);
        let res_syn_on = run(&backend, "wan_egress_l2", &syn_on, SkbInput::default());
        assert_eq!(
            res_syn_on.verdict, TC_ACT_OK,
            "TCP SYN to VPN server while VPN_READY is on should go direct"
        );
        let ack_on = packet(local_ip, vpn_ip, IPPROTO_TCP, 41001, 4500, 0, 0x10);
        let res_ack_on = run(&backend, "wan_egress_l2", &ack_on, SkbInput::default());
        assert!(
            res_ack_on.verdict == TC_ACT_UNSPEC || res_ack_on.verdict == TC_ACT_OK,
            "Following ACK of direct flow should pass (verdict={})",
            res_ack_on.verdict
        );

        // c. TCP pinning: a flow whose SYN was redirected while off keeps TC_ACT_REDIRECT for its ACK
        let ack_off = packet(local_ip, vpn_ip, IPPROTO_TCP, 41000, 4500, 0, 0x10);
        let res_ack_off = run(&backend, "wan_egress_l2", &ack_off, SkbInput::default());
        assert_eq!(
            res_ack_off.verdict, TC_ACT_REDIRECT,
            "TCP ACK of flow redirected while off must stay pinned to redirect"
        );

        // d. VPN_READY on: TCP SYN to 198.51.100.7:443 -> TC_ACT_REDIRECT; SYN to 203.0.113.7:4500 -> TC_ACT_REDIRECT
        let syn_wrong_port = packet(local_ip, vpn_ip, IPPROTO_TCP, 41002, 443, 0, 0x02);
        assert_eq!(
            run(
                &backend,
                "wan_egress_l2",
                &syn_wrong_port,
                SkbInput::default()
            )
            .verdict,
            TC_ACT_REDIRECT,
            "TCP SYN to port not in set should be redirected"
        );
        let syn_wrong_ip = packet(local_ip, other_ip, IPPROTO_TCP, 41003, 4500, 0, 0x02);
        assert_eq!(
            run(
                &backend,
                "wan_egress_l2",
                &syn_wrong_ip,
                SkbInput::default()
            )
            .verdict,
            TC_ACT_REDIRECT,
            "TCP SYN to IP not in set should be redirected"
        );

        // e. VPN_READY on: first UDP packet to 198.51.100.7:4500 -> TC_ACT_OK;
        //    VPN_READY off: first UDP packet of a different source port to 198.51.100.7:4500 -> TC_ACT_REDIRECT
        let udp_on = packet(local_ip, vpn_ip, IPPROTO_UDP, 42000, 4500, 0, 0);
        assert_eq!(
            run(&backend, "wan_egress_l2", &udp_on, SkbInput::default()).verdict,
            TC_ACT_OK,
            "First UDP packet to VPN server while VPN_READY is on should go direct"
        );
        backend.set_datapath_flags(DATAPATH_FLAG_VPN_GATE).unwrap();
        let udp_off = packet(local_ip, vpn_ip, IPPROTO_UDP, 42001, 4500, 0, 0);
        assert_eq!(
            run(&backend, "wan_egress_l2", &udp_off, SkbInput::default()).verdict,
            TC_ACT_REDIRECT,
            "First UDP packet to VPN server while VPN_READY is off should be redirected"
        );
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn vpn_bypass_udp_flow_re_decision_after_retirement() {
    isolated(|| {
        let rules = [rule(
            "proxy-all",
            RoutingCondition {
                ip: vec!["198.51.100.0/24".into()],
                ..Default::default()
            },
            "proxy",
            USER_MARK,
            false,
        )];
        let (mut backend, _, _listeners) = publish(&rules);

        let mut config = honk_config::Config::default();
        config.global.vpn_server_ip = vec!["198.51.100.0/24".to_string()];
        config.global.vpn_server_port = vec!["4500".to_string()];
        config.global.vpn_server_l4proto = vec!["udp".to_string()];
        config.global.wan_interface = vec!["eth0".to_string()];
        let gate = config.global.vpn_server_bypass().unwrap().unwrap();
        backend.populate_vpn_gate(&gate).unwrap();

        let local_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let vpn_ip: IpAddr = "198.51.100.7".parse().unwrap();

        // 1. While not ready, UDP flow is cached as proxied (TC_ACT_REDIRECT).
        backend.set_datapath_flags(DATAPATH_FLAG_VPN_GATE).unwrap();
        let udp_pkt = packet(local_ip, vpn_ip, IPPROTO_UDP, 42002, 4500, 0, 0);
        let res1 = run(&backend, "wan_egress_l2", &udp_pkt, SkbInput::default());
        assert_eq!(
            res1.verdict, TC_ACT_REDIRECT,
            "UDP packet to VPN server while not ready must be redirected"
        );

        // Subsequent packet of the same flow remains redirected.
        let res1_cached = run(&backend, "wan_egress_l2", &udp_pkt, SkbInput::default());
        assert_eq!(
            res1_cached.verdict, TC_ACT_REDIRECT,
            "Cached UDP flow must remain redirected while not ready"
        );

        // 2. Set VPN_READY flag and run retirement for the gate.
        backend
            .set_datapath_flags(DATAPATH_FLAG_VPN_GATE | DATAPATH_FLAG_VPN_READY)
            .unwrap();
        let retired =
            crate::control::vpn_ready::retire_vpn_bypass_udp_backend(&mut backend, &gate, true)
                .unwrap();
        assert!(retired >= 1, "Cached proxied UDP flow must be retired");

        // 3. Next packet of the exact same flow is re-decided under the new flag -> TC_ACT_OK.
        let res2 = run(&backend, "wan_egress_l2", &udp_pkt, SkbInput::default());
        assert_eq!(
            res2.verdict, TC_ACT_OK,
            "Next packet after retirement on readiness change must go direct (TC_ACT_OK)"
        );
    });
}
