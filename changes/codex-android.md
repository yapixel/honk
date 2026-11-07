Fixed

- VPN server bypass notices a VPN that starts or stops after honk, retries failed flow re-decisions, and no longer re-decides LAN client flows to the VPN server.
- VPN server bypass no longer overrides a matching `must` rule or `block` decision.
- `vpn_server_ip` is rejected with a field error above the kernel's 4096-entry limit instead of failing at startup.
- Linux again detaches a leftover `daens` bind mount after a crash and keeps `bpf_redirect_peer` for veth `dae0` pairs; only Android limits it to netkit.
- Android hostname bootstrap no longer queries netd without honk's bypass mark; set `global.bootstrap_resolver` instead.
- Snell nodes that differ only in `snell_obfs`/`snell_obfs_host` get distinct node IDs.
