//! VPN server bypass readiness detection and UDP flow re-decision.

use crate::ebpf::{
    EbpfBackend, FlowScanCursor, RETIRE_BATCH_CAPACITY, RetireKind, RetireOutcome, RetireRequest,
};
use honk_ebpf_common::conn::ConnState;
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::{ROUTING_META_FLAG_OFFLOAD, ROUTING_META_FLAG_PUBLISHED, TuplesKey};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, RwLock, watch};
use tracing::{info, warn};

/// Interfaces owned by honk that must never be treated as candidate VPN interfaces.
const HONK_OWNED_INTERFACES: &[&str] = &["dae0", "dae0peer"];

/// Global unicast check matching Go's `net.IP.IsGlobalUnicast()`.
///
/// Excludes loopback, link-local, multicast, broadcast and unspecified, while
/// admitting private (RFC 1918) and ULA (RFC 4193) addresses assigned by VPN tunnels.
pub fn is_global_unicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            !ipv4.is_loopback()
                && !ipv4.is_link_local()
                && !ipv4.is_broadcast()
                && !ipv4.is_multicast()
                && !ipv4.is_unspecified()
        }
        IpAddr::V6(ipv6) => {
            !ipv6.is_loopback()
                && !ipv6.is_multicast()
                && !ipv6.is_unspecified()
                && (ipv6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

/// Snapshot of an interface used for candidate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceCandidateInfo {
    pub name: String,
    pub ifindex: u32,
    pub flags: u32,
    pub addresses: Vec<IpAddr>,
}

/// Packet counters from `/sys/class/net/<name>/statistics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TunTrafficCounters {
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TunCandidateState {
    Initial(TunTrafficCounters),
    Ready,
}

/// Evaluates whether an interface is an eligible VPN candidate.
pub fn is_candidate_interface(
    info: &InterfaceCandidateInfo,
    interface_address_filter: &[ipnet::IpNet],
) -> bool {
    const IFF_UP: u32 = libc::IFF_UP as u32;
    if info.flags & IFF_UP == 0 {
        return false;
    }
    let lower = info.name.to_ascii_lowercase();
    if !(lower.starts_with("tun") || lower.starts_with("ipsec")) {
        return false;
    }
    if HONK_OWNED_INTERFACES.contains(&lower.as_str()) {
        return false;
    }
    info.addresses.iter().any(|addr| {
        is_global_unicast(addr)
            && (interface_address_filter.is_empty()
                || interface_address_filter
                    .iter()
                    .any(|net| net.contains(addr)))
    })
}

/// Outcome of a single evaluation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnReadinessEvaluation {
    pub ready: bool,
    pub pending: bool,
    pub ready_interface: Option<String>,
}

/// Pure state machine tracking readiness across interface samples.
#[derive(Debug, Default)]
pub struct VpnReadinessTracker {
    tun_states: HashMap<(String, u32), TunCandidateState>,
}

impl VpnReadinessTracker {
    /// Evaluate readiness against supplied interfaces, counter reader and route predicate.
    pub fn evaluate(
        &mut self,
        candidates: &[InterfaceCandidateInfo],
        mut read_counters: impl FnMut(&str) -> Option<TunTrafficCounters>,
        mut has_default_route: impl FnMut(u32) -> bool,
        interface_address_filter: &[ipnet::IpNet],
    ) -> VpnReadinessEvaluation {
        let active_candidates: Vec<&InterfaceCandidateInfo> = candidates
            .iter()
            .filter(|info| is_candidate_interface(info, interface_address_filter))
            .collect();

        // Evict state for interfaces that are no longer candidates.
        let active_identities: HashSet<(String, u32)> = active_candidates
            .iter()
            .map(|info| (info.name.clone(), info.ifindex))
            .collect();
        self.tun_states
            .retain(|id, _| active_identities.contains(id));

        let mut ready_interface = None;
        let mut pending = false;

        for candidate in active_candidates {
            let lower = candidate.name.to_ascii_lowercase();
            let id = (candidate.name.clone(), candidate.ifindex);
            if lower.starts_with("ipsec") {
                if has_default_route(candidate.ifindex) && ready_interface.is_none() {
                    ready_interface = Some(candidate.name.clone());
                }
            } else if lower.starts_with("tun") {
                match self.tun_states.get(&id) {
                    Some(TunCandidateState::Ready) => {
                        if ready_interface.is_none() {
                            ready_interface = Some(candidate.name.clone());
                        }
                    }
                    Some(TunCandidateState::Initial(prev)) => {
                        let prev = *prev;
                        let curr = read_counters(&candidate.name).unwrap_or(prev);
                        if curr.rx_packets > prev.rx_packets || curr.tx_packets > prev.tx_packets {
                            self.tun_states.insert(id, TunCandidateState::Ready);
                            if ready_interface.is_none() {
                                ready_interface = Some(candidate.name.clone());
                            }
                        } else {
                            pending = true;
                        }
                    }
                    None => {
                        let initial = read_counters(&candidate.name).unwrap_or_default();
                        self.tun_states
                            .insert(id, TunCandidateState::Initial(initial));
                        pending = true;
                    }
                }
            }
        }

        VpnReadinessEvaluation {
            ready: ready_interface.is_some(),
            pending,
            ready_interface,
        }
    }
}

/// Convert an In6Addr to standard IpAddr (decoding IPv4-mapped addresses).
pub(crate) fn in6_to_ip(addr: &In6Addr) -> IpAddr {
    if addr.is_v4_mapped() {
        let b = addr.as_bytes();
        IpAddr::V4(std::net::Ipv4Addr::new(b[12], b[13], b[14], b[15]))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(*addr.as_bytes()))
    }
}

/// Read candidates from system interfaces via `getifaddrs`.
fn read_interface_candidates() -> Vec<InterfaceCandidateInfo> {
    let mut map: HashMap<String, InterfaceCandidateInfo> = HashMap::new();
    if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
        for ifa in addrs {
            let entry = map.entry(ifa.interface_name.clone()).or_insert_with(|| {
                let ifindex =
                    nix::net::if_::if_nametoindex(ifa.interface_name.as_str()).unwrap_or(0);
                InterfaceCandidateInfo {
                    name: ifa.interface_name,
                    ifindex,
                    flags: ifa.flags.bits() as u32,
                    addresses: Vec::new(),
                }
            });
            if let Some(storage) = ifa.address {
                if let Some(sin) = storage.as_sockaddr_in() {
                    entry.addresses.push(IpAddr::V4(sin.ip()));
                } else if let Some(sin6) = storage.as_sockaddr_in6() {
                    entry.addresses.push(IpAddr::V6(sin6.ip()));
                }
            }
        }
    }
    map.into_values().collect()
}

/// Read default route output interface indexes across non-local tables.
#[cfg(feature = "ebpf")]
fn read_default_route_ifindexes() -> HashSet<u32> {
    crate::netlink::NlSock::new()
        .and_then(|mut nl| nl.default_route_ifindexes())
        .unwrap_or_else(|err| {
            warn!(%err, "failed to read default routes for VPN readiness");
            HashSet::new()
        })
}

/// Without the eBPF datapath there is no gate to drive.
#[cfg(not(feature = "ebpf"))]
fn read_default_route_ifindexes() -> HashSet<u32> {
    HashSet::new()
}

/// Read interface packet counters from `/sys/class/net/<name>/statistics`.
fn read_interface_counters(name: &str) -> Option<TunTrafficCounters> {
    let rx_path = format!("/sys/class/net/{name}/statistics/rx_packets");
    let tx_path = format!("/sys/class/net/{name}/statistics/tx_packets");
    let rx = std::fs::read_to_string(rx_path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    let tx = std::fs::read_to_string(tx_path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(TunTrafficCounters {
        rx_packets: rx,
        tx_packets: tx,
    })
}

/// Published egress UDP decisions to the gate that disagree with `ready`.
///
/// Unpublished entries belong to an in-flight decision and are left to it.
fn select_vpn_bypass_udp(
    ebpf: &dyn EbpfBackend,
    gate: &honk_config::config::VpnServerBypass,
    ready: bool,
) -> anyhow::Result<Vec<(TuplesKey, ConnState)>> {
    let mut selected = Vec::new();
    if !gate.protocols.contains(&(libc::IPPROTO_UDP as u8)) {
        return Ok(selected);
    }
    let mut cursor = FlowScanCursor::default();
    ebpf.conn_state_for_each_chunk(64, &mut cursor, &mut |chunk| {
        for (key, state) in chunk {
            let raw = unsafe { state.meta.raw };
            if key.l4proto != libc::IPPROTO_UDP as u8
                || state.is_wan_ingress_direction != 0
                || raw & ROUTING_META_FLAG_PUBLISHED == 0
                || (raw & ROUTING_META_FLAG_OFFLOAD != 0) == ready
                || !gate
                    .ports
                    .iter()
                    .any(|&(start, end)| (start..=end).contains(&key.dst_port))
                || !gate
                    .ip
                    .iter()
                    .any(|net| net.contains(&in6_to_ip(&key.dst_ip)))
            {
                continue;
            }
            selected.push((*key, *state));
        }
        true
    })?;
    Ok(selected)
}

/// Retire through the janitor's compare-and-delete path, as if the flows expired now.
fn retire_selected(
    ebpf: &mut dyn EbpfBackend,
    selected: &[(TuplesKey, ConnState)],
    udp_pool: Option<&crate::control::udp_endpoint::UdpEndpointPool>,
) -> usize {
    let requests: Vec<_> = selected
        .iter()
        .map(|(key, expected)| RetireRequest {
            key: *key,
            kind: RetireKind::ExpiredConn {
                expected,
                expired_before_ns: u64::MAX,
            },
        })
        .collect();
    let mut outcomes = vec![RetireOutcome::NotRun; requests.len()];
    let retired = match ebpf.retire_batch(&requests, &mut outcomes) {
        Ok(progress) => progress.conn as usize,
        Err(error) => {
            warn!(error = %format_args!("{:#}", error.source), "failed to retire VPN server bypass UDP flows");
            error.counts.conn as usize
        }
    };
    // Deletes before a failure are real, so their endpoints retire too.
    if let Some(pool) = udp_pool {
        for ((key, expected), outcome) in selected.iter().zip(&outcomes) {
            if *outcome == RetireOutcome::ConnRetired {
                pool.retire_reclaimed(key, expected.incarnation);
            }
        }
    }
    retired
}

#[cfg(test)]
pub(crate) fn retire_vpn_bypass_udp_backend(
    ebpf: &mut dyn EbpfBackend,
    gate: &honk_config::config::VpnServerBypass,
    ready: bool,
) -> anyhow::Result<usize> {
    let selected = select_vpn_bypass_udp(ebpf, gate, ready)?;
    Ok(retire_selected(ebpf, &selected, None))
}

/// Scan under the read lock; take the write lock per retire batch like the janitor.
pub async fn retire_vpn_bypass_udp(
    ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
    gate: &honk_config::config::VpnServerBypass,
    ready: bool,
    udp_pool: &Arc<crate::control::udp_endpoint::UdpEndpointPool>,
) -> anyhow::Result<usize> {
    let selected = select_vpn_bypass_udp(ebpf.read().await.as_ref(), gate, ready)?;
    let mut retired = 0;
    for chunk in selected.chunks(RETIRE_BATCH_CAPACITY) {
        retired += retire_selected(ebpf.write().await.as_mut(), chunk, Some(udp_pool));
    }
    Ok(retired)
}

/// Re-evaluate readiness and drive flags, observation and retirement on state changes.
#[allow(clippy::too_many_arguments)]
pub async fn run_driver_loop<F, Fut, C, Cut, R, RC, DR>(
    gate: &honk_config::config::VpnServerBypass,
    mut set_ready: F,
    mut on_ready_change: C,
    mut read_candidates: R,
    mut read_counters: RC,
    mut has_default_route: DR,
    notify: Arc<Notify>,
    mut stop_rx: watch::Receiver<bool>,
    poll_interval: Duration,
) where
    F: FnMut(bool) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
    C: FnMut(bool, Option<String>) -> Cut,
    Cut: std::future::Future<Output = ()>,
    R: FnMut() -> Vec<InterfaceCandidateInfo>,
    RC: FnMut(&str) -> Option<TunTrafficCounters>,
    DR: FnMut(u32) -> bool,
{
    let mut tracker = VpnReadinessTracker::default();
    let mut current_ready: Option<bool> = Some(false);

    loop {
        if *stop_rx.borrow() {
            break;
        }

        let candidates = read_candidates();
        let eval = tracker.evaluate(
            &candidates,
            &mut read_counters,
            &mut has_default_route,
            &gate.interface_address,
        );

        let next_ready = eval.ready;
        let mut retry_needed = false;
        if current_ready != Some(next_ready) {
            match set_ready(next_ready).await {
                Ok(()) => {
                    current_ready = Some(next_ready);
                    on_ready_change(next_ready, eval.ready_interface.clone()).await;
                    if next_ready {
                        let iface = eval.ready_interface.as_deref().unwrap_or("unknown");
                        info!(interface = iface, "VPN server bypass ready");
                    } else {
                        info!("VPN server bypass not ready");
                    }
                }
                Err(err) => {
                    warn!(%err, "failed to update VPN server bypass readiness; will retry");
                    retry_needed = true;
                }
            }
        }

        let must_poll = eval.pending || retry_needed;
        if must_poll {
            tokio::select! {
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        break;
                    }
                }
                _ = notify.notified() => {}
                _ = tokio::time::sleep(poll_interval) => {}
            }
        } else {
            tokio::select! {
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        break;
                    }
                }
                _ = notify.notified() => {}
            }
        }
    }
}

/// Driver managing the background VPN readiness detection task.
pub struct VpnWatcher {
    notify: Arc<Notify>,
    stop: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl VpnWatcher {
    /// Spawn the VPN readiness watcher task.
    pub fn spawn(
        gate: honk_config::config::VpnServerBypass,
        flags_handle: crate::mode::DatapathFlagsHandle,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        udp_pool: Arc<crate::control::udp_endpoint::UdpEndpointPool>,
    ) -> Self {
        let notify = Arc::new(Notify::new());
        let (stop_tx, stop_rx) = watch::channel(false);
        let notify_clone = Arc::clone(&notify);

        let task = tokio::spawn(async move {
            run_driver_loop(
                &gate,
                |ready| {
                    let flags = flags_handle.clone();
                    async move { flags.set_vpn_ready(ready).await }
                },
                |ready, iface| {
                    let ebpf = Arc::clone(&ebpf);
                    let gate = gate.clone();
                    let pool = Arc::clone(&udp_pool);
                    async move {
                        ebpf.write().await.set_vpn_bypass_interface(if ready {
                            iface
                        } else {
                            None
                        });
                        if let Err(err) = retire_vpn_bypass_udp(&ebpf, &gate, ready, &pool).await {
                            warn!(%err, "failed to retire UDP flows on VPN readiness change");
                        }
                    }
                },
                read_interface_candidates,
                read_interface_counters,
                |ifindex| read_default_route_ifindexes().contains(&ifindex),
                notify_clone,
                stop_rx,
                Duration::from_secs(1),
            )
            .await;
        });

        Self {
            notify,
            stop: stop_tx,
            task: Some(task),
        }
    }

    /// Notify the watcher that network interfaces or routes have changed.
    pub fn notify(&self) {
        self.notify.notify_one();
    }

    /// Stop and join the background watcher.
    pub async fn shutdown(mut self, timeout: Duration) {
        let _ = self.stop.send(true);
        self.notify.notify_one();
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(timeout, task).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::mock::MockEbpfBackend;
    use honk_ebpf_common::conn::ConnState;
    use honk_ebpf_common::{
        OutboundIndex, RoutingMeta, RoutingMetaData, TuplesKey, UdpDecisionState,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn key_bytes(key: &TuplesKey) -> [u8; 40] {
        let mut bytes = [0u8; 40];
        unsafe {
            std::ptr::copy_nonoverlapping(
                key as *const TuplesKey as *const u8,
                bytes.as_mut_ptr(),
                40,
            );
        }
        bytes
    }

    #[test]
    fn global_unicast_admissions_and_exclusions() {
        assert!(is_global_unicast(&"10.8.0.2".parse().unwrap()));
        assert!(is_global_unicast(&"172.16.0.1".parse().unwrap()));
        assert!(is_global_unicast(&"192.168.1.100".parse().unwrap()));
        assert!(is_global_unicast(&"203.0.113.1".parse().unwrap()));
        assert!(is_global_unicast(&"fd00::1".parse().unwrap()));
        assert!(is_global_unicast(&"2001:db8::1".parse().unwrap()));

        assert!(!is_global_unicast(&"127.0.0.1".parse().unwrap()));
        assert!(!is_global_unicast(&"169.254.1.1".parse().unwrap()));
        assert!(!is_global_unicast(&"224.0.0.1".parse().unwrap()));
        assert!(!is_global_unicast(&"255.255.255.255".parse().unwrap()));
        assert!(!is_global_unicast(&"0.0.0.0".parse().unwrap()));
        assert!(!is_global_unicast(&"::1".parse().unwrap()));
        assert!(!is_global_unicast(&"fe80::1".parse().unwrap()));
        assert!(!is_global_unicast(&"ff02::1".parse().unwrap()));
        assert!(!is_global_unicast(&"::".parse().unwrap()));
    }

    #[test]
    fn candidate_interface_filtering() {
        const IFF_UP: u32 = libc::IFF_UP as u32;

        let tun = InterfaceCandidateInfo {
            name: "tun0".into(),
            ifindex: 10,
            flags: IFF_UP,
            addresses: vec!["10.8.0.2".parse().unwrap()],
        };
        assert!(is_candidate_interface(&tun, &[]));

        let ipsec = InterfaceCandidateInfo {
            name: "ipsec0".into(),
            ifindex: 11,
            flags: IFF_UP,
            addresses: vec!["10.0.0.5".parse().unwrap()],
        };
        assert!(is_candidate_interface(&ipsec, &[]));

        let down_tun = InterfaceCandidateInfo {
            name: "tun0".into(),
            ifindex: 10,
            flags: 0,
            addresses: vec!["10.8.0.2".parse().unwrap()],
        };
        assert!(!is_candidate_interface(&down_tun, &[]));

        let dae0 = InterfaceCandidateInfo {
            name: "dae0".into(),
            ifindex: 12,
            flags: IFF_UP,
            addresses: vec!["10.8.0.2".parse().unwrap()],
        };
        assert!(!is_candidate_interface(&dae0, &[]));

        let eth0 = InterfaceCandidateInfo {
            name: "eth0".into(),
            ifindex: 13,
            flags: IFF_UP,
            addresses: vec!["10.8.0.2".parse().unwrap()],
        };
        assert!(!is_candidate_interface(&eth0, &[]));

        let link_local_only = InterfaceCandidateInfo {
            name: "tun1".into(),
            ifindex: 14,
            flags: IFF_UP,
            addresses: vec!["169.254.1.2".parse().unwrap(), "fe80::1".parse().unwrap()],
        };
        assert!(!is_candidate_interface(&link_local_only, &[]));

        let filter: Vec<ipnet::IpNet> = vec!["10.8.0.0/24".parse().unwrap()];
        assert!(is_candidate_interface(&tun, &filter));

        let outside_filter = InterfaceCandidateInfo {
            name: "tun2".into(),
            ifindex: 15,
            flags: IFF_UP,
            addresses: vec!["10.9.0.2".parse().unwrap()],
        };
        assert!(!is_candidate_interface(&outside_filter, &filter));
    }

    #[test]
    fn tun_sampling_latches_and_drops_state() {
        const IFF_UP: u32 = libc::IFF_UP as u32;
        let mut tracker = VpnReadinessTracker::default();
        let tun = InterfaceCandidateInfo {
            name: "tun0".into(),
            ifindex: 10,
            flags: IFF_UP,
            addresses: vec!["10.8.0.2".parse().unwrap()],
        };

        let mut counters = TunTrafficCounters {
            rx_packets: 10,
            tx_packets: 5,
        };

        // First sample records counters: not ready, but pending.
        let eval1 = tracker.evaluate(
            std::slice::from_ref(&tun),
            |_| Some(counters),
            |_| false,
            &[],
        );
        assert!(!eval1.ready);
        assert!(eval1.pending);
        assert_eq!(eval1.ready_interface, None);

        // Counter unchanged: still pending and not ready.
        let eval2 = tracker.evaluate(
            std::slice::from_ref(&tun),
            |_| Some(counters),
            |_| false,
            &[],
        );
        assert!(!eval2.ready);
        assert!(eval2.pending);

        // Counter growth: becomes ready and no longer pending.
        counters.rx_packets = 11;
        let eval3 = tracker.evaluate(
            std::slice::from_ref(&tun),
            |_| Some(counters),
            |_| false,
            &[],
        );
        assert!(eval3.ready);
        assert!(!eval3.pending);
        assert_eq!(eval3.ready_interface.as_deref(), Some("tun0"));

        // Latching: subsequent sample without growth stays ready.
        let eval4 = tracker.evaluate(
            std::slice::from_ref(&tun),
            |_| Some(counters),
            |_| false,
            &[],
        );
        assert!(eval4.ready);
        assert!(!eval4.pending);

        // Interface disappears: dropped from tracker.
        let eval5 = tracker.evaluate(&[], |_| Some(counters), |_| false, &[]);
        assert!(!eval5.ready);
        assert!(!eval5.pending);

        // Interface reappears: resets to first sample (not ready, pending).
        let eval6 = tracker.evaluate(
            std::slice::from_ref(&tun),
            |_| Some(counters),
            |_| false,
            &[],
        );
        assert!(!eval6.ready);
        assert!(eval6.pending);
    }

    #[test]
    fn ipsec_readiness_requires_non_local_default_route() {
        const IFF_UP: u32 = libc::IFF_UP as u32;
        let mut tracker = VpnReadinessTracker::default();
        let ipsec = InterfaceCandidateInfo {
            name: "ipsec0".into(),
            ifindex: 20,
            flags: IFF_UP,
            addresses: vec!["10.0.0.1".parse().unwrap()],
        };

        // Without default route: not ready.
        let eval1 = tracker.evaluate(std::slice::from_ref(&ipsec), |_| None, |_| false, &[]);
        assert!(!eval1.ready);
        assert!(!eval1.pending);

        // With default route: ready immediately.
        let eval2 = tracker.evaluate(
            std::slice::from_ref(&ipsec),
            |_| None,
            |ifindex| ifindex == 20,
            &[],
        );
        assert!(eval2.ready);
        assert!(!eval2.pending);
        assert_eq!(eval2.ready_interface.as_deref(), Some("ipsec0"));
    }

    #[tokio::test]
    async fn driver_calls_set_ready_only_on_change_and_stops_polling() {
        const IFF_UP: u32 = libc::IFF_UP as u32;
        let gate = honk_config::config::VpnServerBypass {
            ip: vec!["198.51.100.0/24".parse().unwrap()],
            ports: vec![(4500, 4500)],
            protocols: vec![17],
            interface_address: vec![],
        };

        let set_ready_calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let read_count = Arc::new(AtomicUsize::new(0));

        let tun = InterfaceCandidateInfo {
            name: "tun0".into(),
            ifindex: 30,
            flags: IFF_UP,
            addresses: vec!["10.8.0.2".parse().unwrap()],
        };

        let notify = Arc::new(Notify::new());
        let (stop_tx, stop_rx) = watch::channel(false);

        let calls = Arc::clone(&set_ready_calls);
        let reads = Arc::clone(&read_count);

        let driver_task = tokio::spawn(async move {
            run_driver_loop(
                &gate,
                |ready| {
                    calls.lock().push(ready);
                    async { Ok(()) }
                },
                |_, _| async {},
                || vec![tun.clone()],
                |name| {
                    assert_eq!(name, "tun0");
                    let count = reads.fetch_add(1, Ordering::SeqCst);
                    Some(TunTrafficCounters {
                        rx_packets: count as u64,
                        tx_packets: 0,
                    })
                },
                |_| false,
                notify,
                stop_rx,
                Duration::from_millis(10),
            )
            .await;
        });

        // Give driver time to observe initial sample (rx=0, not ready) then second sample (rx=1, ready)
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Ready was set once to true (initial was false, change occurred when counters grew).
        assert_eq!(*set_ready_calls.lock(), vec![true]);

        let reads_after_ready = read_count.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Polling stopped because pending is false; reads count did not advance.
        assert_eq!(read_count.load(Ordering::SeqCst), reads_after_ready);

        let _ = stop_tx.send(true);
        let _ = driver_task.await;
    }

    #[test]
    fn mock_backend_udp_retirement_selection() {
        let mut backend = MockEbpfBackend::new();
        let gate = honk_config::config::VpnServerBypass {
            ip: vec!["198.51.100.0/24".parse().unwrap()],
            ports: vec![(4500, 4500)],
            protocols: vec![libc::IPPROTO_UDP as u8],
            interface_address: vec![],
        };

        let client_ip = In6Addr::from_ipv4_bytes([10, 0, 0, 2]);
        let vpn_ip = In6Addr::from_ipv4_bytes([198, 51, 100, 7]);
        let other_ip = In6Addr::from_ipv4_bytes([203, 0, 113, 7]);

        let make_key = |src_port: u16, dst_ip: In6Addr, dst_port: u16, l4proto: u8| TuplesKey {
            src_ip: client_ip,
            dst_ip,
            src_port,
            dst_port,
            l4proto,
            padding: [0; 3],
        };

        let make_state = |ingress: u8, direct: bool, published: bool| {
            let outbound = if direct {
                OutboundIndex::Direct as u8
            } else {
                1
            };
            let mut meta = RoutingMeta {
                data: RoutingMetaData {
                    outbound,
                    mark: 0,
                    must: 0,
                    dscp: 0,
                    _pad: 0,
                },
            };
            if direct {
                unsafe { meta.raw |= ROUTING_META_FLAG_OFFLOAD };
            }
            if published {
                unsafe { meta.raw |= ROUTING_META_FLAG_PUBLISHED };
            }
            ConnState {
                is_wan_ingress_direction: ingress,
                state: UdpDecisionState::None as u8,
                meta,
                ..Default::default()
            }
        };

        let key_udp_proxied = make_key(41000, vpn_ip, 4500, libc::IPPROTO_UDP as u8);
        let key_udp_direct = make_key(41001, vpn_ip, 4500, libc::IPPROTO_UDP as u8);
        let key_wrong_port = make_key(41002, vpn_ip, 443, libc::IPPROTO_UDP as u8);
        let key_wrong_ip = make_key(41003, other_ip, 4500, libc::IPPROTO_UDP as u8);
        let key_tcp = make_key(41004, vpn_ip, 4500, libc::IPPROTO_TCP as u8);
        let key_ingress = make_key(41005, vpn_ip, 4500, libc::IPPROTO_UDP as u8);

        // Flow 1: Matching UDP egress proxied
        backend
            .udp_conn_states
            .insert(key_bytes(&key_udp_proxied), make_state(0, false, true));
        // Flow 3: Wrong port
        backend
            .udp_conn_states
            .insert(key_bytes(&key_wrong_port), make_state(0, false, true));
        // Flow 4: Wrong IP
        backend
            .udp_conn_states
            .insert(key_bytes(&key_wrong_ip), make_state(0, false, true));
        // Flow 5: TCP flow
        backend
            .tcp_conn_states
            .insert(key_bytes(&key_tcp), make_state(0, false, true));
        // Flow 6: Ingress flow
        backend
            .udp_conn_states
            .insert(key_bytes(&key_ingress), make_state(1, false, true));

        // Flow 7: matching but still being decided (unpublished)
        let key_unpublished = make_key(41006, vpn_ip, 4500, libc::IPPROTO_UDP as u8);
        backend
            .udp_conn_states
            .insert(key_bytes(&key_unpublished), make_state(0, false, false));

        // Becoming ready: should retire ONLY the matching proxied UDP flow
        let retired = retire_vpn_bypass_udp_backend(&mut backend, &gate, true).unwrap();
        assert_eq!(retired, 1);
        assert!(
            !backend
                .udp_conn_states
                .contains_key(&key_bytes(&key_udp_proxied))
        );
        assert!(
            backend
                .udp_conn_states
                .contains_key(&key_bytes(&key_wrong_port))
        );
        assert!(
            backend
                .udp_conn_states
                .contains_key(&key_bytes(&key_wrong_ip))
        );
        assert!(backend.tcp_conn_states.contains_key(&key_bytes(&key_tcp)));

        // Now insert matching UDP egress direct flow
        backend
            .udp_conn_states
            .insert(key_bytes(&key_udp_direct), make_state(0, true, true));

        // Becoming not ready: should retire ONLY the matching direct UDP flow
        let retired2 = retire_vpn_bypass_udp_backend(&mut backend, &gate, false).unwrap();
        assert_eq!(retired2, 1);
        assert!(
            !backend
                .udp_conn_states
                .contains_key(&key_bytes(&key_udp_direct))
        );
        assert!(
            backend
                .udp_conn_states
                .contains_key(&key_bytes(&key_unpublished)),
            "an in-flight decision is left to its owner"
        );
    }
}
