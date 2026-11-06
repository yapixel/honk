//! Bind configured interfaces before publishing the real backend.
//! Startup binds before backend publication/admission; watcher rounds need async lock handoffs.

use std::os::fd::OwnedFd;
use std::path::Path;

use super::RealEbpfBackend;
use super::interface_state::{self, InterfaceState};
use crate::degradations::Degradations;
use crate::ebpf::interface::status::{BindFailure, ReconcileStep};
use crate::ebpf::interface::{self, InterfacePlan, Topology};

/// What startup hands the watcher: the subscription opened before the first
/// dump (none when the kernel refused it) and the episode/sysctl bookkeeping
/// startup already advanced.
pub(crate) struct InterfaceHandoff {
    pub(super) subscription: Option<OwnedFd>,
    pub(super) state: InterfaceState,
}

fn android_startup_binding_failure(
    android: bool,
    requested: usize,
    owned: usize,
    failed: usize,
) -> bool {
    android && requested != 0 && owned == 0 && failed == requested
}

/// Fails only when the topology cannot be read (after the bounded dump retry),
/// the default route cannot be read for an `auto` entry, or `load` fails.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_interfaces(
    obj: &[u8],
    pin_root: &Path,
    tproxy_port: u16,
    dae0: &crate::daens::Dae0Setup,
    lan: &[String],
    wan: &[String],
    degradations: &Degradations,
    read_topology: impl Fn(bool) -> anyhow::Result<Topology>,
) -> anyhow::Result<(RealEbpfBackend, InterfaceHandoff)> {
    let subscription = super::iface_watch::subscribe(degradations);
    let mut state = InterfaceState::default();
    let mut topology = read_topology(interface::any_auto(lan, wan)).map_err(|error| {
        error.context("read the network topology for the configured interfaces")
    })?;
    let mut plan = interface::plan(lan, wan, &topology);
    write_sysctls(&mut state, &plan, &topology);
    let mut backend = RealEbpfBackend::load(
        obj,
        pin_root,
        tproxy_port,
        dae0,
        interface::local_ip(&plan),
        &interface::initial_programs(&plan, !lan.is_empty()),
    )
    .await?;

    let mut report = backend.bind_interfaces(&plan, &topology);
    if report.topology_changed {
        match read_topology(interface::any_auto(lan, wan)) {
            Ok(current) => {
                topology = current;
                plan = interface::plan(lan, wan, &topology);
                write_sysctls(&mut state, &plan, &topology);
                report = backend.bind_interfaces(&plan, &topology);
            }
            Err(error) => state.step_failed(ReconcileStep::Topology, &error),
        }
    }
    // Android builds must not report a running datapath when every requested
    // TC attachment was rejected.  A vendor kernel without TCX otherwise
    // leaves the control plane alive while all traffic bypasses interception.
    // Keep the documented pending/empty-interface behavior: this guard only
    // fires when the resolved plan had bindings and every one failed before
    // the first owner was published.  Partial failures remain observable via
    // the existing degradation and watcher retry path.
    if android_startup_binding_failure(
        cfg!(target_os = "android"),
        plan.bindings.len(),
        backend.owned_bindings().count(),
        report.failed.len(),
    ) {
        anyhow::bail!(
            "{}",
            concat!(
                "Android eBPF datapath could not attach any configured interface; ",
                "the kernel likely lacks TCX support (no traffic will be intercepted)"
            )
        );
    }
    let owned: Vec<_> = backend
        .owned_bindings()
        .map(|binding| binding.key())
        .collect();
    let failures: Vec<_> = report
        .failed
        .iter()
        .map(|(binding, error)| BindFailure::new(binding, error))
        .collect();
    state.settle(&plan, &owned, &failures, degradations);
    Ok((
        backend,
        InterfaceHandoff {
            subscription,
            state,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::android_startup_binding_failure;

    #[test]
    fn android_only_fails_when_every_requested_binding_failed() {
        assert!(android_startup_binding_failure(true, 2, 0, 2));
        assert!(!android_startup_binding_failure(false, 2, 0, 2));
        assert!(!android_startup_binding_failure(true, 0, 0, 0));
        assert!(!android_startup_binding_failure(true, 2, 1, 2));
        assert!(!android_startup_binding_failure(true, 2, 0, 1));
    }
}

/// Startup writes run on the startup task (the only place besides the watcher's
/// blocking step where `sysctl -w` may be spawned).
fn write_sysctls(state: &mut InterfaceState, plan: &InterfacePlan, topology: &Topology) {
    let owed = state.claim_sysctls(plan, topology, tokio::time::Instant::now());
    interface_state::perform(&owed, &interface_state::write_sysctl);
}
