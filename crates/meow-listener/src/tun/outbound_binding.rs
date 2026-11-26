//! Outbound-interface binding for TUN route scopes (#375, issue #695).
//!
//! Global route scope (`auto-route: true`, or `global`) steers all traffic
//! into the TUN, so every socket meow opens must be bound to the physical
//! interface (via
//! `meow_common::install_outbound_interface`: `SO_BINDTODEVICE` on Linux,
//! `IP_BOUND_IF` on macOS, `IP_UNICAST_IF` on Windows) or it loops back
//! into the device.
//! Outside global scope the same binding is installed when
//! `auto-detect-interface` is enabled, independently of automatic route
//! installation. An explicit `outbound-interface`/`interface-name` wins
//! over detection, and an explicit detection-off is honored.
//! The binding is per-socket and applied at creation: a socket created
//! before it is installed stays unbound for its whole life, and once the
//! routes into the device go in its traffic re-enters the TUN — a QUIC or mux
//! session opened by an early startup dial (geodata download, provider
//! fetch, health probe) then loops until it times out.
//!
//! [`OutboundBinding`] owns one installation of that process-global
//! binding. The binary installs it *before* the config build performs its
//! first dial, and a config reload installs the new configuration's
//! binding before the reload's first dial (both via
//! `meow_api::preinstall_global_route_binding`); either hands it to
//! [`TunListener::with_outbound_binding`]. A listener started without one
//! (the pre-install failed) installs its own before touching routes.
//! Either way the listener's device owns it, so it is given up exactly
//! when the routes it protects go away — listener teardown, reload, or a
//! startup failure.
//!
//! Owners may overlap — a reload's binding is installed while the old
//! listener still runs. The registry is owner-aware
//! (`meow_common::OutboundIfaceGuard`): the newest live owner is in
//! effect, dropping it restores the newest owner still alive, and dropping
//! a superseded owner is a no-op. So a rejected reload restores the
//! running listener's binding, and an old listener torn down after its
//! successor installed never clears the successor's binding.
//!
//! [`TunListener::with_outbound_binding`]: super::TunListener::with_outbound_binding

use std::io;
use std::sync::{Arc, Weak};

use parking_lot::{Mutex, RwLock};
use tracing::info;

use super::route::{
    fixed_network_identity, register_tun_interface, AutoDetectInterfaceFinder,
    TunInterfaceRegistration,
};

/// Provider transports that may sit outside the live route graph.
type ProviderRoots = Arc<dyn Fn() -> Vec<Arc<dyn meow_common::Proxy>> + Send + Sync + 'static>;

/// Process-wide provider snapshot. The embedder installs it once; any TUN
/// generation — including one spawned later by an API reload — consults it
/// when a network change retires pooled transports. The closure is expected
/// to hold weak state so it cannot keep the provider registry alive.
static PROVIDER_ROOTS: RwLock<Option<ProviderRoots>> = RwLock::new(None);

/// Install the process-wide provider transports that a network change must
/// also retire. Embedders call this once after building the provider
/// registry; the closure runs on each flush, so it sees later refreshes.
pub fn set_outbound_provider_roots(
    roots: impl Fn() -> Vec<Arc<dyn meow_common::Proxy>> + Send + Sync + 'static,
) {
    *PROVIDER_ROOTS.write() = Some(Arc::new(roots));
}

/// Snapshot the process-wide provider transports installed by the embedder.
pub(super) fn provider_roots() -> Vec<Arc<dyn meow_common::Proxy>> {
    let roots = PROVIDER_ROOTS.read().as_ref().map(Arc::clone);
    roots.map_or_else(Vec::new, |roots| roots.as_ref()())
}

/// One owner of the process-global outbound-interface binding; dropping it
/// gives the binding up (the newest owner still alive takes over, or it is
/// cleared when none is left).
#[must_use = "dropping the binding gives it up immediately"]
#[derive(Debug)]
pub struct OutboundBinding {
    guard: Arc<meow_common::OutboundIfaceGuard>,
    /// Destination-aware selector installed in the registry. An explicit
    /// interface suppresses it.
    selector: Option<Arc<AutoDetectInterfaceFinder>>,
    /// Default-interface tracker for network-change monitoring, present
    /// whenever `auto-detect-interface` is enabled even if an explicit
    /// interface owns the binding.
    monitor_finder: Option<Arc<AutoDetectInterfaceFinder>>,
    /// Runtime TUN name in the process-global exclusion set, kept until this
    /// binding's device is torn down so overlapping reload finders skip it.
    tun_registration: Mutex<Option<RegisteredTun>>,
    /// Running owner's last acknowledged network state, inherited only when
    /// this binding keeps the same interface and automatic/fixed strategy.
    inherited_network: Option<meow_common::OutboundNetworkAcknowledgement>,
    /// Whether the first monitor observation is a fresh baseline: a new
    /// process, or a policy change whose transport retirement was already
    /// performed by API adoption.
    accept_first_observation: bool,
}

/// One registered runtime TUN exclusion; dropping it releases this binding's
/// reference without disturbing another owner's registration of the same name.
#[derive(Debug)]
struct RegisteredTun {
    name: String,
    _registration: TunInterfaceRegistration,
}

impl OutboundBinding {
    /// Install the binding with automatic detection enabled.
    /// `outbound_interface` is `tun.outbound-interface`; `None` auto-detects
    /// the interface carrying the default route (`0.0.0.0/0` — the TUN's
    /// own split `/1` routes are skipped, so detection is safe while a
    /// global-scope listener is still running).
    ///
    /// Fails closed: an error means nothing is installed, and callers must
    /// not install global routes. Targets other than Linux, macOS and
    /// Windows always fail — they have no per-socket binding (#375).
    pub fn install(outbound_interface: Option<&str>) -> io::Result<Self> {
        Self::install_with_auto_detect(outbound_interface, true)
    }

    /// Install an explicit interface, or a live destination-aware finder when
    /// `auto_detect_interface` is true. Disabling detection without an
    /// explicit interface fails closed instead of creating unbound sockets.
    pub fn install_with_auto_detect(
        outbound_interface: Option<&str>,
        auto_detect_interface: bool,
    ) -> io::Result<Self> {
        if !cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tun: outbound-interface binding is only implemented on Linux, macOS \
                 and Windows (#375); disable auto-detect-interface or use \
                 auto-route: fake-ip without an explicit outbound-interface here",
            ));
        }
        let finder = if auto_detect_interface {
            Some(Arc::new(super::route::AutoDetectInterfaceFinder::new()))
        } else {
            None
        };
        let selector = if outbound_interface.is_none() {
            finder.clone()
        } else {
            None
        };
        let iface = match (outbound_interface, finder.as_ref()) {
            (Some(name), _) => name.to_owned(),
            (None, Some(finder)) => finder.default_interface_identity()?.0,
            (None, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tun: auto-detect-interface is false; set outbound-interface or \
                     interface-name before enabling global auto-route",
                ));
            }
        };
        let registry_selector = selector
            .as_ref()
            .map(|finder| Arc::clone(finder) as Arc<dyn meow_common::OutboundInterfaceFinder>);
        // Capture the running owner's acknowledged network state before this
        // owner supersedes it. A same-policy successor inherits the baseline
        // so a secondary-family/default/source-address change that happened
        // before its monitor starts still triggers one flush. A policy change
        // is already retired by API adoption at commit, so its monitor starts
        // from a fresh baseline instead of flushing twice.
        let is_auto = selector.is_some();
        let previous = meow_common::outbound_interface_snapshot();
        let keeps_policy = previous.interface.as_deref() == Some(iface.as_str())
            && previous.auto_detect == is_auto;
        let inherited_network = keeps_policy.then_some(previous.network).flatten();
        let accept_first_observation = !keeps_policy;
        let guard = meow_common::install_outbound_interface_with_finder(&iface, registry_selector)
            .map_err(|e| {
                io::Error::other(format!(
                    "tun: outbound interface binding failed ({e}); \
                 refusing to install default routes without loop avoidance"
                ))
            })?;
        if let Some(acknowledgement) = inherited_network {
            guard.acknowledge_network(acknowledgement);
        }
        info!(
            "tun: outbound sockets bound to '{iface}' (auto-detect-interface: {})",
            selector.is_some()
        );
        Ok(Self {
            guard: Arc::new(guard),
            selector,
            monitor_finder: finder,
            tun_registration: Mutex::new(None),
            inherited_network,
            accept_first_observation,
        })
    }

    /// The interface this binding installed.
    pub fn interface(&self) -> &str {
        self.guard.interface()
    }

    /// Mark the binding's listener as up: from here the logbook records
    /// it (`meow_common::OutboundIfaceGuard::commit`). A reload candidate
    /// rejected before its listener starts never gets here.
    pub fn commit(&self) {
        self.guard.commit();
    }

    /// Register the runtime TUN name in the process-global exclusion set
    /// after device creation. The registration is kept until this binding is
    /// dropped, so a reload that creates its finder before its device still
    /// excludes the running TUN. Replacing a rotated retry name releases only
    /// this binding's reference, never another owner's.
    ///
    /// # Errors
    /// Returns an error for an empty runtime name, for a TUN named as this
    /// binding's own outbound interface, and when registration fails. A failed
    /// replacement leaves the previous registration in place.
    pub(super) fn set_tun_interface(&self, name: &str) -> io::Result<()> {
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun: runtime device name is unavailable; refusing to auto-detect \
                 without excluding the TUN itself",
            ));
        }
        if self.interface() == name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun: outbound interface must not be the TUN device itself",
            ));
        }
        let mut registered = self.tun_registration.lock();
        if registered.as_ref().is_some_and(|entry| entry.name == name) {
            return Ok(());
        }
        let registration = register_tun_interface(name)?;
        if let Some(finder) = &self.selector {
            finder.set_tun_interface(name);
        }
        if let Some(finder) = &self.monitor_finder {
            finder.set_tun_interface(name);
        }
        let previous = registered.replace(RegisteredTun {
            name: name.to_owned(),
            _registration: registration,
        });
        drop(registered);
        drop(previous);
        Ok(())
    }

    /// Whether the binding selects an interface per destination instead of a
    /// fixed user override.
    pub fn is_auto_detect(&self) -> bool {
        self.selector.is_some()
    }

    /// Attach default-interface monitoring. Monitoring is independent of
    /// whether an explicit interface leaves the binding fixed, and of
    /// whether routes are installed; it only observes physical changes.
    pub(super) fn enable_monitoring(&mut self, is_monitoring_enabled: bool) {
        if is_monitoring_enabled && self.monitor_finder.is_none() {
            self.monitor_finder = Some(Arc::new(super::route::AutoDetectInterfaceFinder::new()));
        }
    }

    /// Create default-interface monitor state without retaining the device,
    /// routes, or owner. Present when detection is enabled, even when an
    /// explicit interface fixes the binding: network changes still retire
    /// sockets bound before the change.
    pub(super) fn monitor(&self) -> Option<OutboundMonitor> {
        self.monitor_finder.as_ref()?;
        let selection = match &self.selector {
            Some(finder) => MonitorSelection::Default(Arc::clone(finder)),
            None => MonitorSelection::Fixed(Arc::from(self.guard.interface())),
        };
        let acknowledged = self
            .inherited_network
            .map(ObservedNetwork::from_acknowledgement);
        Some(OutboundMonitor {
            guard: Arc::downgrade(&self.guard),
            selection,
            state: Arc::new(Mutex::new(MonitorState::new(
                acknowledged,
                self.accept_first_observation,
            ))),
        })
    }
}

/// Which source a monitor follows: the destination-aware default finder, or
/// the fixed override's own index/address identity.
#[derive(Clone)]
enum MonitorSelection {
    Default(Arc<AutoDetectInterfaceFinder>),
    Fixed(Arc<str>),
}

/// Platform-neutral observed state; `None` is network loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedNetwork {
    fingerprint: Option<u64>,
}

impl ObservedNetwork {
    /// Convert a shared owner acknowledgement into a monitor baseline.
    fn from_acknowledgement(acknowledgement: meow_common::OutboundNetworkAcknowledgement) -> Self {
        Self {
            fingerprint: acknowledgement
                .is_available
                .then_some(acknowledgement.fingerprint),
        }
    }
}

/// A pending observation tagged with the generation an acknowledgement must
/// name, so an older flush never consumes a newer observation.
#[derive(Debug, Clone, Copy)]
struct PendingObservation {
    generation: u64,
    observed: ObservedNetwork,
}

/// Monitor bookkeeping: the last observed state stays pending until an
/// effective owner's successful flush acknowledges exactly that generation.
#[derive(Debug)]
struct MonitorState {
    next_generation: u64,
    pending: Option<PendingObservation>,
    acknowledged: Option<ObservedNetwork>,
    is_dirty: bool,
    accept_first_observation: bool,
}

impl MonitorState {
    /// Create state from an inherited acknowledgement, if any.
    fn new(acknowledged: Option<ObservedNetwork>, accept_first_observation: bool) -> Self {
        Self {
            next_generation: 0,
            pending: None,
            acknowledged,
            is_dirty: false,
            accept_first_observation,
        }
    }

    /// Record one observation and return its generation. A fresh binding
    /// adopts its first observation as the baseline; a same-policy successor
    /// without an inherited acknowledgement keeps it pending for one flush.
    fn record(&mut self, observed: ObservedNetwork) -> u64 {
        self.next_generation = self.next_generation.wrapping_add(1);
        let generation = self.next_generation;
        if self.acknowledged.is_none() && self.accept_first_observation {
            self.accept_first_observation = false;
            self.acknowledged = Some(observed);
        }
        // An observed outage or route transition still requires retirement
        // if the network returns to the acknowledged fingerprint before the
        // owner becomes effective again.
        self.is_dirty |= Some(observed) != self.acknowledged;
        self.pending = Some(PendingObservation {
            generation,
            observed,
        });
        generation
    }

    /// The newest generation awaiting retirement after any observed change.
    fn pending_change(&self) -> Option<u64> {
        let pending = self.pending?;
        self.is_dirty.then_some(pending.generation)
    }

    /// Acknowledge exactly `generation`; a newer pending observation remains.
    fn acknowledge(&mut self, generation: u64) -> Option<ObservedNetwork> {
        let pending = self.pending?;
        if pending.generation != generation {
            return None;
        }
        self.acknowledged = Some(pending.observed);
        self.is_dirty = false;
        Some(pending.observed)
    }
}

/// One monitor poll, tagged with the generation its acknowledgement must name.
#[derive(Debug, Clone, Copy)]
pub(super) struct NetworkObservation {
    generation: u64,
    observed: ObservedNetwork,
}

impl NetworkObservation {
    /// Generation to pass to [`OutboundMonitor::retire_if_effective`] for a flush.
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether the observed state has a usable outbound interface.
    pub(super) fn is_available(&self) -> bool {
        self.observed.fingerprint.is_some()
    }
}

/// Background lookup state that cannot keep a stopped TUN generation alive.
#[derive(Clone)]
pub(super) struct OutboundMonitor {
    guard: Weak<meow_common::OutboundIfaceGuard>,
    selection: MonitorSelection,
    state: Arc<Mutex<MonitorState>>,
}

impl OutboundMonitor {
    /// Check owner identity without retaining it across a potentially
    /// blocking route-table read.
    pub(super) fn is_effective(&self) -> bool {
        self.guard
            .upgrade()
            .is_some_and(|guard| guard.is_effective())
    }

    /// Poll the selected interface once. `None` means the owning guard is gone
    /// and the monitor must stop; a superseded-but-live owner still records
    /// its observation so a rejected reload can flush it after restoration.
    pub(super) fn refresh(&self) -> io::Result<Option<NetworkObservation>> {
        let Some(guard) = self.guard.upgrade() else {
            return Ok(None);
        };
        let is_effective = guard.is_effective();
        let observed = match &self.selection {
            MonitorSelection::Default(finder) => match finder.network_identity() {
                Ok(identity) => {
                    if is_effective {
                        if let Err(error) = guard.refresh_interface(&identity.name) {
                            tracing::debug!(
                                "tun: interface '{}' vanished during monitor refresh: {error}",
                                identity.name
                            );
                            return Ok(Some(self.record(ObservedNetwork { fingerprint: None })));
                        }
                    }
                    ObservedNetwork {
                        fingerprint: Some(identity.fingerprint),
                    }
                }
                Err(error) => {
                    tracing::debug!("tun: default interface lookup failed: {error}");
                    ObservedNetwork { fingerprint: None }
                }
            },
            MonitorSelection::Fixed(name) => match fixed_network_identity(name.as_ref()) {
                Ok(identity) => ObservedNetwork {
                    fingerprint: Some(identity.fingerprint),
                },
                Err(error) => {
                    tracing::debug!("tun: fixed interface '{name}' lookup failed: {error}");
                    ObservedNetwork { fingerprint: None }
                }
            },
        };
        Ok(Some(self.record(observed)))
    }

    /// Generation of the pending state that still needs a successful flush.
    pub(super) fn pending_change(&self) -> Option<u64> {
        self.state.lock().pending_change()
    }

    /// Whether the last acknowledged state had a usable interface.
    pub(super) fn acknowledged_is_available(&self) -> bool {
        self.state
            .lock()
            .acknowledged
            .is_some_and(|state| state.fingerprint.is_some())
    }

    /// Retire sessions for `generation` under the effective owner's registry
    /// lease, then publish the acknowledgement before a successor can install.
    /// Returns false without cleanup when superseded or the generation is stale.
    pub(super) fn retire_if_effective(&self, generation: u64, retire: impl FnOnce()) -> bool {
        let Some(guard) = self.guard.upgrade() else {
            return false;
        };
        guard.retire_network_if_effective(|| {
            let mut state = self.state.lock();
            if state.pending_change() != Some(generation) {
                return None;
            }
            retire();
            state.acknowledge(generation).map(|observed| {
                meow_common::OutboundNetworkAcknowledgement {
                    fingerprint: observed.fingerprint.unwrap_or(0),
                    is_available: observed.fingerprint.is_some(),
                }
            })
        })
    }

    /// Acknowledge a test retirement without taking the production owner lease.
    #[cfg(test)]
    fn acknowledge(&self, generation: u64) -> bool {
        let observed = {
            let mut state = self.state.lock();
            state.acknowledge(generation)
        };
        let Some(observed) = observed else {
            return false;
        };
        if let Some(guard) = self.guard.upgrade() {
            guard.acknowledge_network(meow_common::OutboundNetworkAcknowledgement {
                fingerprint: observed.fingerprint.unwrap_or(0),
                is_available: observed.fingerprint.is_some(),
            });
        }
        true
    }

    /// Record one observation without the blocking route lookup.
    fn record(&self, observed: ObservedNetwork) -> NetworkObservation {
        let generation = self.state.lock().record(observed);
        NetworkObservation {
            generation,
            observed,
        }
    }

    /// Establish an acknowledged baseline without a real flush.
    #[cfg(test)]
    fn seed_acknowledged(&self, fingerprint: Option<u64>) {
        {
            let mut state = self.state.lock();
            state.accept_first_observation = false;
            state.acknowledged = Some(ObservedNetwork { fingerprint });
            state.pending = None;
        }
        if let Some(guard) = self.guard.upgrade() {
            guard.acknowledge_network(meow_common::OutboundNetworkAcknowledgement {
                fingerprint: fingerprint.unwrap_or(0),
                is_available: fingerprint.is_some(),
            });
        }
    }

    /// Record an observation for a deterministic state-machine test.
    #[cfg(test)]
    fn record_observed(&self, fingerprint: Option<u64>) -> u64 {
        self.state.lock().record(ObservedNetwork { fingerprint })
    }

    /// The inherited/acknowledged fingerprint baseline.
    #[cfg(test)]
    fn acknowledged_fingerprint(&self) -> Option<Option<u64>> {
        self.state
            .lock()
            .acknowledged
            .map(|state| state.fingerprint)
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::OutboundBinding;
    use crate::tun::{TunListener, TunListenerConfig, TunRouteScope, TunStack};

    /// Loopback exists on every host.
    const LO: &str = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };

    /// One test drives every case because the registry is process-global;
    /// separate `#[test]` fns would race each other.
    #[test]
    fn binding_installs_fails_closed_and_composes_across_owners() {
        assert!(meow_common::outbound_interface().is_none());

        // A missing interface fails closed and installs nothing.
        assert!(OutboundBinding::install(Some("no-such-iface-zz9")).is_err());
        assert!(OutboundBinding::install_with_auto_detect(None, false).is_err());
        assert!(meow_common::outbound_interface().is_none());

        let binding = OutboundBinding::install(Some(LO)).expect("loopback must exist");
        assert!(!binding.is_auto_detect(), "an explicit interface is fixed");
        assert!(
            binding.monitor().is_some(),
            "detection stays on so network changes still flush a fixed binding"
        );
        assert!(
            binding.set_tun_interface("").is_err(),
            "a monitoring finder still needs the runtime TUN name"
        );
        assert_eq!(binding.interface(), LO);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(binding);
        assert!(meow_common::outbound_interface().is_none());

        // Disabling detection also disables monitoring, even though the
        // explicit interface still binds.
        let mut fixed = OutboundBinding::install_with_auto_detect(Some(LO), false)
            .expect("loopback must exist");
        assert!(!fixed.is_auto_detect());
        assert!(fixed.monitor().is_none());
        fixed.enable_monitoring(false);
        assert!(fixed.monitor().is_none());
        fixed.enable_monitoring(true);
        assert!(
            fixed.monitor().is_some(),
            "an adopted/raw-detection binding still monitors"
        );
        drop(fixed);
        assert!(meow_common::outbound_interface().is_none());

        // Auto-detection, when this host has a default route, installs a
        // live finder and monitor state. Skipped on hosts without one so
        // the test stays portable.
        if let Ok(binding) = OutboundBinding::install_with_auto_detect(None, true) {
            assert!(binding.is_auto_detect());
            assert!(binding.monitor().is_some());
            assert!(
                binding.set_tun_interface("").is_err(),
                "an empty runtime name cannot exclude the TUN from detection"
            );
            drop(binding);
            assert!(meow_common::outbound_interface().is_none());
        }

        // A binding handed to a listener is owned by it: dropping a
        // listener that never ran (startup aborted before the TUN came up)
        // clears the binding instead of leaking it into a TUN-less process.
        let listener = global_listener(OutboundBinding::install(Some(LO)).unwrap());
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(listener);
        assert!(meow_common::outbound_interface().is_none());

        // Reload restart (issue #695): the new config's binding is
        // installed while the old listener still owns its own; tearing the
        // old listener down afterwards must leave the new binding in
        // place (a single-slot registry cleared it here).
        let old = global_listener(OutboundBinding::install(Some(LO)).unwrap());
        let reload = OutboundBinding::install(Some(LO)).expect("loopback must exist");
        drop(old);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        let new = global_listener(reload);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(new);
        assert!(meow_common::outbound_interface().is_none());

        // Rejected reload: its binding goes away first, and the running
        // listener's binding is back in effect rather than cleared.
        let running = global_listener(OutboundBinding::install(Some(LO)).unwrap());
        let rejected = OutboundBinding::install(Some(LO)).expect("loopback must exist");
        drop(rejected);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(running);
        assert!(meow_common::outbound_interface().is_none());

        superseded_observation_flushes_once_after_restore();
        loss_and_recovery_acknowledge_once();
        same_policy_successor_inherits_acknowledged_network();
    }

    /// Observation → supersede → rejected reload → restore: the pending
    /// generation survives the superseded period and is retired exactly once.
    /// Two observations while superseded collapse into one pending retirement.
    fn superseded_observation_flushes_once_after_restore() {
        let running = OutboundBinding::install_with_auto_detect(Some(LO), true).expect("loopback");
        let monitor = running.monitor().expect("monitoring enabled");
        monitor.seed_acknowledged(Some(1));

        let (observed_tx, observed_rx) = std::sync::mpsc::channel();
        let (superseded_tx, superseded_rx) = std::sync::mpsc::channel();
        let worker = {
            let monitor = monitor.clone();
            std::thread::spawn(move || {
                monitor.record_observed(Some(2));
                let generation = monitor.record_observed(Some(3));
                observed_tx.send(()).unwrap();
                superseded_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                // The monitor loop's pre-flush check: superseded, so it must
                // neither retire transports nor acknowledge the change.
                assert!(!monitor.is_effective());
                assert!(monitor.pending_change().is_some());
                generation
            })
        };
        observed_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let candidate =
            OutboundBinding::install_with_auto_detect(Some(LO), true).expect("candidate");
        assert!(!monitor.is_effective(), "the reload candidate supersedes");
        superseded_tx.send(()).unwrap();
        let generation = worker.join().expect("monitor worker");

        drop(candidate);
        assert!(monitor.is_effective(), "rejected reload restores the owner");
        assert_eq!(monitor.pending_change(), Some(generation));

        let mut flushes = 0;
        while let Some(pending) = monitor.pending_change() {
            flushes += 1;
            assert!(flushes <= 1, "the pending change must flush exactly once");
            assert!(monitor.acknowledge(pending));
        }
        assert_eq!(flushes, 1);
        drop(running);
        assert!(meow_common::outbound_interface().is_none());
    }

    /// Loss cannot be consumed by observation alone; recovery of the same
    /// fingerprint still retires once, and a stale acknowledgement never
    /// consumes a newer pending observation.
    fn loss_and_recovery_acknowledge_once() {
        let running = OutboundBinding::install_with_auto_detect(Some(LO), true).expect("loopback");
        let monitor = running.monitor().expect("monitoring enabled");
        monitor.seed_acknowledged(Some(7));

        let loss = monitor.record_observed(None);
        assert_eq!(monitor.pending_change(), Some(loss));
        let candidate =
            OutboundBinding::install_with_auto_detect(Some(LO), true).expect("candidate");
        assert!(!monitor.is_effective());
        assert_eq!(
            monitor.pending_change(),
            Some(loss),
            "a superseded monitor must not consume the loss"
        );
        drop(candidate);
        assert!(monitor.acknowledge(loss));
        assert!(!monitor.acknowledged_is_available());
        assert!(monitor.pending_change().is_none());

        // Repeated loss is already acknowledged: no second retirement.
        monitor.record_observed(None);
        assert!(monitor.pending_change().is_none());

        // Recovering the same fingerprint is a new retirement.
        let recovery = monitor.record_observed(Some(7));
        assert_eq!(monitor.pending_change(), Some(recovery));
        assert!(monitor.acknowledge(recovery));
        assert!(monitor.pending_change().is_none());

        // An older generation must not acknowledge a newer observation.
        let stale = monitor.record_observed(Some(8));
        let newer = monitor.record_observed(Some(9));
        assert!(!monitor.acknowledge(stale));
        assert_eq!(monitor.pending_change(), Some(newer));
        assert!(monitor.acknowledge(newer));
        assert!(monitor.pending_change().is_none());
        drop(running);
    }

    /// A same-policy successor inherits the running owner's acknowledged
    /// baseline, so a change that happened before its monitor starts still
    /// shows up as one pending retirement.
    fn same_policy_successor_inherits_acknowledged_network() {
        let running = OutboundBinding::install_with_auto_detect(Some(LO), true).expect("loopback");
        let monitor = running.monitor().expect("monitoring enabled");
        monitor.seed_acknowledged(Some(11));

        let successor =
            OutboundBinding::install_with_auto_detect(Some(LO), true).expect("successor");
        let successor_monitor = successor.monitor().expect("monitoring enabled");
        assert_eq!(
            successor_monitor.acknowledged_fingerprint(),
            Some(Some(11)),
            "same interface and strategy inherit the acknowledged baseline"
        );
        let generation = successor_monitor.record_observed(Some(12));
        assert_eq!(successor_monitor.pending_change(), Some(generation));

        drop(successor);
        drop(running);
        assert!(meow_common::outbound_interface().is_none());
    }

    fn global_listener(binding: OutboundBinding) -> TunListener {
        TunListener::new(
            crate::test_rule_tunnel(),
            TunListenerConfig {
                device: None,
                mtu: 1500,
                inet4_address: "172.19.0.1/30".parse().unwrap(),
                inet6_address: None,
                auto_route: true,
                route_scope: TunRouteScope::Global,
                outbound_interface: Some(LO.into()),
                auto_detect_interface: true,
                dns_hijack: false,
                udp_timeout: std::time::Duration::from_secs(60),
                max_connections: 0,
                stack: TunStack::Lwip,
            },
            "meow-tun-test".into(),
        )
        .with_outbound_binding(binding)
    }
}
