//! Bounded polling of the physical default interface without retaining the
//! TUN device or tunnel after their owning listener stops.

use std::sync::Weak;
use std::time::Duration;

use meow_tunnel::{TrackedTcp, Tunnel, TunnelInner};
use tracing::warn;

use super::{
    outbound_binding::{self, OutboundMonitor},
    OutboundRoots,
};

/// Poll the owned default binding once per second and flush stale outbound
/// sessions on identity, availability, or recovery transitions. The observed
/// state is acknowledged only after the flush succeeds while this owner is
/// still effective, so a superseded monitor's change survives a rejected
/// reload and flushes once after restoration.
pub(super) async fn run(
    monitor: OutboundMonitor,
    tunnel: Weak<TunnelInner>,
    roots: Option<OutboundRoots>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let lookup = monitor.clone();
        let observation = match tokio::task::spawn_blocking(move || lookup.refresh()).await {
            Ok(Ok(Some(observation))) => observation,
            // The owning binding is gone: stop instead of polling a dead
            // generation forever.
            Ok(Ok(None)) => return,
            Ok(Err(error)) => {
                warn!("tun: interface monitor lookup failed: {error}");
                continue;
            }
            Err(join_error) => {
                warn!("tun: interface monitor task failed: {join_error}");
                continue;
            }
        };
        if !monitor.is_effective() {
            continue;
        }
        if monitor.pending_change().is_none() {
            continue;
        }
        let generation = observation.generation();
        let Some(inner) = tunnel.upgrade() else {
            return;
        };
        let lost_interface = !observation.is_available() && monitor.acknowledged_is_available();
        // Collect provider snapshots before taking the owner lease: snapshot
        // callbacks may acquire locks used by configuration publication.
        let mut extra_roots = roots
            .as_ref()
            .map_or_else(Vec::new, |snapshot| snapshot.as_ref()());
        extra_roots.extend(outbound_binding::provider_roots());
        // Hold the effective-owner lease through retirement and acknowledgement
        // so a successor cannot publish between the identity check and flush.
        monitor.retire_if_effective(generation, || {
            if lost_interface {
                warn!("tun: physical default interface lost; outbound dials fail closed");
            }
            warn!("tun: physical default interface changed; retiring outbound sessions");
            Tunnel::from_inner(inner)
                .flush_for_outbound_interface_change(TrackedTcp::Cancel, extra_roots);
        });
    }
}
