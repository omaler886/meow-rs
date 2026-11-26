//! RAII route installation for the TUN inbound's `auto-route`.
//!
//! Main-table routes into the device: the fake-IP range, or global scope's
//! split defaults (see the module docs in `mod.rs` for which and why;
//! Linux global scope uses `policy_route.rs` instead). Routes are added
//! with the blocking `route_manager` API at listener startup and removed on
//! drop; a failed add is a warning, not a fatal error, because the device
//! subnet's own on-link route frequently already covers the range (in which
//! case some platforms report "route exists").

use ipnet::IpNet;
use parking_lot::RwLock;
use route_manager::{Route, RouteManager};
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::io;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, LazyLock};
use tracing::{debug, warn};

#[path = "route_interfaces.rs"]
mod interface_snapshot;
use interface_snapshot::{InterfaceSnapshot, InterfaceState};

type TunRegistry = Arc<RwLock<BTreeMap<String, usize>>>;

static OWNED_TUN_INTERFACES: LazyLock<TunRegistry> =
    LazyLock::new(|| Arc::new(RwLock::new(BTreeMap::new())));

/// One runtime owner's reference to an excluded TUN name; deliberately not Clone.
#[derive(Debug)]
pub(super) struct TunInterfaceRegistration {
    name: String,
    registry: TunRegistry,
}

impl Drop for TunInterfaceRegistration {
    /// Release this registration's reference; takes no parameters and returns nothing.
    fn drop(&mut self) {
        let mut registry = self.registry.write();
        if let Some(references) = registry.get_mut(&self.name) {
            *references -= 1;
            if *references == 0 {
                registry.remove(&self.name);
            }
        }
    }
}

/// Register an owned runtime TUN `name`; return its exclusion guard or a name error.
pub(super) fn register_tun_interface(name: &str) -> io::Result<TunInterfaceRegistration> {
    register_tun_in_registry(name, &OWNED_TUN_INTERFACES)
}

/// Add `name` to `registry`; return a guard owning exactly one reference or an error.
fn register_tun_in_registry(
    name: &str,
    registry: &TunRegistry,
) -> io::Result<TunInterfaceRegistration> {
    if name.is_empty() || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid TUN interface name",
        ));
    }
    let name = interface_name_key(name);
    let mut registered = registry.write();
    let references = registered.entry(name.clone()).or_default();
    *references = references
        .checked_add(1)
        .ok_or_else(|| io::Error::other("TUN reference overflow"))?;
    Ok(TunInterfaceRegistration {
        name,
        registry: Arc::clone(registry),
    })
}

/// Normalize interface `name` using platform case rules; return its registry key.
fn interface_name_key(name: &str) -> String {
    if cfg!(windows) {
        name.to_ascii_lowercase()
    } else {
        name.to_owned()
    }
}

/// A monitor identity includes the selected interface and the current network state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InterfaceNetworkIdentity {
    pub name: String,
    pub index: u32,
    pub fingerprint: u64,
}

/// Destination-aware hook used by the TUN `auto-detect-interface` option.
/// The route table is consulted for each socket so a default-route change is
/// picked up without restarting the listener.
#[derive(Debug, Default)]
pub(super) struct AutoDetectInterfaceFinder {
    tun_interface: RwLock<Option<String>>,
}

impl AutoDetectInterfaceFinder {
    /// Create a finder without a listener-specific TUN; takes no input and returns the finder.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Set this finder's additional excluded TUN `name`; return nothing.
    pub(super) fn set_tun_interface(&self, name: &str) {
        *self.tun_interface.write() = Some(name.to_owned());
    }

    /// Read the preferred default name/index; takes no input and returns identity or an error.
    pub(super) fn default_interface_identity(&self) -> std::io::Result<(String, u32)> {
        let snapshot = InterfaceSnapshot::capture()?;
        let routes = live_routes(&snapshot)?;
        let excluded = self.excluded_names();
        let route = choose_snapshot_route(&routes, None, &excluded, &snapshot)
            .ok_or_else(no_eligible_interface)?;
        Ok((route.name.clone(), snapshot.interfaces[&route.name].index))
    }

    /// Read dual-stack routing and address identity; takes no input and returns identity or an error.
    pub(super) fn network_identity(&self) -> io::Result<InterfaceNetworkIdentity> {
        let snapshot = InterfaceSnapshot::capture()?;
        let routes = live_routes(&snapshot)?;
        auto_network_identity(&routes, &snapshot, &self.excluded_names())
    }

    /// Snapshot all owned TUN names plus this finder's override; return the exclusions.
    fn excluded_names(&self) -> BTreeSet<String> {
        let mut excluded: BTreeSet<_> = OWNED_TUN_INTERFACES.read().keys().cloned().collect();
        if let Some(name) = self.tun_interface.read().as_deref() {
            excluded.insert(interface_name_key(name));
        }
        excluded
    }
}

impl meow_common::OutboundInterfaceFinder for AutoDetectInterfaceFinder {
    /// Select a live route for `destination`; return its eligible interface name or an error.
    fn find_interface(&self, destination: IpAddr) -> std::io::Result<String> {
        let snapshot = InterfaceSnapshot::capture()?;
        let routes = live_routes(&snapshot)?;
        choose_snapshot_route(
            &routes,
            Some(destination),
            &self.excluded_names(),
            &snapshot,
        )
        .map(|route| route.name.clone())
        .ok_or_else(no_eligible_interface)
    }
}

/// Read the supplied fixed `name` without reselection; return its network identity or an error.
pub(super) fn fixed_network_identity(name: &str) -> io::Result<InterfaceNetworkIdentity> {
    let snapshot = InterfaceSnapshot::capture()?;
    let routes = live_routes(&snapshot)?;
    fixed_identity_from_snapshot(name, &routes, &snapshot)
}

pub(super) struct RouteGuard {
    manager: RouteManager,
    installed: Vec<Route>,
}

impl RouteGuard {
    /// Install one on-link route per net through interface `if_index`.
    /// Individual failures are logged and skipped so a pre-existing
    /// equivalent route does not abort listener startup.
    pub(super) fn setup(if_index: u32, nets: &[IpNet]) -> std::io::Result<Self> {
        let mut manager = RouteManager::new()?;
        let mut installed = Vec::with_capacity(nets.len());
        for net in nets {
            let route = Route::new(net.network(), net.prefix_len()).with_if_index(if_index);
            match manager.add(&route) {
                Ok(()) => {
                    debug!("tun auto-route: added {net} via if_index {if_index}");
                    installed.push(route);
                }
                Err(e) => warn!(
                    "tun auto-route: failed to add {net} via if_index {if_index}: {e} \
                     (continuing — the device subnet may already cover it)"
                ),
            }
        }
        Ok(Self { manager, installed })
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for route in &self.installed {
            if let Err(e) = self.manager.delete(route) {
                warn!("tun auto-route: failed to remove {route}: {e}");
            }
        }
    }
}

#[derive(Debug, Clone)]
struct LiveRoute {
    network: IpNet,
    name: String,
    metric: u32,
    is_default: bool,
    index: Option<u32>,
    details: String,
}

fn no_eligible_interface() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no eligible physical interface route found",
    )
}

fn is_excluded_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "lo" || name == "lo0" || name == "loopback"
}

/// Select from `routes` using one interface `snapshot` and owned-name `excluded` set.
/// Prefer an eligible exact host address before selecting a destination route or default.
fn choose_snapshot_route<'a>(
    routes: &'a [LiveRoute],
    destination: Option<IpAddr>,
    excluded: &BTreeSet<String>,
    snapshot: &InterfaceSnapshot,
) -> Option<&'a LiveRoute> {
    let exact_host = destination.filter(|address| {
        snapshot.interfaces.iter().any(|(name, state)| {
            state.is_eligible()
                && state.addresses.iter().any(|host| host.address == *address)
                && !excluded.contains(&interface_name_key(name))
                && !is_excluded_name(name)
        })
    });
    choose_route_with_exclusions(routes, destination, excluded, |name| {
        snapshot.interfaces.get(name).is_some_and(|state| {
            state.is_eligible()
                && exact_host.is_none_or(|address| {
                    state.addresses.iter().any(|host| host.address == address)
                })
        })
    })
}

/// Select `routes` for `destination`, excluding `tun_name`; use injected `is_up` for pure tests.
#[cfg(test)]
fn choose_route_matching<'a>(
    routes: &'a [LiveRoute],
    destination: Option<IpAddr>,
    tun_name: Option<&str>,
    is_up: impl Fn(&str) -> bool,
) -> Option<&'a LiveRoute> {
    let excluded = tun_name.into_iter().map(interface_name_key).collect();
    choose_route_with_exclusions(routes, destination, &excluded, is_up)
}

/// Select `routes` for `destination` with `excluded` names and memoized `is_up`; return a route.
fn choose_route_with_exclusions<'a>(
    routes: &'a [LiveRoute],
    destination: Option<IpAddr>,
    excluded: &BTreeSet<String>,
    mut is_up: impl FnMut(&str) -> bool,
) -> Option<&'a LiveRoute> {
    let mut eligibility = BTreeMap::<String, bool>::new();
    let mut is_eligible = |route: &&LiveRoute| {
        if excluded.contains(&interface_name_key(&route.name)) || is_excluded_name(&route.name) {
            return false;
        }
        if let Some(is_up) = eligibility.get(&route.name) {
            return *is_up;
        }
        let is_up = is_up(&route.name);
        eligibility.insert(route.name.clone(), is_up);
        is_up
    };
    let mut matching: Vec<&LiveRoute> = routes
        .iter()
        .filter(|route| match destination {
            Some(address) => route.network.contains(&address),
            None => route.is_default,
        })
        .filter(|route| is_eligible(route))
        .collect();
    matching.sort_by_key(|route| (std::cmp::Reverse(route.network.prefix_len()), route.metric));
    if let Some(route) = matching.first() {
        return Some(*route);
    }
    let address_family = destination.map(|address| address.is_ipv6());
    let mut defaults: Vec<&LiveRoute> = routes
        .iter()
        .filter(|route| {
            route.is_default
                && address_family.is_none_or(|ipv6| route.network.addr().is_ipv6() == ipv6)
        })
        .filter(|route| is_eligible(route))
        .collect();
    if defaults.is_empty() && destination.is_some() {
        defaults = routes
            .iter()
            .filter(|route| route.is_default)
            .filter(|route| is_eligible(route))
            .collect();
    }
    defaults.into_iter().min_by_key(|route| route.metric)
}

/// Build automatic identity from `routes`, `snapshot`, and owned `excluded` names; return it or an error.
fn auto_network_identity(
    routes: &[LiveRoute],
    snapshot: &InterfaceSnapshot,
    excluded: &BTreeSet<String>,
) -> io::Result<InterfaceNetworkIdentity> {
    let selected = choose_snapshot_route(routes, None, excluded, snapshot)
        .ok_or_else(no_eligible_interface)?;
    let mut fingerprint = std::collections::hash_map::DefaultHasher::new();
    hash_network_state(routes, snapshot, excluded, None, &mut fingerprint);
    for is_ipv6 in [false, true] {
        let default = routes
            .iter()
            .filter(|route| {
                route.is_default
                    && route.network.addr().is_ipv6() == is_ipv6
                    && !excluded.contains(&interface_name_key(&route.name))
                    && !is_excluded_name(&route.name)
                    && snapshot
                        .interfaces
                        .get(&route.name)
                        .is_some_and(InterfaceState::is_eligible)
            })
            .min_by_key(|route| route.metric);
        default
            .map(|route| (&route.name, snapshot.interfaces[&route.name].index))
            .hash(&mut fingerprint);
    }
    Ok(InterfaceNetworkIdentity {
        name: selected.name.clone(),
        index: snapshot.interfaces[&selected.name].index,
        fingerprint: fingerprint.finish(),
    })
}

/// Observe fixed `name` with `routes` and `snapshot`; return its identity even when its link is down.
fn fixed_identity_from_snapshot(
    name: &str,
    routes: &[LiveRoute],
    snapshot: &InterfaceSnapshot,
) -> io::Result<InterfaceNetworkIdentity> {
    let state = snapshot
        .interfaces
        .get(name)
        .filter(|state| state.index != 0)
        .ok_or_else(no_eligible_interface)?;
    let mut fingerprint = std::collections::hash_map::DefaultHasher::new();
    hash_network_state(
        routes,
        snapshot,
        &BTreeSet::new(),
        Some(name),
        &mut fingerprint,
    );
    Ok(InterfaceNetworkIdentity {
        name: name.to_owned(),
        index: state.index,
        fingerprint: fingerprint.finish(),
    })
}

/// Hash canonical `routes` and actual interface state into `fingerprint`, scoped by exclusions or fixed name.
/// Return nothing; host addresses remain distinct even when their on-link subnets are identical.
fn hash_network_state(
    routes: &[LiveRoute],
    snapshot: &InterfaceSnapshot,
    excluded: &BTreeSet<String>,
    fixed_name: Option<&str>,
    fingerprint: &mut impl Hasher,
) {
    let includes = |name: &str| match fixed_name {
        Some(fixed) => name == fixed,
        None => {
            !excluded.contains(&interface_name_key(name))
                && !is_excluded_name(name)
                && snapshot
                    .interfaces
                    .get(name)
                    .is_none_or(|state| !state.is_loopback)
        }
    };
    let mut route_state: Vec<_> = routes
        .iter()
        .filter(|route| includes(&route.name))
        .map(|route| {
            (
                route.network.addr(),
                route.network.prefix_len(),
                &route.name,
                route.metric,
                route.is_default,
                route.index,
                &route.details,
            )
        })
        .collect();
    route_state.sort_unstable();
    route_state.hash(fingerprint);
    for (name, state) in &snapshot.interfaces {
        if includes(name) {
            name.hash(fingerprint);
            state.hash(fingerprint);
        }
    }
}

/// Read OS routes using `snapshot` for local subnets and interface metrics; return routes or an error.
fn live_routes(snapshot: &InterfaceSnapshot) -> std::io::Result<Vec<LiveRoute>> {
    #[cfg(target_os = "linux")]
    {
        let mut routes = parse_linux_routes(&std::fs::read_to_string("/proc/net/route")?);
        if let Ok(table) = std::fs::read_to_string("/proc/net/ipv6_route") {
            routes.extend(parse_linux_ipv6_routes(&table));
        }
        routes.extend(snapshot.local_routes(&routes));
        return Ok(routes);
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let routes = RouteManager::new()?.list()?;
        let mut live: Vec<_> = routes
            .iter()
            .filter_map(|route| {
                let name = route.if_name()?.clone();
                let network = IpNet::new(route.destination(), route.prefix()).ok()?;
                #[cfg(target_os = "macos")]
                if route.if_scope() {
                    return None;
                }
                #[cfg(target_os = "windows")]
                let metric = route.metric().unwrap_or(0).saturating_add(
                    snapshot.interfaces.get(&name).map_or(0, |state| {
                        if network.addr().is_ipv6() {
                            state.metric_v6
                        } else {
                            state.metric_v4
                        }
                    }),
                );
                #[cfg(target_os = "macos")]
                let metric = 0;
                Some(LiveRoute {
                    is_default: network.prefix_len() == 0,
                    network,
                    name,
                    metric,
                    index: route.if_index(),
                    details: route.to_string(),
                })
            })
            .collect();
        live.extend(snapshot.local_routes(&live));
        return Ok(live);
    }
    #[allow(unreachable_code)]
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "interface route detection is unsupported on this platform",
    ))
}

#[cfg(target_os = "linux")]
fn parse_linux_routes(table: &str) -> Vec<LiveRoute> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let columns: Vec<_> = line.split_whitespace().collect();
            let [name, destination, _gateway, flags, _ref_count, _use_count, metric, mask, ..] =
                columns[..]
            else {
                return None;
            };
            let flags = u32::from_str_radix(flags, 16).ok()?;
            let destination = u32::from_str_radix(destination, 16).ok()?;
            let mask = u32::from_str_radix(mask, 16).ok()?;
            let metric = metric.parse().ok()?;
            if flags & 1 == 0 {
                return None;
            }
            let address = Ipv4Addr::from(destination.to_le_bytes());
            let mask_address = Ipv4Addr::from(mask.to_le_bytes());
            let prefix = mask_address
                .octets()
                .iter()
                .map(|byte| byte.count_ones())
                .sum::<u32>() as u8;
            let network = IpNet::new(IpAddr::V4(address), prefix).ok()?;
            Some(LiveRoute {
                is_default: prefix == 0,
                network,
                name: name.to_owned(),
                metric,
                index: None,
                details: format!("{_gateway}:{flags}"),
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn parse_linux_ipv6_routes(table: &str) -> Vec<LiveRoute> {
    table.lines().filter_map(|line| {
        let columns: Vec<_> = line.split_whitespace().collect();
        let [destination, prefix, _source, _source_prefix, _next_hop, metric, _ref_count, _use_count, flags, name] = columns[..] else {
            return None;
        };
        let flags = u32::from_str_radix(flags, 16).ok()?;
        if flags & 1 == 0 { return None; }
        let bytes = (0..16).map(|offset| u8::from_str_radix(&destination[offset * 2..offset * 2 + 2], 16).ok()).collect::<Option<Vec<_>>>()?;
        let address = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?);
        let prefix = u8::from_str_radix(prefix, 16).ok()?;
        let network = IpNet::new(IpAddr::V6(address), prefix).ok()?;
        let metric = u32::from_str_radix(metric, 16).ok()?;
        Some(LiveRoute { is_default: prefix == 0, network, name: name.to_owned(), metric, index: None,
            details: format!("{_source}:{_source_prefix}:{_next_hop}:{flags}") })
    }).collect()
}

/// Detect the best eligible physical default interface for binding the
/// initial global-route sockets. Per-destination selection lives on the
/// finder, which re-reads the current route table for every socket.
#[cfg(all(test, target_os = "macos"))]
pub(super) fn default_interface() -> std::io::Result<String> {
    AutoDetectInterfaceFinder::new()
        .default_interface_identity()
        .map(|(name, _)| name)
}

/// The fields of a routing-table entry that decide default-interface
/// detection on macOS and Windows, lifted out of `route_manager::Route`
/// (whose platform-specific accessors only exist on their own target) so
/// the selection is unit-testable on every host.
#[cfg(test)]
#[derive(Debug, Clone)]
struct DefaultCandidate {
    destination: std::net::IpAddr,
    prefix: u8,
    if_name: Option<String>,
    /// macOS `RTF_IFSCOPE`: a default that only applies to sockets already
    /// scoped to its interface — every non-primary interface has one.
    scoped: bool,
    /// Effective metric, lower wins. Windows: route metric + interface
    /// metric. macOS has no metric; the table order decides.
    metric: u32,
}

/// Pure selection behind [`default_interface`] on macOS and Windows: the
/// interface of the unscoped IPv4 `0.0.0.0/0` route with the lowest
/// metric, the first listed winning a tie. Requiring prefix `/0` skips the
/// TUN's own `0.0.0.0/1` split route, which shares the destination.
#[cfg(test)]
fn pick_default_interface(routes: impl IntoIterator<Item = DefaultCandidate>) -> Option<String> {
    routes
        .into_iter()
        .filter(|r| {
            r.prefix == 0
                && r.destination == std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                && !r.scoped
        })
        .filter_map(|r| r.if_name.map(|name| (r.metric, name)))
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, name)| name)
}

/// Pure parser behind [`default_interface`], split out for unit testing on
/// every host (hence `test` in the cfg — only Linux uses it at runtime).
/// `/proc/net/route` columns: Iface, Destination (hex LE),
/// Gateway, Flags (hex; bit 0 = RTF_UP), RefCnt, Use, Metric, Mask, … A
/// default route has destination `00000000`, mask `00000000` (a split
/// `0.0.0.0/1` shares the destination but has mask `00000080`) and the UP
/// flag set.
#[cfg(test)]
fn parse_default_interface(table: &str) -> Option<String> {
    for line in table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let [iface, dest, _gateway, flags, _refcnt, _use, _metric, mask, ..] = cols[..] else {
            continue;
        };
        let up = u32::from_str_radix(flags, 16).is_ok_and(|f| f & 0x1 != 0);
        if dest == "00000000" && mask == "00000000" && up {
            return Some(iface.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::interface_snapshot::InterfaceAddress;
    #[cfg(target_os = "linux")]
    use super::parse_linux_ipv6_routes;
    use super::{
        auto_network_identity, choose_route_matching, choose_route_with_exclusions,
        choose_snapshot_route, fixed_identity_from_snapshot, parse_default_interface,
        pick_default_interface, register_tun_in_registry, register_tun_interface,
        AutoDetectInterfaceFinder, DefaultCandidate, InterfaceSnapshot, InterfaceState, LiveRoute,
    };
    use ipnet::IpNet;
    use parking_lot::RwLock;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    fn candidate(net: &str, if_name: &str, scoped: bool, metric: u32) -> DefaultCandidate {
        let net: ipnet::IpNet = net.parse().unwrap();
        DefaultCandidate {
            destination: net.addr(),
            prefix: net.prefix_len(),
            if_name: Some(if_name.to_string()),
            scoped,
            metric,
        }
    }

    /// A macOS table with two uplinks: the primary's default is unscoped,
    /// the secondary's carries `RTF_IFSCOPE` (`netstat -rn` flags `UGScg`
    /// vs `UGScIg`).
    #[test]
    fn macos_picks_the_unscoped_default() {
        let table = [
            candidate("0.0.0.0/0", "en0", true, 0),
            candidate("0.0.0.0/0", "en1", false, 0),
            candidate("127.0.0.0/8", "lo0", false, 0),
            candidate("192.168.0.0/24", "en1", false, 0),
            candidate("::/0", "utun0", false, 0),
        ];
        assert_eq!(pick_default_interface(table).as_deref(), Some("en1"));
    }

    /// Windows ranks defaults by route metric + interface metric; with
    /// automatic metrics the route metric ties at 0 and the interface
    /// decides.
    #[test]
    fn windows_picks_the_lowest_effective_metric() {
        let table = [
            candidate("0.0.0.0/0", "Wi-Fi", false, 35),
            candidate("0.0.0.0/0", "Ethernet", false, 25),
            candidate("::/0", "Ethernet 2", false, 5),
        ];
        assert_eq!(pick_default_interface(table).as_deref(), Some("Ethernet"));
        // A tie keeps table order.
        let tie = [
            candidate("0.0.0.0/0", "Ethernet", false, 25),
            candidate("0.0.0.0/0", "Wi-Fi", false, 25),
        ];
        assert_eq!(pick_default_interface(tie).as_deref(), Some("Ethernet"));
    }

    /// Issue #695, on the route-table platforms: a reload detects the
    /// interface while the running global listener's split defaults are
    /// installed. They share the default's destination (and on Windows may
    /// undercut its metric) but are `/1`, never `/0`.
    #[test]
    fn route_table_detection_skips_the_tun_split_default_routes() {
        let table = [
            candidate("0.0.0.0/1", "utun7", false, 0),
            candidate("128.0.0.0/1", "utun7", false, 0),
            candidate("::/1", "utun7", false, 0),
            candidate("8000::/1", "utun7", false, 0),
            candidate("0.0.0.0/0", "en0", false, 10),
        ];
        assert_eq!(
            pick_default_interface(table.clone()).as_deref(),
            Some("en0")
        );
        // Only the split routes left (no real default): nothing to bind to.
        let only_split = table.into_iter().filter(|r| r.prefix == 1);
        assert_eq!(pick_default_interface(only_split), None);
        // A default whose interface has no resolvable name is unusable.
        let nameless = DefaultCandidate {
            if_name: None,
            ..candidate("0.0.0.0/0", "x", false, 0)
        };
        assert_eq!(pick_default_interface([nameless]), None);
    }

    /// The real routing table, unprivileged: listing routes needs no root.
    /// A host without an IPv4 default route (offline CI) legitimately has
    /// nothing to detect; anything detected must be a real interface.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_detects_a_real_interface_from_the_live_table() {
        match super::default_interface() {
            Ok(name) => {
                let c_name = std::ffi::CString::new(name.clone()).unwrap();
                // SAFETY: `c_name` is a valid NUL-terminated string.
                let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
                assert_ne!(index, 0, "detected interface '{name}' must exist");
                println!("detected default interface: {name} (index {index})");
            }
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        }
    }

    const SAMPLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn picks_the_up_default_route_interface() {
        assert_eq!(parse_default_interface(SAMPLE).as_deref(), Some("eth0"));
    }

    #[test]
    fn ignores_down_defaults_and_empty_tables() {
        // Same default entry but with the UP bit clear → not a candidate.
        let down = SAMPLE.replace("00000000\t0101A8C0\t0003", "00000000\t0101A8C0\t0002");
        assert_eq!(parse_default_interface(&down), None);
        assert_eq!(parse_default_interface("Iface\tDestination\n"), None);
        assert_eq!(parse_default_interface(""), None);
    }

    /// Issue #695: a reload detects the interface while the running global
    /// listener's split defaults are installed, and the kernel lists
    /// `0.0.0.0/1` ahead of the real default (captured from a live table
    /// with `0.0.0.0/1` + `128.0.0.0/1` on the TUN).
    #[test]
    fn skips_the_tun_split_default_routes() {
        let table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
meow-tun\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
meow-tun\t00000080\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";
        assert_eq!(parse_default_interface(table).as_deref(), Some("eth0"));
        // Only the split routes left (no real default): nothing to bind to.
        let only_split: String = table
            .lines()
            .filter(|l| !l.starts_with("eth0"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(parse_default_interface(&only_split), None);
    }

    #[test]
    fn destination_selection_prefers_on_link_route_then_specific_metric() {
        let routes = [
            live("0.0.0.0/0", "eth0", 10),
            live("192.168.4.0/24", "eth1", 90),
            live("192.168.4.0/24", "eth2", 20),
        ];
        assert_eq!(
            choose_route_matching(&routes, Some("192.168.4.22".parse().unwrap()), None, |_| {
                true
            })
            .unwrap()
            .name,
            "eth2"
        );
        assert_eq!(
            choose_route_matching(&routes, Some("8.8.8.8".parse().unwrap()), None, |_| true)
                .unwrap()
                .name,
            "eth0"
        );
    }

    /// Snapshot fallbacks must not reset competing native connected-route metrics.
    #[test]
    fn native_on_link_route_metrics_survive_snapshot_fallbacks() {
        for (network, first_address, second_address, destination) in [
            (
                "192.0.2.0/24",
                "192.0.2.10/24",
                "192.0.2.20/24",
                "192.0.2.200",
            ),
            (
                "2001:db8::/64",
                "2001:db8::10/64",
                "2001:db8::20/64",
                "2001:db8::200",
            ),
        ] {
            let snapshot = snapshot(&[("eth0", 2, first_address), ("eth1", 3, second_address)]);
            let mut routes = vec![live(network, "eth0", 200), live(network, "eth1", 100)];
            let local = snapshot.local_routes(&routes);
            assert!(
                local.is_empty(),
                "native routes already cover both interfaces"
            );
            routes.extend(local);
            let selected = choose_snapshot_route(
                &routes,
                Some(destination.parse().unwrap()),
                &BTreeSet::new(),
                &snapshot,
            )
            .unwrap();
            assert_eq!(selected.name, "eth1");
            assert_eq!(selected.metric, 100);
        }
    }

    /// A native network on one interface must not hide another interface or a missing network.
    #[test]
    fn snapshot_fallbacks_are_scoped_to_network_and_interface() {
        let mut snapshot = snapshot(&[("eth0", 2, "192.0.2.10/24"), ("eth1", 3, "192.0.2.20/24")]);
        snapshot
            .interfaces
            .get_mut("eth0")
            .unwrap()
            .addresses
            .push(InterfaceAddress {
                address: "198.51.100.10".parse().unwrap(),
                prefix: 24,
            });
        // Native route addresses need not have their host bits cleared.
        let native = [live("192.0.2.99/24", "eth0", 200)];
        let local = snapshot.local_routes(&native);
        assert_eq!(local.len(), 2);
        assert!(local.iter().any(|route| {
            route.name == "eth1" && route.network == "192.0.2.0/24".parse::<IpNet>().unwrap()
        }));
        assert!(local.iter().any(|route| {
            route.name == "eth0" && route.network == "198.51.100.0/24".parse::<IpNet>().unwrap()
        }));
    }

    /// Exact host ownership precedes a lower-metric interface sharing the same subnet.
    #[test]
    fn exact_host_destination_precedes_other_on_link_interface_metrics() {
        for (network, first_address, second_address, host, neighbor) in [
            (
                "192.0.2.0/24",
                "192.0.2.10/24",
                "192.0.2.20/24",
                "192.0.2.20",
                "192.0.2.200",
            ),
            (
                "2001:db8::/64",
                "2001:db8::10/64",
                "2001:db8::20/64",
                "2001:db8::20",
                "2001:db8::200",
            ),
        ] {
            let snapshot = snapshot(&[("eth0", 2, first_address), ("eth1", 3, second_address)]);
            let mut routes = vec![live(network, "eth0", 10), live(network, "eth1", 100)];
            routes.extend(snapshot.local_routes(&routes));
            for (destination, expected) in [(host, "eth1"), (neighbor, "eth0")] {
                assert_eq!(
                    choose_snapshot_route(
                        &routes,
                        Some(destination.parse().unwrap()),
                        &BTreeSet::new(),
                        &snapshot,
                    )
                    .unwrap()
                    .name,
                    expected,
                );
            }
        }
    }

    /// Exact-address matching must retain owned-TUN exclusions and operational checks.
    #[test]
    fn exact_host_destination_skips_owned_tun_and_unavailable_interfaces() {
        let mut snapshot = snapshot(&[
            ("eth0", 2, "192.0.2.10/24"),
            ("eth1", 3, "192.0.2.20/24"),
            ("owned0", 4, "192.0.2.30/24"),
        ]);
        let routes = [
            live("192.0.2.0/24", "eth0", 30),
            live("192.0.2.0/24", "eth1", 20),
            live("192.0.2.0/24", "owned0", 0),
        ];
        let excluded = BTreeSet::from([super::interface_name_key("owned0")]);
        assert_eq!(
            choose_snapshot_route(
                &routes,
                Some("192.0.2.30".parse().unwrap()),
                &excluded,
                &snapshot,
            )
            .unwrap()
            .name,
            "eth1",
        );
        snapshot.interfaces.get_mut("eth1").unwrap().is_running = false;
        assert_eq!(
            choose_snapshot_route(
                &routes,
                Some("192.0.2.20".parse().unwrap()),
                &excluded,
                &snapshot,
            )
            .unwrap()
            .name,
            "eth0",
        );
    }

    /// Missing Windows connected routes still use the selected family's interface metric.
    #[cfg(windows)]
    #[test]
    fn windows_snapshot_fallbacks_use_address_family_interface_metrics() {
        let mut snapshot = snapshot(&[("eth0", 2, "192.0.2.10/24"), ("eth1", 3, "192.0.2.20/24")]);
        for (name, metric_v4, metric_v6, address) in [
            ("eth0", 40, 5, "2001:db8::10"),
            ("eth1", 10, 30, "2001:db8::20"),
        ] {
            let state = snapshot.interfaces.get_mut(name).unwrap();
            state.metric_v4 = metric_v4;
            state.metric_v6 = metric_v6;
            state.addresses.push(InterfaceAddress {
                address: address.parse().unwrap(),
                prefix: 64,
            });
        }
        let routes = snapshot.local_routes(&[]);
        for (destination, expected, metric) in
            [("192.0.2.200", "eth1", 10), ("2001:db8::200", "eth0", 5)]
        {
            let selected = choose_snapshot_route(
                &routes,
                Some(destination.parse().unwrap()),
                &BTreeSet::new(),
                &snapshot,
            )
            .unwrap();
            assert_eq!(selected.name, expected);
            assert_eq!(selected.metric, metric);
        }
    }

    #[test]
    fn ipv6_routes_and_family_default_fallback_are_selected() {
        let routes = [
            live("0.0.0.0/0", "v4", 1),
            live("::/0", "v6", 30),
            live("2001:db8:1::/64", "v6-lan", 80),
        ];
        assert_eq!(
            choose_route_matching(
                &routes,
                Some("2001:db8:1::1".parse().unwrap()),
                None,
                |_| true
            )
            .unwrap()
            .name,
            "v6-lan"
        );
        assert_eq!(
            choose_route_matching(
                &routes,
                Some("2001:db8:2::1".parse().unwrap()),
                None,
                |_| true
            )
            .unwrap()
            .name,
            "v6"
        );
        let no_v6_default = [live("0.0.0.0/0", "v4", 1)];
        assert_eq!(
            choose_route_matching(
                &no_v6_default,
                Some("2001:db8::1".parse().unwrap()),
                None,
                |_| true
            )
            .unwrap()
            .name,
            "v4"
        );
    }

    #[test]
    fn excludes_tun_loopback_and_split_defaults_and_fails_without_physical_route() {
        let routes = [
            live("0.0.0.0/1", "tun0", 0),
            live("128.0.0.0/1", "tun0", 0),
            live("0.0.0.0/0", "tun0", 0),
            live("0.0.0.0/0", "lo", 1),
            live("0.0.0.0/0", "eth0", 20),
        ];
        assert_eq!(
            choose_route_matching(&routes, None, Some("tun0"), |_| true)
                .unwrap()
                .name,
            "eth0"
        );
        let no_physical = [live("0.0.0.0/0", "tun0", 0), live("0.0.0.0/1", "eth0", 0)];
        assert!(choose_route_matching(&no_physical, None, Some("tun0"), |_| true).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_v6_route_parser_keeps_up_routes_and_metrics() {
        let table = "20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000014 00000000 00000000 00000001 eth1\n20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000000 00000000 00000000 down0";
        let parsed = parse_linux_ipv6_routes(table);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "eth1");
        assert_eq!(parsed[0].metric, 20);
    }

    /// Verify a fresh bootstrap finder excludes every registered TUN route, while retaining foreign VPNs.
    #[test]
    fn bootstrap_excludes_old_and_fixed_owned_tuns_but_not_foreign_vpns() {
        let old_name = "route-test-owned-old";
        let fixed_name = "route-test-owned-fixed";
        let _old = register_tun_interface(old_name).unwrap();
        let _fixed = register_tun_interface(fixed_name).unwrap();
        let finder = AutoDetectInterfaceFinder::new();
        let routes = [
            live("0.0.0.0/1", old_name, 0),
            live("128.0.0.0/1", old_name, 0),
            live("0.0.0.0/0", old_name, 0),
            live("192.0.2.0/24", old_name, 0),
            live("192.0.2.9/32", fixed_name, 0),
            live("203.0.113.0/24", "foreign-vpn", 0),
            live("0.0.0.0/0", "eth0", 20),
        ];
        let excluded = finder.excluded_names();
        for destination in ["8.8.8.8", "192.0.2.9", "200.0.0.1"] {
            assert_eq!(
                choose_route_with_exclusions(
                    &routes,
                    Some(destination.parse().unwrap()),
                    &excluded,
                    |_| true,
                )
                .unwrap()
                .name,
                "eth0"
            );
        }
        assert_eq!(
            choose_route_with_exclusions(&routes, None, &excluded, |_| true,)
                .unwrap()
                .name,
            "eth0"
        );
        assert_eq!(
            choose_route_with_exclusions(
                &routes,
                Some("203.0.113.8".parse().unwrap()),
                &excluded,
                |_| true,
            )
            .unwrap()
            .name,
            "foreign-vpn"
        );
    }

    /// Verify independent guards hold exclusions until their final drop and reject invalid names.
    #[test]
    fn owned_tun_registration_releases_exactly_its_own_reference() {
        let registry = Arc::new(RwLock::new(BTreeMap::new()));
        let first = register_tun_in_registry("owned0", &registry).unwrap();
        let second = register_tun_in_registry("owned0", &registry).unwrap();
        let other = register_tun_in_registry("owned1", &registry).unwrap();
        assert_eq!(registry.read().get("owned0"), Some(&2));
        drop(first);
        assert_eq!(registry.read().get("owned0"), Some(&1));
        drop(second);
        assert!(!registry.read().contains_key("owned0"));
        assert_eq!(registry.read().get("owned1"), Some(&1));
        drop(other);
        assert!(registry.read().is_empty());
        assert!(register_tun_in_registry("", &registry).is_err());
        assert!(register_tun_in_registry("bad\0name", &registry).is_err());
        assert!(registry.read().is_empty());
    }

    /// Verify an IPv6-only default switch changes identity even when the IPv4 default stays selected.
    #[test]
    fn ipv6_only_default_switch_changes_network_identity() {
        let mut routes = [
            live("0.0.0.0/0", "eth0", 1),
            live("::/0", "eth1", 10),
            live("::/0", "eth2", 20),
        ];
        let snapshot = snapshot(&[
            ("eth0", 2, "192.0.2.5/24"),
            ("eth1", 3, "2001:db8:1::5/64"),
            ("eth2", 4, "2001:db8:2::5/64"),
        ]);
        let before = auto_network_identity(&routes, &snapshot, &BTreeSet::new()).unwrap();
        routes[1].metric = 30;
        let after = auto_network_identity(&routes, &snapshot, &BTreeSet::new()).unwrap();
        assert_eq!((&before.name, before.index), (&after.name, after.index));
        assert_ne!(before.fingerprint, after.fingerprint);
    }

    /// Verify replacing either family's host address changes identity within the same subnet and index.
    #[test]
    fn same_index_source_address_replacement_changes_both_identity_modes() {
        for (network, old_address, new_address) in [
            ("0.0.0.0/0", "192.0.2.10/24", "192.0.2.11/24"),
            ("::/0", "2001:db8::10/64", "2001:db8::11/64"),
        ] {
            let routes = [live(network, "eth0", 10)];
            let before = snapshot(&[("eth0", 2, old_address)]);
            let after = snapshot(&[("eth0", 2, new_address)]);
            assert_eq!(
                before.local_routes(&[])[0].network,
                after.local_routes(&[])[0].network
            );
            assert_ne!(
                auto_network_identity(&routes, &before, &BTreeSet::new()).unwrap(),
                auto_network_identity(&routes, &after, &BTreeSet::new()).unwrap()
            );
            assert_ne!(
                fixed_identity_from_snapshot("eth0", &routes, &before).unwrap(),
                fixed_identity_from_snapshot("eth0", &routes, &after).unwrap()
            );
        }
    }

    /// Verify physical next-hop and metric changes are observable without a default name/index change.
    #[test]
    fn physical_route_state_changes_network_identity() {
        let mut routes = [live("0.0.0.0/0", "eth0", 10)];
        let snapshot = snapshot(&[("eth0", 2, "192.0.2.5/24")]);
        let before = auto_network_identity(&routes, &snapshot, &BTreeSet::new()).unwrap();
        routes[0].details = "gateway-replaced".to_owned();
        let gateway_changed = auto_network_identity(&routes, &snapshot, &BTreeSet::new()).unwrap();
        assert_ne!(before, gateway_changed);
        routes[0].metric = 20;
        assert_ne!(
            gateway_changed,
            auto_network_identity(&routes, &snapshot, &BTreeSet::new()).unwrap()
        );
    }

    /// Verify carrier/down exclusion, fixed-link status fingerprints and explicitly fixed loopback support.
    #[test]
    fn operational_status_controls_auto_selection_without_reselecting_fixed_names() {
        let routes = [live("0.0.0.0/0", "eth0", 10), live("0.0.0.0/0", "eth1", 20)];
        let mut snapshot = snapshot(&[
            ("eth0", 2, "192.0.2.5/24"),
            ("eth1", 3, "198.51.100.5/24"),
            ("lo", 1, "127.0.0.1/8"),
        ]);
        snapshot.interfaces.get_mut("lo").unwrap().is_loopback = true;
        let before = fixed_identity_from_snapshot("eth0", &routes, &snapshot).unwrap();
        for is_up in [true, false] {
            let state = snapshot.interfaces.get_mut("eth0").unwrap();
            state.is_up = is_up;
            state.is_running = false;
            state.operational_status = 2;
            assert_eq!(
                auto_network_identity(&routes, &snapshot, &BTreeSet::new())
                    .unwrap()
                    .name,
                "eth1"
            );
            let fixed = fixed_identity_from_snapshot("eth0", &routes, &snapshot).unwrap();
            assert_eq!((&fixed.name, fixed.index), (&before.name, before.index));
            assert_ne!(fixed.fingerprint, before.fingerprint);
        }
        assert_eq!(
            fixed_identity_from_snapshot("lo", &routes, &snapshot)
                .unwrap()
                .name,
            "lo"
        );
        assert!(fixed_identity_from_snapshot("missing", &routes, &snapshot).is_err());
        assert!(!snapshot.interfaces["lo"].is_eligible());
    }

    /// Verify repeated routes and fallback passes query each interface once, and subsequent lookups refresh.
    #[test]
    fn eligibility_checks_are_bounded_per_interface_per_lookup() {
        let mut routes = Vec::new();
        for _ in 0..128 {
            routes.push(live("::/0", "down0", 1));
            routes.push(live("0.0.0.0/0", "eth0", 20));
        }
        let mut counts = BTreeMap::new();
        for expected_count in [1, 2] {
            let chosen = choose_route_with_exclusions(
                &routes,
                Some("2001:db8::1".parse().unwrap()),
                &BTreeSet::new(),
                |name| {
                    *counts.entry(name.to_owned()).or_insert(0usize) += 1;
                    name != "down0"
                },
            )
            .unwrap();
            assert_eq!(chosen.name, "eth0");
            assert_eq!(counts.get("eth0"), Some(&expected_count));
            assert_eq!(counts.get("down0"), Some(&expected_count));
            assert_eq!(counts.len(), 2);
        }
    }

    /// Build pure interface state from `(name, index, host/prefix)` entries; return an up snapshot.
    fn snapshot(entries: &[(&str, u32, &str)]) -> InterfaceSnapshot {
        let interfaces = entries
            .iter()
            .map(|(name, index, address)| {
                let address: IpNet = address.parse().unwrap();
                (
                    (*name).to_owned(),
                    InterfaceState {
                        index: *index,
                        is_up: true,
                        is_running: true,
                        addresses: vec![InterfaceAddress {
                            address: address.addr(),
                            prefix: address.prefix_len(),
                        }],
                        ..InterfaceState::default()
                    },
                )
            })
            .collect();
        InterfaceSnapshot { interfaces }
    }

    /// Build a pure route from `network`, interface `name` and `metric`; return the route.
    fn live(network: &str, name: &str, metric: u32) -> LiveRoute {
        let network: IpNet = network.parse().unwrap();
        LiveRoute {
            is_default: network.prefix_len() == 0,
            network,
            name: name.to_owned(),
            metric,
            index: None,
            details: String::new(),
        }
    }
}
