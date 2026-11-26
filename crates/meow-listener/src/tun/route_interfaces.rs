//! Per-lookup interface state shared by route selection and monitor fingerprints.

use super::{interface_name_key, LiveRoute};
use ipnet::IpNet;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;

/// An actual host address, kept separate from the truncated on-link network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct InterfaceAddress {
    pub(super) address: IpAddr,
    pub(super) prefix: u8,
}

#[derive(Debug, Clone, Default, Hash)]
pub(super) struct InterfaceState {
    pub(super) index: u32,
    pub(super) is_up: bool,
    pub(super) is_running: bool,
    pub(super) is_loopback: bool,
    pub(super) operational_status: u32,
    pub(super) addresses: Vec<InterfaceAddress>,
    #[cfg(windows)]
    pub(super) index_v6: u32,
    #[cfg(windows)]
    pub(super) metric_v4: u32,
    #[cfg(windows)]
    pub(super) metric_v6: u32,
}

impl InterfaceState {
    /// Check this snapshot's automatic-binding eligibility; takes no input and returns a boolean.
    pub(super) fn is_eligible(&self) -> bool {
        self.index != 0 && self.is_up && self.is_running && !self.is_loopback
    }
}

#[derive(Debug, Default)]
pub(super) struct InterfaceSnapshot {
    pub(super) interfaces: BTreeMap<String, InterfaceState>,
}

impl InterfaceSnapshot {
    /// Capture current OS interface state once; takes no input and returns a snapshot or an error.
    pub(super) fn capture() -> io::Result<Self> {
        #[cfg(unix)]
        let mut snapshot = capture_unix_interfaces()?;
        #[cfg(windows)]
        let mut snapshot = capture_windows_interfaces()?;
        for state in snapshot.interfaces.values_mut() {
            state.addresses.sort_unstable();
            state.addresses.dedup();
        }
        Ok(snapshot)
    }

    /// Derive missing on-link routes from snapshot addresses without replacing `native_routes`.
    /// Return only eligible routes; preserve native metrics for each network/interface pair.
    pub(super) fn local_routes(&self, native_routes: &[LiveRoute]) -> Vec<LiveRoute> {
        let mut native_networks = BTreeMap::<String, BTreeSet<(IpAddr, u8)>>::new();
        for route in native_routes {
            native_networks
                .entry(interface_name_key(&route.name))
                .or_default()
                .insert((route.network.network(), route.network.prefix_len()));
        }
        self.interfaces
            .iter()
            .filter(|(_, state)| state.is_eligible())
            .flat_map(|(name, state)| {
                let native_networks = native_networks.get(&interface_name_key(name));
                state.addresses.iter().filter_map(move |address| {
                    let network = IpNet::new(address.address, address.prefix).ok()?.trunc();
                    if native_networks.is_some_and(|networks| {
                        networks.contains(&(network.addr(), network.prefix_len()))
                    }) {
                        return None;
                    }
                    #[cfg(windows)]
                    let metric = if address.address.is_ipv6() {
                        state.metric_v6
                    } else {
                        state.metric_v4
                    };
                    #[cfg(not(windows))]
                    let metric = 0;
                    Some(LiveRoute {
                        network,
                        name: name.clone(),
                        metric,
                        is_default: false,
                        index: Some(state.index),
                        details: String::new(),
                    })
                })
            })
            .collect()
    }
}

#[cfg(unix)]
struct UnixInterfaceAddresses(*mut libc::ifaddrs);

#[cfg(unix)]
impl Drop for UnixInterfaceAddresses {
    /// Free this getifaddrs list; takes no input and returns nothing.
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns a successful getifaddrs allocation.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

/// Enumerate Unix interface flags, indices and host addresses once; return a snapshot or OS error.
#[cfg(unix)]
fn capture_unix_interfaces() -> io::Result<InterfaceSnapshot> {
    let mut addresses = std::ptr::null_mut();
    // SAFETY: addresses is a valid output pointer; the guard owns the resulting allocation.
    if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let addresses = UnixInterfaceAddresses(addresses);
    let mut snapshot = InterfaceSnapshot::default();
    let mut current = addresses.0;
    while !current.is_null() {
        // SAFETY: the guard keeps every linked entry alive for the entire traversal.
        let entry = unsafe { &*current };
        record_unix_interface(entry, &mut snapshot);
        current = entry.ifa_next;
    }
    #[cfg(target_os = "macos")]
    refresh_macos_carrier(&mut snapshot)?;
    Ok(snapshot)
}

/// The Darwin ifmediareq ABI used to query carrier without starting a subprocess.
#[cfg(target_os = "macos")]
#[repr(C, packed(4))]
struct MacosMediaRequest {
    name: [libc::c_char; libc::IFNAMSIZ],
    current: libc::c_int,
    mask: libc::c_int,
    status: libc::c_int,
    active: libc::c_int,
    count: libc::c_int,
    media: *mut libc::c_int,
}

#[cfg(target_os = "macos")]
const MACOS_SIOCGIFMEDIA: libc::c_ulong = 0xc000_0000
    | ((std::mem::size_of::<MacosMediaRequest>() as libc::c_ulong) << 16)
    | ((b'i' as libc::c_ulong) << 8)
    | 56;

// Darwin packs ifmediareq to four bytes even when pointers are eight bytes.
// Its ABI size is also part of the ioctl request number.
#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
const _: () = {
    assert!(std::mem::size_of::<MacosMediaRequest>() == 44);
    assert!(std::mem::align_of::<MacosMediaRequest>() == 4);
    assert!(std::mem::offset_of!(MacosMediaRequest, status) == 24);
    assert!(std::mem::offset_of!(MacosMediaRequest, media) == 36);
    assert!(MACOS_SIOCGIFMEDIA == 0xc02c_6938);
};

/// Refresh Darwin carrier for each distinct interface in `snapshot`; return success or an OS error.
#[cfg(target_os = "macos")]
fn refresh_macos_carrier(snapshot: &mut InterfaceSnapshot) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: socket takes only integer arguments and transfers ownership on success.
    let descriptor = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this successful socket descriptor has exactly one owner.
    let socket = unsafe { OwnedFd::from_raw_fd(descriptor) };
    for (name, state) in &mut snapshot.interfaces {
        if !state.is_loopback {
            if let Some(is_active) = macos_interface_carrier(socket.as_raw_fd(), name)? {
                state.is_running &= is_active;
            }
        }
    }
    Ok(())
}

/// Query carrier for `name` using `descriptor`; return None for media-less interfaces or an OS error.
#[cfg(target_os = "macos")]
fn macos_interface_carrier(descriptor: libc::c_int, name: &str) -> io::Result<Option<bool>> {
    const IFM_AVALID: libc::c_int = 1;
    const IFM_ACTIVE: libc::c_int = 2;

    if name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name exceeds IFNAMSIZ",
        ));
    }
    // SAFETY: the request has integer fields and a nullable list pointer; no media list is requested.
    let mut request: MacosMediaRequest = unsafe { std::mem::zeroed() };
    for (destination, source) in request.name.iter_mut().zip(name.bytes()) {
        *destination = source as libc::c_char;
    }
    // SAFETY: request matches Darwin's ifmediareq ABI and remains exclusively borrowed for ioctl.
    if unsafe { libc::ioctl(descriptor, MACOS_SIOCGIFMEDIA, &mut request) } < 0 {
        let error = io::Error::last_os_error();
        // Virtual interfaces have no media state, so their operational flags remain authoritative.
        return match error.raw_os_error() {
            Some(libc::ENOTSUP | libc::ENOTTY | libc::EINVAL) => Ok(None),
            _ => Err(error),
        };
    }
    Ok((request.status & IFM_AVALID != 0).then_some(request.status & IFM_ACTIVE != 0))
}

/// Add Unix `entry` state to `snapshot`; retain host bits for fingerprints and return nothing.
#[cfg(unix)]
fn record_unix_interface(entry: &libc::ifaddrs, snapshot: &mut InterfaceSnapshot) {
    if entry.ifa_name.is_null() {
        return;
    }
    // SAFETY: getifaddrs supplies a NUL-terminated interface name for each named entry.
    let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
        .to_string_lossy()
        .into_owned();
    let state = snapshot
        .interfaces
        .entry(name)
        .or_insert_with(|| InterfaceState {
            // SAFETY: the entry's name remains valid while the owning list is alive.
            index: unsafe { libc::if_nametoindex(entry.ifa_name) },
            is_up: entry.ifa_flags & libc::IFF_UP as u32 != 0,
            is_running: entry.ifa_flags & libc::IFF_RUNNING as u32 != 0,
            is_loopback: entry.ifa_flags & libc::IFF_LOOPBACK as u32 != 0,
            operational_status: entry.ifa_flags,
            ..InterfaceState::default()
        });
    if entry.ifa_addr.is_null() || entry.ifa_netmask.is_null() {
        return;
    }
    // SAFETY: both addresses are supplied by getifaddrs and outlive this call.
    let address = unsafe { unix_socket_ip(entry.ifa_addr) };
    let mask = unsafe { unix_socket_ip(entry.ifa_netmask) };
    if let (Some(address), Some(mask)) = (address, mask) {
        if let Some(prefix) = prefix_from_mask(address, mask) {
            state.addresses.push(InterfaceAddress { address, prefix });
        }
    }
}

/// Decode Unix socket `address`; return its IP if it has an Internet address family.
///
/// # Safety
/// `address` must point to a non-null socket structure matching its declared family.
#[cfg(unix)]
unsafe fn unix_socket_ip(address: *const libc::sockaddr) -> Option<IpAddr> {
    // SAFETY: the caller guarantees a readable family field and matching structure layout.
    match unsafe { (*address).sa_family as i32 } {
        libc::AF_INET => {
            // SAFETY: AF_INET guarantees sockaddr_in layout.
            let address = unsafe { &*address.cast::<libc::sockaddr_in>() };
            Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                address.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            // SAFETY: AF_INET6 guarantees sockaddr_in6 layout.
            let address = unsafe { &*address.cast::<libc::sockaddr_in6>() };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(
                address.sin6_addr.s6_addr,
            )))
        }
        _ => None,
    }
}

/// Count prefix bits in `mask` for `address`'s family; return None for mismatched families.
#[cfg(unix)]
fn prefix_from_mask(address: IpAddr, mask: IpAddr) -> Option<u8> {
    match (address, mask) {
        (IpAddr::V4(_), IpAddr::V4(mask)) => Some(
            mask.octets()
                .iter()
                .map(|byte| byte.count_ones())
                .sum::<u32>() as u8,
        ),
        (IpAddr::V6(_), IpAddr::V6(mask)) => Some(
            mask.octets()
                .iter()
                .map(|byte| byte.count_ones())
                .sum::<u32>() as u8,
        ),
        _ => None,
    }
}

/// Enumerate Windows adapters and their unicast addresses once; return a snapshot or API error.
#[cfg(windows)]
fn capture_windows_interfaces() -> io::Result<InterfaceSnapshot> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 15000u32;
    let mut buffer = vec![0u64; size as usize / 8 + 1];
    for _ in 0..4 {
        // SAFETY: u64 storage supplies the required alignment and the requested byte capacity.
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            buffer.resize(size as usize / 8 + 1, 0);
            continue;
        }
        if result == ERROR_NO_DATA {
            return Ok(InterfaceSnapshot::default());
        }
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        return Ok(read_windows_interfaces(&buffer));
    }
    Err(io::Error::other(
        "interface snapshot changed during four enumeration attempts",
    ))
}

/// Decode an initialized GetAdaptersAddresses `buffer`; return owned, per-adapter state.
#[cfg(windows)]
fn read_windows_interfaces(buffer: &[u64]) -> InterfaceSnapshot {
    use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;

    let mut snapshot = InterfaceSnapshot::default();
    let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !current.is_null() {
        // SAFETY: only a successful API allocation reaches here; buffer keeps the list alive.
        let adapter = unsafe { &*current };
        // SAFETY: FriendlyName is null or a NUL-terminated UTF-16 string inside buffer.
        if let Some(name) = unsafe { windows_interface_name(adapter.FriendlyName) } {
            // SAFETY: the API initializes the IfIndex view of this documented union.
            let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            let is_up = adapter.OperStatus == IfOperStatusUp;
            snapshot.interfaces.insert(
                name,
                InterfaceState {
                    index: if index == 0 {
                        adapter.Ipv6IfIndex
                    } else {
                        index
                    },
                    index_v6: adapter.Ipv6IfIndex,
                    is_up,
                    is_running: is_up,
                    is_loopback: adapter.IfType == 24,
                    operational_status: adapter.OperStatus as u32,
                    metric_v4: adapter.Ipv4Metric,
                    metric_v6: adapter.Ipv6Metric,
                    addresses: windows_interface_addresses(adapter),
                },
            );
        }
        current = adapter.Next;
    }
    snapshot
}

/// Decode UTF-16 interface `name`; return an owned name, or None for a missing name.
///
/// # Safety
/// `name` must be null or point to a readable NUL-terminated UTF-16 string.
#[cfg(windows)]
unsafe fn windows_interface_name(name: *const u16) -> Option<String> {
    if name.is_null() {
        return None;
    }
    let mut length = 0;
    // SAFETY: the caller guarantees a readable terminator within the allocation.
    while unsafe { *name.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the loop established the readable string length.
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(name, length)
    }))
}

/// Decode `adapter`'s live unicast list; return actual host addresses with their prefix lengths.
#[cfg(windows)]
fn windows_interface_addresses(
    adapter: &windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH,
) -> Vec<InterfaceAddress> {
    let mut addresses = Vec::new();
    let mut current = adapter.FirstUnicastAddress;
    while !current.is_null() {
        // SAFETY: the adapter and its unicast list share the still-live API buffer.
        let unicast = unsafe { &*current };
        if let Some(address) = windows_socket_ip(&unicast.Address) {
            addresses.push(InterfaceAddress {
                address,
                prefix: unicast.OnLinkPrefixLength,
            });
        }
        current = unicast.Next;
    }
    addresses
}

/// Decode Windows API socket `address`; return an IP for a supported, fully sized structure.
#[cfg(windows)]
fn windows_socket_ip(
    address: &windows_sys::Win32::Networking::WinSock::SOCKET_ADDRESS,
) -> Option<IpAddr> {
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    if address.lpSockaddr.is_null()
        || address.iSockaddrLength < std::mem::size_of::<SOCKADDR>() as i32
    {
        return None;
    }
    // SAFETY: the API buffer is alive and the size check covers the family field.
    match unsafe { (*address.lpSockaddr).sa_family } {
        AF_INET if address.iSockaddrLength >= std::mem::size_of::<SOCKADDR_IN>() as i32 => {
            // SAFETY: the family and size identify the sockaddr layout and initialized union field.
            let value = unsafe {
                (*address.lpSockaddr.cast::<SOCKADDR_IN>())
                    .sin_addr
                    .S_un
                    .S_addr
            };
            Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(value))))
        }
        AF_INET6 if address.iSockaddrLength >= std::mem::size_of::<SOCKADDR_IN6>() as i32 => {
            // SAFETY: the family and size identify the sockaddr layout and initialized union field.
            let value = unsafe {
                (*address.lpSockaddr.cast::<SOCKADDR_IN6>())
                    .sin6_addr
                    .u
                    .Byte
            };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(value)))
        }
        _ => None,
    }
}
