#!/usr/bin/env bash
# Privileged Linux practical regression; never run in the host network namespace.
# Usage: sudo MEOW_BIN=/absolute/path/to/meow bash tests/test_tun_auto_interface_netns.sh
# Needs: full-feature TUN binary, root/CAP_SYS_ADMIN + CAP_NET_ADMIN,
# /dev/net/tun, bash, util-linux, iproute2, python3, tcpdump, coreutils. No curl/dig.
# The complete run has a 240-second deadline plus a 15-second forced-cleanup grace.
# Capture stdout+stderr in the caller's artifact: bash tests/... >tun-netns.log 2>&1.
# Failures retain raw evidence automatically; MEOW_TUN_EVIDENCE_DIR=auto also retains successes.
# An absolute, existing empty dedicated directory may be supplied instead of auto.
# All addresses are documentation/private ranges. No Internet, nodes or proxy ports.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SERVICES="$SCRIPT_DIR/support/tun_netns_services.py"
MEOW_BIN="${MEOW_BIN:-${1:-}}"
[[ "$MEOW_BIN" = /* && -x "$MEOW_BIN" ]] || {
    echo 'ERROR: provide an absolute executable MEOW_BIN path' >&2; exit 2;
}
[[ $(uname -s) = Linux && $EUID = 0 ]] || {
    echo 'ERROR: requires privileged Linux (run with sudo)' >&2; exit 2;
}
for dependency in unshare mount umount ip sysctl python3 tcpdump timeout readlink mktemp cp cmp sed grep sha256sum awk; do
    command -v "$dependency" >/dev/null || { echo "ERROR: missing $dependency" >&2; exit 2; }
done
[[ -c /dev/net/tun && -f "$SERVICES" ]] || {
    echo 'ERROR: /dev/net/tun or support/tun_netns_services.py unavailable' >&2; exit 2;
}

if [[ "${2:-}" != --isolated ]]; then
    export MEOW_BIN
    exec timeout --kill-after=15 240 unshare --net --mount --pid --fork --mount-proc \
        bash "$0" "$MEOW_BIN" --isolated \
        "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/mnt)"
fi
[[ $$ = 1 && $(readlink /proc/self/ns/net) != "$3" && $(readlink /proc/self/ns/mnt) != "$4" ]] || {
    echo 'ERROR: network/mount isolation was not established' >&2; exit 2;
}
mount --make-rprivate /
WORK="$(mktemp -d /tmp/meow-tun-netns.XXXXXXXX)"
chmod 700 "$WORK"
EVIDENCE_ARTIFACT=''
MEOW_PID=''
CAPTURE_PID=''
SERVICE_PID=''
ONLINK_PID=''
NAMESPACES=()
UPLINK0_V4='10.70.0.2'
UPLINK0_V6='fd00:70::2'

# Snapshot only the namespaces created by this lab; argument: filename prefix.
snapshot_network() {
    local prefix=$1 namespace
    ip -details link show > "$WORK/$prefix-link.txt" 2>&1 || true
    ip -4 rule show > "$WORK/$prefix-rule4.txt" 2>&1 || true
    ip -6 rule show > "$WORK/$prefix-rule6.txt" 2>&1 || true
    ip -4 route show table all > "$WORK/$prefix-route4-all.txt" 2>&1 || true
    ip -6 route show table all > "$WORK/$prefix-route6-all.txt" 2>&1 || true
    for namespace in "${NAMESPACES[@]}"; do
        ip -n "$namespace" -details link show > "$WORK/$prefix-$namespace-link.txt" 2>&1 || true
        ip -n "$namespace" -4 rule show > "$WORK/$prefix-$namespace-rule4.txt" 2>&1 || true
        ip -n "$namespace" -6 rule show > "$WORK/$prefix-$namespace-rule6.txt" 2>&1 || true
        ip -n "$namespace" -4 route show table all > "$WORK/$prefix-$namespace-route4-all.txt" 2>&1 || true
        ip -n "$namespace" -6 route show table all > "$WORK/$prefix-$namespace-route6-all.txt" 2>&1 || true
    done
}

# Always use a fresh child directory; never overwrite files in a caller-provided directory.
prepare_evidence() {
    local requested=${MEOW_TUN_EVIDENCE_DIR:-} root
    [[ -n "$requested" ]] || return 0
    if [[ "$requested" = auto ]]; then
        EVIDENCE_ARTIFACT=$(mktemp -d /tmp/meow-tun-evidence.XXXXXXXX)
        return
    fi
    [[ "$requested" = /* && -d "$requested" && ! -L "$requested" ]] || {
        echo 'ERROR: evidence destination must be auto or an existing empty absolute directory' >&2
        return 2
    }
    root=$(readlink -e -- "$requested") || return 2
    case "$root" in
        /|/etc|/etc/*|/run|/run/*|"$WORK"|"$WORK"/*)
            echo 'ERROR: evidence destination is outside the allowed persistent lab output paths' >&2
            return 2 ;;
    esac
    [[ "$root" != *$'\n'* && "$root" != *$'\r'* ]] || return 2
    if ! (shopt -s nullglob dotglob; entries=("$root"/*); ((${#entries[@]} == 0))); then
        echo 'ERROR: evidence parent must be an empty dedicated directory' >&2
        return 2
    fi
    EVIDENCE_ARTIFACT=$(mktemp -d "$root/meow-tun-evidence.XXXXXXXX")
}

# Copy closed logs and generated fixtures to an exclusively created artifact directory.
preserve_evidence() {
    local destination=$1 status=$2 diagnostic
    for diagnostic in "$WORK"/*.log "$WORK"/*.txt "$WORK"/*.yaml "$WORK"/*.json \
                      "$WORK"/rules* "$WORK"/resolv.original "$WORK"/resolv.final; do
        [[ -f "$diagnostic" && ! -L "$diagnostic" ]] || continue
        cp -n -- "$diagnostic" "$destination/" || return 1
    done
    printf 'harness_exit_status=%s\n' "$status" > "$destination/run-status.txt"
}

# Stop only owned children/namespaces, then retain raw evidence before removing the work directory.
cleanup() {
    local status=$? process namespace diagnostic destination marker
    trap - EXIT INT TERM
    set +e
    snapshot_network before-cleanup
    for process in "$MEOW_PID" "$CAPTURE_PID" "$SERVICE_PID" "$ONLINK_PID"; do
        [[ -n "$process" ]] || continue
        kill -TERM "$process" 2>/dev/null || true
    done
    for process in "$MEOW_PID" "$CAPTURE_PID" "$SERVICE_PID" "$ONLINK_PID"; do
        [[ -n "$process" ]] || continue
        for _ in {1..30}; do
            kill -0 "$process" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$process" 2>/dev/null; then kill -KILL "$process" 2>/dev/null || true; fi
        wait "$process" 2>/dev/null || true
    done
    snapshot_network after-process-cleanup
    [[ ! -f /etc/resolv.conf ]] || cp -L -- /etc/resolv.conf "$WORK/resolv.final"
    for namespace in "${NAMESPACES[@]}"; do
        ip netns delete "$namespace" || status=1
    done
    if (( status != 0 )); then
        echo "FAIL: isolated lab exit $status; diagnostic logs follow" >&2
        for diagnostic in "$WORK"/*.log; do
            [[ -f "$diagnostic" ]] || continue
            echo "=== ${diagnostic##*/} ===" >&2
            tail -n 70 "$diagnostic" >&2
        done
    fi
    destination=$EVIDENCE_ARTIFACT
    marker='EVIDENCE ARTIFACT'
    if [[ -z "$destination" ]] && (( status != 0 )); then
        destination=$(mktemp -d /tmp/meow-tun-failure.XXXXXXXX)
        marker='FAILURE ARTIFACT'
    fi
    if [[ -n "$destination" ]]; then
        if ! preserve_evidence "$destination" "$status"; then
            echo 'ERROR: raw evidence preservation failed' >&2
            status=1
        fi
        printf '%s: %s\n' "$marker" "$destination"
    fi
    # /etc is a private copy: DNS guard backup/removal cannot touch the real /etc.
    umount /etc 2>/dev/null || true
    rm -rf -- "$WORK" || status=1
    if (( status == 0 )); then
        echo 'PASS all isolated TUN auto-interface practical regressions'
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
prepare_evidence
binary_hash=$(sha256sum -- "$MEOW_BIN")
binary_hash=${binary_hash%% *}
binary_version=$("$MEOW_BIN" --version)
{
    printf 'source_sha=%s\n' "${MEOW_TUN_SOURCE_SHA:-not-provided}"
    printf 'binary_path=%s\nbinary_sha256=%s\nversion=%s\n' "$MEOW_BIN" "$binary_hash" "$binary_version"
    printf 'net_namespace=%s\nmount_namespace=%s\n' "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/mnt)"
} > "$WORK/binary-identity.txt"
printf 'BINARY IDENTITY: sha256=%s version=%s\n' "$binary_hash" "$binary_version"

# Isolate both resolv.conf and its sibling backup, without copying system secrets.
mkdir "$WORK/etc"
for system_file in hosts nsswitch.conf ld.so.cache passwd group; do
    [[ ! -f "/etc/$system_file" ]] || cp -L "/etc/$system_file" "$WORK/etc/$system_file"
done
printf 'nameserver 203.0.113.9\n' > "$WORK/etc/resolv.conf"
cp "$WORK/etc/resolv.conf" "$WORK/resolv.original"
mount --bind "$WORK/etc" /etc
# Private /run hides foreign namespace handles and host service sockets.
mount -t tmpfs -o mode=755 tmpfs /run
mkdir /run/netns
ip link set lo up
sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv4.conf.all.rp_filter=0
ip netns add server
NAMESPACES+=(server)
ip -n server link set lo up
ip -n server addr add 203.0.113.9/32 dev lo
ip -n server -6 addr add fd00:99::9/128 dev lo nodad

for uplink in 0 1; do
    router="router$uplink"
    ip netns add "$router"
    NAMESPACES+=("$router")
    ip -n "$router" link set lo up
    ip netns exec "$router" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
        net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
    ip link add "uplink$uplink" type veth peer name wan netns "$router"
    ip addr add "10.7$uplink.0.2/24" dev "uplink$uplink"
    ip -6 addr add "fd00:7$uplink::2/64" dev "uplink$uplink" nodad
    ip link set "uplink$uplink" up
    ip -n "$router" addr add "10.7$uplink.0.1/24" dev wan
    ip -n "$router" -6 addr add "fd00:7$uplink::1/64" dev wan nodad
    ip -n "$router" link set wan up
    ip -n "$router" link add lan type veth peer name "server$uplink" netns server
    ip -n "$router" addr add "10.8$uplink.0.1/24" dev lan
    ip -n "$router" -6 addr add "fd00:8$uplink::1/64" dev lan nodad
    ip -n "$router" link set lan up
    ip -n server addr add "10.8$uplink.0.2/24" dev "server$uplink"
    ip -n server -6 addr add "fd00:8$uplink::2/64" dev "server$uplink" nodad
    ip -n server link set "server$uplink" up
    ip -n "$router" route add 203.0.113.9/32 via "10.8$uplink.0.2"
    ip -n "$router" -6 route add fd00:99::9/128 via "fd00:8$uplink::2"
    ip -n server route add "10.7$uplink.0.0/24" via "10.8$uplink.0.1"
    ip -n server -6 route add "fd00:7$uplink::/64" via "fd00:8$uplink::1"
done

# Set both physical defaults; argument: uplink index; returns ip's status.
set_default() {
    ip route replace default via "10.7$1.0.1" dev "uplink$1"
    ip -6 route replace default via "fd00:7$1::1" dev "uplink$1"
}

# Assert the last command's intended condition; arguments: message; never returns on failure.
fail() { echo "ERROR: $*" >&2; exit 1; }

# Read namespace-local packet counters via netlink, not a host-mounted sysfs; returns a count.
tun_packets() {
    ip -j -s link show dev meowtest | python3 -c '
import json, sys
link = json.load(sys.stdin)[0]
stats = link.get("stats64", link.get("stats"))
print(stats["rx"]["packets"] + stats["tx"]["packets"])
'
}

# Write a local DIRECT/fake-IP config; arguments: name, detection flag, optional fixed iface.
write_config() {
    local name=$1 detect=$2 fixed=${3:-}
    cat > "$WORK/$name.yaml" <<EOF
mode: rule
log-level: debug
ipv6: true
dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: [upstream.test, '+.upstream.test']
  use-system-hosts: false
  nameserver: [203.0.113.9]
external-controller: 127.0.0.1:19090
tun:
  enable: true
  device: meowtest
  stack: lwip
  inet4-address: 198.18.0.1/30
  inet6-address: fd00:18::1/126
  auto-route: true
  auto-detect-interface: $detect
  dns-hijack: [any:53]
  mtu: 1500
rules: ['MATCH,DIRECT']
EOF
    if [[ -n "$fixed" ]]; then
        # Insert inside the existing tun mapping, not as a duplicate YAML key.
        sed -i "/  device: meowtest/a\  outbound-interface: $fixed" "$WORK/$name.yaml"
    fi
}

# Start only the requested binary; argument: config name; wait for device and policy readiness.
start_meow() {
    local name=$1
    RUST_LOG=debug "$MEOW_BIN" -d "$WORK" -f "$WORK/$name.yaml" > "$WORK/$name.log" 2>&1 &
    MEOW_PID=$!
    for _ in {1..100}; do
        kill -0 "$MEOW_PID" 2>/dev/null || fail "meow exited during $name startup"
        if ip link show meowtest >/dev/null 2>&1 && \
           ip -4 rule show | grep -q 1835364215 && ip -6 rule show | grep -q 1835364215; then
            echo "PASS $name TUN and dual-stack policy readiness"
            return
        fi
        sleep 0.1
    done
    fail "$name did not establish TUN and policy routes in 10 seconds"
}

# SIGTERM the owned meow and verify route, interface, policy and resolver restoration.
stop_meow() {
    kill -TERM "$MEOW_PID"
    for _ in {1..100}; do
        kill -0 "$MEOW_PID" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$MEOW_PID" 2>/dev/null; then fail 'SIGTERM did not finish in 10 seconds'; fi
    wait "$MEOW_PID" || fail 'meow returned failure after SIGTERM'
    MEOW_PID=''
    ! ip link show meowtest >/dev/null 2>&1 || fail 'TUN interface leaked'
    ip -4 rule show > "$WORK/rules4.after"
    ip -6 rule show > "$WORK/rules6.after"
    cmp "$WORK/rules4.before" "$WORK/rules4.after" || fail 'IPv4 rules leaked'
    cmp "$WORK/rules6.before" "$WORK/rules6.after" || fail 'IPv6 rules leaked'
    [[ -z $(ip -4 route show table 1835364215 2>/dev/null) ]] || fail 'IPv4 TUN table leaked'
    [[ -z $(ip -6 route show table 1835364215 2>/dev/null) ]] || fail 'IPv6 TUN table leaked'
    cmp /etc/resolv.conf "$WORK/resolv.original" || fail 'resolver was not restored'
    echo 'PASS SIGTERM removes owned interface/routes/rules and restores DNS'
}

# Probe all real TUN transports, checking server-observed physical source; args: tag, uplink.
probe_matrix() {
    local tag=$1 uplink=$2 protocol address source
    for protocol in tcp udp; do
        for address in 203.0.113.9 fd00:99::9; do
            source="10.7$uplink.0.2"
            [[ "$address" != *:* ]] || source="fd00:7$uplink::2"
            if [[ "$uplink" = 0 ]]; then
                [[ "$address" = *:* ]] && source=$UPLINK0_V6 || source=$UPLINK0_V4
            fi
            python3 "$SERVICES" probe "$address" "$protocol" "$tag-$protocol-$address" \
                --receipts "$WORK/server.log" --source "$source"
        done
    done
    for address in 203.0.113.9 fd00:99::9; do
        timeout 4 python3 "$SERVICES" http "$address"
    done
}

# Assert DNS interception and its upstream physical receipt; args: phase, expected source.
probe_dns_matrix() {
    local phase=$1 source=$2 address transport name
    for address in 192.0.2.53 2001:db8::53; do
        for transport in udp tcp; do
            name="${phase}-${transport}-$( [[ "$address" = *:* ]] && printf v6 || printf v4 ).upstream.test"
            timeout 5 python3 "$SERVICES" dns "$address" "$transport" "$name" \
                --expect 203.0.113.9/32 --receipts "$WORK/server.log" --source "$source"
        done
    done
}

# Count this daemon generation's watcher observations before each owned network mutation.
watcher_count() {
    grep -c 'physical default interface changed' "$WORK/auto.log" || true
}

# One five-second envelope includes a new watcher count, retry matrix and independent final matrix.
converge_transition() {
    local phase=$1 before=$2 source_v4=$3 source_v6=$4
    shift 4
    timeout --kill-after=1 5 python3 -u "$SERVICES" converge "$phase" \
        --daemon-log "$WORK/auto.log" --receipts "$WORK/server.log" --before "$before" \
        --source-v4 "$source_v4" --source-v6 "$source_v6" --timeout 4.8 "$@" || \
        fail "$phase did not complete watcher observation and both four-protocol matrices within five seconds"
    snapshot_network "$phase"
}

# Allocate once before reload; all later phases dial that saved fake address without re-querying it.
probe_fakeip() {
    local phase=$1 source=$2
    shift 2
    timeout 8 python3 -u "$SERVICES" fakeip "$phase" --state "$WORK/fakeip-state.json" \
        --receipts "$WORK/server.log" --source "$source" "$@"
}

# Replace owned uplink0 addresses in this shell; assert that the interface index stays fixed.
replace_uplink0_addresses() {
    local old_index new_index
    old_index=$(ip -o link show dev uplink0 | awk -F: '{print $1}')
    ip addr del "$UPLINK0_V4/24" dev uplink0
    ip addr add 10.70.0.22/24 dev uplink0
    ip -6 addr del "$UPLINK0_V6/64" dev uplink0
    ip -6 addr add fd00:70::22/64 dev uplink0 nodad
    UPLINK0_V4='10.70.0.22'
    UPLINK0_V6='fd00:70::22'
    # Removing the sole IPv4 address also removes its gateway default on Linux.
    # Restore only this fixture's defaults; the ifindex and source change remain under test.
    set_default 0
    new_index=$(ip -o link show dev uplink0 | awk -F: '{print $1}')
    [[ "$old_index" = "$new_index" ]] || fail 'uplink0 ifindex changed during address replacement'
}

set_default 0
ip -4 rule show > "$WORK/rules4.before"
ip -6 rule show > "$WORK/rules6.before"
ip netns exec server python3 -u "$SERVICES" serve > "$WORK/server.log" 2>&1 &
SERVICE_PID=$!
for _ in {1..50}; do
    grep -q '^READY$' "$WORK/server.log" && break
    kill -0 "$SERVICE_PID" 2>/dev/null || fail 'mock services exited'
    sleep 0.1
done
grep -q '^READY$' "$WORK/server.log" || fail 'mock services did not become ready'
ip netns exec router0 python3 -u "$SERVICES" serve > "$WORK/onlink-server.log" 2>&1 &
ONLINK_PID=$!
for _ in {1..50}; do
    grep -q '^READY$' "$WORK/onlink-server.log" && break
    kill -0 "$ONLINK_PID" 2>/dev/null || fail 'on-link mock services exited'
    sleep 0.1
done
grep -q '^READY$' "$WORK/onlink-server.log" || fail 'on-link mock services not ready'
probe_matrix direct-before 0
write_config auto true
start_meow auto
tcpdump -i meowtest -nn -l 'tcp or udp' > "$WORK/tun-capture.log" 2>&1 &
CAPTURE_PID=$!
sleep 0.2
kill -0 "$CAPTURE_PID" || fail 'tcpdump failed to start'
probe_matrix baseline 0
probe_dns_matrix dns-baseline "$UPLINK0_V4"
probe_fakeip before-reload "$UPLINK0_V4" --allocate
snapshot_network baseline

# A localhost config commit must fetch only the owned mock provider off-TUN.
cat > "$WORK/provider.yaml" <<EOF
mode: rule
log-level: debug
ipv6: true
external-controller: 127.0.0.1:19090
dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: [upstream.test, '+.upstream.test']
  use-system-hosts: false
  nameserver: [203.0.113.9]
tun:
  enable: true
  device: meowtest
  stack: lwip
  inet4-address: 198.18.0.1/30
  inet6-address: fd00:18::1/126
  auto-route: true
  auto-detect-interface: true
  dns-hijack: [any:53]
  mtu: 1500
proxy-providers:
  mock-provider:
    type: http
    url: http://203.0.113.9:18081/provider
    path: $WORK/mock-provider.yaml
    interval: 3600
proxy-groups:
  - name: mock-group
    type: select
    use: [mock-provider]
rules: ['MATCH,DIRECT']
EOF
ip link show meowtest >/dev/null 2>&1 || fail 'TUN disappeared before provider bootstrap check'
timeout 8 python3 "$SERVICES" api-put 127.0.0.1 19090 "$WORK/provider.yaml" \
    --receipts "$WORK/server.log" --source "$UPLINK0_V4" || \
    fail 'PUT /configs provider fetch did not use the physical uplink'
ip link show meowtest >/dev/null 2>&1 || fail 'TUN disappeared during provider fetch check'
echo 'PASS localhost PUT /configs fetches mock provider through physical uplink'
probe_fakeip after-reload "$UPLINK0_V4"

# The destination has no DNS server: only interception can produce these answers.
for address in 192.0.2.53 2001:db8::53; do
    for transport in udp tcp; do
        timeout 4 python3 "$SERVICES" dns "$address" "$transport" fake.tun.test --expect 198.18.0.0/16
        timeout 4 python3 "$SERVICES" dns "$address" "$transport" upstream.test --expect 203.0.113.9/32
    done
done

# Each transition must add a fresh watcher observation before retry/final traffic assertions.
retirements_before=$(watcher_count)
ip -6 route replace default via fd00:71::1 dev uplink1
converge_transition v6-only "$retirements_before" "$UPLINK0_V4" fd00:71::2 --exactly-one
probe_dns_matrix dns-v6-only "$UPLINK0_V4"
probe_fakeip v6-only "$UPLINK0_V4"
echo 'PASS IPv6-only default swap preserves IPv4 uplink with one new watcher observation'

retirements_before=$(watcher_count)
ip -6 route replace default via fd00:70::1 dev uplink0
converge_transition v6-restored "$retirements_before" "$UPLINK0_V4" "$UPLINK0_V6" --exactly-one
probe_dns_matrix dns-v6-restored "$UPLINK0_V4"
echo 'PASS IPv6 default restored with independent dual-stack assertions and one new watcher observation'

retirements_before=$(watcher_count)
set_default 1
converge_transition uplink1 "$retirements_before" 10.71.0.2 fd00:71::2
probe_fakeip uplink1 10.71.0.2
echo 'PASS uplink0 -> uplink1 real dual-stack TCP/UDP and fresh watcher observation within five seconds'

ip route del default
ip -6 route del default
for _ in {1..30}; do
    grep -q 'physical default interface lost' "$WORK/auto.log" && break
    sleep 0.1
done
grep -q 'physical default interface lost' "$WORK/auto.log" || fail 'missing-default watcher not logged'
before=$(tun_packets)
for protocol in tcp udp; do
    for address in 203.0.113.9 fd00:99::9; do
        timeout 3 python3 "$SERVICES" probe "$address" "$protocol" no-default \
            --timeout 0.6 --expect-network-failure || \
            fail 'missing-default probe did not observe a bounded network failure'
    done
done
# Connected prefixes must still bypass the global TUN route during the outage.
for protocol in tcp udp; do
    for address in 10.70.0.1 fd00:70::1; do
        python3 "$SERVICES" probe "$address" "$protocol" "onlink-$protocol-$address"
    done
done
ip -4 route get 10.70.0.1 | grep -q 'dev uplink0' || fail 'unbound IPv4 on-link lookup entered TUN'
ip -6 route get fd00:70::1 | grep -q 'dev uplink0' || fail 'unbound IPv6 on-link lookup entered TUN'
ip route get 10.70.0.1 from 10.70.0.2 | grep -q 'dev uplink0' || fail 'sourced on-link route was disturbed'
after=$(tun_packets)
(( after - before < 200 )) || fail 'TUN packet growth during failed dials suggests recursion'
before=$after
sleep 1
after=$(tun_packets)
(( after - before < 100 )) || fail 'TUN packet growth suggests a recursive route loop'
kill -0 "$MEOW_PID" || fail 'meow died during missing-default test'
echo 'PASS missing default: bounded failures, real on-link TCP/UDP retained, no packet storm'

retirements_before=$(watcher_count)
set_default 0
converge_transition recovered "$retirements_before" "$UPLINK0_V4" "$UPLINK0_V6"
probe_matrix restored 0
probe_dns_matrix dns-recovered "$UPLINK0_V4"
probe_fakeip recovered "$UPLINK0_V4"
retirements_before=$(watcher_count)
uplink0_ifindex=$(ip -o link show dev uplink0 | awk -F: '{print $1}')
replace_uplink0_addresses
converge_transition address-changed "$retirements_before" "$UPLINK0_V4" "$UPLINK0_V6"
[[ $(ip -o link show dev uplink0 | awk -F: '{print $1}') = "$uplink0_ifindex" ]] || \
    fail 'uplink0 ifindex changed after address replacement'
probe_dns_matrix dns-address-changed "$UPLINK0_V4"
probe_fakeip address-changed "$UPLINK0_V4"
echo 'PASS same-ifindex source replacement observed on dual-stack traffic'
kill -INT "$CAPTURE_PID"
wait "$CAPTURE_PID" || true
CAPTURE_PID=''
for pattern in '203\.0\.113\.9\.18080: Flags' 'fd00:99::9\.18080: Flags' \
               '203\.0\.113\.9\.18080: UDP' 'fd00:99::9\.18080: UDP' \
               '192\.0\.2\.53\.53: Flags' '192\.0\.2\.53\.53: [0-9]+.* A\?' \
               '2001:db8::53\.53: Flags' '2001:db8::53\.53: [0-9]+.* A\?'; do
    grep -Eq "$pattern" "$WORK/tun-capture.log" || fail "missing real TUN capture: $pattern"
done
echo 'PASS tcpdump confirms real IPv4/IPv6 TCP/UDP and DNS packets on meowtest'
stop_meow
probe_matrix direct-after 0

write_config fixed false uplink1
# Keep a less-preferred default usable for SO_BINDTODEVICE while main default is uplink0.
ip route add default via 10.71.0.1 dev uplink1 metric 100
ip -6 route add default via fd00:71::1 dev uplink1 metric 100
start_meow fixed
probe_matrix detection-disabled-explicit 1
stop_meow

# The global interface must win a real conflict with tun.outbound-interface.
write_config manual true uplink0
printf 'interface-name: uplink1\n' >> "$WORK/manual.yaml"
start_meow manual
probe_matrix manual-wins 1
grep -q "bound to 'uplink1'.*auto-detect-interface: false" "$WORK/manual.log" || \
    fail 'explicit interface did not disable the automatic finder'
stop_meow

write_config closed false
RUST_LOG=debug "$MEOW_BIN" -d "$WORK" -f "$WORK/closed.yaml" > "$WORK/closed.log" 2>&1 &
MEOW_PID=$!
for _ in {1..50}; do
    grep -Eq 'auto-detect-interface is false|auto-detect-interface.*requires|outbound-interface.*required' \
        "$WORK/closed.log" && break
    sleep 0.1
done
grep -Eq 'auto-detect-interface is false|auto-detect-interface.*requires|outbound-interface.*required' \
    "$WORK/closed.log" || fail 'disabled detection without interface did not report fail-closed error'
! ip link show meowtest >/dev/null 2>&1 || fail 'fail-closed setup leaked a TUN device'
ip -4 rule show > "$WORK/rules4.after"
ip -6 rule show > "$WORK/rules6.after"
cmp "$WORK/rules4.before" "$WORK/rules4.after" || fail 'fail-closed IPv4 policies leaked'
cmp "$WORK/rules6.before" "$WORK/rules6.after" || fail 'fail-closed IPv6 policies leaked'
echo 'PASS disabled auto detection without explicit interface fails closed'
# The final PASS marker is emitted by cleanup only after owned processes and namespaces are removed.
