# Personal TUN test build

This is the build and QA runbook for the fork-only workflow
[`.github/workflows/tun-test.yml`](../.github/workflows/tun-test.yml). The
comparison anchors are meow base `083e4b23` and mihomo reference `0455d0d`.
They identify the source line being compared; they do not establish complete
mihomo TUN compatibility or a successful test run.

## Trigger and version matrix

Pushes to `tun-port-test`, `tun-*`, or `tun-port-test/tun-*`, plus a manual
`workflow_dispatch`, start this workflow. Every job requires
`github.event.repository.fork == true`. It has `contents: read`, uses no
repository secrets, publishes no release/package/tag, and cancels older runs
for the same workflow ref.

The source job resolves the selected branch/tag/SHA once. A blank dispatch
input uses the event commit. Every later checkout uses the resolved full SHA,
so a moving branch cannot give the build and QA different source trees.
The SHA also supplies the seven-character Alpha identifier.

| Flavor | `MEOW_VERSION_SUFFIX` | Expected `meow --version` |
| --- | --- | --- |
| `test` | empty | `meow <workspace version>` |
| `alpha` | `-alpha+<sha7>` | `meow <workspace version>-alpha+<sha7>` |

`test` means the ordinary version string from the candidate checkout; it does
not mean an already released stable tag. Alpha uses the same candidate source
and full feature bundle, with the suffix convention used by `alpha.yml`.
The upstream Alpha workflow is guarded to `meow-rs/meow-rs` and its publishing
path is not invoked here.

Each of the three runners builds both flavors sequentially, sharing compiled
dependencies and copying the first binary before building the second:

| Runner | Target | Test flavor | Alpha flavor |
| --- | --- | --- | --- |
| `ubuntu-24.04` | `x86_64-unknown-linux-gnu` | build + version check + isolated TUN QA | build + version check + isolated TUN QA |
| `macos-15` | `aarch64-apple-darwin` | build + version check | build + version check |
| `windows-2025` | `x86_64-pc-windows-msvc` | build + version check | build + version check |

The pinned channel is read from `rust-toolchain.toml` (currently `1.98.1`).
All six binaries use the same explicit command and assert that the Cargo
feature graph includes `listener-tun`:

```bash
cargo build --release --locked -p meow-app --no-default-features --features full \
  --target <target> --bin meow
```

Linux installs the native C/C++/CMake/bindgen dependencies. macOS uses the
runner's Xcode toolchain plus CMake. All three runners install pinned LLVM
`18.1.8` for bindgen. Windows fetches the pinned official Wintun DLL before
compilation and passes it through `MEOW_WINTUN_DLL`, so it is embedded in
each executable. These are full TUN builds; the size-capped `minimal` bundle
is not a test flavor.

## Source and binary evidence

Each immutable `upload-artifact@v4` artifact name contains its flavor, target,
full source SHA, Actions run ID and attempt. Its files include:

- The frozen executable and its sibling `.sha256` file.
- `build-info.txt`: source SHA/tree, flavor, target, pinned toolchain,
  checked version output, binary SHA256, run ID/attempt and the build command.
- `toolchain.txt`: actual `rustc --version --verbose` and `cargo --version`.
- `feature-graph.txt`: the resolved full-feature dependency graph.

macOS uses `shasum -a 256`; Linux/Windows use `sha256sum`. The checksum-file
formats are compatible. Linux QA downloads the named artifact for each
flavor, verifies its checksum and all recorded identity fields against the
checkout/run, executes `meow --version` again, and then passes that exact
artifact path as `MEOW_BIN` to the practical harness. It never substitutes a
locally rebuilt executable for the downloaded one.

A separate Linux source-regression job uses the same SHA and toolchain and
runs the full app/listener/API feature graph. Its Cargo invocation includes
`--lib --bins --test tun_config_test --test named_tun_config_test --test api_test`.
The explicit integration targets matter: `--lib --bins` alone does not run
them. Both flavor QA jobs require the source-regression job to succeed.
Source test output, the actual command and feature graph are uploaded once.
A separate `quality-gates` job checks out the same resolved SHA and pinned
channel, then runs formatting, default/no-default/all-feature strict Clippy,
the standalone common-stub check, DNS/config/offline/rules/tunnel/API and
workspace-library regressions, the UDP :53 and QUIC DNS regressions, minimal
compilation and strict rustdoc. Its commands and results are retained in a
separate source-labelled quality artifact. Both Linux QA jobs require this
job and the focused TUN source-regression job to succeed.

Each Linux QA job also runs `tests/test_fakeip_filter_binary.py` against its
already downloaded executable; it does not build another binary. The `test`
flavor maps to that driver's `--flavor stable`, and Alpha maps to `alpha`.
The driver uses the candidate's own `-v` convention (`Meow Meta ...`), checks
the source tree is clean, and records source/tree, binary hash, version,
actual build command and fixture logs/results. The workflow's separate
`--version` checks continue to expect the clap form `meow ...`.

Each flavor uploads the binary-driver evidence, practical harness log,
provenance and raw success/failure diagnostics. Both practical steps are
allowed to reach diagnostics collection after failure; a final step fails
the QA job if either step failed. The final harness PASS marker, a retained
successful evidence artifact and matching SHA/hash/version identity are
required for a successful practical harness step.

These records bind the built bytes to the selected checkout within this
Actions run. A checksum alone establishes byte integrity, not successful TUN
behavior; retain the associated QA logs and check the final job conclusions.

## Existing regression coverage

The following tests are present in source and selected by the workflow. Their
presence is not a claim that they have passed on the current candidate:

- `crates/meow-config/tests/tun_config_test.rs`: typed/defaulted automatic
  detection and effective outbound-binding policy, including explicit
  interface precedence and disabled-detection fail-closed policy.
- `crates/meow-config/tests/named_tun_config_test.rs`: named-listener detection
  defaults, typed booleans and raw-config round trips.
- `crates/meow-api/tests/api_test.rs`: TUN configuration PATCH/GET and
  reconciliation contracts; API library tests cover binding preinstallation
  during provider fetch and rollback.
- `crates/meow-listener/src/tun/route.rs`: pure route selection, owned-TUN
  exclusion, IPv4/IPv6 defaults, route/interface metrics, carrier state,
  IPv6-only handovers and source-address changes at the same interface index.
- `crates/meow-listener/src/tun/outbound_binding.rs`: binding ownership,
  fail-closed installation, superseded observations, loss/recovery and
  acknowledgement state. Its live default-route subcase is conditional on
  the host having a usable default; it is not a replacement for the lab.

The practical harness is
[`tests/test_tun_auto_interface_netns.sh`](../tests/test_tun_auto_interface_netns.sh),
with dependency-free, unproxied byte-exact clients/services in
[`tests/support/tun_netns_services.py`](../tests/support/tun_netns_services.py).
It creates private network, mount and PID namespaces before creating test
devices or services, plus two veth uplinks and router/server namespaces.
Private `/etc` and `/run` mounts isolate resolver restoration and namespace
handles. The test network has no host uplink or Internet route.

The harness is intended to assert all of the following separately for each
frozen Linux flavor:

- Real kernel TUN capture for IPv4/IPv6 TCP/UDP, byte-exact replies and
  server-observed physical source addresses.
- UDP/TCP DNS hijack to IPv4/IPv6 destinations without a DNS service,
  including fake-IP/upstream A answers and fresh upstream receipts.
  These are IPv6 transport checks; they do not test AAAA/fake-IPv6 allocation.
- A `fake.tun.test` A allocation obtained before the API reload, followed by
  real TUN TCP/UDP echo probes to that exact saved fake address after reload,
  uplink handover, recovery and source replacement. Its owned upstream is
  A-only (`203.0.113.9`), and fresh server receipts assert the physical IPv4
  source for every new payload. Later phases reuse the original allocation
  without refreshing it through DNS.
- Physical default selection, IPv6-only default changes, both-family
  handover, loss, recovery and source-address replacement at the same ifindex.
- A localhost `PUT /configs` whose owned mock HTTP provider must be fetched
  through the physical uplink while TUN routing is active.
- Explicit `outbound-interface` with detection disabled, plus a conflicting
  `tun.outbound-interface: uplink0` and top-level `interface-name: uplink1`
  proving that the top-level interface wins on real traffic.
- No-default bounded failures, on-link traffic preservation with unsourced
  IPv4/IPv6 route lookups, and bounded TUN packet growth; SIGTERM cleanup of
  owned interfaces/routes/rules and restoration of the private resolver.

After each owned route/address mutation, one five-second outer deadline
covers waiting for a watcher count newer than the phase's baseline, retrying
all four TCP/UDP and IPv4/IPv6 probes, and an independent final four-protocol
matrix. The helper reserves a small startup margin with a 4.8-second monotonic
deadline. Every invocation carries a new nonce, so a previous attempt's
receipt cannot satisfy another attempt. Attempt failures remain in the log.
IPv6-only changes additionally require exactly one new watcher observation.
These checks establish fresh flows and watcher observations; they do not
assert retirement of a particular pre-existing TCP/UDP session. The
same-ifindex address test explicitly restores only its owned defaults after
Linux removes the gateway route with the last old IPv4 address.

The outer lab deadline is 240 seconds plus a 15-second forced-cleanup grace.
Without an evidence option, failures automatically retain a newly created
`/tmp/meow-tun-failure.*` directory and print `FAILURE ARTIFACT: <path>`.
Set `MEOW_TUN_EVIDENCE_DIR=auto` to retain both successful and failed runs in
a new `/tmp/meow-tun-evidence.*` directory and print the parseable
`EVIDENCE ARTIFACT: <path>` marker. An alternative value must name an absolute,
existing, empty dedicated directory: the harness creates a fresh child
inside it, never reuses existing files, and rejects symlinks and paths hidden
by the private `/etc` or `/run` mounts. Output must be outside the lab's own
work directory.

Evidence contains closed daemon logs, raw server receipts, tcpdump output,
phase and cleanup link/rule/route snapshots, generated configurations,
original/final resolver content, the saved FakeIP allocation, actual binary
hash/version and a harness exit-status file. `MEOW_TUN_SOURCE_SHA` is an
optional source label; Actions passes the immutable selected SHA and checks
it and the actual binary identity against the downloaded manifest. Actions
collects both artifact marker forms. The final PASS marker is emitted only
after owned processes/namespaces have been cleaned up and requested evidence
has been saved. Missing privileges, TUN support, isolation or dependencies
fail the run; a syntax check is not a practical test.

## Remote disposable Linux run

Run the commands in this section on a disposable privileged **remote** Linux
worker/container, from the candidate checkout. The local controller only
reviews files and collects results. Pass `/dev/net/tun` through and provide
`CAP_NET_ADMIN` and `CAP_SYS_ADMIN` with mount/PID/net namespace support.
If `unshare --net --mount --pid --fork` fails, fix the worker/profile; keep
the harness isolation flags intact.

Install ordinary build/probe tools on that worker:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake clang libclang-dev pkg-config iproute2 tcpdump \
  util-linux python3 coreutils bash sudo procps
```

Use the checkout's pinned channel. A preinstalled `1.99.0`, a copied target
cache or a deliberate toolchain override does not establish compatibility
with pinned Actions builds. Preserve such a difference as a validation gap.

The commands below build ordinary/Alpha binaries, freeze each one, verify
its version and checksum, and attempt both isolated runs even if one harness
fails. The printed result directory contains both logs and binary identities.
They execute on the remote worker, not the controller:

```bash
set -euo pipefail
sha=$(git rev-parse --verify HEAD)
[[ "$sha" =~ ^[0-9a-f]{40}$ ]]
[[ -z "$(git status --porcelain --untracked-files=no)" ]]
tc=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n1)
base=$(sed -nE '/^\[workspace\.package\]/,/^\[/ s/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' Cargo.toml | head -n1)
rustup toolchain install "$tc" --profile minimal --no-self-update
export RUSTUP_TOOLCHAIN="$tc"
results=$(mktemp -d /tmp/meow-tun-review.XXXXXXXX)
printf 'Results: %s\nSource SHA: %s\n' "$results" "$sha"
rustc --version --verbose | tee "$results/toolchain.txt"
cargo test --locked --no-default-features \
  -p meow-app -p meow-common -p meow-listener -p meow-config -p meow-api \
  --features meow-app/full,meow-listener/listener-tun,meow-api/listener-tun \
  --lib --bins --test tun_config_test --test named_tun_config_test --test api_test \
  -- --test-threads=1 2>&1 | tee "$results/source-tests.log"
failures=0
for flavor in test alpha; do
  suffix=''
  [[ "$flavor" != alpha ]] || suffix="-alpha+${sha:0:7}"
  export MEOW_VERSION_SUFFIX="$suffix"
  cargo build --release --locked -p meow-app --no-default-features --features full --bin meow
  mkdir "$results/$flavor"
  binary="$results/$flavor/meow"
  cp target/release/meow "$binary"
  [[ "$("$binary" --version)" = "meow $base$suffix" ]]
  printf 'source_sha=%s\nflavor=%s\n' "$sha" "$flavor" > "$results/$flavor/build-info.txt"
  "$binary" --version >> "$results/$flavor/build-info.txt"
  (cd "$results/$flavor" && sha256sum meow > meow.sha256 && sha256sum -c meow.sha256)
  evidence_root=$(mktemp -d "$results/$flavor/evidence-root.XXXXXXXX")
  if sudo env MEOW_BIN="$binary" MEOW_TUN_SOURCE_SHA="$sha" \
      MEOW_TUN_EVIDENCE_DIR="$evidence_root" bash tests/test_tun_auto_interface_netns.sh \
      2>&1 | tee "$results/$flavor/tun-netns.log"; then
    grep -Fxq 'PASS all isolated TUN auto-interface practical regressions' \
      "$results/$flavor/tun-netns.log" || failures=$((failures + 1))
  else
    failures=$((failures + 1))
  fi
done
printf 'Results: %s; failed flavors: %s\n' "$results" "$failures"
[[ "$failures" = 0 ]]
```

This native worker example expects an ordinary Linux GNU host and the
default `target/release` output directory. If the task deliberately sets
`CARGO_TARGET_DIR` or a target triple, adjust the copy path accordingly and
record the exact build command. It does not exercise macOS/Windows toolchains.

## Actions run and remaining practical evidence

After remote validation and review, the lead pushes the candidate branch:

```bash
git push origin HEAD:tun-port-test/tun-auto-interface
```

That branch matches the workflow push filter. Manual dispatch may instead
select a branch, tag or SHA in `ref`; all jobs still use the one resolved SHA.
For a completed run, preserve the six binary/provenance artifacts, the focused
source-regression and quality-gate artifacts, both Linux QA artifacts
(including each flavor's binary FakeIP JSON/logs and raw namespace evidence)
and their job conclusions.
Use `sha256sum -c meow.sha256` (macOS: `shasum -a 256 -c meow.sha256`) from
the extracted artifact directory before separately executing its binary.

Actual passing logs are still required for the two Linux harness flavors
and all six native builds/version checks. Windows/macOS TUN operation,
physical-interface changes and cleanup require separate privileged tests on
disposable workers of those platforms. They are not established by Linux
fixtures, pure route tests or `--version`. The reusable `build.yml` has a
broader release-target matrix (including musl, ARM, RISC-V, macOS x86_64 and
other Windows architectures); this three-platform workflow does not validate
those extra targets or their packaging. A release-matrix dry run is a
separate requirement when those release artifacts are being claimed.

No external proxy node, Internet path, DoH/TLS proxy transport or real-device
Wi-Fi/Ethernet transition is exercised by the namespace harness.
`strict-route`, `auto-redirect`, `mtu-v6`, endpoint-independent NAT and upstream
UID filters remain outside the implemented behavior documented here.
The harness selects `stack: lwip`; Linux `system` and the compatibility stack
names have separate semantics described in [TUN setup](tun.md).

## Personal fork settings

The upstream publishing workflows remain separate. Scheduled workloads
(`bench-daily.yml`, `cache-warmup.yml`, `coverage.yml`,
`feature-powerset-daily.yml`, `toolchain-drift.yml`, scheduled `audit.yml`),
release/publishing workflows (`alpha.yml`, `release.yml`, `publish.yml`,
`tag-release.yml`, `prepare-release.yml`) and `pages.yml` may be disabled in a
personal fork when they are not needed. Do not add `pull_request_target`,
write permissions, schedules, release actions or credentials to this test
workflow. The candidate's actual build/test status must come from retained
run logs, not this runbook.
