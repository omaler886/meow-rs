#!/usr/bin/env python3
"""Run only on a remote worker: deterministic released-binary FakeIP regression."""
import argparse
import base64
import hashlib
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.request

REAL4 = '192.0.2.25'
REAL6 = '2001:db8::25'
FAKE4 = ipaddress.ip_network('198.18.0.0/16')
FAKE6 = ipaddress.ip_network('fdfe:dcba:9876::/64')
TOKEN = 'fixture-fakeip-regression'


def wire_name(name):
    return b''.join(bytes([len(p)]) + p.encode('ascii') for p in name.split('.')) + b'\0'


def skip_name(packet, offset):
    while True:
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def unpack_response(packet):
    ident, flags, qd, an, ns, ar = struct.unpack_from('!6H', packet)
    if flags & 15:
        raise AssertionError(f'DNS rcode={flags & 15}')
    offset = 12
    for _ in range(qd):
        offset = skip_name(packet, offset) + 4
    records = []
    for _ in range(an):
        offset = skip_name(packet, offset)
        kind, cls, ttl, length = struct.unpack_from('!HHIH', packet, offset)
        offset += 10
        data = packet[offset:offset + length]
        offset += length
        records.append((kind, data))
    return ident, records


class Upstream:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.stopped = threading.Event()
        self.counts = {}
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                packet, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            end = skip_name(packet, 12)
            kind = struct.unpack_from('!H', packet, end)[0]
            question = packet[12:end + 4]
            with self.lock:
                key = (packet[12:end].lower(), kind)
                self.counts[key] = self.counts.get(key, 0) + 1
            payload = None
            if kind == 1:
                payload = socket.inet_pton(socket.AF_INET, REAL4)
            elif kind == 28:
                payload = socket.inet_pton(socket.AF_INET6, REAL6)
            elif kind in (64, 65):
                # ServiceMode, root target, ipv4hint and ipv6hint.
                payload = (b'\x00\x01\x00'
                           + struct.pack('!HH', 1, 3) + b'\x02h2'
                           + struct.pack('!HH', 3, 2) + struct.pack('!H', 443)
                           + struct.pack('!HH', 4, 4)
                           + socket.inet_pton(socket.AF_INET, REAL4)
                           + struct.pack('!HH', 6, 16)
                           + socket.inet_pton(socket.AF_INET6, REAL6))
            header = struct.pack('!6H', struct.unpack_from('!H', packet)[0],
                                 0x8180, 1, int(payload is not None), 0, 0)
            answer = b'' if payload is None else (
                b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 30, len(payload)) + payload)
            self.socket.sendto(header + question + answer, peer)

    def count(self, name, kind):
        with self.lock:
            return self.counts.get((wire_name(name).lower(), kind), 0)

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=2)
        self.socket.close()


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def dns_query(port, name, kind):
    ident = 0x5a31
    request = struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0) + wire_name(name) + struct.pack('!HH', kind, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(request, ('127.0.0.1', port))
        packet, _ = sock.recvfrom(65535)
    got, records = unpack_response(packet)
    assert got == ident, 'response transaction ID differs'
    return records


def api(port, method, path, data=None):
    body = None if data is None else json.dumps(data).encode()
    request = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=body, method=method,
                                     headers={'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'})
    # Ignore any ambient HTTP_PROXY; all fixtures are on loopback.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def configuration(root, upstream, dns_port, api_port, mode, filters):
    return f'''mixed-port: 0
port: 0
socks-port: 0
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warn
ipv6: true
external-controller: 127.0.0.1:{api_port}
secret: {TOKEN}
rule-providers:
  realset:
    type: file
    behavior: domain
    format: yaml
    path: {json.dumps(str(root / 'provider.yaml'))}
    interval: 3600
rules: ['MATCH,DIRECT']
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: true
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-range6: fdfe:dcba:9876::/64
  nameserver: ['127.0.0.1:{upstream.port}']
  fake-ip-filter-mode: {mode}
  fake-ip-filter: {json.dumps(filters)}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('--flavor', choices=('stable', 'alpha'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    binary = args.binary.resolve()
    source_root = Path(__file__).resolve().parents[1]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not __debug__:
        raise RuntimeError('run this regression without Python optimization')
    args.output.write_text(json.dumps({'status': 'running', 'flavor': args.flavor}) + '\n')

    def command(*argv):
        return subprocess.check_output(argv, cwd=source_root, text=True).strip()

    source = {
        'commit': command('git', 'rev-parse', 'HEAD'),
        'tree': command('git', 'rev-parse', 'HEAD^{tree}'),
        'tracked_worktree_dirty': bool(command('git', 'status', '--porcelain', '--untracked-files=no')),
        'cargo_lock_sha256': hashlib.sha256((source_root / 'Cargo.lock').read_bytes()).hexdigest(),
        'test_driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'profile': 'release', 'features': 'full (default)',
        'rustc': command('rustc', '-Vv'),
        'cargo': command('cargo', '-V'),
        'build_command': os.environ.get('MEOW_TEST_BUILD_COMMAND',
            'cargo build --locked --release -p meow-app --bin meow'),
        'version_suffix': os.environ.get('MEOW_VERSION_SUFFIX', ''),
    }
    if source['tracked_worktree_dirty']:
        raise RuntimeError('refusing to bind a binary test to a dirty source tree')
    source['build_target'] = os.environ.get('CARGO_BUILD_TARGET') or next(
        line.split(': ', 1)[1] for line in source['rustc'].splitlines() if line.startswith('host: '))
    version = subprocess.check_output([str(binary), '-v'], text=True).strip()
    base = tomllib.loads((source_root / 'Cargo.toml').read_text())['workspace']['package']['version']
    suffix = '-alpha+' + source['commit'][:7] if args.flavor == 'alpha' else ''
    assert version == 'Meow Meta ' + base + suffix, (version, base, source['commit'])
    checks = []

    def passed(name):
        checks.append(name)
        print('PASS', name, flush=True)

    passed('binary-version-' + args.flavor)
    upstream = Upstream()
    try:
        with contextlib.nullcontext(tempfile.mkdtemp(prefix=args.flavor + '-cases-', dir=args.output.parent)) as temporary:
            root = Path(temporary)

            @contextlib.contextmanager
            def run_case(mode, filters, geosite=False, provider_payload=None, geosite_kind=2, classical_geosite=False):
                case = root / (str(len(checks)) + '-' + mode)
                case.mkdir()
                (case / 'provider.yaml').write_text("payload:\n  - '+.real.test'\n  - priority.test\n")
                if provider_payload is not None:
                    (case / 'provider.yaml').write_text(provider_payload)
                dns_port = free_port(socket.SOCK_DGRAM)
                api_port = free_port(socket.SOCK_STREAM)
                text = configuration(case, upstream, dns_port, api_port, mode, filters)
                if classical_geosite:
                    (case / 'provider.yaml').write_text("payload: ['GEOSITE,fixture']\n")
                    text = text.replace('behavior: domain', 'behavior: classical').replace(
                        "rules: ['MATCH,DIRECT']", "rules: ['GEOSITE,fixture,DIRECT', 'MATCH,DIRECT']")
                if geosite:
                    # Minimal V2Ray GeoSiteList with a suffix domain, loaded
                    # through the real config discovery path (not DB injection).
                    def field(number, value):
                        assert len(value) < 128
                        return bytes([(number << 3) | 2, len(value)]) + value
                    value = b'needle' if geosite_kind == 0 else b'geo.test'
                    domain = bytes([8, geosite_kind]) + field(2, value)
                    entry = field(1, b'fixture') + field(2, domain)
                    geofile = case / 'geosite.dat'
                    geofile.write_bytes(field(1, entry))
                    text += '\ngeodata:\n  geosite-path: ' + json.dumps(str(geofile)) + '\n'
                config = case / 'config.yaml'
                config.write_text(text)
                case_env = os.environ.copy()
                for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                            'http_proxy', 'https_proxy', 'all_proxy'):
                    case_env.pop(key, None)
                case_env.update(MEOW_RUNTIME_DIR=str(case / 'runtime'),
                                NO_PROXY='*', no_proxy='*')
                offline = subprocess.run([str(binary), '-d', str(case), '-f', str(config), '-t'], cwd=case, env=case_env,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
                (case / 'offline.log').write_text(offline.stdout)
                assert offline.returncode == 0, 'offline validation: ' + offline.stdout
                passed(mode + '-offline-validation')
                with (case / 'daemon.log').open('wb') as log:
                    proc = subprocess.Popen([str(binary), '-d', str(case), '-f', str(config)], cwd=case, env=case_env,
                                            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
                    try:
                        deadline = time.monotonic() + 20
                        while True:
                            assert proc.poll() is None, (case / 'daemon.log').read_text()
                            try:
                                status, _ = api(api_port, 'GET', '/version')
                                if status == 200:
                                    dns_query(dns_port, 'startup.test', 1)
                                    break
                            except (OSError, urllib.error.URLError):
                                pass
                            if time.monotonic() > deadline:
                                raise AssertionError('startup timeout: ' + (case / 'daemon.log').read_text())
                            time.sleep(0.05)
                        yield case, dns_port, api_port, text
                    except Exception:
                        print('DAEMON_LOG', (case / 'daemon.log').read_text(), flush=True)
                        raise
                    finally:
                        if proc.poll() is None:
                            proc.send_signal(signal.SIGTERM)
                            try:
                                proc.wait(timeout=8)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                proc.wait(timeout=3)

            def expect_ip(port, name, fake, label):
                observed = {}
                for kind, family in [(1, 4), (28, 6)]:
                    before_upstream = upstream.count(name, kind)
                    records = dns_query(port, name, kind)
                    data = [payload for record_type, payload in records if record_type == kind]
                    assert len(data) == 1, (name, kind, records)
                    if fake:
                        assert upstream.count(name, kind) == before_upstream, (name, kind, "FakeIP queried upstream")
                    else:
                        assert upstream.count(name, kind) > 0, (name, kind, "real answer missed fixture")
                    address = ipaddress.ip_address(data[0])
                    expected = FAKE4 if family == 4 else FAKE6
                    if fake:
                        assert address in expected, (name, kind, str(address), 'wanted FakeIP')
                    else:
                        assert str(address) == (REAL4 if family == 4 else REAL6), (name, kind, str(address))
                    observed[family] = str(address)
                    passed(f'{label}-ipv{family}')
                return observed

            def expect_hints(port, name, fake, label):
                for kind in (64, 65):
                    records = dns_query(port, name, kind)
                    data = [payload for record_type, payload in records if record_type == kind]
                    assert len(data) == 1, (name, kind, records)
                    payload = data[0]
                    offset = skip_name(payload, 2)
                    fields = {}
                    while offset < len(payload):
                        key, length = struct.unpack_from('!HH', payload, offset)
                        fields[key] = payload[offset + 4:offset + 4 + length]
                        offset += 4 + length
                    assert fields[1] == b'\x02h2' and fields[3] == struct.pack('!H', 443), (name, kind, fields)
                    if fake:
                        assert 4 not in fields and 6 not in fields, (name, kind, fields)
                    else:
                        assert fields[4] == socket.inet_pton(socket.AF_INET, REAL4), (name, kind, fields)
                        assert fields[6] == socket.inet_pton(socket.AF_INET6, REAL6), (name, kind, fields)
                    passed(f'{label}-rr{kind}')

            for mode in ('blacklist', 'whitelist', 'rule'):
                filters = (['GEOSITE,fixture,real-ip', 'MATCH,fake-ip'] if mode == 'rule'
                           else ['geosite:fixture'])
                with run_case(mode, filters, geosite=True, geosite_kind=0) as (_, port, _, _):
                    expect_ip(port, 'xneedle.test', mode == 'whitelist', mode + '-geosite-plain-lower')
                    expect_ip(port, 'XNEEDLE.TEST', mode == 'whitelist', mode + '-geosite-plain-upper')

            for mode in ('blacklist', 'whitelist', 'rule'):
                filters = (['RULE-SET,realset,real-ip', 'MATCH,fake-ip'] if mode == 'rule'
                           else ['rule-set:realset'])
                with run_case(mode, filters, geosite=True, geosite_kind=0, classical_geosite=True) as (_, port, _, _):
                    expect_ip(port, 'xneedle.test', mode == 'whitelist', mode + '-classical-geosite-lower')
                    expect_ip(port, 'XNEEDLE.TEST', mode == 'whitelist', mode + '-classical-geosite-upper')

            for mode in ('blacklist', 'whitelist'):
                with run_case(mode, ['geosite:fixture'], geosite=True) as (_, port, _, _):
                    expect_ip(port, 'www.geo.test', mode == 'whitelist', mode + '-geosite-file-hit')
                    expect_ip(port, 'outside-geo.test', mode == 'blacklist', mode + '-geosite-file-miss')
                with run_case(mode, ['rule-set:realset'], provider_payload='payload: []\n') as (_, port, _, _):
                    expect_ip(port, 'empty-provider.test', mode == 'blacklist', mode + '-configured-empty-provider')
            with run_case('rule', ['GEOSITE,fixture,real-ip'], geosite=True) as (_, port, _, _):
                expect_ip(port, 'www.geo.test', False, 'rule-geosite-file-hit')
                expect_ip(port, 'outside-geo.test', True, 'rule-geosite-file-miss')
            with run_case('blacklist', ['rule-set:realset']) as (_, port, _, _):
                expect_ip(port, 'www.real.test', False, 'blacklist-provider-hit')
                expect_ip(port, 'outside.test', True, 'blacklist-provider-miss')
                expect_hints(port, 'www.real.test', False, 'blacklist-real-hints')
                expect_hints(port, 'outside.test', True, 'blacklist-fake-hints')
            with run_case('whitelist', ['rule-set:realset']) as (_, port, _, _):
                expect_ip(port, 'www.real.test', True, 'whitelist-provider-hit')
                expect_ip(port, 'outside.test', False, 'whitelist-provider-miss')
            rules = ['DOMAIN,priority.test,fake-ip', 'RULE-SET,realset,real-ip',
                     'DOMAIN-SUFFIX,zone.test,real-ip', 'DOMAIN-KEYWORD,needle,real-ip',
                     r'DOMAIN-REGEX,^regex[0-9]+\.test$,real-ip',
                     'DOMAIN-WILDCARD,*.wild.test,real-ip', 'MATCH,fake-ip']
            with run_case('rule', rules) as (case, port, control, text):
                for host, fake, label in [
                    ('priority.test', True, 'rule-first-hit'), ('www.real.test', False, 'rule-provider-hit'),
                    ('sub.zone.test', False, 'rule-suffix'), ('xneedlex.test', False, 'rule-keyword'),
                    ('regex42.test', False, 'rule-regex'), ('one.wild.test', False, 'rule-wildcard'),
                    ('wild.test', True, 'rule-wildcard-apex'), ('outside.test', True, 'rule-match-default')]:
                    expect_ip(port, host, fake, label)
                expect_hints(port, 'www.real.test', False, 'rule-real-hints')
                expect_hints(port, 'outside.test', True, 'rule-fake-hints')
                expect_ip(port, 'added.test', True, 'provider-before-refresh')
                (case / 'provider.yaml').write_text('payload:\n  - added.test\n')
                status, body = api(control, 'PUT', '/providers/rules/realset')
                assert status == 204, (status, body)
                expect_ip(port, 'added.test', False, 'provider-live-addition')
                expect_ip(port, 'www.real.test', True, 'provider-live-removal')
                sticky = expect_ip(port, 'sticky.test', True, 'mapping-before-reload')
                before_file = (case / 'config.yaml').read_bytes()
                status, before_config = api(control, 'GET', '/configs')
                assert status == 200, (status, before_config)
                invalid = text.replace('RULE-SET,realset,real-ip', 'RULE-SET,missing-provider,real-ip')
                payload = base64.b64encode(invalid.encode()).decode()
                status, body = api(control, 'PUT', '/configs', {'payload': payload})
                assert status == 400, (status, body)
                assert b'unknown rule-set' in body and b'missing-provider' in body, body
                (case / 'rejected-reload.json').write_bytes(body)
                passed('invalid-reload-rejected-by-dns-validation')
                status, after_config = api(control, 'GET', '/configs')
                assert status == 200 and json.loads(after_config) == json.loads(before_config)
                assert (case / 'config.yaml').read_bytes() == before_file
                passed('failed-reload-keeps-config-and-disk')
                expect_ip(port, 'added.test', False, 'failed-reload-keeps-live-provider')
                (case / 'provider.yaml').write_text('payload:\n  - reloaded.test\n')
                payload = base64.b64encode(text.encode()).decode()
                status, body = api(control, 'PUT', '/configs', {'payload': payload})
                assert status == 204, (status, body)
                passed('same-raw-reload-accepted')
                expect_ip(port, 'reloaded.test', False, 'same-raw-reload-new-provider')
                expect_ip(port, 'added.test', True, 'same-raw-reload-old-provider-removed')
                (case / 'provider.yaml').write_text('payload:\n  - post-reload-refresh.test\n')
                status, body = api(control, 'PUT', '/providers/rules/realset')
                assert status == 204, (status, body)
                expect_ip(port, 'post-reload-refresh.test', False, 'post-reload-live-provider-refresh')
                expect_ip(port, 'reloaded.test', True, 'post-reload-live-provider-removal')
                assert expect_ip(port, 'sticky.test', True, 'mapping-after-reload') == sticky
                changed = text.replace('DOMAIN,priority.test,fake-ip', 'DOMAIN,priority.test,real-ip')
                payload = base64.b64encode(changed.encode()).decode()
                status, body = api(control, 'PUT', '/configs', {'payload': payload})
                assert status == 204, (status, body)
                expect_ip(port, 'priority.test', False, 'successful-reload-new-rule-verdict')
            with run_case('rule', ['MATCH,real-ip']) as (_, port, _, _):
                expect_ip(port, 'catchall.test', False, 'rule-explicit-real-catchall')
                expect_hints(port, 'catchall.test', False, 'rule-explicit-real-catchall-hints')
            with run_case('rule', ['DOMAIN,only.test,real-ip']) as (_, port, _, _):
                expect_ip(port, 'unmatched.test', True, 'rule-no-match-default')
    finally:
        upstream.close()
    result = {'flavor': args.flavor, 'version': version, 'binary': str(binary),
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'source': source, 'fixture_directory': str(root),
              'status': 'passed', 'count': len(checks), 'checks': checks}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'flavor': args.flavor, 'status': 'passed', 'count': len(checks), 'version': version}), flush=True)


if __name__ == '__main__':
    main()
