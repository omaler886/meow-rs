#!/usr/bin/env python3
"""Dependency-free services and byte-exact, unproxied clients for the TUN lab."""

import argparse
import base64
import errno
import hashlib
import http.client
import http.server
import ipaddress
import json
import secrets
import socket
import socketserver
import struct
import threading
import time

RECEIPT_LOCK = threading.Lock()


def record_request(peer, payload):
    """Print a peer/payload receipt; peer is an address tuple and payload is bytes."""
    receipt = {"peer": peer[0], "digest": hashlib.sha256(payload).hexdigest()}
    with RECEIPT_LOCK:
        print(json.dumps(receipt), flush=True)


def record_dns_request(peer, query, transport):
    """Record DNS peer, question name, and transport; args are peer tuple, query bytes, transport; returns None."""
    offset = 12
    labels = []
    while offset < len(query) and query[offset]:
        size = query[offset]
        if size > 63 or offset + size >= len(query):
            raise ValueError("invalid DNS question name")
        labels.append(query[offset + 1:offset + 1 + size].decode("ascii"))
        offset += size + 1
    if offset + 5 > len(query):
        raise ValueError("truncated DNS question")
    receipt = {"peer": peer[0], "name": ".".join(labels), "transport": transport}
    with RECEIPT_LOCK:
        print(json.dumps(receipt), flush=True)


def record_http_request(peer, path):
    """Record an HTTP request path and peer; args are peer tuple and path; returns None."""
    receipt = {"peer": peer[0], "path": path}
    with RECEIPT_LOCK:
        print(json.dumps(receipt), flush=True)


def set_deadline(connection, deadline):
    """Apply the remaining absolute deadline to one socket operation."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("probe deadline expired")
    connection.settimeout(remaining)


def read_exact(connection, size, deadline=None):
    """Read size bytes, rejecting early EOF and optionally enforcing one absolute deadline."""
    chunks = bytearray()
    while len(chunks) < size:
        if deadline is not None:
            set_deadline(connection, deadline)
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        chunks.extend(chunk)
    return bytes(chunks)


def read_receipts(path):
    """Read complete JSON receipt lines; leave an in-progress final line for the next poll."""
    with open(path, encoding="utf-8") as receipts:
        return [json.loads(line) for line in receipts
                if line.startswith("{") and line.endswith("\n")]


def answer_dns(query):
    """Answer one uncompressed IN A/AAAA question with the lab target address."""
    if len(query) < 17 or query[4:6] != b"\x00\x01":
        raise ValueError("expected one DNS question")
    offset = 12
    labels = []
    while query[offset]:
        length = query[offset]
        if length > 63 or offset + length + 1 >= len(query):
            raise ValueError("invalid DNS question label")
        labels.append(query[offset + 1:offset + length + 1].decode("ascii").lower())
        offset += length + 1
    end = offset + 5
    query_type, query_class = struct.unpack("!HH", query[offset + 1:end])
    addresses = {1: (socket.AF_INET, "203.0.113.9"),
                 28: (socket.AF_INET6, "fd00:99::9")}
    if ".".join(labels) == "fake.tun.test":
        # Keep the FakeIP forwarding fixture A-only, so its actual outbound
        # receipt must be from the expected physical IPv4, independent of dial ordering.
        addresses.pop(28)
    answer = b""
    if query_class == 1 and query_type in addresses:
        family, address = addresses[query_type]
        packed = socket.inet_pton(family, address)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", query_type, 1, 1, len(packed)) + packed
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0)
    return header + query[12:end] + answer


class EchoTcp(socketserver.BaseRequestHandler):
    """Echo streams exactly and record the received payload when the client closes."""

    def handle(self):
        """Read this handler's accepted stream and return identical bytes to its client."""
        self.request.settimeout(4)
        payload = bytearray()
        while chunk := self.request.recv(65536):
            payload.extend(chunk)
            self.request.sendall(chunk)
        record_request(self.client_address, bytes(payload))


class EchoUdp(socketserver.BaseRequestHandler):
    """Echo individual datagrams without interpreting their contents."""

    def handle(self):
        """Record this request's datagram and return it unchanged to the sender."""
        payload, connection = self.request
        record_request(self.client_address, payload)
        connection.sendto(payload, self.client_address)


class DnsTcp(socketserver.BaseRequestHandler):
    """Serve length-prefixed DNS over TCP."""

    def handle(self):
        """Answer one framed query on this handler's connection, returning no value."""
        self.request.settimeout(4)
        size = struct.unpack("!H", read_exact(self.request, 2))[0]
        query = read_exact(self.request, size)
        record_dns_request(self.client_address, query, "tcp")
        answer = answer_dns(query)
        self.request.sendall(struct.pack("!H", len(answer)) + answer)


class DnsUdp(socketserver.BaseRequestHandler):
    """Serve synthetic DNS datagrams."""

    def handle(self):
        """Answer this request's DNS datagram, returning no value."""
        query, connection = self.request
        record_dns_request(self.client_address, query, "udp")
        connection.sendto(answer_dns(query), self.client_address)


class HttpHandler(http.server.BaseHTTPRequestHandler):
    """Serve a fixed body so HTTP checks cannot mistake an error page for success."""

    def do_GET(self):
        """Reply to this request with an exact body and content length."""
        if self.path == "/provider":
            record_http_request(self.client_address, self.path)
            payload = b"proxies:\n  - name: mock-direct\n    type: direct\n"
        else:
            payload = b"meow-netns-http\x00\xff\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, message, *arguments):
        """Send HTTP diagnostics to stdout; message and arguments follow stdlib conventions."""
        with RECEIPT_LOCK:
            print(message % arguments, flush=True)


def serve():
    """Start dual-stack echo, HTTP and DNS services and block until process termination."""
    services = [(socketserver.ThreadingTCPServer, EchoTcp, 18080),
                (socketserver.ThreadingUDPServer, EchoUdp, 18080),
                (socketserver.ThreadingTCPServer, DnsTcp, 53),
                (socketserver.ThreadingUDPServer, DnsUdp, 53),
                (http.server.ThreadingHTTPServer, HttpHandler, 18081)]
    for family, address in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
        for base, handler, port in services:
            server_type = type("LabServer", (base,),
                               {"address_family": family, "allow_reuse_address": True,
                                "daemon_threads": True})
            server = server_type((address, port), handler, bind_and_activate=False)
            if family == socket.AF_INET6:
                server.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            server.server_bind()
            server.server_activate()
            threading.Thread(target=server.serve_forever, daemon=True).start()
    print("READY", flush=True)
    threading.Event().wait()


def probe(arguments):
    """Send one nonce-bearing unbound payload, require TCP EOF, and verify its fresh uplink receipt."""
    family = socket.AF_INET6 if ":" in arguments.address else socket.AF_INET
    kind = socket.SOCK_STREAM if arguments.protocol == "tcp" else socket.SOCK_DGRAM
    nonce = secrets.token_hex(12)
    payload = f"{arguments.tag}:{nonce}:".encode() + bytes(range(256)) * 4
    digest = hashlib.sha256(payload).hexdigest()
    overall_deadline = getattr(arguments, "deadline", float("inf"))
    deadline = min(time.monotonic() + arguments.timeout, overall_deadline)
    print(f"PROBE {arguments.tag} {arguments.protocol} {arguments.address} digest={digest}", flush=True)
    try:
        with socket.socket(family, kind) as connection:
            set_deadline(connection, deadline)
            connection.connect((arguments.address, 18080))
            set_deadline(connection, deadline)
            connection.sendall(payload)
            if kind == socket.SOCK_STREAM:
                connection.shutdown(socket.SHUT_WR)
            if arguments.expect_network_failure:
                set_deadline(connection, deadline)
                if connection.recv(1):
                    raise AssertionError("external traffic returned data without a physical default")
                raise ConnectionError("peer closed without returning data")
            if kind == socket.SOCK_STREAM:
                reply = read_exact(connection, len(payload), deadline)
                set_deadline(connection, deadline)
                if connection.recv(1):
                    raise AssertionError("TCP echo contains extra trailing bytes")
            else:
                set_deadline(connection, deadline)
                reply = connection.recv(65536)
            if reply != payload:
                raise AssertionError("echo payload differs byte-for-byte")
    except (OSError, ConnectionError) as error:
        network_failure = isinstance(error, (TimeoutError, ConnectionError)) or error.errno in {
            errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.ETIMEDOUT,
            errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE,
        }
        if not arguments.expect_network_failure or not network_failure:
            raise
        print(f"PASS expected network failure {arguments.protocol} {arguments.address}: {error}", flush=True)
        return
    if arguments.receipts:
        deadline = min(time.monotonic() + getattr(arguments, "receipt_timeout", 1), overall_deadline)
        while True:
            records = read_receipts(arguments.receipts)
            if any(record.get("digest") == digest and
                   record.get("peer") == arguments.source for record in records):
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"missing fresh receipt from expected uplink {arguments.source}")
            time.sleep(min(0.02, max(0, deadline - time.monotonic())))
    print(f"PASS {arguments.tag} {arguments.protocol} {arguments.address} digest={digest}", flush=True)


def retirement_count(path):
    """Count actual watcher observation lines in this daemon generation's log."""
    with open(path, encoding="utf-8") as daemon_log:
        return sum("physical default interface changed" in line for line in daemon_log)


def transition_matrix(arguments, tag, deadline, retry):
    """Run all four independent TCP/UDP and IPv4/IPv6 probes within one phase deadline."""
    errors = []
    for protocol in ("tcp", "udp"):
        for address, source in (("203.0.113.9", arguments.source_v4),
                                ("fd00:99::9", arguments.source_v6)):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{arguments.phase}: five-second convergence deadline expired")
            probe_arguments = argparse.Namespace(
                address=address, protocol=protocol, tag=f"{tag}-{protocol}-{address}",
                timeout=min(0.4 if retry else 1, remaining),
                receipt_timeout=min(0.2 if retry else 1, remaining), deadline=deadline,
                receipts=arguments.receipts, source=source, expect_network_failure=False)
            try:
                probe(probe_arguments)
            except (OSError, AssertionError) as error:
                errors.append(f"{protocol} {address}: {type(error).__name__}: {error}")
    return errors


def converge(arguments):
    """Wait for a new watcher count, retry a four-protocol matrix, then assert a separate matrix."""
    started = time.monotonic()
    deadline = started + arguments.timeout
    attempt = 0
    while time.monotonic() < deadline:
        observed = retirement_count(arguments.daemon_log)
        if observed <= arguments.before:
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            continue
        attempt += 1
        tag = f"{arguments.phase}-attempt-{attempt}-{secrets.token_hex(4)}"
        print(f"ATTEMPT {tag} watcher_before={arguments.before} watcher_now={observed}", flush=True)
        errors = transition_matrix(arguments, tag, deadline, retry=True)
        if errors:
            print(f"RETRY {tag}: {'; '.join(errors)}", flush=True)
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            continue
        final_tag = f"{arguments.phase}-assert-{secrets.token_hex(4)}"
        print(f"ASSERT {final_tag}: independent post-convergence matrix", flush=True)
        errors = transition_matrix(arguments, final_tag, deadline, retry=False)
        if errors:
            raise AssertionError(f"{arguments.phase}: independent final matrix failed: {'; '.join(errors)}")
        observed = retirement_count(arguments.daemon_log)
        if observed <= arguments.before:
            raise AssertionError(f"{arguments.phase}: no new watcher observation")
        if arguments.exactly_one and observed != arguments.before + 1:
            raise AssertionError(f"{arguments.phase}: expected one new observation; got {observed - arguments.before}")
        elapsed = time.monotonic() - started
        if time.monotonic() > deadline:
            raise TimeoutError(f"{arguments.phase}: final assertions exceeded phase deadline")
        print(f"PASS convergence {arguments.phase} elapsed={elapsed:.3f}s attempts={attempt} "
              f"watcher_before={arguments.before} watcher_after={observed}", flush=True)
        return
    raise TimeoutError(f"{arguments.phase}: no converged matrix and fresh watcher count within {arguments.timeout}s")


def probe_fakeip(arguments):
    """Allocate once, then reuse the same fake IPv4 across reloads/handovers for real TCP/UDP."""
    if arguments.allocate:
        addresses = probe_dns(argparse.Namespace(
            address="192.0.2.53", protocol="udp", name="fake.tun.test", port=53,
            timeout=2, expect="198.18.0.0/16", receipts=None))
        if len(addresses) != 1 or str(addresses[0]) in ("198.18.0.0", "198.18.0.1"):
            raise AssertionError(f"expected one usable fake IPv4 allocation, got {addresses}")
        allocation = {"name": "fake.tun.test", "address": str(addresses[0])}
        with open(arguments.state, "x", encoding="utf-8") as state:
            json.dump(allocation, state)
            state.write("\n")
    else:
        with open(arguments.state, encoding="utf-8") as state:
            allocation = json.load(state)
    address = ipaddress.ip_address(allocation["address"])
    if allocation["name"] != "fake.tun.test" or address not in ipaddress.ip_network("198.18.0.0/16"):
        raise AssertionError("saved FakeIP allocation does not belong to this lab")
    for protocol in ("tcp", "udp"):
        probe(argparse.Namespace(
            address=str(address), protocol=protocol, tag=f"fakeip-{arguments.phase}-{protocol}",
            timeout=2, receipts=arguments.receipts, source=arguments.source,
            expect_network_failure=False))
    print(f"PASS FakeIP {arguments.phase} reused={address} real_target=203.0.113.9 "
          f"source={arguments.source}", flush=True)


def probe_http(arguments):
    """Fetch a numeric HTTP target without proxies and assert status and exact body."""
    connection = http.client.HTTPConnection(arguments.address, arguments.port,
                                            timeout=arguments.timeout)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        payload = response.read(4096)
        if response.status != 200 or payload != b"meow-netns-http\x00\xff\n":
            raise AssertionError(f"unexpected HTTP status/body: {response.status} {payload!r}")
    finally:
        connection.close()
    print(f"PASS HTTP {arguments.address}")


def put_config(arguments):
    """PUT a local config and verify its mock-provider fetch source; args are endpoint, file, receipt and source."""
    with open(arguments.config, "rb") as config_file:
        payload = config_file.read()
    body = json.dumps({"payload": base64.b64encode(payload).decode("ascii")}).encode("utf-8")
    connection = http.client.HTTPConnection(arguments.address, arguments.port,
                                            timeout=arguments.timeout)
    try:
        connection.request("PUT", "/configs", body=body,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = response.read(4096)
        if not 200 <= response.status < 300:
            raise AssertionError(f"PUT /configs failed: {response.status} {body!r}")
    finally:
        connection.close()
    deadline = time.monotonic() + arguments.timeout
    while True:
        records = read_receipts(arguments.receipts)
        if any(record.get("path") == "/provider" and
               record.get("peer") == arguments.source for record in records):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"missing mock provider fetch receipt from physical source {arguments.source}")
        time.sleep(0.02)
    print(f"PASS PUT /configs provider fetch from {arguments.source}")


def patch_config(arguments):
    """Commit an owned live PATCH and require the running TUN to remain enabled."""
    payload = json.loads(arguments.payload)
    connection = http.client.HTTPConnection(arguments.address, arguments.port, timeout=5)
    try:
        connection.request("PATCH", "/configs", body=json.dumps(payload).encode(),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = response.read(4096)
        if response.status != 204:
            raise AssertionError(f"PATCH /configs failed: {response.status} {body!r}")
        connection.request("GET", "/configs")
        response = connection.getresponse()
        document = json.loads(response.read())
        if response.status != 200 or not document.get("tun", {}).get("enable"):
            raise AssertionError("PATCH did not leave a running, enabled TUN")
    finally:
        connection.close()
    print(f"PASS live PATCH {arguments.tag}: TUN remains enabled", flush=True)


def skip_dns_name(message, offset):
    """Skip a bounded DNS label sequence or compression pointer and return its next offset."""
    while offset < len(message):
        length = message[offset]
        offset += 1
        if length == 0:
            return offset
        if length & 0xC0 == 0xC0 and offset < len(message):
            return offset + 1
        if length > 63 or offset + length >= len(message):
            raise ValueError("invalid or truncated DNS name")
        offset += length
    raise ValueError("unterminated DNS name")


def parse_dns_addresses(message, query_id):
    """Validate a DNS response for query_id and return its IN A/AAAA answer addresses."""
    response_id, flags, questions, answers, _, _ = struct.unpack("!6H", message[:12])
    if response_id != query_id or flags & 0xFA0F != 0x8000 or questions != 1:
        raise AssertionError("DNS ID, response flags, question count or result code mismatch")
    offset = skip_dns_name(message, 12) + 4
    addresses = []
    for _ in range(answers):
        offset = skip_dns_name(message, offset)
        record_type, record_class, _, size = struct.unpack("!HHIH", message[offset:offset + 10])
        offset += 10
        end = offset + size
        if end > len(message):
            raise ValueError("truncated DNS answer")
        if record_class == 1 and (record_type, size) in ((1, 4), (28, 16)):
            addresses.append(ipaddress.ip_address(message[offset:end]))
        offset = end
    return addresses


def probe_dns(arguments):
    """Query numeric DNS, verify optional upstream receipt, and return validated answer addresses."""
    query_id = secrets.randbits(16)
    question = b"".join(bytes([len(label)]) + label.encode("ascii")
                        for label in arguments.name.split("."))
    query = struct.pack("!6H", query_id, 0x0100, 1, 0, 0, 0)
    query += question + b"\x00" + struct.pack("!HH", 1, 1)
    family = socket.AF_INET6 if ":" in arguments.address else socket.AF_INET
    kind = socket.SOCK_STREAM if arguments.protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, kind) as connection:
        connection.settimeout(arguments.timeout)
        connection.connect((arguments.address, arguments.port))
        if kind == socket.SOCK_STREAM:
            connection.sendall(struct.pack("!H", len(query)) + query)
            size = struct.unpack("!H", read_exact(connection, 2))[0]
            response = read_exact(connection, size)
        else:
            connection.sendall(query)
            response = connection.recv(65535)
    addresses = parse_dns_addresses(response, query_id)
    expected = ipaddress.ip_network(arguments.expect)
    if not addresses or any(address not in expected for address in addresses):
        raise AssertionError(f"expected DNS answers in {expected}; got {addresses}")
    if arguments.receipts:
        deadline = time.monotonic() + 2
        while True:
            records = read_receipts(arguments.receipts)
            if any(record.get("name") == arguments.name and
                   record.get("peer") == arguments.source and
                   record.get("transport") == arguments.upstream_transport for record in records):
                break
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"missing fresh DNS upstream receipt from {arguments.source} for {arguments.name}")
            time.sleep(0.02)
    print(f"PASS DNS {arguments.address} {arguments.protocol} {arguments.name}: {addresses}", flush=True)
    return addresses


def main():
    """Parse service/client arguments, execute the requested operation and propagate failures."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    client = commands.add_parser("probe")
    client.add_argument("address")
    client.add_argument("protocol", choices=["tcp", "udp"])
    client.add_argument("tag")
    client.add_argument("--timeout", type=float, default=1)
    client.add_argument("--receipts")
    client.add_argument("--source")
    client.add_argument("--expect-network-failure", action="store_true")
    transition = commands.add_parser("converge")
    transition.add_argument("phase")
    transition.add_argument("--daemon-log", required=True)
    transition.add_argument("--receipts", required=True)
    transition.add_argument("--before", type=int, required=True)
    transition.add_argument("--source-v4", required=True)
    transition.add_argument("--source-v6", required=True)
    transition.add_argument("--timeout", type=float, default=4.8)
    transition.add_argument("--exactly-one", action="store_true")
    fakeip = commands.add_parser("fakeip")
    fakeip.add_argument("phase")
    fakeip.add_argument("--state", required=True)
    fakeip.add_argument("--receipts", required=True)
    fakeip.add_argument("--source", required=True)
    fakeip.add_argument("--allocate", action="store_true")
    http = commands.add_parser("http")
    http.add_argument("address")
    http.add_argument("--port", type=int, default=18081)
    http.add_argument("--timeout", type=float, default=2)
    api = commands.add_parser("api-put")
    api.add_argument("address")
    api.add_argument("port", type=int)
    api.add_argument("config")
    api.add_argument("--timeout", type=float, default=5)
    api.add_argument("--receipts", required=True)
    api.add_argument("--source", required=True)
    patch = commands.add_parser("api-patch")
    patch.add_argument("address")
    patch.add_argument("port", type=int)
    patch.add_argument("tag")
    patch.add_argument("payload")
    dns = commands.add_parser("dns")
    dns.add_argument("address")
    dns.add_argument("protocol", choices=["tcp", "udp"])
    dns.add_argument("name")
    dns.add_argument("--expect", required=True)
    dns.add_argument("--port", type=int, default=53)
    dns.add_argument("--timeout", type=float, default=2)
    dns.add_argument("--receipts")
    dns.add_argument("--source")
    dns.add_argument("--upstream-transport", choices=["tcp", "udp"], default="udp")
    arguments = parser.parse_args()
    operations = {"serve": lambda _: serve(), "probe": probe, "converge": converge,
                  "fakeip": probe_fakeip, "http": probe_http, "api-put": put_config,
                  "api-patch": patch_config, "dns": probe_dns}
    operations[arguments.command](arguments)


if __name__ == "__main__":
    main()
