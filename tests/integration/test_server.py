#!/usr/bin/env python3
"""End-to-end checks of the octet executable over real sockets.

    test_server.py --server PATH --mkcert PATH --workdir DIR

Starts the server in several configurations and talks to it the way real clients do:
Python's ssl module for TLS, plain sockets for HTTP and for the malformed and hostile
openers. Each check prints PASS or FAIL; the exit status is the number of failures.
"""

import argparse
import os
import socket
import ssl
import subprocess
import sys
import time

HOST = "127.0.0.1"
GET = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

failures = 0
passes = 0


def check(name, condition, detail=""):
    global failures, passes
    if condition:
        passes += 1
        print(f"  [PASS] {name}")
    else:
        failures += 1
        print(f"  [FAIL] {name}  {detail}")


class Server:
    def __init__(self, exe, *args):
        self.proc = subprocess.Popen([exe, "--port", "0", *args], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline()
        if "listening on" not in line:
            err = self.proc.stderr.read()
            raise RuntimeError(f"server did not start: {line!r} {err!r}")
        self.port = int(line.split("listening on ")[1].split(" ")[0].rsplit(":", 1)[1])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.proc.kill()
        self.proc.wait()


def recv_all(sock, timeout=3.0):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except (ConnectionResetError, ConnectionAbortedError):
        pass
    return data


def raw(port, payload, timeout=3.0):
    """Sends bytes in the clear and returns everything the server sends back."""
    with socket.create_connection((HOST, port), timeout=timeout) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if payload:
            s.sendall(payload)
        return recv_all(s, timeout)


def tls_context(ca, alpn=("http/1.1",), max_version=None):
    ctx = ssl.create_default_context(cafile=ca)
    if alpn:
        ctx.set_alpn_protocols(list(alpn))
    if max_version is not None:
        ctx.maximum_version = max_version
    return ctx


def tls_get(port, ca, **kw):
    """A verified TLS request. Returns (body, version, alpn) or raises ssl.SSLError."""
    ctx = tls_context(ca, **kw)
    with socket.create_connection((HOST, port), timeout=3) as s:
        with ctx.wrap_socket(s, server_hostname="localhost") as t:
            t.sendall(GET)
            data = b""
            while True:
                try:
                    chunk = t.recv(4096)
                except (ssl.SSLEOFError, ConnectionResetError):
                    break
                if not chunk:
                    break
                data += chunk
            return data, t.version(), t.selected_alpn_protocol()


def tls_fails(port, ca, **kw):
    try:
        tls_get(port, ca, **kw)
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return str(e)
    return None


# TLSPlaintext: ContentType alert (21), legacy version 3.3, length 2, then the Alert:
# level fatal (2), description no_application_protocol (120). RFC 8446 sections 5.1 and
# 6, RFC 7301 section 3.2. Sent before ServerHello, so it is not encrypted.
NO_APPLICATION_PROTOCOL_ALERT = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x78])


def first_server_flight(port, ca, alpn):
    """Sends one ClientHello over a raw socket and returns the server answer as bytes."""
    ctx = tls_context(ca, alpn=alpn)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname="localhost")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall(outgoing.read())
        return recv_all(s, timeout=3)


def dribbled_tls_get(port, ca):
    """Sends the ClientHello one octet per TCP segment, then completes the handshake."""
    ctx = tls_context(ca)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname="localhost")
    with socket.create_connection((HOST, port), timeout=5) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        first_flight = True
        while True:
            try:
                obj.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            out = outgoing.read()
            if out:
                if first_flight:
                    for b in out:
                        s.send(bytes([b]))
                        time.sleep(0.001)
                    first_flight = False
                else:
                    s.sendall(out)
            if done:
                break
            data = s.recv(65536)
            if not data:
                raise ConnectionError("server closed during the handshake")
            incoming.write(data)
        obj.write(GET)
        s.sendall(outgoing.read())
        body = b""
        while True:
            data = s.recv(65536)
            if not data:
                break
            incoming.write(data)
            try:
                body += obj.read(65536)
            except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                pass
        return body


def one_port_both_transports(exe, pki, record):
    print("one listening socket, detection on, certificate configured")
    with Server(exe, "--cert", pki["chain"], "--key", pki["key"], "--handshake-timeout-ms", "700",
                "--record", record, "--label", "integration") as srv:
        body, version, alpn = tls_get(srv.port, pki["ca"])
        check("TLS is served", body.endswith(b"octet: tls\n"), repr(body[-40:]))
        check("TLS 1.3 is negotiated", version == "TLSv1.3", version)
        check("ALPN selects http/1.1", alpn == "http/1.1", alpn)

        reply = raw(srv.port, GET)
        check("cleartext is served on the same port", reply.endswith(b"octet: cleartext\n"), repr(reply[-40:]))

        check("binary junk gets no reply", raw(srv.port, b"\x00\x01\x02\x03") == b"")
        check("a lower-case method gets no reply", raw(srv.port, b"get / HTTP/1.1\r\n\r\n") == b"")
        check("a TLS alert record as opener gets no reply", raw(srv.port, b"\x15\x03\x03\x00\x02\x02\x28") == b"")

        reply = raw(srv.port, b"ZZZ / HTTP/1.1\r\nHost: x\r\n\r\n")
        check("an unknown upper-case method reaches the parser and gets 501",
              reply.startswith(b"HTTP/1.1 501"), repr(reply[:40]))

        reply = raw(srv.port, b"\x16\xff\xff\x00\x00garbage")
        check("0x16 followed by garbage is not answered in cleartext", not reply.startswith(b"HTTP/"),
              repr(reply[:40]))

        reply = raw(srv.port, b"GET index HTTP/1.1\r\n\r\n")
        check("a malformed request line gets 400", reply.startswith(b"HTTP/1.1 400"), repr(reply[:40]))

        big = b"GET / HTTP/1.1\r\nX: " + b"a" * 9000 + b"\r\n\r\n"
        reply = raw(srv.port, big)
        check("an oversized request head gets 431", reply.startswith(b"HTTP/1.1 431"), repr(reply[:40]))

        check("a client offering only h2 is refused", tls_fails(srv.port, pki["ca"], alpn=("h2",)) is not None)
        reply = first_server_flight(srv.port, pki["ca"], alpn=("h2",))
        check("the refusal is the alert itself: fatal no_application_protocol (120), in the clear",
              NO_APPLICATION_PROTOCOL_ALERT in reply, reply.hex())

        body, _, alpn = tls_get(srv.port, pki["ca"], alpn=())
        check("a client offering no ALPN is served", body.endswith(b"octet: tls\n") and alpn is None)

        # A peer that connects and says nothing must not hold the server: it is closed at
        # the deadline, and other clients are served while it waits.
        silent = socket.create_connection((HOST, srv.port))
        start = time.monotonic()
        body, _, _ = tls_get(srv.port, pki["ca"])
        served_in = time.monotonic() - start
        check("other clients are served while a silent peer waits",
              body.endswith(b"octet: tls\n") and served_in < 0.5, f"{served_in:.3f}s")
        closed = recv_all(silent, timeout=3)
        waited = time.monotonic() - start
        silent.close()
        check("a silent peer is closed at the handshake deadline", closed == b"" and 0.5 < waited < 2.5,
              f"{waited:.3f}s")

        # A peer that opens like TLS and then stalls is held to the same deadline.
        stalled = socket.create_connection((HOST, srv.port))
        stalled.sendall(b"\x16\x03\x01")
        start = time.monotonic()
        recv_all(stalled, timeout=3)
        waited = time.monotonic() - start
        stalled.close()
        check("a TLS opener that stalls is closed at the same deadline", 0.4 < waited < 2.5, f"{waited:.3f}s")

    time.sleep(0.2)
    outcomes = [line.split(",")[2] for line in open(record, encoding="utf-8") if line.strip()]
    for wanted in ("served", "unknown_protocol", "tls_failed", "timeout", "bad_request", "too_large",
                   "not_implemented"):
        check(f"the record holds an outcome of {wanted}", wanted in outcomes)


def dribbled_client_hello(exe, pki, record):
    # A ClientHello is about 500 octets; at one per segment with a millisecond between
    # them that takes longer than the short deadline above, which would (correctly) close
    # it. This server has the default five second budget.
    print("ClientHello one octet per TCP segment")
    with Server(exe, "--cert", pki["chain"], "--key", pki["key"], "--record", record, "--label", "dribble") as srv:
        body = dribbled_tls_get(srv.port, pki["ca"])
        check("a ClientHello sent one octet per segment still completes", body.endswith(b"octet: tls\n"),
              repr(body[-40:]))
    time.sleep(0.2)
    rows = [line.strip().split(",") for line in open(record, encoding="utf-8") if line.startswith("dribble,")]
    # How many octets the first read caught depends on scheduling: a few may have arrived
    # before the connection thread read. What matters is that classification saw a small
    # part of the ClientHello and the rest kept trickling in for a long time after it.
    ok = len(rows) == 1 and rows[0][2] == "served"
    check("the server classified it from a partial ClientHello, then waited for the rest",
          ok and int(rows[0][6]) < 100 and int(rows[0][4]) > 300_000, rows)


def no_certificate(exe, pki):
    print("detection on, no certificate configured")
    with Server(exe) as srv:
        check("a TLS client is closed, not answered in cleartext", tls_fails(srv.port, pki["ca"]) is not None)
        check("cleartext is still served", raw(srv.port, GET).endswith(b"octet: cleartext\n"))


def version_floor(exe, pki):
    print("minimum TLS version 1.3")
    with Server(exe, "--cert", pki["chain"], "--key", pki["key"], "--min-tls", "1.3") as srv:
        check("a TLS 1.2 client is refused",
              tls_fails(srv.port, pki["ca"], max_version=ssl.TLSVersion.TLSv1_2) is not None)
        _, version, _ = tls_get(srv.port, pki["ca"])
        check("a TLS 1.3 client is served", version == "TLSv1.3", version)


def dedicated_listeners(exe, pki):
    print("dedicated listeners, detection off")
    with Server(exe, "--cert", pki["chain"], "--key", pki["key"], "--no-detect", "--dedicated", "tls") as srv:
        body, _, _ = tls_get(srv.port, pki["ca"])
        check("the dedicated TLS listener serves TLS", body.endswith(b"octet: tls\n"))
        reply = raw(srv.port, GET)
        check("the dedicated TLS listener does not answer cleartext HTTP", not reply.startswith(b"HTTP/"),
              repr(reply[:40]))
    with Server(exe, "--no-detect", "--dedicated", "cleartext") as srv:
        check("the dedicated cleartext listener serves HTTP", raw(srv.port, GET).endswith(b"octet: cleartext\n"))
        check("the dedicated cleartext listener does not complete a handshake",
              tls_fails(srv.port, pki["ca"]) is not None)


def connection_limit(exe):
    print("connection limit 2")
    with Server(exe, "--max-connections", "2", "--handshake-timeout-ms", "3000") as srv:
        held = [socket.create_connection((HOST, srv.port)) for _ in range(2)]
        time.sleep(0.2)
        start = time.monotonic()
        reply = raw(srv.port, GET, timeout=2)
        waited = time.monotonic() - start
        check("a third connection is closed at once", reply == b"" and waited < 1.0, f"{waited:.3f}s")
        for s in held:
            s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--mkcert", required=True)
    ap.add_argument("--workdir", required=True)
    args = ap.parse_args()

    os.makedirs(args.workdir, exist_ok=True)
    pki_dir = os.path.join(args.workdir, "pki")
    subprocess.run([args.mkcert, pki_dir], check=True, stdout=subprocess.DEVNULL)
    pki = {"ca": os.path.join(pki_dir, "ca.pem"), "chain": os.path.join(pki_dir, "server.pem"),
           "key": os.path.join(pki_dir, "server.key")}
    record = os.path.join(args.workdir, "integration.csv")
    if os.path.exists(record):
        os.remove(record)

    one_port_both_transports(args.server, pki, record)
    dribbled_client_hello(args.server, pki, record)
    no_certificate(args.server, pki)
    version_floor(args.server, pki)
    dedicated_listeners(args.server, pki)
    connection_limit(args.server)

    print(f"{passes}/{passes + failures} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
