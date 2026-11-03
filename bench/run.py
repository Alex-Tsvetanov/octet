#!/usr/bin/env python3
"""Measures what first-octet detection costs octet, per connection, on this machine.

    run.py --server PATH --mkcert PATH --out DIR [--reps 5] [--conns 400] [--rate 100]

Four arms, each a separate server process on loopback:

    tls-detect        one socket, classification on, TLS client
    tls-dedicated     classification off, the listener expects TLS (no first read)
    clear-detect      one socket, classification on, cleartext client
    clear-dedicated   classification off, the listener expects cleartext

Every connection carries one request and closes, so a per-connection cost is paid once
per request rather than spread over a keep-alive session. The client is sequential and
paced: it opens a connection every 1/rate seconds, or straight after the previous one if
that took longer. The server times each connection itself, from accept, and writes one
CSV line per connection. The arm order is shuffled in every repetition with a recorded
seed, so a slow drift of the machine does not land on one arm.
"""

import argparse
import json
import os
import platform
import random
import socket
import ssl
import subprocess
import sys
import time

HOST = "127.0.0.1"
GET = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
WARMUP = 20
ARMS = {
    "tls-detect": ("tls", []),
    "tls-dedicated": ("tls", ["--no-detect", "--dedicated", "tls"]),
    "clear-detect": ("clear", []),
    "clear-dedicated": ("clear", ["--no-detect", "--dedicated", "cleartext"]),
}


def start(exe, pki, extra, record, label):
    args = [exe, "--port", "0", "--cert", pki["chain"], "--key", pki["key"], "--record", record,
            "--label", label, *extra]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    if "listening on" not in line:
        raise RuntimeError(f"server did not start: {line!r} {proc.stderr.read()!r}")
    port = int(line.split("listening on ")[1].split(" ")[0].rsplit(":", 1)[1])
    return proc, port


def one_request(port, ctx):
    t0 = time.perf_counter_ns()
    s = socket.create_connection((HOST, port), timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if ctx is not None:
        s = ctx.wrap_socket(s, server_hostname="localhost")
    s.sendall(GET)
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
        except (ssl.SSLEOFError, ConnectionResetError):
            break
        if not chunk:
            break
        data += chunk
    s.close()
    t1 = time.perf_counter_ns()
    if not data.startswith(b"HTTP/1.1 200"):
        raise RuntimeError(f"unexpected reply: {data[:60]!r}")
    return (t1 - t0) // 1000


def run_arm(exe, pki, arm, rep, out_dir, conns, rate):
    transport, extra = ARMS[arm]
    label = f"{arm},{rep}"
    record = os.path.join(out_dir, "server.csv")
    proc, port = start(exe, pki, extra, record, label)
    ctx = None
    if transport == "tls":
        ctx = ssl.create_default_context(cafile=pki["ca"])
        ctx.set_alpn_protocols(["http/1.1"])
    client_rows = []
    try:
        for _ in range(WARMUP):
            one_request(port, ctx)
        interval = 1.0 / rate
        next_at = time.perf_counter()
        for i in range(conns):
            now = time.perf_counter()
            if now < next_at:
                time.sleep(next_at - now)
            next_at = max(next_at + interval, time.perf_counter())
            client_rows.append((arm, rep, i, one_request(port, ctx)))
        time.sleep(0.2)  # the last record line is written after the response
    finally:
        proc.kill()
        proc.wait()
    with open(os.path.join(out_dir, "client.csv"), "a", encoding="utf-8") as f:
        for row in client_rows:
            f.write(",".join(str(x) for x in row) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--mkcert", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--conns", type=int, default=400)
    ap.add_argument("--rate", type=float, default=100.0)
    ap.add_argument("--seed", type=int, default=20261103)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    for name in ("server.csv", "client.csv"):
        path = os.path.join(args.out, name)
        if os.path.exists(path):
            sys.exit(f"{path} exists; use a new --out directory")

    pki_dir = os.path.join(args.out, "pki")
    subprocess.run([args.mkcert, pki_dir], check=True, stdout=subprocess.DEVNULL)
    pki = {"ca": os.path.join(pki_dir, "ca.pem"), "chain": os.path.join(pki_dir, "server.pem"),
           "key": os.path.join(pki_dir, "server.key")}

    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                            cwd=os.path.dirname(os.path.abspath(__file__))).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], capture_output=True,
                           text=True, cwd=os.path.dirname(os.path.abspath(__file__))).stdout.strip() != ""
    rng = random.Random(args.seed)
    orders = []
    started = time.time()
    for rep in range(1, args.reps + 1):
        order = list(ARMS)
        rng.shuffle(order)
        orders.append(order)
        for arm in order:
            run_arm(args.server, pki, arm, rep, args.out, args.conns, args.rate)
            print(f"rep {rep} {arm} done", flush=True)

    meta = {
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(started)),
        "duration_s": round(time.time() - started, 1),
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_openssl": ssl.OPENSSL_VERSION,
        "commit": commit,
        "dirty": dirty,
        "reps": args.reps,
        "conns_per_arm_per_rep": args.conns,
        "warmup_per_arm_per_rep": WARMUP,
        "offered_rate_per_s": args.rate,
        "seed": args.seed,
        "arm_orders": orders,
        "server_columns": "arm,rep,wire,outcome,decide_us,ready_us,served_us,first_read,tls_version,alpn,start_us",
        "client_columns": "arm,rep,index,client_total_us",
    }
    with open(os.path.join(args.out, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
