#!/usr/bin/env python3
"""ngtcp2 in both directions, in both versions.

The client is ngtcp2's own example (`osslclient`), built from a pinned tag: it opens a stream,
sends an HTTP/0.9 request and reads the answer, so a run that completes says the handshake, the
stream and the flow control all worked against an implementation that is not this one. That is
the direction in which this library is the server.

The other direction needs a peer ngtcp2 does not ship. Its examples are HTTP/3 servers, and the
one that reads a raw stream (`h09server`) is not a CMake target and hard-codes the h3 ALPN.
`integration/ngtcp2-peer` is a small server built on `ngtcp2_conn_server_new` that echoes a raw
bidirectional stream under whatever ALPN the client offers. This script runs this library's
client against it in both versions, and once more with the peer preferring version 2 so that
ngtcp2 converts a version 1 first flight (RFC 9368 §2.3) and this library's client adopts it.

    scripts/quic/check_ngtcp2.py --client PATH --server PATH \
        [--raw-server PATH --our-client PATH]

`--server` is the `integration` module's server, built for native.
"""

import argparse
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from interop_certs import write as write_certs

WIRE = {"1": "0x00000001", "2": "0x6b3343cf"}
PAYLOAD = "moonquic-interop"


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def certificates(where):
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1", "-days", "2", "-nodes",
         "-keyout", f"{where}/key.pem", "-out", f"{where}/cert.pem",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)


def wait_for_port(log_path, process, seconds=10.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        if log_path.exists() and "port " in log_path.read_text(errors="replace"):
            return True
        time.sleep(0.05)
    return False


class Report:
    def __init__(self):
        self.checks = []

    def check(self, label, ok):
        self.checks.append((label, ok))


def example_client_against_us(work, client, server, version, report):
    """ngtcp2's example client -> this library's server."""
    where = work / f"example-{version}"
    where.mkdir(parents=True, exist_ok=True)
    certificates(where)
    port = free_port()
    log_path = where / "server.log"
    log = log_path.open("w")
    process = subprocess.Popen(
        [str(server), "echo", str(port), f"cert={where}/cert.pem",
         f"key={where}/key.pem", f"version={version}"],
        stdout=log, stderr=subprocess.STDOUT)
    time.sleep(0.6)
    try:
        result = subprocess.run(
            [str(client), "--version", f"v{version}", "--groups", "X25519",
             "127.0.0.1", str(port), f"https://127.0.0.1:{port}/"],
            capture_output=True, text=True, timeout=60)
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()
    output = result.stdout + result.stderr
    print(f"  ngtcp2 client -> our server, version {version}: exit {result.returncode}")
    for line in output.strip().splitlines()[-4:]:
        print(f"    {line}")
    report.check(f"v{version}: ngtcp2 finished the exchange", result.returncode == 0)
    # The example logs the packet it opens with, which names the version it speaks.
    report.check(f"v{version}: it spoke version {version}",
                 f"version={WIRE[version]}" in output)


def our_client_against_raw(work, raw, ours, version, report, prefer=None):
    """This library's client -> the raw-stream ngtcp2 server."""
    where = work / f"raw-{version}-{prefer or 'plain'}"
    where.mkdir(parents=True, exist_ok=True)
    certs = write_certs(where / "certs")
    port = free_port()
    log_path = where / "peer.log"
    log = log_path.open("w")
    command = [str(raw), str(port), f"{certs}/key.pem", f"{certs}/cert.pem", version]
    if prefer:
        command.append(prefer)
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    ready = wait_for_port(log_path, process)
    client_command = [
        str(ours), "echo", "127.0.0.1", str(port),
        f"ca={certs}/ca.pem", "name=localhost", f"payload={PAYLOAD}",
        # ngtcp2's OpenSSL backend negotiates X25519; the default hybrid share is exercised
        # against quic-go by check_versions.py instead.
        "groups=x25519",
    ]
    # With a preferred version the client offers both and starts in version 1; otherwise it
    # starts in the version the peer was asked to speak.
    client_command.append("versions=1,2" if prefer else f"versions={version}")
    try:
        result = subprocess.run(client_command, capture_output=True, text=True,
                                timeout=60) if ready else None
    finally:
        if process.poll() is None:
            # Give the peer a moment to see the last ACK before it is stopped.
            time.sleep(0.4)
            process.terminate()
        process.wait(timeout=10)
        log.close()
    output = result.stdout + result.stderr if result else ""
    peer_log = log_path.read_text(errors="replace")
    label = f"v{version}" if not prefer else f"v{version} first flight, peer prefers v{prefer}"
    print(f"  our client -> ngtcp2 raw-stream server, {label}")
    for line in output.strip().splitlines():
        print(f"    {line}")
    for line in peer_log.strip().splitlines():
        print(f"    peer: {line}")
    report.check(f"{label}: the handshake finished", "alpn h3" in output)
    report.check(f"{label}: the peer echoed the stream", "returned true" in output)
    report.check(f"{label}: the peer spoke version {version}",
                 f"version={WIRE[version]}" in peer_log)
    report.check(f"{label}: the peer completed the handshake",
                 "handshake completed" in peer_log)
    echoed = re.search(r"echoed (\d+) bytes", peer_log)
    report.check(f"{label}: the peer echoed back every byte it received",
                 bool(echoed and int(echoed.group(1)) >= len(PAYLOAD)))
    if prefer:
        # RFC 9368 §2.3: ngtcp2 converts the version 1 first flight into its preferred
        # version 2. Our client only completes if it adopted that version from the long
        # headers, so a green handshake is the assertion on the negotiated version too.
        report.check(f"{label}: the peer converted the first flight to version {prefer}",
                     f"negotiated version={WIRE[prefer]}" in peer_log)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", required=True, help="ngtcp2's example client")
    parser.add_argument("--server", required=True, help="this library's server")
    parser.add_argument("--raw-server", help="the raw-stream ngtcp2 peer")
    parser.add_argument("--our-client", help="this library's client")
    args = parser.parse_args()

    work = pathlib.Path(tempfile.mkdtemp(prefix="moonquic-ngtcp2-"))
    server = work / "our-server"
    shutil.copyfile(args.server, server)
    server.chmod(0o755)
    raw = ours = None
    if args.raw_server and args.our_client:
        raw = work / "raw-peer"
        ours = work / "our-client"
        shutil.copyfile(args.raw_server, raw)
        shutil.copyfile(args.our_client, ours)
        raw.chmod(0o755)
        ours.chmod(0o755)

    report = Report()
    for version in ("1", "2"):
        example_client_against_us(work, pathlib.Path(args.client), server, version, report)
        if raw:
            our_client_against_raw(work, raw, ours, version, report)
    if raw:
        our_client_against_raw(work, raw, ours, "1", report, prefer="2")

    print()
    for label, ok in report.checks:
        print(f"  {'pass' if ok else 'FAIL'}  {label}")
    failed = [label for label, ok in report.checks if not ok]
    print("status " + ("pass" if not failed else "fail: " + "; ".join(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
