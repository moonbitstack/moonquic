#!/usr/bin/env python3
"""Version 2 and version negotiation, against an implementation that is not this one.

Runs in both directions: this library's client with a peer server it did not write, and the
peer's client with this library's server, each in version 1 and version 2. Then one more run in
which the client offers both versions to a peer that speaks only version 2, so the connection
restarts after a Version Negotiation packet (RFC 9000 §6.2) and completes in version 2.

The version a connection settled on is read from both ends — the peer prints the version it
answered in, and this library's server prints the one it accepted — so a run cannot pass by
agreeing with itself.

    scripts/quic/check_versions.py --peer PATH --client PATH --server PATH

The peer is `integration/quic-go-peer`, built with a Go toolchain; the two MoonBit binaries are
the `integration` module's client and server, built for native.
"""

import argparse
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def certificates(where):
    shutil.os.makedirs(where, exist_ok=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1", "-days", "2", "-nodes",
         "-keyout", f"{where}/key.pem", "-out", f"{where}/cert.pem",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    return where


class Report:
    def __init__(self):
        self.checks = []

    def check(self, label, ok):
        self.checks.append((label, ok))


def our_client(work, version, offered, report):
    """This library's client against the peer's server."""
    where = work / f"peer-{version}-{offered or 'one'}"
    certificates(where)
    port = free_port()
    log_path = where / "peer.log"
    log = log_path.open("w")
    server = subprocess.Popen(
        [str(work / "peer"), "-mode", "server", "-addr", f"127.0.0.1:{port}",
         "-certs", str(where), "-version", version],
        stdout=log, stderr=subprocess.STDOUT)
    time.sleep(0.6)
    command = [str(work / "client"), "echo", "127.0.0.1", str(port),
               f"ca={where}/ca.pem", "name=localhost", "payload=moonquic-interop"]
    if offered:
        command.append(f"versions={offered}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=40)
    finally:
        server.terminate()
        server.wait(timeout=10)
        log.close()
    output = result.stdout + result.stderr
    peer_log = log_path.read_text()
    label = f"version {version}" if not offered else f"offered {offered}, peer {version}"
    print(f"  our client -> peer server, {label}")
    for line in output.strip().splitlines():
        print(f"    {line}")
    for line in peer_log.strip().splitlines():
        print(f"    peer: {line}")
    report.check(f"{label}: the handshake finished", "alpn h3" in output)
    report.check(f"{label}: the peer echoed the stream", "returned true" in output)
    report.check(f"{label}: the peer answered in version {version}",
                 f"connection version v{version}" in peer_log)
    # Offered no groups at all, the client sends its defaults, and the peer names the one it ran.
    report.check(f"{label}: the default key share is the hybrid one",
                 "group \"X25519MLKEM768\"" in peer_log)


def peer_client(work, version, report):
    """The peer's client against this library's server."""
    where = work / f"ours-{version}"
    certificates(where)
    port = free_port()
    log_path = where / "ours.log"
    log = log_path.open("w")
    server = subprocess.Popen(
        [str(work / "server"), "echo", str(port),
         f"cert={where}/cert.pem", f"key={where}/key.pem", f"version={version}"],
        stdout=log, stderr=subprocess.STDOUT)
    time.sleep(0.6)
    try:
        result = subprocess.run(
            [str(work / "peer"), "-mode", "client",
             "-addr", f"127.0.0.1:{port}", "-ca", f"{where}/cert.pem",
             "-version", version, "-payload", "moonquic-interop"],
            capture_output=True, text=True, timeout=40)
    finally:
        server.terminate()
        server.wait(timeout=10)
        log.close()
    output = result.stdout + result.stderr
    print(f"  peer client -> our server, version {version}")
    for line in output.strip().splitlines():
        print(f"    {line}")
    report.check(f"v{version}: the peer's handshake finished",
                 f"connected v{version}" in output)
    report.check(f"v{version}: this server echoed it back",
                 "echo moonquic-interop" in output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer", required=True, help="the built quic-go peer")
    parser.add_argument("--client", required=True, help="this library's client")
    parser.add_argument("--server", required=True, help="this library's server")
    args = parser.parse_args()

    work = pathlib.Path(tempfile.mkdtemp(prefix="moonquic-versions-"))
    for name in ("peer", "client", "server"):
        source = pathlib.Path(getattr(args, name))
        target = work / name
        shutil.copyfile(source, target)
        target.chmod(0o755)

    report = Report()
    for version in ("1", "2"):
        our_client(work, version, None, report)
        peer_client(work, version, report)
    # The client offers both and prefers version 1; the peer speaks only version 2, so the
    # exchange starts with a Version Negotiation packet and restarts in version 2.
    our_client(work, "2", "1,2", report)

    print()
    for label, ok in report.checks:
        print(f"  {'pass' if ok else 'FAIL'}  {label}")
    failed = [label for label, ok in report.checks if not ok]
    print("status " + ("pass" if not failed else "fail: " + "; ".join(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
