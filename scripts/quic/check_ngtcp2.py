#!/usr/bin/env python3
"""ngtcp2's client against this library's server, in both versions.

The client is ngtcp2's own example (`osslclient`), built from a pinned tag: it opens a stream,
sends an HTTP/0.9 request and reads the answer, so a run that completes says the handshake, the
stream and the flow control all worked against an implementation that is not this one. What this
library's server logs is the other half: the peer read bytes it sent.

    scripts/quic/check_ngtcp2.py --client PATH --server PATH

The server is the `integration` module's, built for native.
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", required=True, help="ngtcp2's example client")
    parser.add_argument("--server", required=True, help="this library's server")
    args = parser.parse_args()

    work = pathlib.Path(tempfile.mkdtemp(prefix="moonquic-ngtcp2-"))
    server = work / "server"
    shutil.copyfile(args.server, server)
    server.chmod(0o755)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1", "-days", "2", "-nodes",
         "-keyout", f"{work}/key.pem", "-out", f"{work}/cert.pem",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)

    checks = []
    for version in ("1", "2"):
        port = free_port()
        log_path = work / f"server-{version}.log"
        log = log_path.open("w")
        process = subprocess.Popen(
            [str(server), "echo", str(port), f"cert={work}/cert.pem",
             f"key={work}/key.pem", f"version={version}"],
            stdout=log, stderr=subprocess.STDOUT)
        time.sleep(0.6)
        try:
            result = subprocess.run(
                [args.client, "--version", f"v{version}", "--groups", "X25519",
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
        checks.append((f"v{version}: ngtcp2 finished the exchange", result.returncode == 0))
        # The example logs the packet it opens with, which names the version it speaks.
        wire = "0x6b3343cf" if version == "2" else "0x00000001"
        checks.append((f"v{version}: it spoke version {version}", f"version={wire}" in output))

    print()
    for label, ok in checks:
        print(f"  {'pass' if ok else 'FAIL'}  {label}")
    failed = [label for label, ok in checks if not ok]
    print("status " + ("pass" if not failed else "fail: " + "; ".join(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
