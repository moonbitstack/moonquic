#!/usr/bin/env python3
"""Multipath against picoquic: two paths, both carrying application data, acknowledged with a
PATH_ACK on each side.

picoquic is the peer, run as a server serving one file over HTTP/0.9. The MoonBit client opens the
handshake's path, learns the connection id picoquic offers for a second path, challenges that path
on its own socket, and — once the path answers — asks for the same file again *on that path*. The
answer has to come back on it, and picoquic's own log has to show a PATH_ACK for path 1 in both
directions.

    scripts/quic/check_picoquic_multipath.py --picoquic /path/to/picoquicdemo [--client PATH]

Build picoquic with `-DCMAKE_BUILD_TYPE=RelWithDebInfo`: as built at -O3 (its default Release),
the demo server segfaults in `picoquic_create_packet_header` while preparing a packet for the
second path, often enough that the run cannot be relied on. Nothing in this repository reaches
that code, and the same source at -O2 with debug information runs the exchange repeatedly.

Needs `cryptography` for the certificate both ends use, which is what lets the client verify the
peer instead of trusting anything.
"""

import argparse
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import interop_certs  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def client_binary(named):
    if named:
        return pathlib.Path(named)
    for suffix in ("", ".exe"):
        found = (
            ROOT
            / "_build/native/debug/build/moonbitstack/moonquic-integration/client"
            / f"client{suffix}"
        )
        if found.exists():
            return found
    raise SystemExit("no client binary; run `moon build --target native` in integration/")


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def facts(text):
    out = {}
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        out[key] = value
    return out


def qlog_events(directory):
    """Every event of every qlog in `directory`, tolerating a file cut short by a kill."""
    decoder = json.JSONDecoder()
    out = []
    for path in sorted(pathlib.Path(directory).glob("*.qlog")):
        text = path.read_text(encoding="utf-8", errors="replace")
        at = text.find('"events"')
        if at < 0:
            continue
        start = text.find("[", at)
        while start != -1:
            try:
                value, end = decoder.raw_decode(text, start)
            except json.JSONDecodeError:
                start = text.find("[", start + 1)
                continue
            if isinstance(value, list) and len(value) >= 4:
                out.append(value)
            start = text.find("[", end)
        # A file whose outer array parsed whole arrives as one event list of events.
        flat = []
        for event in out:
            if event and isinstance(event[0], list):
                flat.extend(event)
            else:
                flat.append(event)
        out = flat
    return out


def sent_path_acks(events):
    """The path ids a PATH_ACK in picoquic's own log names, by direction."""
    sent, received = set(), set()
    for event in events:
        if len(event) < 5 or event[3] not in ("packet_sent", "packet_received"):
            continue
        for frame in event[4].get("frames", []):
            if frame.get("frame_type") == "path_ack":
                (sent if event[3] == "packet_sent" else received).add(frame["path_id"])
    return sent, received


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", help="the built quic-client binary")
    parser.add_argument("--picoquic", required=True, help="the built picoquicdemo binary")
    parser.add_argument("--timeout", type=float, default=40.0)
    args = parser.parse_args()
    args.client = client_binary(args.client)

    work = pathlib.Path(tempfile.mkdtemp(prefix="moonquic-multipath-"))
    www = work / "www"
    qlog = work / "qlog"
    www.mkdir()
    qlog.mkdir()
    body = "hello from picoquic\n"
    (www / "index.html").write_text(body)
    certs = interop_certs.write(work / "certs")
    port = free_port()

    server = subprocess.Popen(
        [
            str(args.picoquic),
            "-p", str(port),
            "-c", str(certs / "cert.pem"),
            "-k", str(certs / "key.pem"),
            "-a", "hq-interop",
            "-w", str(www),
            "-q", str(qlog),
            "-M",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    # Wait for the port to answer: picoquic binds before it prints anything useful.
    time.sleep(0.7)
    output = ""
    try:
        run = subprocess.run(
            [
                str(args.client),
                "multipath",
                "127.0.0.1",
                str(port),
                f"ca={certs / 'ca.pem'}",
                r"payload=GET /index.html\r\n",
                "alpn=hq-interop",
            ],
            capture_output=True,
            text=True,
            timeout=args.timeout,
        )
        output = run.stdout + run.stderr
        status = run.returncode
    except subprocess.TimeoutExpired as expired:
        output = (expired.stdout or b"").decode("utf-8", "replace")
        status = -1
    time.sleep(0.5)
    alive = server.poll() is None
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()

    print(output, end="")
    seen = facts(output)
    events = qlog_events(qlog)
    sent, received = sent_path_acks(events)
    answer = body.encode().decode()
    payload = "GET /index.html\r\n".encode()

    def number(name):
        try:
            return int(seen.get(name, "0"))
        except ValueError:
            return 0

    def answered(name):
        # The file comes back whole; picoquic sends it as its own bytes.
        return body.strip() in seen.get(name, "")

    checks = {
        "the peer kept the run alive": alive,
        "the handshake settled on hq-interop": seen.get("alpn") == "hq-interop",
        "the peer offered a second path": number("peer_max_path") >= 1,
        "the peer named a connection id for it": len(seen.get("path1_cid", "")) > 0,
        "the second path answered its challenge": seen.get("path1_validated") == "true",
        "the request on the handshake's path was answered": number("path0_stream_bytes")
        == len(answer.encode())
        and answered("path0_answer"),
        "the request on the second path was answered": number("path1_stream_bytes")
        == len(answer.encode())
        and answered("path1_answer"),
        "the second path carried bytes both ways": number("path1_sent") > 0
        and number("path1_received") > 0,
        "the peer's PATH_ACK settled the second path": number("path1_in_flight") == 0,
        "the peer sent a PATH_ACK naming path 1": 1 in sent,
        "the peer read a PATH_ACK naming path 1": 1 in received,
    }
    print()
    for label, ok in checks.items():
        print(f"  {'pass' if ok else 'FAIL'}  {label}")
    failed = [label for label, ok in checks.items() if not ok]
    print("status " + ("pass" if not failed else "fail: " + "; ".join(failed)))
    print(f"picoquic logs and certificates: {work}")
    if failed:
        print("payload was", payload)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
