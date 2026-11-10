#!/usr/bin/env python3
"""Early data, read by aioquic before its handshake completes.

Two connections are made by the MoonBit client in one run. The first is a plain handshake and an
exchange; aioquic issues a session ticket on the way out. The second resumes with that ticket and
writes its request before the handshake finishes: with neither `Config` credit field set, what it
may spend comes from the transport parameters the ticket remembered (RFC 9000 §7.4.1).

What is being checked is not that the bytes eventually arrive, but *when* they arrive: the
server records whether each stream read happened before that connection's handshake completed.

    scripts/quic/check_aioquic_early_data.py [--client PATH] [--payload TEXT]

Needs `aioquic` (pip install aioquic) and `cryptography`. The client is this repository's
`integration/src/client`, built for native.
"""

import argparse
import asyncio
import os
import pathlib
import subprocess
import sys
import tempfile

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived

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


class Echo(QuicConnectionProtocol):
    """Reads whatever arrives on any stream, notes when it arrived, and sends it back."""

    def __init__(self, quic, report):
        super().__init__(quic)
        self.report = report
        self.completed = False
        self.echoed = False

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.completed = True
            self.report["handshakes"] += 1
        elif isinstance(event, StreamDataReceived):
            self.report["reads"].append(
                {
                    "stream": event.stream_id,
                    "bytes": len(event.data),
                    "before_handshake": not self.completed,
                }
            )
            # The answer goes back once. A repeat of the same stream data is the peer's own
            # retransmission, and writing it again after FIN is not allowed.
            if not self.echoed and event.stream_id == 0:
                self.echoed = True
                self._quic.send_stream_data(
                    event.stream_id, event.data, end_stream=event.end_stream
                )
                self.transmit()


async def run(args, report):
    tickets = {}

    def keep(ticket):
        tickets[ticket.ticket] = ticket

    def find(identity):
        return tickets.get(identity)

    configuration = QuicConfiguration(
        is_client=False, alpn_protocols=["h3"], verify_mode=False
    )
    configuration.load_cert_chain(args.certs / "cert.pem", args.certs / "key.pem")
    server = await serve(
        "127.0.0.1",
        0,
        configuration=configuration,
        create_protocol=lambda quic, stream_handler=None: Echo(quic, report),
        session_ticket_handler=keep,
        session_ticket_fetcher=find,
    )
    port = server._transport.get_extra_info("sockname")[1]
    print(f"server 127.0.0.1:{port}")

    command = [
        str(args.client),
        "resume",
        "127.0.0.1",
        str(port),
        f"ca={args.certs / 'ca.pem'}",
        f"payload={args.payload}",
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        output, _ = await asyncio.wait_for(process.communicate(), args.timeout)
    except asyncio.TimeoutError:
        process.kill()
        output, _ = await process.communicate()
        report["error"] = "the client did not finish"
    report["client"] = output.decode("utf-8", "replace")
    report["status"] = process.returncode
    # Let the last datagrams land: a closing connection still has a close to send.
    await asyncio.sleep(0.2)
    server.close()


def facts(text):
    out = {}
    for line in text.splitlines():
        if " " in line:
            key, _, value = line.partition(" ")
            out[key] = value
        else:
            out[line] = ""
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", help="the built quic-client binary")
    parser.add_argument("--payload", default="moonquic early data")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    args.client = client_binary(args.client)

    with tempfile.TemporaryDirectory() as work:
        args.certs = interop_certs.write(pathlib.Path(work) / "certs")
        report = {"handshakes": 0, "reads": [], "client": "", "status": None}
        asyncio.run(run(args, report))

    print(report["client"], end="")
    reads = [read for read in report["reads"] if read["bytes"] > 0]
    early = [read for read in reads if read["before_handshake"]]
    payload = args.payload.encode()
    checks = {
        "two handshakes": report["handshakes"] == 2,
        "the client exited zero": report["status"] == 0,
        "both requests were read": [r["bytes"] for r in reads]
        == [len(payload)] * 2,
        "the resumed request was read before the handshake finished": len(early) == 1
        and early[0]["bytes"] == len(payload),
        "the client sent 0-RTT datagrams": int(facts(report["client"]).get(
            "early_datagrams", "0"
        ))
        > 0,
        "aioquic accepted the early data": facts(report["client"]).get(
            "early_accepted"
        )
        == "true",
    }
    print()
    for label, ok in checks.items():
        print(f"  {'pass' if ok else 'FAIL'}  {label}")
    failed = [label for label, ok in checks.items() if not ok]
    print("status " + ("pass" if not failed else "fail: " + "; ".join(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
