#!/usr/bin/env python3
"""Interop against a server built on this library, from an independent QUIC implementation.

aioquic is the other end. The script completes a handshake, sends a stream and checks the echo;
it repeats the exchange through a proxy that drops datagrams, so the server's loss recovery and
pacing are exercised by a peer that is not this library's own client. A server that answers the
first Initial with a Retry is covered by the same run: aioquic follows it, and the echo only
comes back if the token, the new connection id and the Initial keys derived from it are right.

    scripts/quic/check_interop.py --host 127.0.0.1 --port 12000
    scripts/quic/check_interop.py --host 127.0.0.1 --port 12000 --loss 0.2

Needs `aioquic` (pip install aioquic). The server is the caller's: this repository has no
socket, and the harness that binds one is the server repository's.
"""

import argparse
import asyncio
import random
import socket
import sys

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived


class Echo(QuicConnectionProtocol):
    """Sends one stream and waits for the same bytes back."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = bytearray()
        self.done: asyncio.Future = asyncio.get_event_loop().create_future()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            self.received += event.data
            if event.end_stream and not self.done.done():
                self.done.set_result(bytes(self.received))


class Side(asyncio.DatagramProtocol):
    """One side of the relay: hands what it receives to the other side's socket.

    A datagram leaves from the socket the other end will answer, so the two directions are two
    sockets that write into each other rather than one socket doing both.
    """

    def __init__(self, loss, rng, learn=None, source=None):
        self.loss = loss
        self.rng = rng
        # The transport to send through and the address to send to; both set by the proxy.
        self.out = None
        self.peer = None
        self.transport = None
        # The client-facing side records where the client is; the other side answers there.
        self.learn = learn
        self.source = source

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.learn is not None:
            self.learn["client"] = addr
        if self.peer is None and self.source is not None:
            self.peer = self.source["client"]
        if self.loss > 0.0 and self.rng.random() < self.loss:
            return
        self.out.sendto(data, self.peer)


class Proxy:
    """A UDP relay between a client and the server, with a drop rate on both directions."""

    def __init__(self, target, loss, seed):
        self.target = target
        self.loss = loss
        self.rng = random.Random(seed)
        self.port = None

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        state = {}
        client = Side(self.loss, self.rng, learn=state)
        server = Side(self.loss, self.rng, source=state)
        client_transport, _ = await loop.create_datagram_endpoint(
            lambda: client, local_addr=("127.0.0.1", 0)
        )
        server_transport, _ = await loop.create_datagram_endpoint(
            lambda: server, local_addr=("127.0.0.1", 0)
        )
        self._client_transport = client_transport
        self._server_transport = server_transport
        self.port = client_transport.get_extra_info("sockname")[1]
        # What the client sends leaves from the server-facing socket, so the server answers
        # there; what the server sends leaves from the client-facing one.
        client.out = server_transport
        client.peer = self.target
        server.out = client_transport
        server.peer = None
        self._client = client
        self._server = server
        return self

    async def __aexit__(self, *exc):
        self._client_transport.close()
        self._server_transport.close()
        return False


async def exchange(host, port, message, timeout, label):
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=False)
    config.server_name = host
    try:
        async with connect(
            host, port, configuration=config, create_protocol=Echo, wait_connected=True
        ) as client:
            stream_id = client._quic.get_next_available_stream_id()
            client._quic.send_stream_data(stream_id, message.encode(), end_stream=True)
            client.transmit()
            data = await asyncio.wait_for(client.done, timeout)
    except asyncio.TimeoutError:
        print(f"{label}: timeout, no echo")
        return False
    except Exception as error:  # a handshake that fails is a result, not a crash
        print(f"{label}: {type(error).__name__}: {error}")
        return False
    if data.decode() != message:
        print(f"{label}: echo mismatch, {data!r}")
        return False
    print(f"{label}: handshake and {len(data)} bytes back")
    return True


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12000)
    parser.add_argument("--message", default="moonquic interop")
    parser.add_argument("--loss", type=float, default=0.2, help="drop rate for the lossy run")
    parser.add_argument("--loss-seed", type=int, default=7)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--skip-plain", action="store_true")
    args = parser.parse_args()

    ok = True
    if not args.skip_plain:
        ok &= await exchange(args.host, args.port, args.message, args.timeout, "plain")
    async with Proxy((args.host, args.port), args.loss, args.loss_seed) as proxy:
        ok &= await exchange(
            "127.0.0.1",
            proxy.port,
            args.message,
            args.timeout,
            f"loss {int(args.loss * 100)}%",
        )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
