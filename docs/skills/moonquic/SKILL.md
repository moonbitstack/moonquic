---
name: moonquic
description: "QUIC transport for MoonBit: frame and packet codecs, packet protection, the client and server handshakes, loss recovery and congestion control, streams and flow control, 0-RTT resumption and multipath. Use it when writing a QUIC endpoint, proxy, or test harness that owns its own socket, or when reading and building QUIC packets and frames."
---

# moonquic

`moon add moonbitstack/moonquic`, then import the packages you need: `@conn` for the connection,
`@frame` and `@packet` for the wire, `@crypto` for the keys, `@recovery` and `@stream` for what a
connection is made of.

The library holds no socket and no clock. Every entry point takes `now` in microseconds, the peer
address is a type parameter, and a socket loop is yours to write: `poll_out` gives datagrams to send,
`recv` takes what arrived.

## Encode and decode frames

`@frame.encode` and `@frame.decode` cover the whole RFC 9000 §19 set plus RFC 9221's datagram and the
multipath frames, and a decode answers how many bytes the frame took, so a packet's payload is a loop.

```moonbit
let frames : Array[@frame.Frame] = [
  @frame.Crypto(offset=0UL, data=b"hello"),
  @frame.MaxData(1_000_000UL),
  @frame.PathStatus(path_id=1UL, seq=1UL, available=true),
]
let mut wire = b""
for frame in frames {
  wire = wire + @frame.encode(frame)
}
let mut at = 0
let back : Array[@frame.Frame] = []
while at < wire.length() {
  let (frame, used) = @frame.decode(wire[at:]) catch {
    _ => abort("a frame did not decode")
  }
  back.push(frame)
  at = at + used
}
assert_eq(back, frames)
```

## Protect a packet, and read it back

`@crypto.initial` gives the Initial keys that a connection id alone fixes. A packet is sealed with
the header as associated data, so the pieces have to be built in that order: header with the packet
number in it, then `seal`, which protects the header too.

```moonbit
let dcid : Bytes = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
let scid : Bytes = b"\xaa\xbb\xcc\xdd"
let (rx, tx) = @crypto.initial(dcid[:])
let wire = @conn.seal_long(
  @packet.Kind::Initial, 1U, dcid, scid, 0L, 4,
  @packet.payload([@frame.Ping]), tx,
)
let opened = @conn.recv_long(wire, rx, largest=-1L) catch {
  _ => abort("the packet did not open")
}
guard opened is Some((read, number)) else { abort("the packet did not open") }
assert_eq(number, 0L)
assert_eq(read, [@frame.Ping])
```

On a connection with more than one path, seal under the path's nonce: the path id is part of it, so
two paths may use the same packet number without ever reusing a nonce.

```moonbit
let path_packet = @conn.send_short(dcid, 0L, 4, [@frame.Ping], tx, path=1UL)
assert_true(
  @conn.recv_short(path_packet, scid.length(), rx, largest=-1L, path=0UL) is None,
)
```

## Drive a connection

A server owns its connections: `Endpoint::recv` takes a datagram and the address it came from,
`poll_out` gives the next datagram with the address to send it to, and `tick` runs the timers,
including the probe timeouts that recover a lost handshake flight.

```moonbit
let cfg = @conn.Config::default()
assert_eq(cfg.max_datagram, 1200L)
// The parameter block a client declares: RFC 9000 §18.2 defaults, plus its own ids.
let declared = @conn.Limits::new(data=1_000_000UL, streams_bidi=16UL).params()
assert_true(@conn.find(declared[:], @conn.MaxData) is Some(_))
```

Rules that catch people out:

- **`now` is microseconds, `wall` is seconds.** Timers, RTT and PTO all read `now`; a session ticket
  is judged at `wall` in seconds since the epoch, and an endpoint given no `wall` neither issues nor
  takes one.
- **0-RTT needs the ticket's parameters, not just the ticket.** Keep `Client::remembered` and pass it
  back as `resumption`; `Config`'s `zero_rtt_data` and `zero_rtt_stream_data` overrule what was
  remembered, and zero — the default — means "use what it remembered". RFC 9000 §7.4.1 makes the
  remembered value a ceiling, so a larger override earns a flow-control error.
- **A server must allow early data**: `@tls.Tickets::new(keys, early=n)`. Without it the client's
  0-RTT write is refused and re-sent as 1-RTT, which costs a round trip.
- **A client says which path a datagram arrived on.** `recv_on(path, datagram, now)` and
  `poll_paths`, whose entries carry the path id, because the sockets are the caller's. A server's
  paths are addresses, so `Endpoint::add_path` and `poll_out` handle it.
- **A path is identified by its connection id**, not by its address: `Endpoint::add_path` makes the id
  for you, and a packet that names a path's id belongs to that path's packet numbers.
- **The peer's id for a path arrives before the path exists.** A `PATH_NEW_CONNECTION_ID` for an id
  the peer said it would accept creates the path, so `paths().peer_cid(n)` is what `add_path` is
  given. A stream whose frames you place on a path yourself needs `open_stream` first: RFC 9000
  §19.8 lets the peer answer only on a bidirectional stream this end opened.
- **Nothing is retransmitted by the caller.** `poll_out`, `poll_lane` and `poll_paths` hand back what
  a lost packet carried once the timers say so; keep calling `tick`.

## Speak version 2, and negotiate a version

`Config.versions` is what an endpoint speaks, first-listed first: a client sends its first flight in
the first, a server answers in the client's version when it has it and offers a Version Negotiation
packet when it does not. Version 2 changes the Initial salt, the four HKDF labels, the Retry key and
the long-header type codes, so a packet is sealed and read with the version it carries.

```moonbit
let v2 = @crypto.Version::of(@packet.version2).unwrap()
assert_eq(v2.key, b"quicv2 key")
// A server that speaks version 2 only: a version 1 client is offered the one it has.
let cfg = { ..@conn.Config::default(), versions: [@packet.version2], }
assert_eq(cfg.versions, [@packet.version2])
assert_eq(@packet.Kind::Initial.code(@packet.version1), 0)
assert_eq(@packet.Kind::Initial.code(@packet.version2), 1)
```

- **Both ends send `version_information`**, and a client checks the peer's against the version the
  handshake settled on. A mismatch closes the connection with `VERSION_NEGOTIATION_ERROR` (0x11).
- **A client that acted on a Version Negotiation packet restarts**, and `Client::versions` says what
  the packet offered. The restart keeps the connection id and the packet numbers, and drops early
  data: RFC 9368 §7.3 leaves a compatible negotiation free to reject 0-RTT, which is what this library does.
- **A server may convert a first flight.** With `versions: [version2, version1]`, a server reads
  the client's `version_information` before it starts the TLS connection, picks version 2, re-derives
  both directions' Initial keys, and answers in version 2 — no Version Negotiation packet. Its own
  `version_information` names the version it chose. A client that offers only its Chosen Version
  disables this, and a parameter that does not parse closes the connection (RFC 9368 §2.3, §4).
- **A server's connection keeps its version for life.** A packet naming another version is not that
  connection's traffic, so a migration does not change it. The one exception is an Initial packet
  still carrying the first flight's version, readable until the handshake is confirmed.
