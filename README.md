# moonquic

<p>
  <a href="https://moonbitstack.github.io/moonquic/"><b>Home</b></a> ·
  <a href="https://moonbitstack.github.io/moonquic/guide.html">Guide</a> ·
  <a href="https://moonbitstack.github.io/moonquic/api.html">API</a> ·
  <a href="https://moonbitstack.github.io/moonquic/capture.html">A packet, opened</a> ·
  <a href="https://mooncakes.io/docs/moonbitstack/moonquic">mooncakes</a>
</p>

The QUIC transport for MoonBit ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001), [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002)) — bytes in, events out. No sockets, no handshake of its own: the TLS 1.3 handshake is [`moontls`](https://github.com/moonbitstack/moontls)'s and the ciphers are [`mooncrypt`](https://github.com/moonbitstack/mooncrypt)'s.

```moonbit
// A protected Initial packet, from the connection ID up (RFC 9001 §5.2–§5.4).
let dcid : Bytes = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
let (client, server) = @crypto.initial(dcid[:])
let wire = @conn.seal_long(
  @packet.Kind::Initial, 1U, dcid, b"\xaa\xbb\xcc\xdd", 1L, 4,
  @packet.payload([@frame.Ping]), server,
)

// And back, with the packet number recovered against what this space has seen.
let opened = @conn.recv_long(wire, client, largest=-1L) catch {
  _ => abort("the packet did not open")
}
guard opened is Some((frames, n)) else { abort("the packet did not open") }
assert_eq(n, 1L)
assert_eq(frames, [@frame.Ping])
```

Run `moon run src/examples/tour` for the whole surface in one go, or one of the eight worked examples a package at a time:

```
moon run src/examples/02-frames     moon run src/examples/05-ack        moon run src/examples/08-streams
moon run src/examples/03-params     moon run src/examples/06-flow       moon run src/examples/09-sender
moon run src/examples/04-crypto     moon run src/examples/07-recovery
```

## Packages

|  | What it covers |
|:--:|:--|
| `frame` | [§19](https://www.rfc-editor.org/rfc/rfc9000#section-19) every frame type, [§19.3.1](https://www.rfc-editor.org/rfc/rfc9000#section-19.3.1) the ACK range encoding both ways, and the multipath frames of [draft-ietf-quic-multipath §4](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) with their own type codes |
| `packet` | [§17](https://www.rfc-editor.org/rfc/rfc9000#section-17) long and short headers, Retry, Version Negotiation, [§17.1](https://www.rfc-editor.org/rfc/rfc9000#section-17.1) packet numbers, [§12.3](https://www.rfc-editor.org/rfc/rfc9000#section-12.3) the three spaces |
| `crypto` | [§5](https://www.rfc-editor.org/rfc/rfc9001#section-5) packet protection, header protection and the Retry tag, [§6](https://www.rfc-editor.org/rfc/rfc9001#section-6) key update, and the path-and-packet-number nonce multipath needs |
| `recovery` | [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) the round-trip estimate, both loss thresholds, the probe timeout, and NewReno, CUBIC ([RFC 9438](https://www.rfc-editor.org/rfc/rfc9438)) and BBR behind one controller trait, with persistent congestion; [§7.7](https://www.rfc-editor.org/rfc/rfc9002#section-7.7) pacing as a token bucket over bytes |
| `stream` | [§2](https://www.rfc-editor.org/rfc/rfc9000#section-2) stream IDs and reassembly, [§3](https://www.rfc-editor.org/rfc/rfc9000#section-3) both state machines, [§4](https://www.rfc-editor.org/rfc/rfc9000#section-4) data flow control and the stream quota, and a round-robin scheduler |
| `conn` | [§18](https://www.rfc-editor.org/rfc/rfc9000#section-18) transport parameters, [§12.3](https://www.rfc-editor.org/rfc/rfc9000#section-12.3) the three spaces and their CRYPTO streams, the client and server handshakes, the connection table and event loop with its timers and amplification limit ([§8.1](https://www.rfc-editor.org/rfc/rfc9000#section-8.1), [§10](https://www.rfc-editor.org/rfc/rfc9000#section-10), [§14.1](https://www.rfc-editor.org/rfc/rfc9000#section-14.1)), [§9](https://www.rfc-editor.org/rfc/rfc9000#section-9) migration and path validation, [§10.3](https://www.rfc-editor.org/rfc/rfc9000#section-10.3) stateless reset, [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) datagrams, 0-RTT and resumption, [§6](https://www.rfc-editor.org/rfc/rfc9000#section-6) Retry and version negotiation, the frame and parameter checks [§12.4](https://www.rfc-editor.org/rfc/rfc9000#section-12.4) and [§18](https://www.rfc-editor.org/rfc/rfc9000#section-18) require, many client connections on one id space, and multipath: a packet-number space, a congestion window and a PATH_ACK for each path |

`frame` and `packet` are pure codecs over [`moonvar/quic`](https://github.com/moonbitstack/moonvar), so a tool that only wants to read packets off a capture links nothing else — the variable-length integer went to a library of its own, because QUIC is not the only thing that writes one.

A long header splits in two on purpose. `Long` is the version-independent part [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999) pins down — form, version, connection IDs — which anything can read without knowing the version. `Tail` is version 1's continuation, the Initial token and the Length field, and it is where a reader needs to know which version it is looking at.

## Serving

`Endpoint::server` runs the TLS handshake itself, on moontls's QUIC mode. Datagrams go in with `recv` and come out of `poll_out`, the timers run on `tick`, and each takes the time from the caller:

<!-- nocheck -->
```moonbit
let server : @conn.Endpoint[Addr] = @conn.Endpoint::server(
  @conn.Config::default(),
  @tls.Server::new(chain, key, alpn=["h3"]),
  rand=entropy,
)
server.recv(datagram, from, now)
for conn in server.take_busy() {
  for event in conn.take_events() {
    match event {
      Readable(id) => {
        let bytes = conn.read(id)
        conn.write(id, reply(bytes), fin=conn.finished(id))
      }
      _ => ()
    }
  }
}
while server.poll_out(now) is Some((datagram, to)) {
  send(datagram, to)
}
```

A stream's credit goes back to the peer as `read` takes its bytes, so a slow application slows its peer down. `buffered` says how much written data is still unacknowledged, which is what a writer paces itself by.

The connection ids the server issues are `cid_size` bytes drawn from `rand`. Several processes behind one port, or a load balancer that routes on the id, pass `cid` to make them: `cid=() => b"" + entropy(cid_size - 1)` puts the number 2 where a router can read it from every datagram that follows. A packet from a new address begins a move: the path is challenged, and it is only trusted once the challenge comes back as a PATH_RESPONSE. A datagram that names no connection is answered with a stateless reset, so a peer learns the connection is gone instead of waiting out its idle timer.

## Connecting

`Client` drives the other side of the handshake. It splits the ClientHello across as many Initial packets as it needs — a post-quantum hello is over a kilobyte, past the 1200-byte datagram — and reassembles the server's flights per encryption level, installing each key as it arrives:

<!-- nocheck -->
```moonbit
let client = @conn.Client::new(
  @tls.Client::new(roots, alpn=["h3"]),
  "a.example",
  @conn.encode(params),
  rand=entropy,
  dcid=Bytes::make(8, 1),
  scid=Bytes::make(8, 2),
  now,
)
for datagram in client.poll_out(now) { send(datagram, to) }
for datagram in receive() {
  client.recv(datagram, now)
  for answer in client.poll_out(now) { send(answer, to) }
}
```

`alpn` and `suite_code` say what the handshake settled on once it is done, and `server_cid` is the id the peer wants addressed. Once it is connected the client carries streams: `write` and `read` are the same shape as the server's, and `take_events` says when a stream is readable.

A client has a clock as well, and nothing moves without it. `tick` runs the probe timeout on each handshake level, the send loop's own, the idle timeout and the closing period, and it sends the padded Initial with a PING that a server whose amplification budget is spent needs before it can answer (RFC 9002 §6.2.2.1):

<!-- nocheck -->
```moonbit
client.tick(now)
for datagram in client.poll_out(now) { send(datagram, to) }
```

`close` takes the same arguments as the server's and names the level by what is available: before 1-RTT keys exist, an application close goes as a transport close carrying `APPLICATION_ERROR`, because §10.2.3 leaves no other way to say it.

## Resuming a connection

A server's tickets come in 1-RTT CRYPTO frames after the handshake and land in the client's `@tls.Sessions`. A client given one of them has its early keys before its first packet goes out, so anything written now leaves in 0-RTT packets until the handshake finishes:

<!-- nocheck -->
```moonbit
client.write(0UL, request, fin=true)
for datagram in client.poll_out(now) { send(datagram, to) }
```

Early data spends the flow-control credit the previous connection left, and RFC 9000 §7.4.1 forbids guessing it: the client has to remember the transport parameters the ticket was issued under. `Client::remembered` is that pair — the session and the parameter block exactly as it arrived — and passing it back as `resumption` is all the next connection needs:

<!-- nocheck -->
```moonbit
let kept = client.remembered().unwrap()   // a ticket and the parameters it was issued under
let next = @conn.Client::new(
  @tls.Client::new(roots, alpn=["h3"], sessions=store, early=true),
  "a.example",
  @conn.encode(params),
  rand=entropy,
  dcid=Bytes::make(8, 3),
  scid=Bytes::make(8, 4),
  now,
  resumption=kept,
)
```

`Config`'s `zero_rtt_data` and `zero_rtt_stream_data` overrule what was remembered rather than being the only source; zero, the default, means the remembered value governs. A client with no ticket and no overrides has no credit at all, so its early data waits for the handshake rather than risking a flow-control error:

```moonbit
let cfg = @conn.Config::default()
assert_eq(cfg.zero_rtt_data, 0UL)
assert_eq(cfg.zero_rtt_stream_data, 0UL)
// A caller that knows better than the last connection says so; §7.4.1 makes the
// remembered value the ceiling, so a larger override earns a flow-control error.
let small = { ..cfg, zero_rtt_data: 4096UL, zero_rtt_stream_data: 4096UL }
assert_eq(small.zero_rtt_data, 4096UL)
```

`early_accepted` says afterwards whether the server took the data; if it did not, everything still in flight is queued again and leaves as 1-RTT, so a refused early write costs a round trip rather than the bytes.

A server allows it with `@tls.Tickets::new(keys, early=n)`, and judges tickets at the `wall` argument of `Endpoint::recv`: seconds since the Unix epoch, a different clock from `now`, which is in microseconds and only drives timers. An endpoint given no `wall` neither issues nor takes a ticket. 0-RTT data can be replayed by whoever recorded it (RFC 8446 §8), so it stays off until a server sets `early`. `install_zero_rtt` remains for keys that came from elsewhere.

## Several connections on one socket

One client endpoint holds many connections and tells their datagrams apart by connection id, which is all §5.2 asks of the routing:

<!-- nocheck -->
```moonbit
let endpoint = @conn.ClientEndpoint::new(@conn.Config::default(), rand=entropy)
let id = endpoint.connect(
  @tls.Client::new(roots, alpn=["h3"]),
  "a.example",
  params,
  now,
)
endpoint.recv(datagram, now)
for answer in endpoint.poll_out(now) { send(answer, to) }
endpoint.tick(now)
let client = endpoint.client(id).unwrap()
```

`connect` adds the `initial_source_connection_id` parameter itself when the block does not carry one, since the id it hands back is drawn inside the call. `ids` and `count` say what the endpoint holds, and `remove` forgets a connection that has closed.

## Paths

[Multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) is served from the transport parameter down: a connection offers `initial_max_path_id` (parameter `0x3e`), agrees with its peer on a path id, and then gives every path its own packet numbers, its own round-trip estimate and congestion window, and its own acknowledgement. The connection keeps what the two ends share — the streams, the flow control, the scheduler — because that is what the draft leaves connection-wide.

|  | What it does |
|:--|:--|
| `Paths::new(local_max=)` | the paths of one connection, path 0 being the one the handshake ran on |
| `Paths::bind`, `bind_local`, `path_of` | the peer's id for a path, this end's id for it, and the path an id belongs to |
| `Paths::openable`, `open`, `abandon` | which path ids may be opened, which are carrying traffic, and giving one up |
| `Paths::start`, `prove`, `validated` | challenging a path and knowing when it has answered |
| `Paths::on_max_path_id`, `on_status`, `next_status` | the peer's word on the path count and on which paths are available |
| `Endpoint::add_path`, `Session::add_path` | opening a second path, with a connection id the endpoint makes |
| `Session::send_on`, `poll_lane`, `path_lane` | a packet on a named path, the datagrams that path has ready, its state |
| `Client::add_path`, `send_on`, `recv_on`, `poll_paths` | the same for a client, whose caller owns the sockets and says which path a datagram came in on |
| `Lane` | one path's packet numbers, congestion window, pacing, and what its packets carried |

A path's state is state, and nothing here needs a socket to try:

```moonbit
let paths = @conn.Paths::new(local_max=2UL)   // what this end will maintain
paths.on_max_path_id(1UL)                     // what the peer said it would
assert_true(paths.openable(1UL))
assert_false(paths.openable(2UL))             // the peer offered one path, not two
let spare : Bytes = b"\xaa\xbb\xcc\xdd"
paths.bind(1UL, spare)                        // the peer's id for the path
ignore(paths.bind_local(1UL, b"\x01\x02"))    // this end's
assert_eq(paths.path_of(b"\x01\x02"), 1UL)
assert_false(paths.validated(1UL))
ignore(paths.start(1UL, b"\x10\x20\x30\x40\x50\x60\x70\x80"))
assert_true(paths.prove(1UL, b"\x10\x20\x30\x40\x50\x60\x70\x80"))
assert_true(paths.validated(1UL))
```

Each path's packets are sealed under a nonce that names it (draft §2.4), so two paths may use the same packet number without ever using the same nonce. Path 0 gives exactly the nonce RFC 9001 §5.3 describes, which is why a connection with one path is unaffected:

```moonbit
let (_, keys) = @crypto.initial(b"\x83\x94\xc8\xf0\x3e\x51\x57\x08")
assert_eq(keys.nonce_at(0UL, 54321L), keys.nonce(54321L))
assert_true(keys.nonce_at(1UL, 54321L) != keys.nonce(54321L))
```

The frames carry the path they are about, and a packet is placed on a path by the connection id it names rather than by the address it came from — a path whose 4-tuple changes is a migration, not a new path:

```moonbit
let status = @frame.PathStatus(path_id=1UL, seq=1UL, available=true)
let wire = @frame.encode(status)
let (back, used) = @frame.decode(wire[:]) catch {
  _ => abort("the frame did not decode")
}
assert_eq(used, wire.length())
assert_eq(back, status)
// PATH_ACK names the path whose packet numbers it settles.
let ack = @frame.PathAck(path_id=1, largest=9UL, delay=0UL, first_range=1UL, ranges=[])
assert_eq(@frame.encode(ack).length(), 4)
```

What the draft leaves open — which path carries which byte, when a backup path becomes the one to use — is the caller's: `send_on` puts frames on the path it is told, `poll_lane` hands back the datagrams that path has ready with the address they belong on, and `Lane` reports the window and the outstanding count for a scheduler to work from.

## Datagrams

RFC 9221's unreliable datagrams ride 1-RTT packets and are never retransmitted. An endpoint enables them by advertising `max_datagram_frame_size`, zero by default; a datagram larger than the peer accepts, or one the peer never offered to receive, is refused rather than sent and lost:

```moonbit
let cfg = { ..@conn.Config::default(), max_datagram_frame_size: 1200UL }
assert_eq(cfg.max_datagram_frame_size, 1200UL)
```

## Everything the protocol leaves open is a parameter

The cipher suite is a record with a public preset:

```moonbit
let dcid : Bytes = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
let (initial, _) = @crypto.initial(dcid[:])            // AEAD_AES_128_GCM, RFC 9001 §5.2
let strong = @crypto.Keys::of(initial.key, suite=@crypto.aes256)
let others = @crypto.Keys::of(initial.key, suite=@crypto.chacha20)
assert_eq(strong.iv.length(), 12)
assert_eq(others.iv.length(), 12)
```

`Suite` carries the AEAD as a function, so a cipher this module has none of plugs in by implementing `@spec.Aead` and changing nothing here. `Version` does the same for the constants a QUIC version fixes: the Initial salt, the four HKDF labels, and the Retry integrity key. The preset is version 1; [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) changes every one of them for version 2, and that is a record away.

`@recovery.Policy` holds every constant RFC 9002 marks as a tunable — the two loss thresholds, the granularity, the initial round trip, the persistent-congestion threshold, the loss reduction factor — at the values the RFC recommends. The congestion controller is a trait, because §7 opens by saying an endpoint may use any: NewReno is the default, and CUBIC and BBR implement the same contract.

```moonbit
let reno = @recovery.State::new()
let cubic = @recovery.State::new(control=@recovery.Cubic::new())
let bbr = @recovery.State::new(control=@recovery.Bbr::new())
assert_true(reno.window() > 0L)
assert_true(cubic.window() > 0L)
assert_true(bbr.window() > 0L)
```

CUBIC follows a cubic function of the time since the last reduction and falls to 0.7 rather than to half. BBR sizes the window from the bandwidth-delay product times a probing gain and does not treat a loss as its congestion signal. Both get the clock and the round-trip sample through two defaulted `Control` methods, so a controller that only implements the original seven is unaffected.

## What is not here

Sockets, and anything that needs a clock of its own. The TLS handshake — that is `moontls`, whose key schedule RFC 9001 §5.2 reuses verbatim. HTTP/3 and QPACK — those are [`moonhttp`](https://github.com/moonbitstack/moonhttp)'s, because HTTP/3 is a version of HTTP and QPACK is to it what HPACK is to HTTP/2.

A connection moves only for a packet that authenticated, is the newest seen, and carries more than probing frames. A challenge is answered on the path it came from, a new address has three times what it sent to spend until it answers, a path that will not answer is given up after three probe timeouts, and the round trip and window start over once it does (RFC 9000 §8.2, §9). A server names its stateless reset token in its transport parameters, and a client closes on a packet that will not open and ends in it.

A server hands out spare connection ids up to what the client will hold and `Config.connection_ids` allows, and replaces the ones retired. `Client::next_cid` moves to one, for a change of path nobody should be able to link to the last. `Client::update_keys` starts a key update, and either end follows the other's.

A server can ask a client to prove its address before keeping anything for it: `Config.retry` answers the first Initial with a Retry whose token carries the client's address, the connection id its Initial named and when it was issued, tagged with a key only the server holds (RFC 9000 §8.1.2). The second Initial is opened with the Initial keys the Retry's id yields, and `retry_source_connection_id` names that id so the client can hold the handshake to it (§7.3). A token older than ten seconds, or tagged with another key, or stamped for another address, draws a fresh Retry; a replayed Initial finds the connection already there and is dropped as a duplicate.

A signing key never enters this library. A server's handshake flight takes the CertificateVerify as a function of the transcript hash, so whoever holds the key builds the body at the one moment §4.4.3 says to sign — `@conn.signed(key)` is that function for a `@spec.Signer`.

## Verification

Packet protection is checked against [RFC 9001 Appendix A](https://www.rfc-editor.org/rfc/rfc9001#appendix-A), read out of the RFC's own text rather than typed in. The A.3 server Initial seals to the published 135-byte packet byte for byte and opens back to its payload, which in one assertion covers the Initial salt, all four HKDF labels, the key and IV lengths, the nonce construction, AES-128-GCM, header protection, the truncated packet number, and the Initial header's token and Length fields. A.1's secrets, A.2's header-protection mask and A.4's Retry integrity tag are checked separately, so a failure says which step broke.

The multipath nonce is checked the same way, against the draft's own Figure 3: an IV, path 3 and packet number 54321 give `6b2611489cba2b63a9e8097e`, and the same IV with path 0 gives the nonce RFC 9001 would.

The gate is `moon clean` → `moon fmt` → `moon check --target all --deny-warn` → `moon build --target all` → `moon test --target all`, across `wasm`, `wasm-gc`, `js` and `native`.

## Conformance

[h3spec](https://github.com/kazu-yamamoto/h3spec) v0.1.14's "QUIC servers" section is the authority on what a server must refuse, and every case is mirrored in `src/conn/h3spec_wbtest.mbt`, each test naming the RFC section it comes from. The cases that need a frame in a live 1-RTT packet take one from a connected client, the way the tool injects them.

| h3spec case | RFC | code |
|:--|:--|:--|
| STREAM offset past the stream's credit | 4.1 | `FLOW_CONTROL_ERROR` |
| stream id past the limit | 4.6 | `STREAM_LIMIT_ERROR` |
| `initial_source_connection_id` missing | 7.3 | `TRANSPORT_PARAMETER_ERROR` |
| a client declaring a server's parameter | 18.2 | `TRANSPORT_PARAMETER_ERROR` |
| a parameter whose value is not a varint | 18.1 | `TRANSPORT_PARAMETER_ERROR` |
| `max_udp_payload_size` below 1200 | 18.2 | `TRANSPORT_PARAMETER_ERROR` |
| `ack_delay_exponent` above 20 | 18.2 | `TRANSPORT_PARAMETER_ERROR` |
| `max_ack_delay` at or above 2^14 | 18.2 | `TRANSPORT_PARAMETER_ERROR` |
| `initial_max_streams_*` past 2^60 | 18.2 | `TRANSPORT_PARAMETER_ERROR` |
| ACK range below packet zero | 19.3.1 | `FRAME_ENCODING_ERROR` |
| ACK of a packet never sent | 13.1 | `PROTOCOL_VIOLATION` |
| a frame of unknown type | 12.4 | `FRAME_ENCODING_ERROR` |
| a packet with no frames | 12.4 | `PROTOCOL_VIOLATION` |
| reserved bits set in a Handshake or 1-RTT packet | 17.2 | `PROTOCOL_VIOLATION` |
| CRYPTO buffered past the limit | 7.5 | `CRYPTO_BUFFER_EXCEEDED` |
| PATH_CHALLENGE, DATA_BLOCKED or STREAM_DATA_BLOCKED in a Handshake packet | 12.4 | `PROTOCOL_VIOLATION` |
| RETIRE_CONNECTION_ID for an id never issued | 19.16 | `PROTOCOL_VIOLATION` |
| RESET_STREAM or STREAM on a send-only stream | 19.4, 19.8 | `STREAM_STATE_ERROR` |
| STREAM on a locally initiated stream not opened | 19.8 | `STREAM_STATE_ERROR` |
| STOP_SENDING or MAX_STREAM_DATA for a stream that does not exist | 19.5, 19.10 | `STREAM_STATE_ERROR` |
| MAX_STREAM_DATA for a receive-only stream | 19.10 | `STREAM_STATE_ERROR` |
| invalid MAX_STREAMS | 19.11 | `FRAME_ENCODING_ERROR` |
| invalid STREAMS_BLOCKED | 19.14 | `STREAM_LIMIT_ERROR` |
| NEW_CONNECTION_ID with a zero-length id or a bad `retire_prior_to` | 19.15 | `FRAME_ENCODING_ERROR` |
| NEW_TOKEN or HANDSHAKE_DONE from a client | 19.7, 19.20 | `PROTOCOL_VIOLATION` |
| KeyUpdate in Handshake or 1-RTT | RFC 9001 §6 | `CRYPTO_ERROR` with `unexpected_message` |
| EndOfEarlyData, or no ALPN overlap | RFC 8446 | `CRYPTO_ERROR` with the alert |
| a PATH_STATUS or PATH_ABANDON for a path id this end never offered | draft §3.1, §4.2 | `PROTOCOL_VIOLATION` |
| a path id above 2^32-1 in PATH_NEW_CONNECTION_ID, MAX_PATH_ID or PATHS_BLOCKED | draft §2.1, §4.6 | `TRANSPORT_PARAMETER_ERROR`, `PROTOCOL_VIOLATION` |

`scripts/quic/check_interop.py --host <host> --port <port>` is the other half: an aioquic client completes a handshake, sends a stream and checks the echo, then repeats it through a proxy that drops one datagram in five, so recovery and pacing are exercised by a peer that is not this library's own. A server in Retry mode is covered by the same run.

`scripts/quic/check_h3spec.sh <host> <port>` downloads that pinned release and runs the section against a server. It is a client, so it needs a server on the other end: this library has no socket, and the harness that binds one is the server repository's.

Run against a server built on this library, all 43 examples pass. One of them, CRYPTO in 0-RTT, the tool skips of its own accord when the server issues no ticket; with tickets on it runs and is the one case that does not close as it expects, because the client resends the injected fragment at 1-RTT and is answered with `CRYPTO_ERROR` rather than `PROTOCOL_VIOLATION`.

## License

Apache-2.0. See [LICENSE](LICENSE).
