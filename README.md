# moonquic

The QUIC transport for MoonBit ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001), [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002)) — bytes in, events out. No sockets, no handshake of its own: the TLS 1.3 handshake is [`moontls`](https://github.com/moonbitstack/moontls)'s and the ciphers are [`mooncrypt`](https://github.com/moonbitstack/mooncrypt)'s.

```moonbit
// A protected packet, from the connection ID up (RFC 9001 §5.2–§5.4).
let (_, server) = @crypto.initial(dcid[:])
let number = @packet.number(1L, None)
let header = long.header(number[:], payload=payload.length() + 16)
let wire = server.seal(header[:], payload[:], number=1L)

// And back, with the packet number recovered against what this space has seen.
let (plain, n) = server.open(wire[:], largest=0L).unwrap()
let frames = @packet.read_payload(plain)
```

Run `moon run src/examples/tour` for the whole surface in one go, or one of the eight worked examples a package at a time:

```
moon run src/examples/02-frames     moon run src/examples/05-ack        moon run src/examples/08-streams
moon run src/examples/03-params     moon run src/examples/06-flow       moon run src/examples/09-sender
moon run src/examples/04-crypto     moon run src/examples/07-recovery
```

## Packages

|  | Specification | State |
|:--:|:--|:--:|
| `frame` | [§19](https://www.rfc-editor.org/rfc/rfc9000#section-19) every frame type, and [§19.3.1](https://www.rfc-editor.org/rfc/rfc9000#section-19.3.1) the ACK range encoding both ways | **0.1.0** |
| `packet` | [§17](https://www.rfc-editor.org/rfc/rfc9000#section-17) long and short headers, Retry, Version Negotiation, [§17.1](https://www.rfc-editor.org/rfc/rfc9000#section-17.1) packet numbers, [§12.3](https://www.rfc-editor.org/rfc/rfc9000#section-12.3) the three spaces | **0.1.0** |
| `crypto` | [§5](https://www.rfc-editor.org/rfc/rfc9001#section-5) packet protection, header protection and the Retry tag, [§6](https://www.rfc-editor.org/rfc/rfc9001#section-6) key update | **0.1.0** |
| `recovery` | [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) the round-trip estimate, both loss thresholds, the probe timeout, and NewReno, CUBIC ([RFC 9438](https://www.rfc-editor.org/rfc/rfc9438)) and BBR behind one controller trait, with persistent congestion; [§7.7](https://www.rfc-editor.org/rfc/rfc9002#section-7.7) pacing as a token bucket over bytes | **0.1.0** |
| `stream` | [§2](https://www.rfc-editor.org/rfc/rfc9000#section-2) stream IDs and reassembly, [§3](https://www.rfc-editor.org/rfc/rfc9000#section-3) both state machines, [§4](https://www.rfc-editor.org/rfc/rfc9000#section-4) data flow control and the stream quota, and a round-robin scheduler | **0.1.0** |
| `conn` | [§18](https://www.rfc-editor.org/rfc/rfc9000#section-18) transport parameters, [§12.3](https://www.rfc-editor.org/rfc/rfc9000#section-12.3) the three spaces and their CRYPTO streams, the client and server handshakes, the connection table and event loop with its timers and amplification limit ([§8.1](https://www.rfc-editor.org/rfc/rfc9000#section-8.1), [§10](https://www.rfc-editor.org/rfc/rfc9000#section-10), [§14.1](https://www.rfc-editor.org/rfc/rfc9000#section-14.1)), [§9](https://www.rfc-editor.org/rfc/rfc9000#section-9) migration and path validation, [§10.3](https://www.rfc-editor.org/rfc/rfc9000#section-10.3) stateless reset, [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) datagrams, 0-RTT packets, [§6](https://www.rfc-editor.org/rfc/rfc9000#section-6) Retry and version negotiation, the frame and parameter checks [§12.4](https://www.rfc-editor.org/rfc/rfc9000#section-12.4) and [§18](https://www.rfc-editor.org/rfc/rfc9000#section-18) require, many client connections on one id space, and the first stage of [multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) | **0.1.0** |

`frame` and `packet` are pure codecs over [`moonvar/quic`](https://github.com/moonbitstack/moonvar), so a tool that only wants to read packets off a capture links nothing else — the variable-length integer went to a library of its own, because QUIC is not the only thing that writes one.

A long header splits in two on purpose. `Long` is the version-independent part [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999) pins down — form, version, connection IDs — which anything can read without knowing the version. `Tail` is version 1's continuation, the Initial token and the Length field, and it is where a reader needs to know which version it is looking at.

## Serving

`Endpoint::server` runs the TLS handshake itself, on moontls's QUIC mode. Datagrams go in with `recv` and come out of `poll_out`, the timers run on `tick`, and each takes the time from the caller:

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

The connection ids the server issues are `cid_size` bytes drawn from `rand`. Several processes behind one port, or a load balancer that routes on the id, pass `cid` to make them: `cid=() => b"" + entropy(cid_size - 1)` puts the number 2 where a router can read it from every datagram that follows. A packet from a new address begins a move: the path is challenged, and it is only trusted once the challenge comes back as a PATH_RESPONSE. A datagram that names no connection is answered with a stateless reset, so a peer learns the connection is gone instead of waiting out its idle timer.

## Connecting

`Client` drives the other side of the handshake. It splits the ClientHello across as many Initial packets as it needs — a post-quantum hello is over a kilobyte, past the 1200-byte datagram — and reassembles the server's flights per encryption level, installing each key as it arrives:

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

```moonbit
client.tick(now)
for datagram in client.poll_out(now) { send(datagram, to) }
```

`close` takes the same arguments as the server's and names the level by what is available: before 1-RTT keys exist, an application close goes as a transport close carrying `APPLICATION_ERROR`, because §10.2.3 leaves no other way to say it.

A server's tickets come in 1-RTT CRYPTO frames after the handshake and land in the client's `@tls.Sessions`. A client given one of them and `early=true` has its early keys before its first packet goes out, so anything written now leaves in 0-RTT packets until the handshake finishes:

```moonbit
client.write(0UL, request, fin=true)
for datagram in client.poll_out(now) { send(datagram, to) }
```

Early data spends the flow-control credit the previous connection left, which a resuming client supplies as `Config.zero_rtt_data` and `Config.zero_rtt_stream_data` — RFC 9000 §7.4.1 forbids guessing it, and zero means early data waits for the handshake rather than risking a flow-control error. `early_accepted` says afterwards whether the server took it; if it did not, everything still in flight is queued again and leaves as 1-RTT, so a refused early write costs a round trip rather than the data.

A server allows it with `@tls.Tickets::new(keys, early=n)`, and judges tickets at the `wall` argument of `Endpoint::recv`: seconds since the Unix epoch, a different clock from `now`, which is in microseconds and only drives timers. An endpoint given no `wall` neither issues nor takes a ticket. 0-RTT data can be replayed by whoever recorded it (RFC 8446 §8), so it stays off until a server sets `early`. `install_zero_rtt` remains for keys that came from elsewhere.

## Several connections on one socket

One client endpoint holds many connections and tells their datagrams apart by connection id, which is all §5.2 asks of the routing:

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

The first stage of [multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) is here: the `initial_max_path_id` transport parameter, the four frames the draft assigns from `0x15228c00` — PATH_ABANDON, PATH_STATUS in its available and backup forms, MAX_PATH_ID and PATHS_BLOCKED — and the path state a connection keeps. A path has an id both ends use, the connection id traffic on it is addressed by, whether it has answered a challenge, and the peer's latest word on whether it is available:

```moonbit
let paths = conn.paths()
paths.on_max_path_id(2UL)          // what the peer said it will accept
paths.bind(1UL, spare_cid)         // give a path an id of its own
conn.send(@conn.Level::Application, [@frame.PathStatus(path_id=1UL, seq=1UL, available=true)])
```

What the first stage does not do is give each path its own packet-number space and congestion state: that is what the draft's §3.4 asks for next, and it needs the packet-number space to grow a path dimension rather than a second space beside it. Until then a connection keeps one path's worth of numbering, and `Paths` holds everything the two ends have to agree on before that can be built.

## Datagrams

RFC 9221's unreliable datagrams ride 1-RTT packets and are never retransmitted. An endpoint enables them by advertising `max_datagram_frame_size`, zero by default; a datagram larger than the peer accepts, or one the peer never offered to receive, is refused rather than sent and lost:

```moonbit
let cfg = { ..@conn.Config::default(), max_datagram_frame_size: 1200UL }
let taken = conn.send_datagram(payload)
for datagram in conn.take_datagrams() { handle(datagram) }
```

## Everything the protocol leaves open is a parameter

The cipher suite is a record with a public preset:

```moonbit
@crypto.initial(dcid[:])                              // AEAD_AES_128_GCM, RFC 9001 §5.2
@crypto.Keys::of(secret[:], suite=@crypto.aes256)     // AEAD_AES_256_GCM
@crypto.Keys::of(secret[:], suite=@crypto.chacha20)   // AEAD_CHACHA20_POLY1305
```

`Suite` carries the AEAD as a function, so a cipher this module has none of plugs in by implementing `@spec.Aead` and changing nothing here. `Version` does the same for the constants a QUIC version fixes: the Initial salt, the four HKDF labels, and the Retry integrity key. The preset is version 1; [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) changes every one of them for version 2, and that is a record away.

`@recovery.Policy` holds every constant RFC 9002 marks as a tunable — the two loss thresholds, the granularity, the initial round trip, the persistent-congestion threshold, the loss reduction factor — at the values the RFC recommends. The congestion controller is a trait, because §7 opens by saying an endpoint may use any: NewReno is the default, and CUBIC and BBR implement the same contract.

```moonbit
@recovery.State::new()                                   // NewReno
@recovery.State::new(control=@recovery.Cubic::new())     // CUBIC, RFC 9438
@recovery.State::new(control=@recovery.Bbr::new())       // BBR
```

CUBIC follows a cubic function of the time since the last reduction and falls to 0.7 rather than to half. BBR sizes the window from the bandwidth-delay product times a probing gain and does not treat a loss as its congestion signal. Both get the clock and the round-trip sample through two defaulted `Control` methods, so a controller that only implements the original seven is unaffected.

## What is not here

Sockets, and anything that needs a clock of its own. The TLS handshake — that is `moontls`, whose key schedule RFC 9001 §5.2 reuses verbatim. HTTP/3 and QPACK — those are [`moonhttp`](https://github.com/moonbitstack/moonhttp)'s, because HTTP/3 is a version of HTTP and QPACK is to it what HPACK is to HTTP/2.

A connection moves only for a packet that authenticated, is the newest seen, and carries more than probing frames. A challenge is answered on the path it came from, a new address has three times what it sent to spend until it answers, a path that will not answer is given up after three probe timeouts, and the round trip and window start over once it does (RFC 9000 §8.2, §9). A server names its stateless reset token in its transport parameters, and a client closes on a packet that will not open and ends in it.

A server hands out spare connection ids up to what the client will hold and `Config.connection_ids` allows, and replaces the ones retired. `Client::next_cid` moves to one, for a change of path nobody should be able to link to the last. `Client::update_keys` starts a key update, and either end follows the other's.

Connection migration, path validation, stateless reset, 0-RTT, the client's 1-RTT stream layer, many client connections on one id space and the first stage of multipath are here.

A server can ask a client to prove its address before keeping anything for it: `Config.retry` answers the first Initial with a Retry whose token carries the client's address, the connection id its Initial named and when it was issued, tagged with a key only the server holds (RFC 9000 §8.1.2). The second Initial is opened with the Initial keys the Retry's id yields, and `retry_source_connection_id` names that id so the client can hold the handshake to it (§7.3). A token older than ten seconds, or tagged with another key, or stamped for another address, draws a fresh Retry; a replayed Initial finds the connection already there and is dropped as a duplicate.

A signing key never enters this library. A server's handshake flight takes the CertificateVerify as a function of the transcript hash, so whoever holds the key builds the body at the one moment §4.4.3 says to sign — `@conn.signed(key)` is that function for a `@spec.Signer`.

## Verification

Packet protection is checked against [RFC 9001 Appendix A](https://www.rfc-editor.org/rfc/rfc9001#appendix-A), read out of the RFC's own text rather than typed in. The A.3 server Initial seals to the published 135-byte packet byte for byte and opens back to its payload, which in one assertion covers the Initial salt, all four HKDF labels, the key and IV lengths, the nonce construction, AES-128-GCM, header protection, the truncated packet number, and the Initial header's token and Length fields. A.1's secrets, A.2's header-protection mask and A.4's Retry integrity tag are checked separately, so a failure says which step broke.

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

`scripts/quic/check_h3spec.sh <host> <port>` downloads that pinned release and runs the section against a server. It is a client, so it needs a server on the other end: this library has no socket, and the harness that binds one is the server repository's.

Run against a server built on this library, all 43 examples pass. One of them, CRYPTO in 0-RTT, the tool skips of its own accord when the server issues no ticket; with tickets on it runs and is the one case that does not close as it expects, because the client resends the injected fragment at 1-RTT and is answered with `CRYPTO_ERROR` rather than `PROTOCOL_VIOLATION`.

## License

Apache-2.0. See [LICENSE](LICENSE).
