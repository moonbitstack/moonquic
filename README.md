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
| `recovery` | [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) the round-trip estimate, both loss thresholds, the probe timeout, and NewReno, CUBIC ([RFC 9438](https://www.rfc-editor.org/rfc/rfc9438)) and BBR behind one controller trait, with persistent congestion | **0.1.0** |
| `stream` | [§2](https://www.rfc-editor.org/rfc/rfc9000#section-2) stream IDs and reassembly, [§3](https://www.rfc-editor.org/rfc/rfc9000#section-3) both state machines, [§4](https://www.rfc-editor.org/rfc/rfc9000#section-4) data flow control and the stream quota, and a round-robin scheduler | **0.1.0** |
| `conn` | [§18](https://www.rfc-editor.org/rfc/rfc9000#section-18) transport parameters, [§12.3](https://www.rfc-editor.org/rfc/rfc9000#section-12.3) the three spaces and their CRYPTO streams, the client and server handshakes, the connection table and event loop with its timers and amplification limit ([§8.1](https://www.rfc-editor.org/rfc/rfc9000#section-8.1), [§10](https://www.rfc-editor.org/rfc/rfc9000#section-10), [§14.1](https://www.rfc-editor.org/rfc/rfc9000#section-14.1)), [§9](https://www.rfc-editor.org/rfc/rfc9000#section-9) migration and path validation, [§10.3](https://www.rfc-editor.org/rfc/rfc9000#section-10.3) stateless reset, [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) datagrams, and 0-RTT packets | **0.1.0** |

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

0-RTT rides the same client. Supply the early keys from a resumed session and queue frames; they go out in 0-RTT packets until the handshake finishes:

```moonbit
client.install_zero_rtt(@crypto.zero_rtt(early_secret[:]))
client.send_zero_rtt([
  @frame.Stream(id=0UL, offset=0UL, fin=false, data=request),
])
```

On the server, `Session::install_zero_rtt` takes the same keys, after which a 0-RTT packet's frames are handled like any other. (`moontls`, the handshake, does not yet hand a QUIC client its early secret, so the caller derives it from the resumed session.)

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

Connection migration, path validation and stateless reset are here, and so is the client's 1-RTT stream layer. 0-RTT packets are here too, but the pinned `moontls` does not hand a QUIC client its early traffic secret, so a caller supplies the keys from a resumed session; without them a 0-RTT packet is dropped. A client `Endpoint` over many connections, and multipath, are the next step.

A signing key never enters this library. A server's handshake flight takes the CertificateVerify as a function of the transcript hash, so whoever holds the key builds the body at the one moment §4.4.3 says to sign — `@conn.signed(key)` is that function for a `@spec.Signer`.

## Verification

Packet protection is checked against [RFC 9001 Appendix A](https://www.rfc-editor.org/rfc/rfc9001#appendix-A), read out of the RFC's own text rather than typed in. The A.3 server Initial seals to the published 135-byte packet byte for byte and opens back to its payload, which in one assertion covers the Initial salt, all four HKDF labels, the key and IV lengths, the nonce construction, AES-128-GCM, header protection, the truncated packet number, and the Initial header's token and Length fields. A.1's secrets, A.2's header-protection mask and A.4's Retry integrity tag are checked separately, so a failure says which step broke.

The gate is `moon clean` → `moon fmt` → `moon check --target all --deny-warn` → `moon build --target all` → `moon test --target all`, across `wasm`, `wasm-gc`, `js` and `native`.

## License

Apache-2.0. See [LICENSE](LICENSE).
