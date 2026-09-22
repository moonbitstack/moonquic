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

Run `moon run examples/tour` for the whole surface in one go, or one of the nine worked examples a package at a time:

```
moon run examples/01-varint     moon run examples/04-crypto     moon run examples/07-recovery
moon run examples/02-frames     moon run examples/05-ack        moon run examples/08-streams
moon run examples/03-params     moon run examples/06-flow       moon run examples/09-sender
```

## Packages

|  | Specification | State |
|:--:|:--|:--:|
| `varint` | [§16](https://www.rfc-editor.org/rfc/rfc9000#section-16) the variable-length integer everything else is written in | **0.1.0** |
| `frame` | [§19](https://www.rfc-editor.org/rfc/rfc9000#section-19) every frame type, and [§19.3.1](https://www.rfc-editor.org/rfc/rfc9000#section-19.3.1) the ACK range encoding both ways | **0.1.0** |
| `packet` | [§17](https://www.rfc-editor.org/rfc/rfc9000#section-17) long and short headers, Retry, Version Negotiation, [§17.1](https://www.rfc-editor.org/rfc/rfc9000#section-17.1) packet numbers, [§12.3](https://www.rfc-editor.org/rfc/rfc9000#section-12.3) the three spaces | **0.1.0** |
| `crypto` | [§5](https://www.rfc-editor.org/rfc/rfc9001#section-5) packet protection, header protection and the Retry tag, [§6](https://www.rfc-editor.org/rfc/rfc9001#section-6) key update | **0.1.0** |
| `recovery` | [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) the round-trip estimate, both loss thresholds, the probe timeout, NewReno and persistent congestion | **0.1.0** |
| `stream` | [§2](https://www.rfc-editor.org/rfc/rfc9000#section-2) stream IDs and reassembly, [§3](https://www.rfc-editor.org/rfc/rfc9000#section-3) both state machines, [§4](https://www.rfc-editor.org/rfc/rfc9000#section-4) data flow control and the stream quota, and a round-robin scheduler | **0.1.0** |
| `conn` | [§18](https://www.rfc-editor.org/rfc/rfc9000#section-18) transport parameters, [§12.3](https://www.rfc-editor.org/rfc/rfc9000#section-12.3) the three spaces and their CRYPTO streams, and a server's connection table, timers and amplification limit ([§8.1](https://www.rfc-editor.org/rfc/rfc9000#section-8.1), [§10](https://www.rfc-editor.org/rfc/rfc9000#section-10), [§14.1](https://www.rfc-editor.org/rfc/rfc9000#section-14.1)) | **0.1.0** |

`varint`, `frame` and `packet` have no dependencies outside this module; `frame` and `packet` are pure codecs, so a tool that only wants to read packets off a capture links nothing else.

A long header splits in two on purpose. `Long` is the version-independent part [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999) pins down — form, version, connection IDs — which anything can read without knowing the version. `Tail` is version 1's continuation, the Initial token and the Length field, and it is where a reader needs to know which version it is looking at.

## Everything the protocol leaves open is a parameter

The cipher suite is a record with a public preset:

```moonbit
@crypto.initial(dcid[:])                              // AEAD_AES_128_GCM, RFC 9001 §5.2
@crypto.initial(dcid[:], suite={ ..@crypto.suite, key: 32 })   // AES-256-GCM
```

`Suite` carries the AEAD as a function, so a cipher this module has none of — ChaCha20-Poly1305, say — plugs in by implementing `@spec.Aead` and changing nothing here. `Version` does the same for the constants a QUIC version fixes: the Initial salt, the four HKDF labels, and the Retry integrity key. The preset is version 1; [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) changes every one of them for version 2, and that is a record away.

`@recovery.Policy` holds every constant RFC 9002 marks as a tunable — the two loss thresholds, the granularity, the initial round trip, the persistent-congestion threshold, the loss reduction factor — at the values the RFC recommends. The congestion controller is a trait, because §7 opens by saying an endpoint may use any: NewReno is what ships, and Cubic or BBR answer the same seven questions.

## What is not here

Sockets, and anything that needs a clock of its own. The TLS handshake — that is `moontls`, whose key schedule RFC 9001 §5.2 reuses verbatim. HTTP/3 and QPACK — those are [`moonhttp`](https://github.com/moonbitstack/moonhttp)'s, because HTTP/3 is a version of HTTP and QPACK is to it what HPACK is to HTTP/2.

Connection migration, path validation, stateless reset, 0-RTT and coalesced packets are not implemented. The client side of the connection is not either: `conn` has a server's table and event loop, and a client drives the same packages by hand.

A signing key never enters this library. A server's handshake flight takes the CertificateVerify as a function of the transcript hash, so whoever holds the key builds the body at the one moment §4.4.3 says to sign — `@conn.signed(key)` is that function for a `@spec.Signer`.

## Verification

Packet protection is checked against [RFC 9001 Appendix A](https://www.rfc-editor.org/rfc/rfc9001#appendix-A), read out of the RFC's own text rather than typed in. The A.3 server Initial seals to the published 135-byte packet byte for byte and opens back to its payload, which in one assertion covers the Initial salt, all four HKDF labels, the key and IV lengths, the nonce construction, AES-128-GCM, header protection, the truncated packet number, and the Initial header's token and Length fields. A.1's secrets, A.2's header-protection mask and A.4's Retry integrity tag are checked separately, so a failure says which step broke.

The gate is `moon clean` → `moon fmt` → `moon check --target all --deny-warn` → `moon build --target all` → `moon test --target all`, across `wasm`, `wasm-gc`, `js` and `native`.

## License

Apache-2.0. See [LICENSE](LICENSE).
