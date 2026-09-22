// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A hex string as bytes, and back — the shape RFC 9000's appendices print
/// their vectors in. Eight lines beat a dependency the package does not have.
fn qv_hexb(h : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < h.length(); i = i + 2 {
    buf.write_byte(
      ((qv_nibble(h[i].to_int()) << 4) | qv_nibble(h[i + 1].to_int())).to_byte(),
    )
  }
  buf.to_bytes()
}

///|
fn qv_nibble(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    0
  }
}

///|
fn qv_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}

///|
test "parse the RFC 9001 A.1 sample client Initial long header" {
  // The header prefix of RFC 9001 Appendix A.1's sample client Initial packet:
  // first byte c3 (Initial, packet-number length 4), version 1, an 8-byte DCID,
  // and an empty SCID.
  let bytes = qv_hexb("c300000001088394c8f03e51570800")
  match read_long(bytes[:]) {
    Some((h, consumed)) => {
      assert_eq(h.packet_type, Kind::Initial)
      assert_eq(h.type_specific, 3)
      assert_eq(h.version, 1)
      assert_eq(qv_hex(h.dcid), "8394c8f03e515708")
      assert_eq(qv_hex(h.scid), "")
      assert_eq(consumed, 15)
    }
    None => fail("expected a valid long header")
  }
}

///|
test "long header round-trips for every packet type" {
  let types = [Kind::Initial, ZeroRtt, Kind::Handshake, Retry]
  for t in types {
    let h : Long = {
      packet_type: t,
      type_specific: 2,
      version: 1,
      dcid: qv_hexb("0102030405"),
      scid: qv_hexb("aabb"),
    }
    let encoded = encode_long(h)
    match read_long(encoded[:]) {
      Some((decoded, consumed)) => {
        assert_eq(decoded, h)
        assert_eq(consumed, encoded.length())
      }
      None => fail("round-trip failed for a long header")
    }
  }
}

///|
test "a short header (high bit clear) and a truncated header are rejected" {
  // A short-header first byte (0x40) is not a long header.
  assert_eq(read_long(qv_hexb("40000000")[:]) is None, true)
  // A DCID length that overruns the buffer decodes to None.
  assert_eq(read_long(qv_hexb("c3000000010899")[:]) is None, true)
}

///|
test "QUIC packet number encodes per RFC 9000 A.2" {
  // full = 0xac5c02, largest acked = 0xabe8bc -> two bytes, 0x5c02.
  assert_eq(number_size(0xac5c02L, Some(0xabe8bcL)), 2)
  assert_eq(qv_hex(number(0xac5c02L, Some(0xabe8bcL))), "5c02")
}

///|
test "QUIC packet number decodes per RFC 9000 A.3" {
  // largest received = 0xa82f30ea, truncated = 0x9b32 (16 bits) -> 0xa82f9b32.
  assert_eq(read_number(0xa82f30eaL, 0x9b32L, 16), 0xa82f9b32L)
}

///|
test "QUIC packet number encode/decode round-trips" {
  let cases = [
    (0xac5c02L, 0xabe8bcL),
    (0xa82f9b32L, 0xa82f30eaL),
    (100L, 50L),
    (0xffffL, 0x8000L),
    (0x3fffffffL, 0x3ffffff0L),
  ]
  for c in cases {
    let (full, lacked) = c
    let nb = number_size(full, Some(lacked))
    let enc = number(full, Some(lacked))
    assert_eq(enc.length(), nb)
    let mut tr = 0L
    for i = 0; i < enc.length(); i = i + 1 {
      tr = (tr << 8) | enc[i].to_int().to_int64()
    }
    assert_eq(read_number(lacked, tr, nb * 8), full)
  }
}

// Packet-number-space bookkeeping (RFC 9000 §12.3, §13.2): monotonic send numbering,
// recording received packets, ACK generation and the ack-pending flag, and the largest
// acknowledged high-water mark.

///|
test "pn space: send numbers are monotonic from zero" {
  let s = Space::new()
  assert_eq(s.next_packet_number(), 0)
  assert_eq(s.next_packet_number(), 1)
  assert_eq(s.next_packet_number(), 2)
}

///|
test "pn space: an ack-eliciting packet owes an ACK; building it clears the flag" {
  let s = Space::new()
  assert_eq(s.ack_pending(), false)
  s.on_packet_received(0, true)
  s.on_packet_received(1, true)
  s.on_packet_received(2, true)
  assert_eq(s.ack_pending(), true)
  match s.build_ack(0) {
    Some(Ack(largest~, first_range~, ranges~, ..)) => {
      assert_eq(largest, 2)
      assert_eq(first_range, 2) // 0..2 contiguous below the largest
      assert_eq(ranges, [])
    }
    _ => abort("expected an ACK frame")
  }
  assert_eq(s.ack_pending(), false)
}

///|
test "pn space: a pure-ACK packet is recorded but owes no new ACK" {
  let s = Space::new()
  s.on_packet_received(0, false) // not ack-eliciting
  assert_eq(s.ack_pending(), false)
  // It is still acknowledged when an ACK is eventually built.
  match s.build_ack(5) {
    Some(Ack(largest~, delay~, ..)) => {
      assert_eq(largest, 0)
      assert_eq(delay, 5)
    }
    _ => abort("expected an ACK frame")
  }
}

///|
test "pn space: no ACK is built before anything is received" {
  let s = Space::new()
  assert_eq(s.build_ack(0), None)
}

///|
test "pn space: largest acknowledged only advances" {
  let s = Space::new()
  assert_eq(s.largest_acked(), None)
  s.on_ack_received(5)
  assert_eq(s.largest_acked(), Some(5))
  s.on_ack_received(3) // an older ACK does not lower it
  assert_eq(s.largest_acked(), Some(5))
  s.on_ack_received(9)
  assert_eq(s.largest_acked(), Some(9))
}

///|
test "pn space: a gap in received packets produces a multi-range ACK" {
  let s = Space::new()
  for pn in [0, 1, 3] {
    s.on_packet_received(pn.to_int64(), true)
  }
  match s.build_ack(0) {
    Some(Ack(largest~, first_range~, ranges~, ..)) => {
      assert_eq(largest, 3)
      assert_eq(first_range, 0) // only 3 in the top range
      assert_eq(ranges, [(0, 1)]) // gap 0, then 0..1
    }
    _ => abort("expected an ACK frame")
  }
}

///|
test "short header encodes its first byte per RFC 9000 §17.3" {
  // spin set, key phase clear, packet-number length 2 -> 0x40 | 0x20 | 0x01 = 0x61.
  let h : Short = {
    spin: true,
    key_phase: false,
    pn_length: 2,
    dcid: qv_hexb("01020304"),
  }
  assert_eq(qv_hex(encode_short(h)), "6101020304")
}

///|
test "short header round-trips across spin, key-phase, and pn length" {
  let dcid = qv_hexb("8394c8f0")
  for spin in [false, true] {
    for kp in [false, true] {
      for pnl in [1, 2, 3, 4] {
        let h : Short = { spin, key_phase: kp, pn_length: pnl, dcid, }
        let encoded = encode_short(h)
        match read_short(encoded[:], dcid.length()) {
          Some((decoded, consumed)) => {
            assert_eq(decoded, h)
            assert_eq(consumed, encoded.length())
          }
          None => fail("short header round-trip failed")
        }
      }
    }
  }
}

///|
test "a long-header first byte and a truncated buffer are rejected" {
  // A long-header first byte (high bit set) is not a short header.
  assert_eq(read_short(qv_hexb("c001020304")[:], 4) is None, true)
  // Fewer bytes than the declared DCID length decodes to None.
  assert_eq(read_short(qv_hexb("610102")[:], 4) is None, true)
}

// QUIC packet payload assembly (RFC 9000 §12.4, §13.2.1, §14.1): frame-list round trip,
// padding, ack-eliciting classification.

///|
test "payload: a frame list round-trips through encode and parse" {
  let frames : Array[@frame.Frame] = [
    Ping,
    Crypto(offset=0, data=b"hello"),
    MaxData(1000),
    Ack(largest=5, delay=0, first_range=5, ranges=[]),
  ]
  let payload = payload(frames)
  assert_eq(read_payload(payload), frames)
}

///|
test "payload: trailing PADDING parses as one Padding frame" {
  // One PING then four zero octets.
  let payload = pad(payload([Ping]), 5)
  assert_eq(payload.length(), 5)
  assert_eq(read_payload(payload), [Ping, Padding(4)])
}

///|
test "payload: pad is a no-op when already long enough" {
  let payload = payload([Crypto(offset=0, data=b"abcdef")])
  let padded = pad(payload, 3)
  assert_eq(padded, payload)
}

///|
test "payload: ack-eliciting classification (RFC 9000 §13.2.1)" {
  // ACK, PADDING, CONNECTION_CLOSE are not ack-eliciting; everything else is.
  assert_eq(@frame.elicits_ack(Ping), true)
  assert_eq(
    @frame.elicits_ack(Ack(largest=0, delay=0, first_range=0, ranges=[])),
    false,
  )
  assert_eq(@frame.elicits_ack(Padding(4)), false)
  assert_eq(
    @frame.elicits_ack(
      ConnectionClose(error_code=0, frame_type=None, reason=b""),
    ),
    false,
  )
  // A payload of only ACK + PADDING is not ack-eliciting; adding any other frame is.
  assert_eq(
    payload_elicits_ack([
      Ack(largest=0, delay=0, first_range=0, ranges=[]),
      Padding(2),
    ]),
    false,
  )
  assert_eq(
    payload_elicits_ack([
      Ack(largest=0, delay=0, first_range=0, ranges=[]),
      Ping,
    ]),
    true,
  )
}

///|
test "payload: an empty payload has no frames" {
  assert_eq(read_payload(b""), [])
}

///|
test "payload: a truncated frame raises" {
  // A CRYPTO frame (type 0x06) with an offset but a length that overruns the buffer.
  let truncated = try {
    let _ = read_payload(b"\x06\x00\x0a\x68\x69")
    false
  } catch {
    _ => true
  }
  assert_eq(truncated, true)
}

///|
/// RFC 9001 §A.2 publishes the client Initial's unprotected header; nothing else in this
/// package is checked against bytes an outside implementation produced.
let a2_initial : String = "c30000000108" +
  "8394c8f03e515708" +
  "0000449e00000002"

///|
test "the RFC 9001 A.2 client Initial header is written byte for byte" {
  let h : Long = {
    packet_type: Initial,
    type_specific: 0,
    version: 1,
    dcid: qv_hexb("8394c8f03e515708"),
    scid: b"",
  }
  // Length is 1182: the four packet-number bytes and 1178 of sealed payload.
  let bytes = h.header(qv_hexb("00000002")[:], payload=1178)
  assert_eq(qv_hex(bytes), a2_initial)
}

///|
test "the A.2 header reads back into its header and tail" {
  guard read_header(qv_hexb(a2_initial)[:]) is Some((h, tail)) else {
    fail("the published header should parse")
  }
  assert_eq(h.packet_type, Initial)
  assert_eq(h.version, 1)
  assert_eq(qv_hex(h.dcid), "8394c8f03e515708")
  assert_eq(h.scid.length(), 0)
  assert_eq(tail.token.length(), 0)
  assert_eq(tail.length, 1182UL)
  // 1 first byte + 4 version + 1 + 8 dcid + 1 + 0 scid + 1 token length + 2 length.
  assert_eq(tail.at, 18)
}

///|
test "an Initial carries its token and a Handshake has no token field" {
  let token = qv_hexb("0badc0de")
  let initial : Long = {
    packet_type: Initial,
    type_specific: 0,
    version: 1,
    dcid: qv_hexb("aabb"),
    scid: qv_hexb("ccdd"),
  }
  let with_token = initial.header(qv_hexb("0001")[:], payload=20, token~)
  guard read_header(with_token[:]) is Some((_, tail)) else {
    fail("an Initial with a token should parse")
  }
  assert_eq(qv_hex(tail.token), "0badc0de")
  assert_eq(tail.length, 22UL)
  assert_eq(with_token.length(), tail.at + 2)

  // The same header as a Handshake: one byte shorter, because the token length field
  // is Initial's alone, and a token handed to it is not written.
  let hs : Long = { ..initial, packet_type: Handshake, }
  let plain = hs.header(qv_hexb("0001")[:], payload=20, token~)
  assert_eq(plain.length(), with_token.length() - 5)
  guard read_header(plain[:]) is Some((got, hs_tail)) else {
    fail("a Handshake header should parse")
  }
  assert_eq(got.packet_type, Handshake)
  assert_eq(hs_tail.token.length(), 0)
  assert_eq(hs_tail.length, 22UL)
}

///|
test "the first byte's low bits follow the packet number's length" {
  let h : Long = {
    packet_type: Handshake,
    type_specific: 0,
    version: 1,
    dcid: b"",
    scid: b"",
  }
  for size in [1, 2, 3, 4] {
    let pn = Bytes::make(size, b'\x07')
    let bytes = h.header(pn[:], payload=0)
    assert_eq(bytes[0].to_int() & 0x03, size - 1)
    guard read_header(bytes[:]) is Some((_, tail)) else {
      fail("a header should parse at every packet-number length")
    }
    assert_eq(tail.length, size.to_uint64())
  }
}

///|
test "a header truncated in the token or the length reads as None" {
  let h : Long = {
    packet_type: Initial,
    type_specific: 0,
    version: 1,
    dcid: b"",
    scid: b"",
  }
  let full = h.header(qv_hexb("00")[:], payload=4, token=qv_hexb("11223344"))
  // Cut anywhere inside the token or the length field and nothing comes back.
  for cut in [8, 9, 10, 11, 12] {
    assert_eq(read_header(full[0:cut]) is None, true)
  }
  assert_eq(read_header(full[:]) is None, false)
}

///|
test "a Retry has no tail to read" {
  let h : Long = {
    packet_type: Retry,
    type_specific: 0,
    version: 1,
    dcid: qv_hexb("aabb"),
    scid: b"",
  }
  let packet = retry(h, token=qv_hexb("6f6b656e"), tag=Bytes::make(16, b'\x5a'))
  assert_eq(read_header(packet[:]) is None, true)
  guard read_retry(packet[:]) is Some((got, token, tag)) else {
    fail("a Retry should parse")
  }
  assert_eq(got, h)
  assert_eq(qv_hex(token), "6f6b656e")
  assert_eq(tag.length(), 16)
  assert_eq(qv_hex(tag), "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
}

///|
test "a Retry shorter than its tag, and a packet that is not one, read as None" {
  let h : Long = {
    packet_type: Retry,
    type_specific: 0,
    version: 1,
    dcid: b"",
    scid: b"",
  }
  let packet = retry(h, token=b"", tag=Bytes::make(16, b'\x00'))
  assert_eq(read_retry(packet[0:packet.length() - 1]) is None, true)
  let initial : Long = { ..h, packet_type: Initial, }
  assert_eq(read_retry(encode_long(initial)[:]) is None, true)
}

///|
test "Version Negotiation round-trips, and its first byte is the caller's" {
  let dcid = qv_hexb("0011223344556677")
  let scid = qv_hexb("8899")
  let offered : Array[UInt] = [1U, 0x6b3343cfU, 0xff00001dU]
  let packet = versions(dcid~, scid~, offered[:])
  // Version zero is what marks the packet (RFC 9000 §17.2.1).
  assert_eq(qv_hex(packet[1:5].to_owned()), "00000000")
  guard read_versions(packet[:]) is Some((d, s, got)) else {
    fail("a Version Negotiation packet should parse")
  }
  assert_eq(qv_hex(d), "0011223344556677")
  assert_eq(qv_hex(s), "8899")
  assert_eq(got, offered)

  // The unused bits are the server's to vary, and varying them changes nothing else.
  let varied = versions(dcid~, scid~, offered[:], first=0x4c)
  assert_eq(varied[0].to_int(), 0xcc)
  assert_eq(qv_hex(varied[1:].to_owned()), qv_hex(packet[1:].to_owned()))
  guard read_versions(varied[:]) is Some((_, _, same)) else {
    fail("a varied first byte should not stop it parsing")
  }
  assert_eq(same, offered)
}

///|
test "a non-zero version and a partial version list are not Version Negotiation" {
  let h : Long = {
    packet_type: Initial,
    type_specific: 0,
    version: 1,
    dcid: b"",
    scid: b"",
  }
  assert_eq(read_versions(encode_long(h)[:]) is None, true)
  let packet = versions(dcid=b"", scid=b"", [1U][:])
  assert_eq(read_versions(packet[0:packet.length() - 1]) is None, true)
  // An empty list is well-formed: a server that speaks nothing says so.
  guard read_versions(packet[0:packet.length() - 4]) is Some((_, _, none)) else {
    fail("an empty version list should parse")
  }
  assert_eq(none.length(), 0)
}

///|
test "a short header ends in its packet number, and its low bits say how long" {
  let h : Short = {
    spin: true,
    key_phase: false,
    pn_length: 1,
    dcid: qv_hexb("c0ffee"),
  }
  for size in [1, 2, 3, 4] {
    let pn = Bytes::make(size, b'	')
    let bytes = h.header(pn[:])
    // First byte, three connection-id bytes, then the number.
    assert_eq(bytes.length(), 4 + size)
    assert_eq(bytes[0].to_int() & 0x03, size - 1)
    assert_eq(qv_hex(bytes[4:].to_owned()), qv_hex(pn))
    guard read_short(bytes[:], 3) is Some((got, at)) else {
      fail("a short header should parse")
    }
    assert_eq(got.pn_length, size)
    assert_eq(got.dcid, h.dcid)
    assert_eq(got.spin, true)
    assert_eq(at, 4)
  }
}
