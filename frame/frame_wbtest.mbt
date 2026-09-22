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
test "CRYPTO frame encodes and parses per RFC 9000 §19.6" {
  // offset 1, data aabb -> type 06, offset 01, length 02, then the data.
  let f : Frame = Crypto(offset=1UL, data=qv_hexb("aabb"))
  assert_eq(qv_hex(encode(f)), "060102aabb")
  match parse(qv_hexb("060102aabb")[:]) {
    Some((g, n)) => {
      assert_eq(g, f)
      assert_eq(n, 5)
    }
    None => fail("expected a CRYPTO frame")
  }
}

///|
test "PING and PADDING frames round-trip" {
  assert_eq(qv_hex(encode(Ping)), "01")
  match parse(qv_hexb("01")[:]) {
    Some((g, n)) => {
      assert_eq(g, Ping)
      assert_eq(n, 1)
    }
    None => fail("expected PING")
  }
  assert_eq(qv_hex(encode(Padding(3))), "000000")
  // A run of zero bytes is one PADDING frame; it stops at the following PING byte.
  match parse(qv_hexb("00000001")[:]) {
    Some((g, n)) => {
      assert_eq(g, Padding(3))
      assert_eq(n, 3)
    }
    None => fail("expected PADDING")
  }
}

///|
test "CRYPTO frame with a large offset uses a multi-byte varint" {
  let f : Frame = Crypto(offset=15293UL, data=qv_hexb("00"))
  // offset 15293 encodes as the two-byte varint 7bbd.
  let enc = encode(f)
  assert_eq(qv_hex(enc), "067bbd0100")
  match parse(enc[:]) {
    Some((g, _)) => assert_eq(g, f)
    None => fail("expected CRYPTO")
  }
}

///|
test "a truncated CRYPTO frame parses to None" {
  // Declares 4 bytes of crypto data but supplies only 1.
  assert_eq(parse(qv_hexb("060004aa")[:]) is None, true)
}

///|
test "STREAM frame round-trips with offset, length, and FIN (RFC 9000 §19.8)" {
  // type 0e (OFF + LEN), stream 4, offset 0, length 5, data "hello".
  let f : Frame = Stream(
    id=4UL,
    offset=0UL,
    fin=false,
    data=qv_hexb("68656c6c6f"),
  )
  assert_eq(qv_hex(encode(f)), "0e04000568656c6c6f")
  match parse(qv_hexb("0e04000568656c6c6f")[:]) {
    Some((g, n)) => {
      assert_eq(g, f)
      assert_eq(n, 9)
    }
    None => fail("expected a STREAM frame")
  }
  // FIN rides the low bit of the type (0f).
  let ff : Frame = Stream(id=4UL, offset=10UL, fin=true, data=qv_hexb("78"))
  assert_eq(qv_hex(encode(ff)), "0f040a0178")
  match parse(qv_hexb("0f040a0178")[:]) {
    Some((g, _)) => assert_eq(g, ff)
    None => fail("expected a STREAM frame with FIN")
  }
}

///|
test "ACK frame encodes and parses per RFC 9000 §19.3" {
  // largest 10, delay 0, no additional ranges, first range 3.
  let f : Frame = Ack(largest=10UL, delay=0UL, first_range=3UL, ranges=[])
  assert_eq(qv_hex(encode(f)), "020a000003")
  match parse(qv_hexb("020a000003")[:]) {
    Some((g, n)) => {
      assert_eq(g, f)
      assert_eq(n, 5)
    }
    None => fail("expected an ACK frame")
  }
  // With one extra range: gap 1, range length 3.
  let f2 : Frame = Ack(largest=10UL, delay=0UL, first_range=2UL, ranges=[
    (1UL, 3UL),
  ])
  assert_eq(qv_hex(encode(f2)), "020a0001020103")
  match parse(qv_hexb("020a0001020103")[:]) {
    Some((g, n)) => {
      assert_eq(g, f2)
      assert_eq(n, 7)
    }
    None => fail("expected an ACK frame with a range")
  }
}

///|
test "a truncated ACK frame parses to None" {
  // Declares one range but supplies no gap/length pair.
  assert_eq(parse(qv_hexb("020a000102")[:]) is None, true)
}

///|
test "MAX_DATA and HANDSHAKE_DONE frames round-trip (RFC 9000 §19.9 / §19.20)" {
  assert_eq(qv_hex(encode(MaxData(15293UL))), "107bbd")
  match parse(qv_hexb("107bbd")[:]) {
    Some((g, n)) => {
      assert_eq(g, MaxData(15293UL))
      assert_eq(n, 3)
    }
    None => fail("expected MAX_DATA")
  }
  assert_eq(qv_hex(encode(HandshakeDone)), "1e")
  match parse(qv_hexb("1e")[:]) {
    Some((g, n)) => {
      assert_eq(g, HandshakeDone)
      assert_eq(n, 1)
    }
    None => fail("expected HANDSHAKE_DONE")
  }
}

///|
test "CONNECTION_CLOSE transport and application variants (RFC 9000 §19.19)" {
  // Transport close (0x1c): error code, triggering frame type, reason.
  let t : Frame = ConnectionClose(
    error_code=7UL,
    frame_type=Some(8UL),
    reason=qv_hexb("6279"),
  )
  assert_eq(qv_hex(encode(t)), "1c0708026279")
  match parse(qv_hexb("1c0708026279")[:]) {
    Some((g, _)) => assert_eq(g, t)
    None => fail("expected a transport CONNECTION_CLOSE")
  }
  // Application close (0x1d): error code, reason, no frame type.
  let a : Frame = ConnectionClose(
    error_code=1UL,
    frame_type=None,
    reason=qv_hexb(""),
  )
  assert_eq(qv_hex(encode(a)), "1d0100")
  match parse(qv_hexb("1d0100")[:]) {
    Some((g, _)) => assert_eq(g, a)
    None => fail("expected an application CONNECTION_CLOSE")
  }
}

///|
test "a STREAM frame with no length field runs to the end of the buffer" {
  // type 0c = OFF set, LEN clear: stream id, offset, then data to the end.
  match parse(qv_hexb("0c0400aabb")[:]) {
    Some((g, n)) => {
      assert_eq(g, Stream(id=4UL, offset=0UL, fin=false, data=qv_hexb("aabb")))
      assert_eq(n, 5)
    }
    None => fail("expected a length-less STREAM frame")
  }
}

///|
test "RESET_STREAM and STOP_SENDING round-trip (RFC 9000 §19.4/§19.5)" {
  let rs : Frame = ResetStream(id=4UL, error_code=0UL, final_size=100UL)
  // type 04, id 04, error 00, final_size 100 -> two-byte varint 4064.
  assert_eq(qv_hex(encode(rs)), "0404004064")
  match parse(qv_hexb("0404004064")[:]) {
    Some((g, n)) => {
      assert_eq(g, rs)
      assert_eq(n, 5)
    }
    None => fail("expected RESET_STREAM")
  }
  let ss : Frame = StopSending(id=8UL, error_code=2UL)
  assert_eq(qv_hex(encode(ss)), "050802")
  match parse(qv_hexb("050802")[:]) {
    Some((g, _)) => assert_eq(g, ss)
    None => fail("expected STOP_SENDING")
  }
}

///|
test "flow-control frames round-trip (RFC 9000 §19.10-§19.14)" {
  let frames : Array[Frame] = [
    MaxStreamData(id=4UL, max=1024UL),
    MaxStreams(bidi=true, max=5UL),
    MaxStreams(bidi=false, max=3UL),
    DataBlocked(2048UL),
    StreamDataBlocked(id=8UL, max=512UL),
    StreamsBlocked(bidi=true, max=1UL),
    StreamsBlocked(bidi=false, max=7UL),
  ]
  for f in frames {
    let enc = encode(f)
    match parse(enc[:]) {
      Some((g, n)) => {
        assert_eq(g, f)
        assert_eq(n, enc.length())
      }
      None => fail("flow-control frame should parse")
    }
  }
  // MAX_STREAMS bidi uses type 0x12, uni 0x13.
  assert_eq(qv_hex(encode(MaxStreams(bidi=true, max=5UL))), "1205")
  assert_eq(qv_hex(encode(MaxStreams(bidi=false, max=5UL))), "1305")
}

///|
test "connection-management and path frames round-trip (RFC 9000 §19.7/§19.15-§19.18)" {
  let nt : Frame = NewToken(token=qv_hexb("aabbcc"))
  assert_eq(qv_hex(encode(nt)), "0703aabbcc")
  match parse(qv_hexb("0703aabbcc")[:]) {
    Some((g, _)) => assert_eq(g, nt)
    None => fail("expected NEW_TOKEN")
  }
  let nci : Frame = NewConnectionId(
    seq=1UL,
    retire_prior_to=0UL,
    conn_id=qv_hexb("aabbccdd"),
    reset_token=qv_hexb("000102030405060708090a0b0c0d0e0f"),
  )
  assert_eq(
    qv_hex(encode(nci)),
    "18010004aabbccdd000102030405060708090a0b0c0d0e0f",
  )
  match parse(encode(nci)[:]) {
    Some((g, _)) => assert_eq(g, nci)
    None => fail("expected NEW_CONNECTION_ID")
  }
  let rci : Frame = RetireConnectionId(3UL)
  assert_eq(qv_hex(encode(rci)), "1903")
  match parse(qv_hexb("1903")[:]) {
    Some((g, _)) => assert_eq(g, rci)
    None => fail("expected RETIRE_CONNECTION_ID")
  }
  let pc : Frame = PathChallenge(qv_hexb("0011223344556677"))
  assert_eq(qv_hex(encode(pc)), "1a0011223344556677")
  match parse(qv_hexb("1a0011223344556677")[:]) {
    Some((g, n)) => {
      assert_eq(g, pc)
      assert_eq(n, 9)
    }
    None => fail("expected PATH_CHALLENGE")
  }
  let pr : Frame = PathResponse(qv_hexb("8899aabbccddeeff"))
  assert_eq(qv_hex(encode(pr)), "1b8899aabbccddeeff")
  match parse(qv_hexb("1b8899aabbccddeeff")[:]) {
    Some((g, _)) => assert_eq(g, pr)
    None => fail("expected PATH_RESPONSE")
  }
}

///|
test "ACK_ECN encodes and parses per RFC 9000 §19.3.2" {
  // Type 03, the ACK body, then the ECT(0), ECT(1) and CE counts.
  let f : Frame = AckEcn(
    largest=233UL,
    delay=23UL,
    first_range=2UL,
    ranges=[(1UL, 3UL)],
    ect0=66UL,
    ect1=6UL,
    ce=1UL,
  )
  assert_eq(qv_hex(encode(f)), "0340e9170102010340420601")
  match parse(encode(f)[:]) {
    Some((g, n)) => {
      assert_eq(g, f)
      assert_eq(n, encode(f).length())
    }
    None => fail("expected an ACK_ECN frame")
  }
}

///|
test "ACK_ECN acknowledges the same packets an ACK does, and elicits no ACK itself" {
  let plain : Frame = Ack(largest=233UL, delay=23UL, first_range=2UL, ranges=[
    (1UL, 3UL),
  ])
  let ecn : Frame = AckEcn(
    largest=233UL,
    delay=23UL,
    first_range=2UL,
    ranges=[(1UL, 3UL)],
    ect0=66UL,
    ect1=6UL,
    ce=1UL,
  )
  // The ECN counts are congestion feedback, not acknowledgement: the ranges must agree, or
  // loss recovery would read an ECN-enabled peer's ACKs differently from a plain peer's.
  assert_eq(ecn.acked(), plain.acked())
  assert_eq(elicits_ack(ecn), false)
}

///|
test "a truncated ACK_ECN parses to None" {
  // The ACK body is complete but only two of the three ECN counts follow.
  assert_eq(parse(qv_hexb("0340e91701020103404206")[:]) is None, true)
}

///|
test "a truncated PATH_CHALLENGE parses to None" {
  // Declares the frame but supplies only 4 of the 8 data bytes.
  assert_eq(parse(qv_hexb("1a00112233")[:]) is None, true)
}

// QUIC ACK generation (RFC 9000 §19.3): building the Largest / First Range / (Gap,
// Length) fields from a received-packet set, the inverse reconstruction, and a
// round-trip through the ACK frame codec.

///|
test "ack: fields for a set with two gaps match RFC 9000 §19.3" {
  let set = Seen::new()
  for pn in [0, 1, 2, 4, 5, 7] {
    set.add(pn.to_uint64())
  }
  assert_eq(set.largest(), Some(7))
  assert_eq(set.contains(3), false)
  assert_eq(set.contains(5), true)
  // Largest 7, First Range 0 (only 7 in the top range), then two (Gap, Length) pairs.
  match set.fields() {
    Some((largest, first_range, pairs)) => {
      assert_eq(largest, 7)
      assert_eq(first_range, 0)
      assert_eq(pairs, [(0, 1), (0, 2)])
    }
    None => abort("expected ack fields")
  }
}

///|
test "ack: fields and ack_fields_to_ranges round-trip" {
  let set = Seen::new()
  for pn in [0, 1, 2, 4, 5, 7] {
    set.add(pn.to_uint64())
  }
  guard set.fields() is Some((largest, first_range, pairs)) else {
    fail("fields should be Some for this ack set")
  }
  assert_eq(Seen::read(largest, first_range, pairs).ranges(), [
    (0, 2),
    (4, 5),
    (7, 7),
  ])
}

///|
test "ack: fields survive the ACK frame codec (encode then parse)" {
  let set = Seen::new()
  for pn in [10, 11, 12, 20] {
    set.add(pn.to_uint64())
  }
  guard set.fields() is Some((largest, first_range, pairs)) else {
    fail("fields should be Some for this ack set")
  }
  let frame : Frame = Ack(largest~, delay=42, first_range~, ranges=pairs)
  match parse(encode(frame)[:]) {
    Some((decoded, _)) => assert_eq(decoded, frame)
    None => abort("expected a parsable ACK frame")
  }
  // And the reconstructed ranges match what went in.
  assert_eq(Seen::read(largest, first_range, pairs).ranges(), [
    (10, 12),
    (20, 20),
  ])
}

///|
test "ack: a single packet and a contiguous run" {
  let one = Seen::new()
  one.add(5)
  match one.fields() {
    Some((largest, first_range, pairs)) => {
      assert_eq(largest, 5)
      assert_eq(first_range, 0)
      assert_eq(pairs, [])
    }
    None => abort("expected ack fields")
  }
  let run = Seen::new()
  for pn in [3, 4, 5, 6] {
    run.add(pn.to_uint64())
  }
  guard run.fields() is Some((largest, first_range, pairs)) else {
    fail("fields should be Some for this ack set")
  }
  assert_eq((largest, first_range), (6, 3))
  assert_eq(pairs, [])
}

///|
test "ack: out-of-order and duplicate additions coalesce" {
  let set = Seen::new()
  for pn in [7, 3, 5, 4, 3, 6] {
    // 3..7 with a duplicate 3, arriving out of order
    set.add(pn.to_uint64())
  }
  guard set.fields() is Some((largest, first_range, pairs)) else {
    fail("fields should be Some for this ack set")
  }
  assert_eq((largest, first_range), (7, 4)) // 3..7 is one range
  assert_eq(pairs, [])
}

///|
test "ack: empty set has no fields" {
  let set = Seen::new()
  assert_eq(set.is_empty(), true)
  assert_eq(set.largest(), None)
  assert_eq(set.fields(), None)
}

///|
test "ack: a gap that underflows the packet-number space is rejected" {
  // Largest 3, first range 0 -> smallest 3; a Gap of 5 would put the next range below 0.
  let bad = try {
    let _ = Seen::read(3, 0, [(5, 0)]).ranges()
    false
  } catch {
    _ => true
  }
  assert_eq(bad, true)
}
