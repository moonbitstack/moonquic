// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Decode a hex string to bytes.
fn qv_hexb(h : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < h.length(); i = i + 2 {
    let hi = qv_nibble(h[i].to_int())
    let lo = qv_nibble(h[i + 1].to_int())
    buf.write_byte(((hi << 4) | lo).to_byte())
  }
  buf.to_bytes()
}

///|
fn qv_nibble(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else {
    0
  }
}

///|
/// Bytes as a lowercase hex string.
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
test "QUIC varint decodes the RFC 9000 A.1 vectors" {
  assert_eq(
    decode(qv_hexb("c2197c5eff14e88c")[:]),
    Some((151288809941952652UL, 8)),
  )
  assert_eq(decode(qv_hexb("9d7f3e7d")[:]), Some((494878333UL, 4)))
  assert_eq(decode(qv_hexb("7bbd")[:]), Some((15293UL, 2)))
  assert_eq(decode(qv_hexb("25")[:]), Some((37UL, 1)))
  // The non-minimal two-byte encoding of 37 also decodes to 37 (RFC 9000 A.1).
  assert_eq(decode(qv_hexb("4025")[:]), Some((37UL, 2)))
  // A prefix that promises more bytes than are present decodes to None.
  assert_eq(decode(qv_hexb("c2")[:]), None)
  assert_eq(decode(qv_hexb("")[:]), None)
}

///|
test "QUIC varint encodes to the shortest RFC 9000 form" {
  assert_eq(qv_hex(encode(37UL)), "25")
  assert_eq(qv_hex(encode(15293UL)), "7bbd")
  assert_eq(qv_hex(encode(494878333UL)), "9d7f3e7d")
  assert_eq(qv_hex(encode(151288809941952652UL)), "c2197c5eff14e88c")
}

///|
test "QUIC varint round-trips across every length boundary" {
  let cases = [
    0UL, 1UL, 63UL, 64UL, 16383UL, 16384UL, 1073741823UL, 1073741824UL, 4611686018427387903UL,
  ]
  for v in cases {
    let encoded = encode(v)
    match decode(encoded[:]) {
      Some((dv, n)) => {
        assert_eq(dv, v)
        assert_eq(n, encoded.length())
      }
      None => fail("round-trip decode failed for " + v.to_string())
    }
  }
}
