// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// QUIC (RFC 9000) — the transport under HTTP/3. Built on the UDP datagram socket
// moonbitlang/async provides (`@socket.UdpClient`). This file is the first brick:
// the variable-length integer that every QUIC packet and frame field is measured
// in. The rest of the QUIC stack (packet headers, frames, the RFC 9001 TLS
// handshake, RFC 9114 HTTP/3, RFC 9204 QPACK) lands on top of it.

///|
/// Encode `v` as a QUIC variable-length integer (RFC 9000 §16) in the shortest
/// form that holds it: the two most-significant bits of the first byte select the
/// length (00 → 1 byte / 6-bit value, 01 → 2 / 14-bit, 10 → 4 / 30-bit, 11 → 8 /
/// 62-bit) and the remaining bits carry the value big-endian. `v` must be below
/// 2^62 (QUIC's varint ceiling).
pub fn encode(v : UInt64) -> Bytes {
  let buf = Buffer()
  if v <= 0x3fUL {
    buf.write_byte(v.to_byte())
  } else if v <= 0x3fffUL {
    buf.write_byte((0x40UL | (v >> 8)).to_byte())
    buf.write_byte(v.to_byte())
  } else if v <= 0x3fffffffUL {
    buf.write_byte((0x80UL | (v >> 24)).to_byte())
    buf.write_byte((v >> 16).to_byte())
    buf.write_byte((v >> 8).to_byte())
    buf.write_byte(v.to_byte())
  } else {
    buf.write_byte((0xc0UL | (v >> 56)).to_byte())
    buf.write_byte((v >> 48).to_byte())
    buf.write_byte((v >> 40).to_byte())
    buf.write_byte((v >> 32).to_byte())
    buf.write_byte((v >> 24).to_byte())
    buf.write_byte((v >> 16).to_byte())
    buf.write_byte((v >> 8).to_byte())
    buf.write_byte(v.to_byte())
  }
  buf.to_bytes()
}

///|
/// Decode a QUIC variable-length integer at the start of `b`, returning its value
/// and the number of bytes it occupied, or `None` when `b` is shorter than the
/// length its first byte's prefix declares.
pub fn decode(b : BytesView) -> (UInt64, Int)? {
  if b.length() == 0 {
    return None
  }
  let first = b[0].to_int()
  let length = 1 << (first >> 6)
  if b.length() < length {
    return None
  }
  let mut v = (first & 0x3f).to_uint64()
  for i = 1; i < length; i = i + 1 {
    v = (v << 8) | b[i].to_int().to_uint64()
  }
  Some((v, length))
}
