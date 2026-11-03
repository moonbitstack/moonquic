// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Stateless reset (RFC 9000 §10.3): when a datagram names a connection this endpoint no
// longer holds, it answers with a packet indistinguishable from a 1-RTT one whose last
// sixteen bytes are the reset token the peer was given for that connection id. The token is
// a function of the id and a key this endpoint keeps, so the same id always yields the same
// token and no per-connection state is needed to answer.

///|
/// The sixteen-byte stateless reset token for `cid`, derived from the endpoint's `key`. The
/// same pair always yields the same token, which is what lets an endpoint answer for a
/// connection it has already forgotten.
pub fn reset_token(key : Bytes, cid : Bytes) -> Bytes {
  // A labelled HKDF expansion over the id, with the key as the secret: deterministic, and
  // different for every id.
  @crypto.update(join(key, cid)[:], suite=@crypto.suite)[0:16].to_owned()
}

///|
/// A stateless reset carrying `token`: a short-header-looking packet of at least `min` bytes
/// whose last sixteen are the token (RFC 9000 §10.3). The bytes before the token are random,
/// so two resets for the same connection do not look alike.
pub fn stateless_reset(
  token : Bytes,
  rand : (Int32) -> Bytes,
  min~ : Int32 = 21,
) -> Bytes {
  let len = if min < 21 { 21 } else { min }
  let noise = rand(len)
  let buf = Buffer()
  // The high bit clear and the fixed bit set, which is what a short header looks like.
  buf.write_byte(((noise[0].to_int() & 0x3f) | 0x40).to_byte())
  buf.write_bytes(noise[1:len - 16])
  buf.write_bytes(token[0:16])
  buf.to_bytes()
}

///|
/// Whether `packet` is a stateless reset carrying `token`: a short-header-form datagram of at
/// least 21 bytes whose last sixteen bytes are the token.
pub fn is_stateless_reset(packet : BytesView, token : BytesView) -> Bool {
  if token.length() < 16 || packet.length() < 21 {
    return false
  }
  // A long header is never a stateless reset.
  if (packet[0].to_int() & 0x80) != 0 {
    return false
  }
  let cut = packet.length() - 16
  let mut diff = 0
  for i = 0; i < 16; i = i + 1 {
    diff = diff | (packet[cut + i].to_int() ^ token[i].to_int())
  }
  diff == 0
}
