// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Address validation tokens (RFC 9000 §8.1.2, §17.2.5): what a server gives a client in a
// Retry, and what the client hands back on every Initial after it. A token is the server's own
// bytes — no state is kept between the two packets — and it carries what the server has to know
// when the second one arrives: who it was talking to, which connection id the first Initial
// named, and when. The tag makes the rest unforgeable, and the time bound stops a token being
// used long after it was issued.

///|
/// How long a token stays good, in microseconds. Long enough for a client's second flight,
/// short enough that a recorded token is of little use (RFC 9000 §8.1.2 asks for a bound).
let token_life : Int64 = 10_000_000L

///|
/// The token's first byte, so a later change of layout can be told from this one.
let token_format : Byte = b'\x01'

///|
/// What a token says: the address it was issued for, and the connection id the first Initial
/// named (the Retry's tag and the Initial keys are bound to it).
pub struct Token {
  address : Bytes
  odcid : Bytes
}

///|
/// The token for a client at `address` whose first Initial named `odcid`, stamped with `now`.
/// An endpoint that cannot name an address passes an empty one, and the token then binds the
/// connection id and the time alone.
pub fn issue_token(
  key : Bytes,
  address : Bytes,
  odcid : Bytes,
  now : Int64,
) -> Bytes {
  let body = Buffer()
  body.write_byte(token_format)
  body.write_byte(address.length().to_byte())
  body.write_bytes(address)
  body.write_byte(odcid.length().to_byte())
  body.write_bytes(odcid)
  @fixed.write_u64(body, now.reinterpret_as_uint64())
  let pre = body.to_bytes()
  let tag = @crypto.token_tag(key[:], pre[:])
  let out = Buffer()
  out.write_bytes(pre)
  out.write_bytes(tag)
  out.to_bytes()
}

///|
/// What a token says, or `None` when it is short, of another format, tagged with another key, or
/// older than `token_life`. `now` is the same clock the token was stamped from.
pub fn read_token(
  key : Bytes,
  token : Bytes,
  now : Int64,
  address : Bytes,
) -> Token? {
  guard token.length() >= 2 + 1 + 8 + 16 else { return None }
  guard @crypto.token_ok(key[:], token[:]) else { return None }
  let body = token.length() - 16
  guard token[0] == token_format else { return None }
  let addr_len = token[1].to_int()
  let mut at = 2
  guard body >= at + addr_len + 1 else { return None }
  let bound = token[at:at + addr_len].to_owned()
  at = at + addr_len
  let odcid_len = token[at].to_int()
  at = at + 1
  guard body >= at + odcid_len + 8 else { return None }
  let odcid = token[at:at + odcid_len].to_owned()
  at = at + odcid_len
  let stamped = match @fixed.read_u64(token[:], at~) {
    Some(v) => v.reinterpret_as_int64()
    None => return None
  }
  if now - stamped > token_life || stamped > now {
    return None
  }
  // An endpoint given no way to name its peers issues tokens with an empty address, and those
  // are good for any address: nothing was bound.
  if bound.length() > 0 && bound != address {
    return None
  }
  Some({ address: bound, odcid, })
}
