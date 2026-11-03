// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Path validation (RFC 9000 §8.2, §9.3): a path is proven when a PATH_CHALLENGE sent on it
// comes back as a PATH_RESPONSE carrying the same eight bytes. Until then the path is
// unvalidated, and a connection that has moved must not trust it with anything it would not
// send a stranger. This is the state; the frames are `frame`'s and the sending is the
// connection's.

///|
/// One path's validation state: the challenge outstanding, if any, and whether the path has
/// ever been proven.
pub struct Path {
  mut challenge : Bytes
  mut validated : Bool
}

///|
/// A path nothing has been sent on yet: no challenge, not validated.
pub fn Path::new() -> Path {
  { challenge: b"", validated: false, }
}

///|
/// Begin validating the path with the eight-byte `nonce`, answering the challenge to put in a
/// PATH_CHALLENGE. A new challenge supersedes one still outstanding, and a path that was
/// validated has to prove itself again.
pub fn Path::start(self : Path, nonce : Bytes) -> Bytes {
  self.challenge = nonce
  self.validated = false
  nonce
}

///|
/// The challenge still outstanding, or empty when there is none.
pub fn Path::challenge(self : Path) -> Bytes {
  self.challenge
}

///|
/// Whether a PATH_RESPONSE's `data` answers the outstanding challenge. The comparison runs
/// over the whole challenge and accumulates rather than stopping at the first byte, so how
/// long it takes says nothing about how much of the value was guessed. A response with no
/// challenge outstanding, or of another length, never validates.
pub fn Path::check(self : Path, data : Bytes) -> Bool {
  if self.challenge.length() == 0 || data.length() != self.challenge.length() {
    return false
  }
  let mut diff = 0
  for i = 0; i < data.length(); i = i + 1 {
    diff = diff | (data[i].to_int() ^ self.challenge[i].to_int())
  }
  if diff == 0 {
    self.validated = true
    self.challenge = b""
    true
  } else {
    false
  }
}

///|
/// Whether the path has been proven.
pub fn Path::validated(self : Path) -> Bool {
  self.validated
}

///|
/// Forget the path: no challenge outstanding and no proof, as after a connection moves to a
/// path that has never answered.
pub fn Path::reset(self : Path) -> Unit {
  self.challenge = b""
  self.validated = false
}
