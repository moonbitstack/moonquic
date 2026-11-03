// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// DATAGRAM frames (RFC 9221): the length-prefixed form round-trips, the length-less form
// runs to the end of the packet, a truncated one is refused, and either is ack-eliciting.

///|
test "a datagram round-trips through the length-prefixed form" {
  let frame : Frame = Datagram(data=b"hello")
  let wire = encode(frame)
  // 0x31, then a one-byte length of 5, then the bytes.
  assert_eq(wire[0], b'\x31')
  assert_eq(wire[1], b'\x05')
  match decode(wire[:]) {
    Some((got, used)) => {
      assert_eq(got, frame)
      assert_eq(used, wire.length())
    }
    None => abort("a datagram did not decode")
  }
}

///|
test "a datagram without a length runs to the end of the packet" {
  let wire = b"\x30hello"
  match decode(wire[:]) {
    Some((Datagram(data~), used)) => {
      assert_eq(data, b"hello")
      assert_eq(used, wire.length())
    }
    _ => abort("a length-less datagram did not decode")
  }
}

///|
test "a truncated datagram is refused" {
  // The length says five bytes but only two follow.
  assert_eq(decode(b"\x31\x05hi"[:]) is None, true)
}

///|
test "a datagram is ack-eliciting" {
  assert_eq(elicits_ack(Datagram(data=b"x")), true)
  assert_eq(elicits_ack(Padding(3)), false)
}
