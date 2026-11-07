// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The nonce a multipath packet is packet under (draft-ietf-quic-multipath §2.4). The draft's own
// vector is the authority: an IV, a path id and a packet number go in, one nonce comes out.

///|
test "the draft's nonce vector comes out of the path-and-packet-number" {
  let iv = b"\x6b\x26\x11\x4b\x9c\xba\x2b\x63\xa9\xe8\xdd\x4f"
  // Figure 3: path 3, packet number 54321 (0xd431).
  assert_eq(
    path_nonce(iv[:], 3UL, 54321L),
    b"\x6b\x26\x11\x48\x9c\xba\x2b\x63\xa9\xe8\x09\x7e",
  )
}

///|
test "path 0 gives the nonce RFC 9001 gives" {
  let iv = b"\x6b\x26\x11\x4b\x9c\xba\x2b\x63\xa9\xe8\xdd\x4f"
  // The same IV with no path: only the low eight bytes are touched.
  assert_eq(
    path_nonce(iv[:], 0UL, 54321L),
    b"\x6b\x26\x11\x4b\x9c\xba\x2b\x63\xa9\xe8\x09\x7e",
  )
}

///|
test "two paths never share a nonce for the same packet number" {
  let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
  let one = path_nonce(iv[:], 1UL, 7L)
  let two = path_nonce(iv[:], 2UL, 7L)
  assert_true(one != two)
  // The path id rides in the top four bytes, in network order, and the packet number in the low
  // eight. IV 00010203 040506070809 0a0b, so path 1 gives 00010202 and path 2 gives 00010201.
  assert_eq(one[0:4].to_owned(), b"\x00\x01\x02\x02")
  assert_eq(two[0:4].to_owned(), b"\x00\x01\x02\x01")
  // The packet number keeps the low eight bytes: 0x0b XOR 7 is 0x0c.
  assert_eq(one[11], b'\x0c')
  assert_eq(two[11], b'\x0c')
}

///|
test "a key seals and opens under a path, and another path's nonce does not open it" {
  let (_, keys) = initial(b"\x83\x94\xc8\xf0\x3e\x51\x57\x08")
  let header = b"\x43\xaa\xbb\xcc\xdd\x00\x00\x00\x07"
  let payload = b"the path's own packet"
  let packet = keys.seal(header[:], payload[:], number=7L, path=1UL)
  let opened = keys.open(packet[:], largest=-1L, at=5, path=1UL)
  guard opened is Some((plain, pn)) else { fail("the packet did not open") }
  assert_eq(plain, payload)
  assert_eq(pn, 7L)
  // The same bytes under path 0 are a different nonce, so the tag does not match.
  assert_true(keys.open(packet[:], largest=-1L, at=5, path=0UL) is None)
}
