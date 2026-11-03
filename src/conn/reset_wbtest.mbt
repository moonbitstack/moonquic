// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
test "a reset token is deterministic per connection id" {
  let key = Bytes::make(32, 7)
  let a = reset_token(key, b"conn-1")
  let b = reset_token(key, b"conn-1")
  let c = reset_token(key, b"conn-2")
  assert_eq(a, b)
  assert_eq(a.length(), 16)
  assert_eq(a == c, false)
}

///|
test "a stateless reset is recognised by its token and nothing else" {
  let token = reset_token(Bytes::make(32, 7), b"conn-1")
  let reset = stateless_reset(token, fake_rand(3))
  assert_eq(reset.length(), 21)
  assert_eq(reset[0].to_int() & 0x80, 0)
  assert_eq(is_stateless_reset(reset[:], token), true)
  let other = reset_token(Bytes::make(32, 7), b"conn-2")
  assert_eq(is_stateless_reset(reset[:], other), false)
  // A long header is never a stateless reset, however its bytes end.
  let buf = Buffer()
  buf.write_byte(b'\xc0')
  buf.write_bytes(Bytes::make(20, 0))
  assert_eq(is_stateless_reset(buf.to_bytes()[:], token), false)
}
