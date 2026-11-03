// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
test "a challenge is answered only by the same eight bytes" {
  let p = Path::new()
  assert_eq(p.validated(), false)
  let c = p.start(b"12345678")
  assert_eq(c, b"12345678")
  // A response one byte off, or of another length, proves nothing.
  assert_eq(p.check(b"12345679"), false)
  assert_eq(p.check(b"1234567"), false)
  assert_eq(p.validated(), false)
  assert_eq(p.check(b"12345678"), true)
  assert_eq(p.validated(), true)
  // The challenge is consumed, so a further response proves nothing.
  assert_eq(p.check(b"12345678"), false)
}

///|
test "a new challenge unvalidates a proven path" {
  let p = Path::new()
  let _ = p.start(b"aaaaaaaa")
  assert_eq(p.check(b"aaaaaaaa"), true)
  assert_eq(p.validated(), true)
  let _ = p.start(b"bbbbbbbb")
  assert_eq(p.validated(), false)
  assert_eq(p.challenge(), b"bbbbbbbb")
}

///|
test "resetting a path forgets its proof" {
  let p = Path::new()
  let _ = p.start(b"aaaaaaaa")
  assert_eq(p.check(b"aaaaaaaa"), true)
  p.reset()
  assert_eq(p.validated(), false)
  assert_eq(p.challenge().length(), 0)
}
