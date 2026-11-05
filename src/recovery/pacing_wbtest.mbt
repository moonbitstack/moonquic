// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Pacing (RFC 9002 §7.7): a burst is allowed, and the rest of the window is spread over the
// round trip.

///|
test "a pacer lets a burst through and spaces what follows" {
  let pacer = Pacer::new(burst_bytes=1200L)
  pacer.set_rate(1.0)
  assert_true(pacer.allow(0L, 1200L))
  pacer.spend(0L, 1200L)
  assert_false(pacer.allow(0L, 1200L))
  // One byte a microsecond: the next datagram's worth is 1200 microseconds away.
  assert_eq(pacer.next_at(0L, 1200L), Some(1200L))
  assert_true(pacer.allow(1200L, 1200L))
}

///|
test "an unpaced pacer holds nothing back" {
  let pacer = Pacer::new(burst_bytes=1L)
  for _ in 0..<100 {
    assert_true(pacer.allow(0L, 1200L))
    pacer.spend(0L, 1200L)
  }
  assert_eq(pacer.next_at(0L, 1200L), None)
}

///|
test "a rate of zero turns pacing off again" {
  let pacer = Pacer::new(burst_bytes=1200L)
  pacer.set_rate(1.0)
  pacer.spend(0L, 1200L)
  assert_false(pacer.allow(0L, 1200L))
  pacer.set_rate(0.0)
  assert_true(pacer.allow(0L, 1200L))
}
