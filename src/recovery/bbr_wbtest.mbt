// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// BBR's model: the window is the bandwidth-delay product times a gain, and loss is not the
// signal. These check the model is what sizes the window, that a loss leaves it alone, and
// that the floor holds.

///|
test "bbr starts at newreno's initial window" {
  assert_eq(Bbr::new().window(), NewReno::new().window())
  assert_eq(Bbr::new().in_flight(), 0L)
}

///|
test "an acknowledgement takes its bytes out of flight" {
  let cc = Bbr::new()
  cc.on_sent(1200L)
  assert_eq(cc.in_flight(), 1200L)
  cc.on_ack(1200L)
  assert_eq(cc.in_flight(), 0L)
  cc.on_sent(1200L)
  cc.on_lost(1200L)
  assert_eq(cc.in_flight(), 0L)
}

///|
test "the smallest round trip is kept and never raised by a later sample" {
  let cc = Bbr::new()
  cc.on_rtt(sample=80_000L, now=0L)
  assert_eq(cc.min_rtt(), 80_000L)
  cc.on_rtt(sample=120_000L, now=1L)
  assert_eq(cc.min_rtt(), 80_000L)
  cc.on_rtt(sample=60_000L, now=2L)
  assert_eq(cc.min_rtt(), 60_000L)
}

///|
test "a rising delivery rate grows the window above its start" {
  let cc = Bbr::new()
  cc.on_rtt(sample=1000L, now=0L)
  // A rising rate: each one-millisecond sample acknowledges more than the last.
  for k in 1..<=5 {
    cc.on_ack_at(1200L * k.to_int64(), now=k.to_int64() * 1000L)
  }
  assert_eq(cc.bandwidth() > 0.0, true)
  // The estimate is six bytes a microsecond over a one-millisecond path: a six-kilobyte
  // bandwidth-delay product, scaled by startup's gain.
  assert_eq(cc.window() > 12000L, true)
}

///|
test "a loss does not halve a bbr window" {
  let cc = Bbr::new()
  cc.on_rtt(sample=1000L, now=0L)
  for k in 1..<=3 {
    cc.on_ack_at(1200L * k.to_int64(), now=k.to_int64() * 1000L)
  }
  let before = cc.window()
  cc.on_congestion(at=3000L, now=3000L)
  assert_eq(cc.window(), before)
}

///|
test "the window is the model's target or the floor, never less (§7.2)" {
  let cc = Bbr::new()
  cc.on_rtt(sample=1000L, now=0L)
  for k in 1..<=4 {
    cc.on_ack_at(1200L * k.to_int64(), now=k.to_int64() * 1000L)
  }
  assert_eq(cc.window() >= cc.minimum(), true)
  assert_eq(cc.window(), cc.target())
}

///|
test "persistent congestion returns the window to the minimum" {
  let cc = Bbr::new()
  cc.on_rtt(sample=1000L, now=0L)
  for k in 1..<=3 {
    cc.on_ack_at(1200L * k.to_int64(), now=k.to_int64() * 1000L)
  }
  cc.on_persistent()
  assert_eq(cc.window(), cc.minimum())
  assert_eq(cc.bandwidth(), 0.0)
}

///|
test "the state machine drives bbr through the timed acknowledgement" {
  let cc = Bbr::new()
  let s = State::new(control=cc)
  s.on_sent(0L, at=0L, size=1200L)
  let ack : @frame.Frame = Ack(largest=0UL, delay=0UL, first_range=0UL, ranges=[])
  let _ = s.on_ack(ack, 50000L, ack_delay=0L)
  // The one ACK sampled a round trip and a rate; the window is the model's now.
  assert_eq(s.window() >= cc.minimum(), true)
}
