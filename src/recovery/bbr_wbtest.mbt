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

///|
test "startup ends after three rounds without a quarter more bandwidth" {
  let cc = Bbr::new()
  cc.on_rtt(sample=1000L, now=0L)
  // Enough in flight that drain does not finish on the same call.
  cc.on_sent(50_000L)
  cc.on_ack_at(1200L, now=1000L)
  cc.on_ack_at(1200L, now=2000L)
  cc.on_ack_at(1200L, now=3000L)
  assert_eq(cc.mode(), Startup)
  cc.on_ack_at(1200L, now=4000L)
  assert_eq(cc.mode(), Drain)
}

///|
test "drain gives way to probe-bandwidth once what is in flight fits the model" {
  let cc = Bbr::new()
  cc.on_rtt(sample=1000L, now=0L)
  cc.on_sent(50_000L)
  for k in 1..<=4 {
    cc.on_ack_at(1200L, now=k.to_int64() * 1000L)
  }
  assert_eq(cc.mode(), Drain)
  // Everything acknowledged: nothing is in flight, which is below the model.
  cc.on_ack_at(40_000L, now=5000L)
  assert_eq(cc.mode(), ProbeBw)
  // It enters at a gain of 1: the bandwidth was just measured.
  assert_eq(cc.cycle, 2)
}

///|
test "the probe-bandwidth cycle walks a round per position" {
  assert_eq(probe_gain(0), 1.25)
  assert_eq(probe_gain(1), 0.75)
  assert_eq(probe_gain(2), 1.0)
  let cc = Bbr::new()
  cc.on_rtt(sample=1000L, now=0L)
  cc.on_sent(50_000L)
  for k in 1..<=4 {
    cc.on_ack_at(1200L, now=k.to_int64() * 1000L)
  }
  cc.on_ack_at(40_000L, now=5000L)
  assert_eq(cc.mode(), ProbeBw)
  let at = cc.cycle
  // One round later the position has moved; the cycle is what selects the gain.
  cc.on_ack_at(1200L, now=5000L + cc.min_rtt())
  assert_eq(cc.cycle, at + 1)
}

///|
test "probe-rtt waits for a quiet path, holds four datagrams, and leaves on a sample" {
  let cc = Bbr::new()
  cc.on_rtt(sample=1000L, now=0L)
  cc.on_ack_at(1200L, now=1000L)
  assert_eq(cc.mode() is ProbeRtt, false)
  // Ten seconds without a fresher round-trip minimum.
  cc.on_ack_at(1200L, now=12_000_000L)
  assert_eq(cc.mode(), ProbeRtt)
  assert_eq(cc.window(), 4L * 1200L)
  // The stay is 200 ms, and it needs a sample before it can end.
  cc.on_rtt(sample=900L, now=12_050_000L)
  cc.on_ack_at(1200L, now=12_100_000L)
  // Still inside the 200 milliseconds.
  assert_eq(cc.mode(), ProbeRtt)
  cc.on_ack_at(1200L, now=12_200_001L)
  assert_eq(cc.mode(), ProbeBw)
}

///|
test "pacing is the bandwidth times the pacing gain, which is not the window gain" {
  let cc = Bbr::new()
  cc.on_rtt(sample=1000L, now=0L)
  assert_true(cc.pacing_rate() is None)
  cc.on_ack_at(1200L, now=1000L)
  guard cc.pacing_rate() is Some(rate) else { fail("no pacing rate") }
  // Startup paces at 2.885 times the measured rate, while the window holds 2.885 times the
  // bandwidth-delay product plus headroom.
  assert_true(rate > cc.bandwidth())
  assert_true(cc.window() > cc.bdp())
}
