// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// CUBIC's own arithmetic, worked out here so a failure says which part of RFC 9438 moved.
// The curve test recomputes the target from the RFC's formula rather than calling the
// implementation's own helper, so a changed exponent or scaling constant shows up as a
// different window.

///|
test "cubic starts at newreno's initial window (§7.2)" {
  assert_eq(Cubic::new().window(), NewReno::new().window())
  assert_eq(Cubic::new().in_flight(), 0L)
}

///|
test "before its first reduction cubic slow-starts by every acknowledged byte" {
  let cc = Cubic::new()
  let start = cc.window()
  cc.on_ack_at(1200L, now=0L)
  assert_eq(cc.window(), start + 1200L)
}

///|
test "an acknowledgement takes its bytes out of flight" {
  let cc = Cubic::new()
  cc.on_sent(1200L)
  assert_eq(cc.in_flight(), 1200L)
  cc.on_ack(1200L)
  assert_eq(cc.in_flight(), 0L)
  // A loss takes them out too, without touching the window.
  cc.on_sent(1200L)
  let before = cc.window()
  cc.on_lost(1200L)
  assert_eq(cc.in_flight(), 0L)
  assert_eq(cc.window(), before)
}

///|
test "a reduction falls to seven tenths, not to half (§4.6)" {
  let cc = Cubic::new()
  let start = cc.window()
  cc.on_congestion(at=1000L, now=1000L)
  let expected = (start.to_double() * 0.7).to_int64()
  assert_eq(cc.window(), expected)
  assert_eq(cc.ssthresh(), expected)
}

///|
test "the window after a reduction follows C·(t−K)³ + W_max (§4.2)" {
  let cc = Cubic::new()
  cc.on_congestion(at=0L, now=0L)
  // Independently reproduce the RFC's arithmetic: W_max = 10 segments, the reduced
  // window 7, K = cbrt((10 − 7)/0.4). At ten seconds the cubic term dominates the
  // Reno-friendly estimate, so a change to C or the exponent changes the answer.
  let seg = 1200.0
  let t = 10.0
  let w_max = 12000.0 / seg
  let w_epoch = 8400.0 / seg
  let k = @math.cbrt((w_max - w_epoch) / 0.4)
  let cubic = 0.4 * (t - k) * (t - k) * (t - k) + w_max
  let est = w_max * 0.7 + 3.0 * 0.3 / 1.7 * (t / 0.333)
  let want = if cubic > est { cubic } else { est }
  let expected = (want * seg).to_int64()
  cc.on_ack_at(1200L, now=10_000_000L)
  assert_eq(cc.window(), expected)
  // And it grew: the curve is above the reduced window.
  assert_eq(cc.window() > 8400L, true)
}

///|
test "a second signal from inside the recovery period costs nothing" {
  let cc = Cubic::new()
  cc.on_congestion(at=1000L, now=1000L)
  let reduced = cc.window()
  cc.on_congestion(at=500L, now=1100L)
  assert_eq(cc.window(), reduced)
}

///|
test "fast convergence lowers W_max when a window is already shrinking (§4.6)" {
  let cc = Cubic::new()
  cc.on_congestion(at=1000L, now=1000L)
  // 8400 < the last W_max of 12000, so W_max becomes 8400·(1+0.7)/2 = 7140 and the
  // window falls to 0.7·8400 = 5880.
  cc.on_congestion(at=2000L, now=2000L)
  assert_eq(cc.window(), 5880L)
}

///|
test "the window never drops below two datagrams (§7.2)" {
  let cc = Cubic::new()
  for i = 0; i < 20; i = i + 1 {
    let at = (i + 1).to_int64() * 10L
    cc.on_congestion(at~, now=at)
  }
  assert_eq(cc.window(), 2400L)
  assert_eq(cc.minimum(), 2400L)
}

///|
test "persistent congestion collapses to the minimum (§7.6)" {
  let cc = Cubic::new()
  cc.on_congestion(at=0L, now=0L)
  cc.on_persistent()
  assert_eq(cc.window(), cc.minimum())
}

///|
test "the smallest round trip seen feeds the reno-friendly estimate" {
  let cc = Cubic::new()
  cc.on_rtt(sample=80_000L, now=0L)
  cc.on_rtt(sample=120_000L, now=0L)
  assert_eq(cc.rtt, 80_000L)
}

///|
test "the state machine drives cubic through the timed acknowledgement" {
  let cc = Cubic::new()
  let s = State::new(control=cc)
  let start = s.window()
  s.on_sent(0L, at=0L, size=1200L)
  let ack : @frame.Frame = Ack(largest=0UL, delay=0UL, first_range=0UL, ranges=[])
  let _ = s.on_ack(ack, 50000L, ack_delay=0L)
  // Slow start: the acknowledged byte grows the window through on_ack_at.
  assert_eq(s.window(), start + 1200L)
}
