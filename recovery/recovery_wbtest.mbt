// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9002's own arithmetic, worked out by hand in the comments so a failure says which
// step of §5.3, §6.1 or §7 moved. Microseconds throughout, bytes for sizes.

///|
/// A threshold large enough that the other one is the only thing that can fire.
let never : Int64 = 1L << 40

///|
test "the first sample seeds the smoothed estimate and half its deviation (§5.3)" {
  let rtt = Rtt::new()
  assert_eq(rtt.sampled(), false)
  rtt.sample(100000L, ack_delay=0L)
  assert_eq(rtt.sampled(), true)
  assert_eq(rtt.latest(), 100000L)
  assert_eq(rtt.min(), 100000L)
  assert_eq(rtt.smoothed(), 100000L)
  assert_eq(rtt.variation(), 50000L)
}

///|
test "later samples move the average and discount the peer's ack delay (§5.3)" {
  let rtt = Rtt::new()
  rtt.sample(100000L, ack_delay=0L)
  // Below the minimum seen: subtracting the delay would take it under, so it is not.
  rtt.sample(80000L, ack_delay=5000L)
  assert_eq(rtt.min(), 80000L)
  // variation = (3·50000 + |100000-80000|)/4 = 170000/4
  assert_eq(rtt.variation(), 42500L)
  // smoothed = (7·100000 + 80000)/8
  assert_eq(rtt.smoothed(), 97500L)
  // Above the minimum plus the delay: the delay comes off.
  rtt.sample(120000L, ack_delay=10000L)
  assert_eq(rtt.min(), 80000L)
  // adjusted = 110000; variation = (3·42500 + 12500)/4
  assert_eq(rtt.variation(), 35000L)
  // smoothed = (7·97500 + 110000)/8 = 792500/8, rounded down
  assert_eq(rtt.smoothed(), 99062L)
}

///|
test "a peer cannot claim more ack delay than it advertised (§5.3)" {
  let rtt = Rtt::new()
  rtt.sample(100000L, ack_delay=0L)
  // 40000 reported against a 25000 maximum is taken as 25000.
  rtt.sample(200000L, ack_delay=40000L)
  // adjusted = 175000; smoothed = (7·100000 + 175000)/8
  assert_eq(rtt.smoothed(), 109375L)
}

///|
test "the probe timeout is the estimate plus four deviations (§6.2.1)" {
  let rtt = Rtt::new()
  rtt.sample(100000L, ack_delay=0L)
  rtt.sample(80000L, ack_delay=5000L)
  rtt.sample(120000L, ack_delay=10000L)
  // smoothed 99062, variation 35000; 4·35000 clears the 1000 granularity.
  assert_eq(rtt.pto(), 99062L + 140000L + 25000L)
}

///|
test "before the first sample the probe timeout is twice the initial RTT (§6.2.2)" {
  let rtt = Rtt::new()
  assert_eq(rtt.pto(), 2L * 333_000L)
  // And the initial RTT is a knob, because a connection that knows the path need not
  // start at a third of a second.
  assert_eq(rtt.pto(policy={ ..policy, initial_rtt: 10_000L, }), 20_000L)
}

///|
test "the loss time threshold is 9/8 of the larger estimate, floored (§6.1.2)" {
  let rtt = Rtt::new()
  rtt.sample(100000L, ack_delay=0L)
  assert_eq(rtt.threshold(), 112500L)
  // A round trip small enough that 9/8 of it is under the granularity floors there.
  let small = Rtt::new()
  small.sample(400L, ack_delay=0L)
  assert_eq(small.threshold(), 1000L)
  // Both the ratio and the floor are knobs.
  assert_eq(rtt.threshold(policy={ ..policy, time: 2.0, }), 200000L)
  assert_eq(small.threshold(policy={ ..policy, granularity: 100L, }), 450L)
}

///|
test "an ACK drops what it acknowledges, sums the bytes, and moves the largest" {
  let f = Flight::new()
  for pn = 0L; pn < 5L; pn = pn + 1L {
    f.on_sent(pn, at=pn * 1000L, size=1200L)
  }
  assert_eq(f.largest_acked(), -1L)
  assert_eq(f.on_ack([(2L, 2L), (4L, 4L)]), 2400L)
  assert_eq(f.outstanding(), [0L, 1L, 3L])
  assert_eq(f.largest_acked(), 4L)
}

///|
test "packets three or more behind the largest acknowledged are lost (§6.1.1)" {
  let f = Flight::new()
  for pn = 0L; pn < 5L; pn = pn + 1L {
    f.on_sent(pn, at=0L, size=1200L)
  }
  let _ = f.on_ack([(2L, 2L), (4L, 4L)])
  // largest 4, threshold 3: lost when 4 - pn >= 3.
  assert_eq(f.lost(0L, packets=3L, time=never).map(p => p.pn), [0L, 1L])
  // 3 is one behind the largest, so it stays outstanding.
  assert_eq(f.outstanding(), [3L])
}

///|
test "nothing is lost until the gap opens" {
  let f = Flight::new()
  for pn = 0L; pn < 3L; pn = pn + 1L {
    f.on_sent(pn, at=0L, size=1200L)
  }
  let _ = f.on_ack([(2L, 2L)])
  assert_eq(f.lost(0L, packets=3L, time=never).length(), 0)
  assert_eq(f.outstanding(), [0L, 1L])
}

///|
test "an ACK frame's ranges acknowledge packets and drive loss detection" {
  let f = Flight::new()
  for pn = 0L; pn < 10L; pn = pn + 1L {
    f.on_sent(pn, at=0L, size=1200L)
  }
  // Acknowledges [5,9] and, one gap back, [0,2]: 3 and 4 are the hole.
  let ack : @frame.Frame = Ack(largest=9UL, delay=0UL, first_range=4UL, ranges=[
    (1UL, 2UL),
  ])
  let ranges = ack
    .acked()
    .map(r => (r.0.reinterpret_as_int64(), r.1.reinterpret_as_int64()))
  assert_eq(ranges, [(0L, 2L), (5L, 9L)])
  assert_eq(f.on_ack(ranges), 9600L)
  assert_eq(f.outstanding(), [3L, 4L])
  assert_eq(f.largest_acked(), 9L)
  assert_eq(f.lost(0L, packets=3L, time=never).map(p => p.pn), [3L, 4L])
}

///|
test "packets older than the time threshold are lost (§6.1.2)" {
  let f = Flight::new()
  for pn = 0L; pn < 5L; pn = pn + 1L {
    f.on_sent(pn, at=pn * 1000L, size=1200L)
  }
  let _ = f.on_ack([(4L, 4L)])
  // At 4000 with a 1500 threshold, anything sent at or before 2500 is lost.
  assert_eq(f.lost(4000L, packets=never, time=1500L).map(p => p.pn), [
    0L, 1L, 2L,
  ])
  assert_eq(f.outstanding(), [3L])
}

///|
test "the initial window is ten datagrams, bounded either way (§7.2)" {
  let cc = NewReno::new()
  // min(10·1200, max(2·1200, 14720)) = min(12000, 14720)
  assert_eq(cc.window(), 12000L)
  // A large datagram size runs into the ten-datagram cap.
  let big = NewReno::new(policy={ ..policy, datagram: 4000L, })
  assert_eq(big.window(), 14720L)
  // A tiny one runs into the 14720 floor.
  let small = NewReno::new(policy={ ..policy, datagram: 500L, })
  assert_eq(small.window(), 5000L)
  assert_eq(cc.in_flight(), 0L)
}

///|
test "slow start grows the window by every acknowledged byte (§7.3.1)" {
  let cc = NewReno::new()
  let start = cc.window()
  cc.on_sent(1200L)
  assert_eq(cc.in_flight(), 1200L)
  cc.on_ack(1200L)
  assert_eq(cc.in_flight(), 0L)
  assert_eq(cc.window(), start + 1200L)
}

///|
test "congestion avoidance grows by one datagram per window (§7.3.2)" {
  let cc = NewReno::new()
  cc.on_sent(12000L)
  cc.on_congestion(at=0L, now=1L)
  // Now below the threshold no longer: the window is the threshold.
  let after = cc.window()
  assert_eq(after, cc.ssthresh())
  cc.on_ack(1200L)
  assert_eq(cc.window(), after + 1200L * 1200L / after)
}

///|
test "a congestion signal halves the window, once per recovery period (§7.3.2)" {
  let cc = NewReno::new()
  let start = cc.window()
  cc.on_congestion(at=1000L, now=1000L)
  assert_eq(cc.ssthresh(), start / 2L)
  assert_eq(cc.window(), start / 2L)
  // A second signal from a packet sent before the period began is the same loss
  // reported twice, and costs nothing more.
  cc.on_congestion(at=500L, now=1100L)
  assert_eq(cc.window(), start / 2L)
  // One from a packet sent after it is a new loss, and halves again.
  cc.on_congestion(at=2000L, now=2000L)
  assert_eq(cc.window(), start / 4L)
}

///|
test "the window never drops below two datagrams (§7.2)" {
  let cc = NewReno::new()
  for i = 0; i < 20; i = i + 1 {
    cc.on_congestion(at=i.to_int64() * 10L, now=i.to_int64() * 10L)
  }
  assert_eq(cc.window(), 2400L)
  assert_eq(cc.minimum(), 2400L)
  // The reduction factor is a knob; a tenth drops to the floor in one step.
  let steep = NewReno::new(policy={ ..policy, reduction: 0.1, })
  steep.on_congestion(at=0L, now=0L)
  assert_eq(steep.window(), 2400L)
}

///|
test "persistent congestion collapses the window to the minimum (§7.6)" {
  let cc = NewReno::new()
  cc.on_congestion(at=0L, now=0L)
  let halved = cc.window()
  cc.on_persistent()
  assert_eq(cc.window(), cc.minimum())
  assert_eq(halved > cc.window(), true)
  // And the recovery period is over, so the next loss counts again.
  cc.on_congestion(at=0L, now=1L)
  assert_eq(cc.window(), cc.minimum())
}

///|
test "what fits in the window is the window less what is in flight" {
  let cc = NewReno::new()
  assert_eq(can_send(cc, 12000L), true)
  assert_eq(can_send(cc, 12001L), false)
  cc.on_sent(11000L)
  assert_eq(can_send(cc, 1000L), true)
  assert_eq(can_send(cc, 1001L), false)
}

///|
test "an ACK samples the round trip, frees bytes and grows the window" {
  let s = State::new()
  let start = s.window()
  s.on_sent(0L, at=0L, size=1200L)
  assert_eq(s.in_flight(), 1200L)
  let ack : @frame.Frame = Ack(largest=0UL, delay=0UL, first_range=0UL, ranges=[])
  let lost = s.on_ack(ack, 50000L, ack_delay=0L)
  assert_eq(lost.length(), 0)
  assert_eq(s.in_flight(), 0L)
  assert_eq(s.rtt().smoothed(), 50000L)
  assert_eq(s.window(), start + 1200L)
  assert_eq(s.outstanding().length(), 0)
}

///|
test "an ACK that reveals loss halves the window once, however many were lost" {
  let s = State::new()
  let start = s.window()
  // A microsecond apart, so nothing is old enough for the time threshold and the
  // order threshold is the only one that can fire.
  for pn = 0L; pn < 6L; pn = pn + 1L {
    s.on_sent(pn, at=pn, size=1200L)
  }
  // Acknowledges 5 alone, so 0, 1 and 2 are three or more behind it.
  let ack : @frame.Frame = Ack(largest=5UL, delay=0UL, first_range=0UL, ranges=[])
  let lost = s.on_ack(ack, 5000L, ack_delay=0L)
  assert_eq(lost, [0L, 1L, 2L])
  // The acknowledged bytes grow the window before loss detection halves it, which is
  // the order RFC 9002 §A.7 gives.
  assert_eq(s.window(), (start + 1200L) / 2L)
  assert_eq(s.outstanding(), [3L, 4L])
}

///|
test "the probe timer arms from the last send, backs off, and resets on an ACK" {
  let s = State::new()
  assert_eq(s.pto_deadline(), None)
  s.on_sent(0L, at=1000L, size=1200L)
  let pto = s.pto()
  assert_eq(s.pto_deadline(), Some(1000L + pto))
  s.on_pto()
  assert_eq(s.pto_count(), 1)
  assert_eq(s.pto_deadline(), Some(1000L + pto * 2L))
  s.on_pto()
  assert_eq(s.pto_deadline(), Some(1000L + pto * 4L))
  // An acknowledgement ends the backoff and disarms the timer.
  let ack : @frame.Frame = Ack(largest=0UL, delay=0UL, first_range=0UL, ranges=[])
  let _ = s.on_ack(ack, 2000L, ack_delay=0L)
  assert_eq(s.pto_count(), 0)
  assert_eq(s.pto_deadline(), None)
}

///|
test "an ACK for nothing outstanding changes nothing" {
  let s = State::new()
  let start = s.window()
  let ping : @frame.Frame = Ping
  assert_eq(s.on_ack(ping, 100L, ack_delay=0L).length(), 0)
  assert_eq(s.window(), start)
  assert_eq(s.in_flight(), 0L)
}

///|
test "a malformed ACK is refused rather than read as an acknowledgement" {
  let s = State::new()
  let bad : @frame.Frame = Ack(largest=3UL, delay=0UL, first_range=9UL, ranges=[])
  let mut refused = false
  try {
    let _ = s.on_ack(bad, 100L, ack_delay=0L)
  } catch {
    Malformed(_) => refused = true
  }
  assert_eq(refused, true)
}

///|
/// A controller that records what it was told, to show the state machine drives the
/// trait and not one particular controller.
struct Counting {
  mut sent : Int64
  mut acked : Int64
  mut lost : Int64
  mut congestion : Int
  mut persistent : Int
}

///|
impl Control for Counting with fn window(_) {
  1L << 40
}

///|
impl Control for Counting with fn in_flight(self) {
  self.sent - self.acked - self.lost
}

///|
impl Control for Counting with fn on_sent(self, size) {
  self.sent = self.sent + size
}

///|
impl Control for Counting with fn on_ack(self, size) {
  self.acked = self.acked + size
}

///|
impl Control for Counting with fn on_lost(self, size) {
  self.lost = self.lost + size
}

///|
impl Control for Counting with fn on_congestion(self, at~, now~) {
  ignore(at)
  ignore(now)
  self.congestion = self.congestion + 1
}

///|
impl Control for Counting with fn on_persistent(self) {
  self.persistent = self.persistent + 1
}

///|
test "another controller receives the same events, and nothing here knows which" {
  let cc : Counting = {
    sent: 0,
    acked: 0,
    lost: 0,
    congestion: 0,
    persistent: 0,
  }
  let s = State::new(control=cc)
  for pn = 0L; pn < 6L; pn = pn + 1L {
    s.on_sent(pn, at=pn, size=1200L)
  }
  assert_eq(cc.sent, 7200L)
  let ack : @frame.Frame = Ack(largest=5UL, delay=0UL, first_range=0UL, ranges=[])
  let lost = s.on_ack(ack, 5000L, ack_delay=0L)
  assert_eq(lost, [0L, 1L, 2L])
  assert_eq(cc.acked, 1200L)
  assert_eq(cc.lost, 3600L)
  assert_eq(cc.congestion, 1)
  // The window is boundless here, so the state machine never stops sending.
  assert_eq(s.can_send(1L << 30), true)
}

///|
test "a loss spanning more than a congestion period is persistent congestion (§7.6)" {
  let cc : Counting = {
    sent: 0,
    acked: 0,
    lost: 0,
    congestion: 0,
    persistent: 0,
  }
  let s = State::new(control=cc)
  // Ten seconds apart. The ACK samples a one-second round trip, so the congestion
  // period is 3 · (1 s + 4 · 0.5 s + 25 ms) ≈ 9 s, and the lost packets span forty.
  for pn = 0L; pn < 6L; pn = pn + 1L {
    s.on_sent(pn, at=pn * 10_000_000L, size=1200L)
  }
  let ack : @frame.Frame = Ack(largest=5UL, delay=0UL, first_range=0UL, ranges=[])
  let _ = s.on_ack(ack, 51_000_000L, ack_delay=0L)
  assert_eq(cc.persistent, 1)
}

///|
test "a loss inside one congestion period is not persistent congestion" {
  let cc : Counting = {
    sent: 0,
    acked: 0,
    lost: 0,
    congestion: 0,
    persistent: 0,
  }
  let s = State::new(control=cc)
  // The default initial RTT gives a period of 3 · 666 ms; these span three microseconds.
  for pn = 0L; pn < 6L; pn = pn + 1L {
    s.on_sent(pn, at=pn, size=1200L)
  }
  let ack : @frame.Frame = Ack(largest=5UL, delay=0UL, first_range=0UL, ranges=[])
  let _ = s.on_ack(ack, 10L, ack_delay=0L)
  assert_eq(cc.congestion, 1)
  assert_eq(cc.persistent, 0)
}

///|
test "the named constructor and the record update agree" {
  assert_eq(Policy::new().packets, policy.packets)
  assert_eq(Policy::new(packets=5L).packets, { ..policy, packets: 5L, }.packets)
  assert_eq(Policy::new(datagram=1500L).datagram, 1500L)
  assert_eq(NewReno::new(policy=Policy::new(datagram=1500L)).minimum(), 3000L)
}
