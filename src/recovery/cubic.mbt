// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// CUBIC (RFC 9438): the congestion window follows a cubic function of the time since the
// last reduction, C·(t−K)³ + W_max, instead of NewReno's one datagram per round. On a long
// fat pipe that climbs back to the old rate quickly without over-running a shallow buffer,
// and it falls to β = 0.7 of the window rather than NewReno's half. It answers the same
// `Control` questions; only the growth rule and the reduction factor differ.

///|
/// The multiplicative decrease factor β (RFC 9438 §4.6): a CUBIC window falls to seven
/// tenths of itself, not to half.
let beta : Double = 0.7

///|
/// The cubic scaling constant C, in segments per second cubed (RFC 9438 §4.2).
let scaling : Double = 0.4

///|
/// A CUBIC congestion controller (RFC 9438), an implementation of `Control`.
pub struct Cubic {
  mut window : Int64
  mut ssthresh : Int64
  mut in_flight : Int64
  mut recovery : Int64
  /// The window at the last reduction, the W_max the cubic climbs back to (bytes).
  mut w_max : Int64
  /// When the current congestion-avoidance epoch began, in microseconds.
  mut epoch : Int64
  /// K, the seconds the cubic takes to return to W_max, fixed at the reduction.
  mut k : Double
  /// The smallest round trip seen, for the Reno-friendly estimate; the initial RTT until
  /// one arrives.
  mut rtt : Int64
  policy : Policy
}

///|
/// A fresh CUBIC controller at RFC 9002 §7.2's initial window: the same start as NewReno,
/// since how a controller begins is not what makes it CUBIC.
pub fn Cubic::new(policy~ : Policy = policy) -> Cubic {
  let two = 2L * policy.datagram
  let ten = 10L * policy.datagram
  let floor = if two > 14_720L { two } else { 14_720L }
  let initial = if ten < floor { ten } else { floor }
  {
    window: initial,
    ssthresh: 1L << 60,
    in_flight: 0,
    recovery: -1L,
    w_max: 0,
    epoch: 0,
    k: 0.0,
    rtt: policy.initial_rtt,
    policy,
  }
}

///|
/// The smallest window the controller will reduce to (RFC 9002 §7.2).
pub fn Cubic::minimum(self : Cubic) -> Int64 {
  2L * self.policy.datagram
}

///|
/// The slow-start threshold in bytes.
pub fn Cubic::ssthresh(self : Cubic) -> Int64 {
  self.ssthresh
}

///|
/// Whether a packet sent at `at` falls inside the recovery period already under way.
pub fn Cubic::recovering(self : Cubic, at : Int64) -> Bool {
  self.recovery >= 0L && at <= self.recovery
}

///|
/// The window the cubic and the Reno-friendly estimate ask for at `now`, in bytes — the
/// larger of the two (RFC 9438 §4.2, §4.3). A test reproduces this arithmetic itself so a
/// change to the curve is visible as a changed window.
pub fn Cubic::target(self : Cubic, now : Int64) -> Int64 {
  let seg = self.policy.datagram.to_double()
  let t = (now - self.epoch).to_double() / 1_000_000.0
  let w_max = self.w_max.to_double() / seg
  let cubic = scaling * (t - self.k) * (t - self.k) * (t - self.k) + w_max
  let rtt = self.rtt.to_double() / 1_000_000.0
  let est = w_max * beta +
    3.0 * (1.0 - beta) / (1.0 + beta) * (if rtt > 0.0 { t / rtt } else { 0.0 })
  let want = if cubic > est { cubic } else { est }
  (want * seg).to_int64()
}

///|
/// One acknowledgement's growth: below the threshold every acknowledged byte is added as in
/// slow start; above it the window follows the curve, never falling back.
fn Cubic::grow(self : Cubic, size : Int64, now : Int64) -> Unit {
  if self.window < self.ssthresh {
    self.window = self.window + size
  } else {
    let want = self.target(now)
    if want > self.window {
      self.window = want
    }
  }
}

///|
impl Control for Cubic with fn window(self) {
  self.window
}

///|
impl Control for Cubic with fn in_flight(self) {
  self.in_flight
}

///|
impl Control for Cubic with fn on_sent(self, size) {
  self.in_flight = self.in_flight + size
}

///|
/// Without a clock this can only take the bytes out of flight; the growth on an
/// acknowledgement comes through `on_ack_at`, which has the time.
impl Control for Cubic with fn on_ack(self, size) {
  self.in_flight = if self.in_flight > size {
    self.in_flight - size
  } else {
    0L
  }
}

///|
impl Control for Cubic with fn on_ack_at(self, size, now~) {
  self.in_flight = if self.in_flight > size {
    self.in_flight - size
  } else {
    0L
  }
  self.grow(size, now)
}

///|
impl Control for Cubic with fn on_lost(self, size) {
  self.in_flight = if self.in_flight > size {
    self.in_flight - size
  } else {
    0L
  }
}

///|
/// A congestion signal (RFC 9438 §4.6): W_max remembers the window it fell from, the window
/// drops to β of it (with fast convergence when it was already below the last W_max), a new
/// epoch starts, and K is recomputed as the time it takes the cubic to climb back.
impl Control for Cubic with fn on_congestion(self, at~, now~) {
  if self.recovering(at) {
    return
  }
  let previous = self.window
  if self.w_max > 0L && previous < self.w_max {
    self.w_max = (previous.to_double() * (1.0 + beta) / 2.0).to_int64()
  } else {
    self.w_max = previous
  }
  let reduced = (previous.to_double() * beta).to_int64()
  let floor = self.minimum()
  self.window = if reduced > floor { reduced } else { floor }
  self.ssthresh = self.window
  self.recovery = now
  self.epoch = now
  let seg = self.policy.datagram.to_double()
  let gap = (self.w_max.to_double() - self.window.to_double()) / seg
  self.k = @math.cbrt(if gap > 0.0 { gap / scaling } else { 0.0 })
}

///|
/// Persistent congestion collapses the window to the minimum and clears the recovery period,
/// as NewReno's does; the ssthresh left above it puts the next acknowledgement in slow start.
impl Control for Cubic with fn on_persistent(self) {
  self.window = self.minimum()
  self.recovery = -1L
}

///|
impl Control for Cubic with fn on_rtt(self, sample~, now~) {
  ignore(now)
  if sample > 0L && sample < self.rtt {
    self.rtt = sample
  }
}

///|
pub extend Cubic with Control::{
  window,
  in_flight,
  on_sent,
  on_ack,
  on_ack_at,
  on_lost,
  on_congestion,
  on_persistent,
  on_rtt,
}

///|
impl Control for Cubic with fn on_new_path(self) {
  let fresh = Cubic::new(policy=self.policy)
  self.window = fresh.window
  self.ssthresh = fresh.ssthresh
  self.recovery = fresh.recovery
  self.w_max = fresh.w_max
  self.epoch = fresh.epoch
  self.k = fresh.k
  self.rtt = fresh.rtt
}
