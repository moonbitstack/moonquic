// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// BBR (Bottleneck Bandwidth and Round-trip propagation time): the window is the path's
// bandwidth-delay product times a gain that walks through startup, drain, probe-bandwidth
// and probe-RTT. It models the pipe rather than counting acknowledgements, so a loss is not
// its congestion signal — a loss does not halve the window the way NewReno's does, and a
// connection whose bottleneck buffer is shallow keeps its rate. It implements the same
// `Control` contract as NewReno and CUBIC.

///|
/// Where a BBR sender is in its bandwidth-probing cycle.
#derive(Eq, Debug)
pub(all) enum Mode {
  /// Grow the window 2.885× per round until the delivered rate stops rising.
  Startup
  /// Drain the queue startup built, down to the bandwidth-delay product.
  Drain
  /// Walk the gain around 1 to probe for more bandwidth, then yield it.
  ProbeBw
  /// Hold the window at the minimum for one round trip so the path drains and a fresh
  /// round-trip minimum can be sampled.
  ProbeRtt
}

///|
/// The startup gain, `2/ln(2)` (BBR's high gain), rounded.
let startup_gain : Double = 2.885

///|
/// The probe-bandwidth gain for a cycle position: 1.25 to probe, 0.75 to yield, then 1 while
/// the estimate is held.
fn probe_gain(index : Int32) -> Double {
  match index % 8 {
    0 => 1.25
    1 => 0.75
    _ => 1.0
  }
}

///|
/// A BBR congestion controller, an implementation of `Control`.
pub struct Bbr {
  mut window : Int64
  mut in_flight : Int64
  /// The maximum delivery rate seen, in bytes per microsecond.
  mut btl_bw : Double
  /// The smallest round trip seen, in microseconds; the initial RTT until one arrives.
  mut min_rtt : Int64
  /// When `min_rtt` last improved, for the ten-second probe-RTT trigger.
  mut min_rtt_at : Int64
  mut mode : Mode
  /// Bytes acknowledged in total, the numerator of a delivery-rate sample.
  mut delivered : Int64
  mut sample_at : Int64
  mut sample_delivered : Int64
  /// The bandwidth at the last startup round that still rose, and how many rounds since.
  mut full_bw : Double
  mut full_bw_count : Int32
  mut cycle : Int32
  mut cycle_at : Int64
  mut probe_rtt_at : Int64
  policy : Policy
}

///|
/// A fresh BBR controller at RFC 9002 §7.2's initial window, in startup.
pub fn Bbr::new(policy~ : Policy = policy) -> Bbr {
  let two = 2L * policy.datagram
  let ten = 10L * policy.datagram
  let floor = if two > 14_720L { two } else { 14_720L }
  let initial = if ten < floor { ten } else { floor }
  {
    window: initial,
    in_flight: 0,
    btl_bw: 0.0,
    min_rtt: policy.initial_rtt,
    min_rtt_at: 0,
    mode: Startup,
    delivered: 0,
    sample_at: 0,
    sample_delivered: 0,
    full_bw: 0.0,
    full_bw_count: 0,
    cycle: 0,
    cycle_at: 0,
    probe_rtt_at: 0,
    policy,
  }
}

///|
/// The smallest window the controller will set (RFC 9002 §7.2).
pub fn Bbr::minimum(self : Bbr) -> Int64 {
  2L * self.policy.datagram
}

///|
/// Where the controller is in its probing cycle.
pub fn Bbr::mode(self : Bbr) -> Mode {
  self.mode
}

///|
/// The maximum delivery rate seen, in bytes per microsecond.
pub fn Bbr::bandwidth(self : Bbr) -> Double {
  self.btl_bw
}

///|
/// The smallest round trip seen, in microseconds.
pub fn Bbr::min_rtt(self : Bbr) -> Int64 {
  self.min_rtt
}

///|
/// The gain the current mode applies to the bandwidth-delay product.
fn Bbr::gain(self : Bbr) -> Double {
  match self.mode {
    Startup => startup_gain
    Drain => 1.0 / startup_gain
    ProbeBw => probe_gain(self.cycle)
    ProbeRtt => 1.0
  }
}

///|
/// The bandwidth-delay product in bytes: how much the path can hold in flight at once at the
/// best rate and the smallest round trip seen.
pub fn Bbr::bdp(self : Bbr) -> Int64 {
  (self.btl_bw * self.min_rtt.to_double()).to_int64()
}

///|
/// The window the model asks for: the bandwidth-delay product times the mode's gain, three
/// datagrams of headroom, floored at the minimum. A test holds a loss to leaving it
/// unchanged, which is what tells BBR from NewReno.
pub fn Bbr::target(self : Bbr) -> Int64 {
  let scaled = (self.bdp().to_double() * self.gain()).to_int64()
  let want = scaled + 3L * self.policy.datagram
  let floor = self.minimum()
  if want > floor {
    want
  } else {
    floor
  }
}

///|
impl Control for Bbr with fn window(self) {
  self.window
}

///|
impl Control for Bbr with fn in_flight(self) {
  self.in_flight
}

///|
impl Control for Bbr with fn on_sent(self, size) {
  self.in_flight = self.in_flight + size
}

///|
impl Control for Bbr with fn on_ack(self, size) {
  self.in_flight = if self.in_flight > size {
    self.in_flight - size
  } else {
    0L
  }
}

///|
impl Control for Bbr with fn on_lost(self, size) {
  self.in_flight = if self.in_flight > size {
    self.in_flight - size
  } else {
    0L
  }
}

///|
/// A congestion signal. BBR does not treat loss as its signal: it leaves the window the
/// model computes alone, and a loss in startup only ends startup early.
impl Control for Bbr with fn on_congestion(self, at~, now~) {
  ignore(at)
  ignore(now)
  if self.mode == Startup {
    self.mode = Drain
  }
}

///|
/// Persistent congestion is the one loss that resets the model: the path is not delivering,
/// so the window drops to the minimum and a fresh round-trip minimum is taken.
impl Control for Bbr with fn on_persistent(self) {
  self.window = self.minimum()
  self.btl_bw = 0.0
  self.mode = ProbeRtt
  self.probe_rtt_at = 0L
}

///|
/// An acknowledgement at a known time: out of flight, into the delivery-rate sample, and the
/// window recomputed from the model.
impl Control for Bbr with fn on_ack_at(self, size, now~) {
  self.in_flight = if self.in_flight > size {
    self.in_flight - size
  } else {
    0L
  }
  self.delivered = self.delivered + size
  let elapsed = now - self.sample_at
  if elapsed >= self.min_rtt && elapsed > 0L {
    let rate = (self.delivered - self.sample_delivered).to_double() /
      elapsed.to_double()
    if rate > self.btl_bw {
      self.btl_bw = rate
    }
    self.sample_delivered = self.delivered
    self.sample_at = now
    if self.mode == Startup {
      if self.btl_bw >= self.full_bw * 1.25 {
        self.full_bw = self.btl_bw
        self.full_bw_count = 0
      } else {
        self.full_bw_count = self.full_bw_count + 1
        if self.full_bw_count >= 3 {
          self.mode = Drain
        }
      }
    }
  }
  if self.btl_bw > 0.0 &&
    self.mode != ProbeRtt &&
    now - self.min_rtt_at > 10_000_000L {
    self.mode = ProbeRtt
    self.probe_rtt_at = now
  }
  match self.mode {
    Startup => ()
    Drain =>
      if self.in_flight <= self.bdp() {
        self.mode = ProbeBw
        self.cycle = 0
        self.cycle_at = now
      }
    ProbeBw =>
      if now - self.cycle_at >= self.min_rtt {
        self.cycle = self.cycle + 1
        self.cycle_at = now
      }
    ProbeRtt =>
      if now - self.probe_rtt_at >= self.min_rtt {
        self.mode = ProbeBw
        self.cycle = 0
        self.cycle_at = now
      }
  }
  self.window = if self.mode == ProbeRtt {
    self.minimum()
  } else {
    self.target()
  }
}

///|
/// A round-trip sample: keep the smallest, and note when it was taken so probe-RTT knows how
/// long the path has gone without a fresher one.
impl Control for Bbr with fn on_rtt(self, sample~, now~) {
  if sample > 0L && sample < self.min_rtt {
    self.min_rtt = sample
    self.min_rtt_at = now
    if self.mode == ProbeRtt {
      self.mode = ProbeBw
      self.cycle = 0
      self.cycle_at = now
    }
  }
}

///|
pub extend Bbr with Control::{
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
pub extend Mode with Debug::{to_repr}

///|
pub extend Mode with Eq::{not_equal, equal}
