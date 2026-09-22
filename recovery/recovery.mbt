// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The constants RFC 9002 leaves as tunables, and the two connection parameters the
/// timers are computed from. Every duration is microseconds and every size is bytes.
///
/// The presets are the values the RFC itself recommends (§6.1.1, §6.1.2, §6.2.2, §7.2,
/// §7.3, §7.6) together with RFC 9000 §18.2's default `max_ack_delay` and RFC 9000 §14's
/// minimum datagram size, which is the one every path is required to carry.
pub(all) struct Policy {
  packets : Int64
  time : Double
  granularity : Int64
  initial_rtt : Int64
  persistent : Int64
  reduction : Double
  datagram : Int64
  ack_delay : Int64
}

///|
/// RFC 9002's recommended constants.
pub let policy : Policy = {
  packets: 3,
  time: 9.0 / 8.0,
  granularity: 1_000,
  initial_rtt: 333_000,
  persistent: 3,
  reduction: 0.5,
  datagram: 1_200,
  ack_delay: 25_000,
}

///|
/// A policy by name, each part defaulting to RFC 9002's recommendation.
///
/// `packets` is kPacketThreshold, `time` kTimeThreshold, `granularity` kGranularity,
/// `initial_rtt` kInitialRtt, `persistent` kPersistentCongestionThreshold, `reduction`
/// kLossReductionFactor. `datagram` is the sender's maximum datagram size and
/// `ack_delay` the peer's advertised `max_ack_delay`, both of which a real connection
/// learns from its transport parameters rather than keeps at the default.
pub fn Policy::new(
  packets? : Int64 = 3,
  time? : Double = 9.0 / 8.0,
  granularity? : Int64 = 1_000,
  initial_rtt? : Int64 = 333_000,
  persistent? : Int64 = 3,
  reduction? : Double = 0.5,
  datagram? : Int64 = 1_200,
  ack_delay? : Int64 = 25_000,
) -> Policy {
  {
    packets,
    time,
    granularity,
    initial_rtt,
    persistent,
    reduction,
    datagram,
    ack_delay,
  }
}

///|
/// An endpoint's round-trip estimate for one packet-number space (RFC 9002 §5).
pub struct Rtt {
  mut latest : Int64
  mut min : Int64
  mut smoothed : Int64
  mut variation : Int64
  mut sampled : Bool
}

///|
/// A fresh estimate, with no sample yet.
pub fn Rtt::new() -> Rtt {
  { latest: 0, min: 0, smoothed: 0, variation: 0, sampled: false, }
}

///|
/// Fold in a round-trip sample (RFC 9002 §5.3).
///
/// `ack_delay` is what the peer said it waited before acknowledging; it is capped at the
/// policy's `ack_delay` and subtracted only while doing so keeps the sample at or above
/// the minimum seen, so a peer cannot talk the estimate below the path's real latency.
/// The first sample seeds the estimate outright; later ones move the weighted average.
pub fn Rtt::sample(
  self : Rtt,
  latest : Int64,
  ack_delay~ : Int64,
  policy? : Policy = policy,
) -> Unit {
  self.latest = latest
  if self.sampled {
    if latest < self.min {
      self.min = latest
    }
    let capped = if ack_delay < policy.ack_delay {
      ack_delay
    } else {
      policy.ack_delay
    }
    let adjusted = if latest >= self.min + capped {
      latest - capped
    } else {
      latest
    }
    let diff = self.smoothed - adjusted
    let spread = if diff < 0L { -diff } else { diff }
    self.variation = (3L * self.variation + spread) / 4L
    self.smoothed = (7L * self.smoothed + adjusted) / 8L
  } else {
    self.min = latest
    self.smoothed = latest
    self.variation = latest / 2L
    self.sampled = true
  }
}

///|
/// The most recent sample.
pub fn Rtt::latest(self : Rtt) -> Int64 {
  self.latest
}

///|
/// The smallest sample seen, which is the closest this endpoint has come to measuring the
/// path itself rather than the path plus the peer's delays.
pub fn Rtt::min(self : Rtt) -> Int64 {
  self.min
}

///|
/// The smoothed estimate the timers are built on.
pub fn Rtt::smoothed(self : Rtt) -> Int64 {
  self.smoothed
}

///|
/// The mean deviation of the samples.
pub fn Rtt::variation(self : Rtt) -> Int64 {
  self.variation
}

///|
/// Whether any sample has arrived. Before the first one the timers fall back to the
/// policy's initial RTT, which is the whole of what an endpoint knows at that point.
pub fn Rtt::sampled(self : Rtt) -> Bool {
  self.sampled
}

///|
/// The Probe Timeout: `smoothed + max(4·variation, granularity) + ack_delay`
/// (RFC 9002 §6.2.1), or twice the policy's initial RTT before the first sample
/// (§6.2.2).
pub fn Rtt::pto(self : Rtt, policy? : Policy = policy) -> Int64 {
  if !self.sampled {
    return 2L * policy.initial_rtt
  }
  let four = 4L * self.variation
  let spread = if four > policy.granularity { four } else { policy.granularity }
  self.smoothed + spread + policy.ack_delay
}

///|
/// The loss time threshold: `max(time · max(smoothed, latest), granularity)`
/// (RFC 9002 §6.1.2).
pub fn Rtt::threshold(self : Rtt, policy? : Policy = policy) -> Int64 {
  let m = if self.smoothed > self.latest { self.smoothed } else { self.latest }
  let scaled = (m.to_double() * policy.time).to_int64()
  if scaled > policy.granularity {
    scaled
  } else {
    policy.granularity
  }
}

///|
/// A sent, not yet acknowledged ack-eliciting packet (RFC 9002 §A.1): its number, when it
/// went out, and how many bytes it put in flight.
pub(all) struct Sent {
  pn : Int64
  at : Int64
  size : Int64
} derive(Eq, Debug)

///|
/// What is outstanding in one packet-number space, and the largest number acknowledged so
/// far — `-1` before any ACK has arrived.
pub struct Flight {
  mut packets : Array[Sent]
  mut largest_acked : Int64
}

///|
/// A fresh flight, with nothing outstanding.
pub fn Flight::new() -> Flight {
  { packets: [], largest_acked: -1L, }
}

///|
/// Record that an ack-eliciting packet went out.
pub fn Flight::on_sent(
  self : Flight,
  pn : Int64,
  at~ : Int64,
  size~ : Int64,
) -> Unit {
  self.packets.push({ pn, at, size, })
}

///|
/// Process an ACK's acknowledged ranges: drop every outstanding packet that falls in one,
/// advance the largest acknowledged, and answer with the bytes taken out of flight.
pub fn Flight::on_ack(self : Flight, ranges : Array[(Int64, Int64)]) -> Int64 {
  let kept : Array[Sent] = []
  let mut freed = 0L
  for p in self.packets {
    let mut acked = false
    for r in ranges {
      if p.pn >= r.0 && p.pn <= r.1 {
        acked = true
        break
      }
    }
    if acked {
      freed = freed + p.size
    } else {
      kept.push(p)
    }
  }
  self.packets = kept
  for r in ranges {
    if r.1 > self.largest_acked {
      self.largest_acked = r.1
    }
  }
  freed
}

///|
/// Declare lost every outstanding packet that either sits at least `packets` behind the
/// largest acknowledged (RFC 9002 §6.1.1) or was sent longer than `time` ago while a later
/// packet has been acknowledged (§6.1.2), and stop tracking them.
///
/// The records come back whole, sizes included, because the congestion controller has to
/// take those bytes out of flight and only the caller knows which controller that is.
pub fn Flight::lost(
  self : Flight,
  now : Int64,
  packets~ : Int64,
  time~ : Int64,
) -> Array[Sent] {
  let lost : Array[Sent] = []
  let kept : Array[Sent] = []
  for p in self.packets {
    let by_order = self.largest_acked >= 0L &&
      self.largest_acked - p.pn >= packets
    let by_time = self.largest_acked > p.pn && now - p.at >= time
    if by_order || by_time {
      lost.push(p)
    } else {
      kept.push(p)
    }
  }
  self.packets = kept
  lost
}

///|
/// When the outstanding packet numbered `pn` was sent, or `None` if it is not outstanding.
pub fn Flight::time_of(self : Flight, pn : Int64) -> Int64? {
  for p in self.packets {
    if p.pn == pn {
      return Some(p.at)
    }
  }
  None
}

///|
/// The packet numbers still outstanding.
pub fn Flight::outstanding(self : Flight) -> Array[Int64] {
  self.packets.map(p => p.pn)
}

///|
/// The largest packet number acknowledged, or `-1` before any ACK.
pub fn Flight::largest_acked(self : Flight) -> Int64 {
  self.largest_acked
}

///|
/// A congestion controller (RFC 9002 §7): how much may be in flight, and what to make of
/// each packet sent, acknowledged or lost.
///
/// NewReno is the one RFC 9002 specifies, and the reason this is a trait rather than that
/// struct is §7's own opening — an endpoint may use any controller, and Cubic and BBR
/// answer the same questions. Implementing this is all it takes; nothing here changes.
pub(open) trait Control {
  /// The congestion window in bytes.
  fn window(Self) -> Int64
  /// The bytes currently in flight.
  fn in_flight(Self) -> Int64
  /// A packet of `size` bytes went out.
  fn on_sent(Self, Int64) -> Unit
  /// `size` bytes were acknowledged and are out of flight.
  fn on_ack(Self, Int64) -> Unit
  /// `size` bytes of a lost packet are out of flight. The window reduction is a separate
  /// call, because many lost packets are one congestion signal.
  fn on_lost(Self, Int64) -> Unit
  /// A congestion signal from a packet sent at `at`, seen at `now`. A signal from a packet
  /// sent before the current recovery period began is a second report of a loss already
  /// paid for, so a controller ignores it.
  fn on_congestion(Self, at~ : Int64, now~ : Int64) -> Unit
  /// Persistent congestion (§7.6): the path stopped delivering for longer than a
  /// congestion period, and the window collapses to the minimum.
  fn on_persistent(Self) -> Unit
}

///|
/// Whether `bytes` more fit in the window.
pub fn can_send(control : &Control, bytes : Int64) -> Bool {
  control.in_flight() + bytes <= control.window()
}

///|
/// NewReno, the controller RFC 9002 §7 specifies.
pub struct NewReno {
  mut window : Int64
  mut ssthresh : Int64
  mut in_flight : Int64
  mut recovery : Int64
  policy : Policy
}

///|
/// A fresh controller (RFC 9002 §7.2): the initial window is
/// `min(10·datagram, max(2·datagram, 14720))`, the slow-start threshold is unbounded, and
/// nothing is in flight or in recovery.
pub fn NewReno::new(policy? : Policy = policy) -> NewReno {
  let two = 2L * policy.datagram
  let ten = 10L * policy.datagram
  let floor = if two > 14_720L { two } else { 14_720L }
  let initial = if ten < floor { ten } else { floor }
  { window: initial, ssthresh: 1L << 60, in_flight: 0, recovery: -1L, policy, }
}

///|
/// The smallest window the controller will reduce to (RFC 9002 §7.2).
pub fn NewReno::minimum(self : NewReno) -> Int64 {
  2L * self.policy.datagram
}

///|
/// The slow-start threshold in bytes.
pub fn NewReno::ssthresh(self : NewReno) -> Int64 {
  self.ssthresh
}

///|
/// Whether a packet sent at `at` falls inside the recovery period already under way.
pub fn NewReno::recovering(self : NewReno, at : Int64) -> Bool {
  self.recovery >= 0L && at <= self.recovery
}

///|
impl Control for NewReno with fn window(self) {
  self.window
}

///|
impl Control for NewReno with fn in_flight(self) {
  self.in_flight
}

///|
impl Control for NewReno with fn on_sent(self, size) {
  self.in_flight = self.in_flight + size
}

///|
/// Acknowledgement (RFC 9002 §7.3.1–§7.3.2): out of flight, then grow — by every
/// acknowledged byte below the threshold, and by one datagram per window above it.
impl Control for NewReno with fn on_ack(self, size) {
  self.in_flight = if self.in_flight > size {
    self.in_flight - size
  } else {
    0L
  }
  if self.window < self.ssthresh {
    self.window = self.window + size
  } else {
    self.window = self.window + self.policy.datagram * size / self.window
  }
}

///|
impl Control for NewReno with fn on_lost(self, size) {
  self.in_flight = if self.in_flight > size {
    self.in_flight - size
  } else {
    0L
  }
}

///|
/// A congestion signal (RFC 9002 §7.3.2): the window falls to the reduction factor of
/// itself, floored at the minimum, and a recovery period begins. A signal from a packet
/// sent inside the period already under way is ignored, so one round of loss costs one
/// halving rather than one per packet.
impl Control for NewReno with fn on_congestion(self, at~, now~) {
  if self.recovering(at) {
    return
  }
  self.recovery = now
  self.ssthresh = (self.window.to_double() * self.policy.reduction).to_int64()
  let floor = self.minimum()
  self.window = if self.ssthresh > floor { self.ssthresh } else { floor }
}

///|
/// Persistent congestion (RFC 9002 §7.6): the window collapses to the minimum and slow
/// start begins again, because nothing got through for longer than a congestion period.
impl Control for NewReno with fn on_persistent(self) {
  self.window = self.minimum()
  self.recovery = -1L
}

///|
pub extend NewReno with Control::{
  window,
  in_flight,
  on_sent,
  on_ack,
  on_lost,
  on_congestion,
  on_persistent,
}

///|
/// A sender's recovery state for one packet-number space: the round-trip estimate, what is
/// outstanding, and the congestion controller, driven by the two events a sender has —
/// a packet went out, an ACK came back.
pub struct State {
  rtt : Rtt
  flight : Flight
  control : &Control
  policy : Policy
  mut pto_count : Int
  mut last_sent : Int64
}

///|
/// A fresh state. Leave `control` out for NewReno under the same policy; give one to use
/// another controller.
pub fn State::new(policy? : Policy = policy, control? : &Control) -> State {
  {
    rtt: Rtt::new(),
    flight: Flight::new(),
    control: match control {
      Some(c) => c
      None => NewReno::new(policy~)
    },
    policy,
    pto_count: 0,
    last_sent: -1L,
  }
}

///|
/// An ack-eliciting packet went out: track it for acknowledgement and charge the window.
pub fn State::on_sent(
  self : State,
  pn : Int64,
  at~ : Int64,
  size~ : Int64,
) -> Unit {
  self.flight.on_sent(pn, at~, size~)
  self.control.on_sent(size)
  self.last_sent = at
}

///|
/// An ACK arrived (RFC 9002 §5–§7): sample the round trip off the largest newly
/// acknowledged packet, free the acknowledged bytes, then run loss detection over both
/// thresholds. Answers with the packet numbers declared lost — the frames to send again.
///
/// `ack_delay` is what the ACK frame said, in microseconds; the frame's own field is in
/// the peer's exponent and decoding it is the connection's job, not this one's.
///
/// One round of loss is one congestion signal however many packets it covers, and a round
/// spanning more than `persistent` probe timeouts is persistent congestion (§7.6).
pub fn State::on_ack(
  self : State,
  frame : @frame.Frame,
  now : Int64,
  ack_delay~ : Int64,
) -> Array[Int64] raise @frame.Refused {
  let ranges = frame.acked()
  if ranges.length() == 0 {
    return []
  }
  let mut largest = -1L
  for r in ranges {
    if r.1.reinterpret_as_int64() > largest {
      largest = r.1.reinterpret_as_int64()
    }
  }
  let signed = ranges.map(r => {
    (r.0.reinterpret_as_int64(), r.1.reinterpret_as_int64())
  })
  let was = self.flight.largest_acked()
  let sample_at = self.flight.time_of(largest)
  let freed = self.flight.on_ack(signed)
  self.control.on_ack(freed)
  if freed > 0L {
    self.pto_count = 0
  }
  // Only the largest newly acknowledged packet gives a usable round-trip sample: an
  // older one's ACK may have been sitting in the peer's queue for an unknown while.
  match sample_at {
    Some(at) =>
      if largest > was {
        self.rtt.sample(now - at, ack_delay~, policy=self.policy)
      }
    None => ()
  }
  let lost = self.flight.lost(
    now,
    packets=self.policy.packets,
    time=self.rtt.threshold(policy=self.policy),
  )
  if lost.length() > 0 {
    let mut earliest = lost[0].at
    let mut latest = lost[0].at
    for p in lost {
      self.control.on_lost(p.size)
      if p.at < earliest {
        earliest = p.at
      }
      if p.at > latest {
        latest = p.at
      }
    }
    self.control.on_congestion(at=earliest, now~)
    // §7.6.2: nothing got through across a span longer than a congestion period, and
    // two lost packets are the least that can bound such a span.
    if lost.length() >= 2 &&
      latest - earliest >
      self.rtt.pto(policy=self.policy) * self.policy.persistent {
      self.control.on_persistent()
    }
  }
  lost.map(p => p.pn)
}

///|
/// Whether `bytes` more may go out without exceeding the congestion window.
pub fn State::can_send(self : State, bytes : Int64) -> Bool {
  can_send(self.control, bytes)
}

///|
/// The congestion window in bytes.
pub fn State::window(self : State) -> Int64 {
  self.control.window()
}

///|
/// The bytes currently in flight.
pub fn State::in_flight(self : State) -> Int64 {
  self.control.in_flight()
}

///|
/// The round-trip estimate this space has built.
pub fn State::rtt(self : State) -> Rtt {
  self.rtt
}

///|
/// The probe timeout in microseconds, before backoff.
pub fn State::pto(self : State) -> Int64 {
  self.rtt.pto(policy=self.policy)
}

///|
/// How many probe timeouts have fired without an acknowledgement since the last one that
/// did — the backoff exponent.
pub fn State::pto_count(self : State) -> Int {
  self.pto_count
}

///|
/// When the probe timer fires: the last ack-eliciting packet's send time plus the timeout
/// backed off by `2^pto_count` (RFC 9002 §6.2.1). `None` when nothing is outstanding,
/// which is the timer disarmed.
pub fn State::pto_deadline(self : State) -> Int64? {
  if self.flight.outstanding().length() == 0 {
    None
  } else {
    Some(self.last_sent + self.pto() * exp2(self.pto_count))
  }
}

///|
/// The probe timer fired (RFC 9002 §6.2.4): back off for the next arming. Sending the
/// probes is the caller's, because what to put in them is the connection's business.
pub fn State::on_pto(self : State) -> Unit {
  self.pto_count = self.pto_count + 1
}

///|
/// The packet numbers still outstanding.
pub fn State::outstanding(self : State) -> Array[Int64] {
  self.flight.outstanding()
}

///|
/// Two to the `n`, by doubling: the backoff multiplier is small and a shift on `Int64`
/// would need `n` bounded anyway.
fn exp2(n : Int) -> Int64 {
  let mut r = 1L
  for _i = 0; _i < n; _i = _i + 1 {
    r = r * 2L
  }
  r
}

///|
pub extend Sent with Debug::{to_repr}

///|
pub extend Sent with Eq::{not_equal, equal}
