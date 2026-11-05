// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Pacing (RFC 9002 §7.7): an endpoint spreads a window over the round trip instead of putting
// all of it on the wire at once. A burst fills a bottleneck queue and then loses a whole window
// of packets, which costs more than the slower start did. The pacer is a token bucket: bytes
// accrue at the congestion controller's rate, and a packet may go when its share has accrued.
// It holds no clock, so a caller drives it with the same `now` every other timer uses.

///|
/// How many datagrams may leave back to back before the rate applies: enough for the ack clock
/// to keep the pipe full, small enough not to make a queue.
let burst : Int64 = 10

///|
/// A token bucket over bytes, at a rate in bytes per microsecond. A rate of zero means the
/// connection is not paced and everything is allowed.
pub struct Pacer {
  priv mut tokens : Double
  /// When the bucket was last brought up to date.
  priv mut at : Int64
  priv mut rate : Double
  priv burst : Double
  priv mut started : Bool
}

///|
/// A pacer that lets everything through until a rate is set.
pub fn Pacer::new(burst_bytes~ : Int64 = burst * 1200L) -> Pacer {
  {
    tokens: 0.0,
    at: 0L,
    rate: 0.0,
    burst: burst_bytes.to_double(),
    started: false,
  }
}

///|
/// The rate in bytes per microsecond; zero when unpaced.
pub fn Pacer::rate(self : Pacer) -> Double {
  self.rate
}

///|
/// Set the rate, in bytes per microsecond. Zero turns pacing off. The bucket starts full, so
/// the first burst after a quiet period is not delayed.
pub fn Pacer::set_rate(self : Pacer, rate : Double) -> Unit {
  if rate < 0.0 {
    self.rate = 0.0
  } else {
    self.rate = rate
  }
  if !self.started {
    self.tokens = self.burst
    self.started = true
  }
}

///|
/// Bring the bucket up to `now`.
fn Pacer::refill(self : Pacer, now : Int64) -> Unit {
  if !self.started {
    self.at = now
    self.tokens = self.burst
    self.started = true
    return
  }
  if now > self.at && self.rate > 0.0 {
    self.tokens = self.tokens + (now - self.at).to_double() * self.rate
    if self.tokens > self.burst {
      self.tokens = self.burst
    }
  }
  self.at = now
}

///|
/// Whether `bytes` may go at `now`. Unpaced, always.
pub fn Pacer::allow(self : Pacer, now : Int64, bytes : Int64) -> Bool {
  if self.rate <= 0.0 {
    return true
  }
  self.refill(now)
  self.tokens >= bytes.to_double()
}

///|
/// Take `bytes` out of the bucket.
pub fn Pacer::spend(self : Pacer, now : Int64, bytes : Int64) -> Unit {
  if self.rate <= 0.0 {
    return
  }
  self.refill(now)
  self.tokens = self.tokens - bytes.to_double()
  if self.tokens < 0.0 {
    self.tokens = 0.0
  }
}

///|
/// When `bytes` will have accrued, or `None` when it already has or nothing is paced. A driver
/// arms a timer on this and comes back for the packet.
pub fn Pacer::next_at(self : Pacer, now : Int64, bytes : Int64) -> Int64? {
  if self.rate <= 0.0 {
    return None
  }
  self.refill(now)
  if self.tokens >= bytes.to_double() {
    return None
  }
  let missing = bytes.to_double() - self.tokens
  // Rounded up: a truncated microsecond would come back a hair short and wait again.
  let wait = (missing / self.rate).ceil().to_int64()
  Some(now + (if wait < 1L { 1L } else { wait }))
}
