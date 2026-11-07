// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The transmission state of one path (draft-ietf-quic-multipath §2.3, §5.4, §5.5): its own
// packet numbers, its own round-trip estimate, loss detection and congestion window, and what
// each of its packets carried so that a lost one can go out again. Flow control and the stream
// scheduler stay on the connection — the draft keeps those connection-wide, and makes only the
// numbers and the congestion state per path. That split is why a second path costs one of these
// rather than a second connection: the bytes are the connection's, the wire is the path's.

///|
/// One path's sending state. `space` is the path's packet-number space, which is the same object
/// the connection's core numbers that path's received packets in, so a number is used once
/// whichever end asks. `recovery` is this path's alone: a path that loses a packet says nothing
/// about the congestion on another.
pub struct Lane[A] {
  id : UInt64
  mut peer : A
  space : @packet.Space
  recovery : @recovery.State
  pacer : @recovery.Pacer
  /// What each packet of this path carried, by number, until it is acknowledged or lost.
  flight : Map[Int64, Array[@frame.Frame]]
  /// The frames each lost packet carried, waiting to go out again on this path.
  lost : Array[Array[@frame.Frame]]
  /// Probes this path owes after a probe timeout (§6.2.4), as PINGs when nothing else waits.
  mut probes : Int32
}

///|
/// A path's state with nothing on it yet.
pub fn[A] Lane::new(
  id : UInt64,
  peer : A,
  space : @packet.Space,
  recovery : @recovery.State,
  max_datagram : Int64,
) -> Lane[A] {
  {
    id,
    peer,
    space,
    recovery,
    pacer: @recovery.Pacer::new(burst_bytes=10L * max_datagram),
    flight: Map([]),
    lost: [],
    probes: 0,
  }
}

///|
/// The path id this state belongs to.
pub fn[A] Lane::id(self : Lane[A]) -> UInt64 {
  self.id
}

///|
/// The address this path's datagrams go to.
pub fn[A] Lane::peer(self : Lane[A]) -> A {
  self.peer
}

///|
/// The address this path's datagrams go to, changed when the peer rebinds it (draft §5.1).
pub fn[A] Lane::rebind(self : Lane[A], peer : A) -> Unit {
  self.peer = peer
}

///|
/// This path's packet-number space.
pub fn[A] Lane::space(self : Lane[A]) -> @packet.Space {
  self.space
}

///|
/// This path's round-trip estimate, loss detection and congestion window.
pub fn[A] Lane::recovery(self : Lane[A]) -> @recovery.State {
  self.recovery
}

///|
/// How many of this path's packets are outstanding.
pub fn[A] Lane::in_flight(self : Lane[A]) -> Int32 {
  self.flight.length()
}

///|
/// Whether `bytes` more may go on this path without exceeding its congestion window.
pub fn[A] Lane::can_send(self : Lane[A], bytes : Int64) -> Bool {
  self.recovery.can_send(bytes) || self.probes > 0
}

///|
/// Number `frames` into a packet on this path at `now`, or `None` when its window is closed or
/// its pacing bucket is empty. The caller seals the packet; this keeps the numbering and the
/// record a lost packet is sent again from.
pub fn[A] Lane::send(
  self : Lane[A],
  now : Int64,
  frames : Array[@frame.Frame],
  size : Int64,
) -> Int64? {
  let probing = self.probes > 0
  guard frames.length() > 0 else { return None }
  guard self.recovery.can_send(size) || probing else { return None }
  guard probing || self.pacer.allow(now, size) else { return None }
  if probing {
    self.probes = self.probes - 1
  }
  self.pacer.spend(now, size)
  let pn = self.space.next_packet_number()
  self.recovery.on_sent(pn, at=now, size~)
  self.flight[pn] = frames
  Some(pn)
}

///|
/// The frames waiting to go out again on this path: what a lost packet carried, then a PING if a
/// probe is owed and nothing else waits.
pub fn[A] Lane::due(self : Lane[A]) -> Array[@frame.Frame]? {
  if self.lost.length() > 0 {
    let frames = self.lost.remove(0)
    return Some(frames)
  }
  if self.probes > 0 {
    return Some([Ping])
  }
  None
}

///|
/// An acknowledgement for this path (draft-ietf-quic-multipath §4.1): what it settles leaves the
/// flight, and what it declares lost is queued for this path. Answers with the bytes that are
/// still outstanding, which is what the caller's window is read from.
pub fn[A] Lane::on_ack(
  self : Lane[A],
  frame : @frame.Frame,
  now : Int64,
  ack_exponent : Int32,
) -> Unit raise {
  let delay = match frame {
    Ack(delay~, ..)
    | AckEcn(delay~, ..)
    | PathAck(delay~, ..)
    | PathAckEcn(delay~, ..) => delay.reinterpret_as_int64() << ack_exponent
    _ => 0L
  }
  let lost = self.recovery.on_ack(frame, now, ack_delay=delay)
  self.pacer.set_rate(self.recovery.pacing_rate())
  for pn in lost {
    if self.flight.get(pn) is Some(carried) {
      self.flight.remove(pn)
      self.lost.push(carried)
    }
  }
  let acked = frame.acked()
  for pn in self.flight.keys().collect() {
    let number = pn.reinterpret_as_uint64()
    if acked.iter().any(r => number >= r.0 && number <= r.1) {
      self.flight.remove(pn)
    }
  }
}

///|
/// The probe timeout fired at `now`: the two oldest packets still outstanding go out again as
/// probes, and the timer backs off (RFC 9002 §6.2.4). Answers whether this path had anything to
/// send, which is what tells a driver to call `due`.
pub fn[A] Lane::on_pto(self : Lane[A], now : Int64) -> Bool {
  guard self.recovery.pto_deadline() is Some(deadline) else { return false }
  guard now >= deadline else { return false }
  let out = self.recovery.outstanding()
  guard out.length() > 0 else { return false }
  let oldest = out.filter(pn => self.flight.contains(pn))
  oldest.sort()
  for pn in oldest[:if oldest.length() < 2 { oldest.length() } else { 2 }] {
    if self.flight.get(pn) is Some(carried) {
      self.flight.remove(pn)
      self.lost.push(carried)
    }
  }
  self.probes = 2
  self.recovery.on_pto()
  true
}
