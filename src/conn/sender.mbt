// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The QUIC send loop, assembled (RFC 9000 §13, RFC 9002): the deterministic core a connection
// drives to put stream data on the wire and recover from loss. It composes the stream scheduler
// (which stream sends how much, bounded by flow control), the loss-recovery state (RTT,
// congestion window, loss detection), and a record of what each packet carried. `poll_send`
// yields the next packet: control frames, then a retransmission or freshly scheduled data,
// charging the congestion window. `on_ack` clears acknowledged packets and re-queues whatever
// the ACK reveals as lost.

///|
/// How many bytes of control frames go in a packet beside its stream data. A STREAM frame is at
/// most `max_frame`, so this has to leave the frame and the ACK that may join it inside a datagram.
let control_room : Int32 = 64

///|
/// A run of a stream's bytes, kept until all of it is acknowledged. `live` counts what is not.
priv struct Part {
  offset : UInt64
  bytes : Bytes
  mut live : UInt64
}

///|
/// What is still held for one stream, and where the next write starts.
priv struct Held {
  parts : Array[Part]
  mut end : UInt64
  mut finished : Bool
}

///|
/// What one packet carried, for the day it is lost.
priv struct Carried {
  chunks : Array[@stream.Chunk]
  control : Array[@frame.Frame]
}

///|
/// A connection's send state for one packet-number space.
pub struct Sender {
  sched : @stream.Scheduler
  recovery : @recovery.State
  priv held : Map[UInt64, Held]
  priv control : Array[@frame.Frame]
  priv in_packet : Map[Int64, Carried]
  priv retransmit : Array[@stream.Chunk]
  mut next_pn : Int64
  mut ack_exponent : Int32
  mut probes : Int32
}

///|
/// A fresh sender: `initial_max_data`/`initial_max_stream_data` are the peer's advertised flow
/// limits, `max_datagram_size` sizes the congestion window, `max_ack_delay`/`granularity` tune
/// the timers (microseconds), and `max_frame` caps a STREAM frame's payload.
pub fn Sender::new(
  initial_max_data : UInt64,
  initial_max_stream_data : UInt64,
  max_datagram_size : Int64,
  max_ack_delay : Int64,
  granularity : Int64,
  max_frame : UInt64,
) -> Sender {
  {
    sched: @stream.Scheduler::new(
      @stream.Budget::new(initial_max_data, initial_max_stream_data),
      frame=max_frame,
    ),
    recovery: @recovery.State::new(
      policy=@recovery.Policy::new(
        datagram=max_datagram_size,
        ack_delay=max_ack_delay,
        granularity~,
      ),
    ),
    held: Map([]),
    control: [],
    in_packet: Map([]),
    retransmit: [],
    next_pn: 0L,
    ack_exponent: 3,
    probes: 0,
  }
}

///|
/// Skip the send counter past `pn`, so a packet this sender did not build — a driver's
/// ACK-only packet in the same space — does not collide with a number it later assigns. A
/// `pn` the sender is already past leaves it alone.
pub fn Sender::advance_past(self : Sender, pn : Int64) -> Unit {
  if pn >= self.next_pn {
    self.next_pn = pn + 1L
  }
}

///|
/// Queue `bytes` of application data to send on stream `id`, after anything queued before.
pub fn Sender::queue_stream(self : Sender, id : UInt64, bytes : Bytes) -> Unit {
  guard bytes.length() > 0 else { return }
  let held = match self.held.get(id) {
    Some(h) => h
    None => {
      let h : Held = { parts: [], end: 0UL, finished: false, }
      self.held[id] = h
      h
    }
  }
  let size = bytes.length().to_uint64()
  held.parts.push({ offset: held.end, bytes, live: size, })
  held.end = held.end + size
  self.sched.queue(id, size)
}

///|
/// Mark stream `id` finished.
pub fn Sender::queue_fin(self : Sender, id : UInt64) -> Unit {
  self.sched.queue_fin(id)
  if self.held.get(id) is Some(held) {
    held.finished = true
  }
}

///|
/// Queue a control frame to go out reliably: it is sent again if the packet carrying it is lost.
pub fn Sender::queue_control(self : Sender, frame : @frame.Frame) -> Unit {
  self.control.push(frame)
}

///|
/// Raise the connection-wide send limit from a received MAX_DATA frame.
pub fn Sender::on_max_data(self : Sender, new_max : UInt64) -> Unit {
  self.sched.on_max_data(new_max)
}

///|
/// Raise stream `id`'s send limit from a received MAX_STREAM_DATA frame.
pub fn Sender::on_max_stream_data(
  self : Sender,
  id : UInt64,
  new_max : UInt64,
) -> Unit {
  self.sched.on_max_stream_data(id, new_max)
}

///|
/// Stop sending on stream `id`: nothing queued or lost on it goes out from now on, and a
/// RESET_STREAM tells the peer where it ended.
pub fn Sender::abandon(self : Sender, id : UInt64, code : UInt64) -> Unit {
  guard self.held.get(id) is Some(held) else { return }
  self.held.remove(id)
  self.sched.cancel(id)
  self.queue_control(ResetStream(id~, error_code=code, final_size=held.end))
}

///|
/// How many bytes written to stream `id` the peer has not acknowledged yet.
pub fn Sender::buffered(self : Sender, id : UInt64) -> UInt64 {
  match self.held.get(id) {
    Some(h) => h.parts.fold(init=0UL, (sum, p) => sum + p.live)
    None => 0UL
  }
}

///|
fn Sender::materialize(self : Sender, send : @stream.Chunk) -> @frame.Frame {
  let out = Buffer()
  let stop = send.offset + send.length
  if self.held.get(send.stream) is Some(held) {
    for part in held.parts {
      let end = part.offset + part.bytes.length().to_uint64()
      if end <= send.offset || part.offset >= stop {
        continue
      }
      let from = if send.offset > part.offset {
        (send.offset - part.offset).to_int()
      } else {
        0
      }
      let to = if stop < end {
        (stop - part.offset).to_int()
      } else {
        part.bytes.length()
      }
      out.write_bytesview(part.bytes[from:to])
    }
  }
  Stream(id=send.stream, offset=send.offset, fin=send.fin, data=out.to_bytes())
}

///|
/// The next piece of stream data to send, skipping what belongs to a stream since abandoned. What
/// was lost goes oldest first, since that is what the peer's reassembly is waiting on.
fn Sender::next_chunk(self : Sender) -> @stream.Chunk? raise {
  while self.retransmit.length() > 0 {
    let chunk = self.retransmit.remove(0)
    if self.held.contains(chunk.stream) || chunk.length == 0UL {
      return Some(chunk)
    }
  }
  self.sched.next()
}

///|
/// The next packet to send at `now`, or `None` when the congestion window is closed or nothing
/// is queued (RFC 9002 §7). Control frames go first, then one retransmission or one fresh chunk;
/// the packet is recorded in the recovery state and its contents remembered for retransmission.
/// A probe is sent whatever the window says, since it is how a sender whose whole window was lost
/// finds out (RFC 9002 §7.5), and is a PING when there is nothing else to carry.
pub fn Sender::poll_send(
  self : Sender,
  now : Int64,
) -> (Int64, Array[@frame.Frame])? raise {
  let probing = self.probes > 0
  guard self.recovery.can_send(1L) || probing else { return None }
  let frames : Array[@frame.Frame] = []
  let carried : Carried = { chunks: [], control: [], }
  let mut size = 0
  while self.control.length() > 0 {
    let cost = @frame.encode(self.control[0]).length()
    if size > 0 && size + cost > control_room {
      break
    }
    let frame = self.control.remove(0)
    frames.push(frame)
    carried.control.push(frame)
    size = size + cost
  }
  if self.next_chunk() is Some(chunk) {
    let frame = self.materialize(chunk)
    frames.push(frame)
    carried.chunks.push(chunk)
    size = size + chunk.length.to_int()
  }
  if frames.length() == 0 && probing {
    frames.push(Ping)
    size = 1
  }
  guard frames.length() > 0 else { return None }
  if probing {
    self.probes = self.probes - 1
  }
  let pn = self.next_pn
  self.next_pn = self.next_pn + 1L
  self.recovery.on_sent(pn, at=now, size=size.to_int64())
  self.in_packet[pn] = carried
  Some((pn, frames))
}

///|
/// Put what packet `pn` carried back in line.
fn Sender::requeue(self : Sender, pn : Int64) -> Unit {
  guard self.in_packet.get(pn) is Some(carried) else { return }
  self.in_packet.remove(pn)
  for chunk in carried.chunks {
    self.retransmit.push(chunk)
  }
  for frame in carried.control {
    self.control.push(frame)
  }
}

///|
/// Packet `pn` arrived: what it carried need not be held any longer.
fn Sender::settle(self : Sender, pn : Int64) -> Unit {
  guard self.in_packet.get(pn) is Some(carried) else { return }
  self.in_packet.remove(pn)
  for chunk in carried.chunks {
    guard self.held.get(chunk.stream) is Some(held) else { continue }
    let stop = chunk.offset + chunk.length
    for part in held.parts {
      let end = part.offset + part.bytes.length().to_uint64()
      let from = if chunk.offset > part.offset {
        chunk.offset
      } else {
        part.offset
      }
      let to = if stop < end { stop } else { end }
      if to > from {
        part.live = part.live - (to - from)
      }
    }
    while held.parts.length() > 0 && held.parts[0].live == 0UL {
      held.parts.remove(0) |> ignore
    }
    if held.finished && held.parts.length() == 0 {
      self.held.remove(chunk.stream)
    }
  }
}

///|
/// Process a received ACK `frame` at `now`: clear acknowledged packets from the recovery state
/// and re-queue the contents of any packet the ACK reveals as lost, to be retransmitted by a
/// later `poll_send` (RFC 9002 §6). Raises on a malformed ACK.
pub fn Sender::on_ack(
  self : Sender,
  frame : @frame.Frame,
  now : Int64,
) -> Unit raise {
  let delay = match frame {
    Ack(delay~, ..) | AckEcn(delay~, ..) =>
      delay.reinterpret_as_int64() << self.ack_exponent
    _ => 0L
  }
  let lost = self.recovery.on_ack(frame, now, ack_delay=delay)
  for pn in lost {
    self.requeue(pn)
  }
  let acked = frame.acked()
  for pn in self.in_packet.keys().collect() {
    let number = pn.reinterpret_as_uint64()
    if acked.iter().any(r => number >= r.0 && number <= r.1) {
      self.settle(pn)
    }
  }
}

///|
/// Handle the probe timeout firing at `now` (RFC 9002 §6.2.4). If the PTO deadline has passed with
/// packets still outstanding, re-queue the contents of the two oldest packets that still hold any
/// as probes (§6.2.4 allows two, so one lost does not cost another timeout) — a later `poll_send`
/// puts them back on the wire — and back off the timer for the next arming. A packet that went out
/// again at an earlier timeout stays outstanding until an ACK settles it, which is why the oldest
/// alone will not do. Unlike loss detection, this neither declares packets lost nor reduces the
/// congestion window. Returns whether a probe was armed.
pub fn Sender::on_pto_timeout(self : Sender, now : Int64) -> Bool {
  guard self.recovery.pto_deadline() is Some(deadline) else { return false }
  guard now >= deadline else { return false }
  let out = self.recovery.outstanding()
  guard out.length() > 0 else { return false }
  let oldest = out.filter(pn => self.in_packet.contains(pn))
  oldest.sort()
  for pn in oldest[:if oldest.length() < 2 { oldest.length() } else { 2 }] {
    self.requeue(pn)
  }
  self.probes = 2
  self.recovery.on_pto()
  true
}

///|
/// The packet numbers still outstanding (sent, not yet acknowledged or declared lost).
pub fn Sender::outstanding(self : Sender) -> Array[Int64] {
  self.recovery.outstanding()
}

///|
/// The current congestion window (bytes).
pub fn Sender::window(self : Sender) -> Int64 {
  self.recovery.window()
}
