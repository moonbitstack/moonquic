// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Moving a connection to another address (RFC 9000 §8.2, §9). A UDP source address proves nothing
// and a connection id is in the clear, so a connection moves only for a packet that authenticated,
// that says something other than probing, and that is the newest it has seen: anything less lets
// whoever can put a packet on the wire choose where this server's answers go.

///|
/// The frames a packet may carry on a path without moving the connection to it (RFC 9000 §9.1).
fn is_probing(frame : @frame.Frame) -> Bool {
  frame
  is (PathChallenge(_) | PathResponse(_) | NewConnectionId(..) | Padding(_))
}

///|
/// How many probe timeouts a path has to answer a challenge (RFC 9000 §8.2.4 says three).
let path_timeouts : Int64 = 3L

///|
/// Where a connection came from while a new address has yet to prove itself, and what it knew
/// about that path, so a move that was never answered can be undone (RFC 9000 §9.3.2).
priv struct Moved[A] {
  peer : A
  validated : Bool
  rx : Int64
  tx : Int64
  give_up : Int64
  mut resend : Int64
}

///|
/// How much more may go to the current address, which an unvalidated one limits (RFC 9000 §8.1).
fn[A] Session::budget(self : Session[A]) -> Int64 {
  if self.validated {
    9223372036854775807L
  } else {
    amplification * self.rx - self.tx
  }
}

///|
/// One packet of path frames to `to`, outside the send loop: a PATH_CHALLENGE or PATH_RESPONSE is
/// sent on one particular path and is never retransmitted as it stands (RFC 9000 §13.3). It is
/// padded to 1200 bytes, which is how a path shows it carries a full-size datagram (§8.2.1, §8.2.2),
/// unless the budget allows less.
fn[A] Session::probe(
  self : Session[A],
  frames : Array[@frame.Frame],
  to : A,
  budget : Int64,
) -> Unit {
  guard self.app_tx is Some(_) else { return }
  let pn = self.core.conn.next_packet_number(Level::Application)
  self.sender.advance_past(pn)
  let payload = @packet.payload(frames)
  let build = p => self.seal(Level::Application, p, pn)
  let full = pad(payload, build, min_datagram)
  let datagram = if full.length().to_int64() <= budget {
    full
  } else {
    build(payload)
  }
  guard datagram.length().to_int64() <= budget else { return }
  self.probes.push((datagram, to))
}

///|
/// An authenticated packet from an address other than the connection's. A challenge is answered
/// where it came from; the connection moves only if this packet is not just probing and is the
/// newest, since an older one is a reordered packet from before the peer moved (§9.3). The frames
/// handed back are what is left to act on.
fn[A] Session::on_other_path(
  self : Session[A],
  frames : Array[@frame.Frame],
  newest : Bool,
  from : A,
  addressed : Bytes,
  nonce : Bytes,
  size : Int32,
  now : Int64,
) -> Array[@frame.Frame] {
  if self.phase == Active && newest && !frames.iter().all(is_probing) {
    self.move_to(from, addressed, nonce, size, now)
    return frames
  }
  let budget = amplification * size.to_int64()
  for frame in frames {
    if frame is PathChallenge(data) {
      self.probe([PathResponse(data)], from, budget)
    }
  }
  frames.filter(frame => !(frame is PathChallenge(_)))
}

///|
/// Start answering at `to`, and challenge it. Until it answers it is an address like any other that
/// has never proven itself, so its budget starts over at what it has just sent (§9.4).
fn[A] Session::move_to(
  self : Session[A],
  to : A,
  addressed : Bytes,
  nonce : Bytes,
  size : Int32,
  now : Int64,
) -> Unit {
  let pto = self.sender.recovery.pto()
  let give_up = now + path_timeouts * pto
  self.moved = match self.moved {
    // A second move before the first was answered still goes back to the last proven address.
    Some(earlier) => Some({ ..earlier, give_up, resend: now + pto, })
    None =>
      Some({
        peer: self.peer,
        validated: self.validated,
        rx: self.rx,
        tx: self.tx,
        give_up,
        resend: now + pto,
      })
  }
  self.peer = to
  self.validated = false
  self.rx = size.to_int64()
  self.tx = 0L
  // A peer that changed its id on the way here does not want the two paths linked, so this end
  // changes too, if it can (RFC 9000 §9.5). A NAT rebinding keeps the id, and so does this.
  if self.ids.heard_on != addressed {
    ignore(self.next_peer_id())
  }
  self.challenge(self.path.start(nonce))
}

///|
/// Send the outstanding challenge to the current address, on its budget.
fn[A] Session::challenge(self : Session[A], data : Bytes) -> Unit {
  let before = self.probes.length()
  self.probe([PathChallenge(data)], self.peer, self.budget())
  if self.probes.length() > before {
    self.tx = self.tx + self.probes[before].0.length().to_int64()
  }
}

///|
/// The current address answered its challenge, so it is the peer's, and what this connection knew
/// about the path it left no longer applies (§9.4).
fn[A] Session::on_path_proven(self : Session[A]) -> Unit {
  guard self.moved is Some(_) else { return }
  self.moved = None
  self.validated = true
  self.sender.recovery.on_new_path()
}

///|
/// A moved connection's clock: challenge again a probe timeout on, and after three go back where
/// it came from, since a path that will not answer is not where the peer is (§9.3.2).
fn[A] Session::tick_path(self : Session[A], now : Int64) -> Unit {
  guard self.moved is Some(moved) else { return }
  if now >= moved.give_up {
    self.peer = moved.peer
    self.validated = moved.validated
    self.rx = moved.rx
    self.tx = moved.tx
    self.moved = None
    self.path.reset()
    self.path.validated = moved.validated
    return
  }
  if now >= moved.resend {
    moved.resend = now + self.sender.recovery.pto()
    self.challenge(self.path.challenge())
  }
}
