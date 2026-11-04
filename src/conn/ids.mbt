// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Spare connection ids (RFC 9000 §5.1, §19.15, §19.16). A peer that changes path changes its id too,
// so the two ends of the old path and the new cannot be linked by anyone watching; for that each
// end hands the other ids in advance. A server's come from its endpoint, since they have to be
// unique across connections, and this is the bookkeeping on either side of that.

///|
/// What a connection has given its peer, and what the peer has given it.
priv struct Ids {
  /// The spare ids this end has issued and not had retired, by sequence number.
  issued : Map[UInt64, Bytes]
  /// Whether the peer is done with the id from the handshake, which is sequence number 0.
  mut handshake_retired : Bool
  mut next_seq : UInt64
  /// How many the peer will take at once (its active_connection_id_limit).
  mut limit : UInt64
  /// Retired, and not yet forgotten by the endpoint.
  retired : Array[Bytes]
  /// What the peer has offered: sequence number, id and reset token.
  offered : Array[(UInt64, Bytes, Bytes)]
  /// The sequence number of the id being sent to.
  mut peer_seq : UInt64
  /// The id the peer last addressed this end by.
  mut heard_on : Bytes
}

///|
fn Ids::new() -> Ids {
  {
    issued: Map([]),
    handshake_retired: false,
    next_seq: 1UL,
    limit: 2UL,
    retired: [],
    offered: [],
    peer_seq: 0UL,
    heard_on: b"",
  }
}

///|
fn Ids::take_retired(self : Ids) -> Array[Bytes] {
  let out = self.retired.copy()
  self.retired.clear()
  out
}

///|
/// Whether this connection's peer is owed another id: the handshake's counts as one held, unless it
/// has been retired.
fn[A] Session::owes_id(self : Session[A]) -> Bool {
  guard self.phase == Active && self.handshake_done() else { return false }
  let cap = if self.ids.limit < self.cfg.connection_ids {
    self.ids.limit
  } else {
    self.cfg.connection_ids
  }
  let held = self.ids.issued.length().to_uint64() +
    (if self.ids.handshake_retired { 0UL } else { 1UL })
  held < cap
}

///|
/// Whether the handshake is over, so 1-RTT frames can go out.
fn[A] Session::handshake_done(self : Session[A]) -> Bool {
  match self.tls {
    Some(tls) => tls.is_connected()
    None => self.app_tx is Some(_)
  }
}

///|
fn[A] Session::issue_id(self : Session[A], cid : Bytes, token : Bytes) -> Unit {
  let seq = self.ids.next_seq
  self.ids.next_seq = seq + 1UL
  self.ids.issued[seq] = cid
  self.sender.queue_control(
    NewConnectionId(seq~, retire_prior_to=0UL, conn_id=cid, reset_token=token),
  )
}

///|
/// The peer is done with an id of ours. Naming one never issued is a protocol violation (§19.16).
fn[A] Session::on_retire_id(
  self : Session[A],
  seq : UInt64,
  now : Int64,
) -> Unit {
  if seq >= self.ids.next_seq {
    return self.close(protocol_violation, b"retired an id never issued", now)
  }
  // The handshake's id stays routable: it is the connection's key, and retiring it frees nothing.
  if seq == 0UL {
    self.ids.handshake_retired = true
  } else if self.ids.issued.get(seq) is Some(cid) {
    self.ids.issued.remove(seq)
    self.ids.retired.push(cid)
  }
}

///|
/// An id from the peer, for when this end has to change the one it sends to (§5.1.2). Anything
/// below `retire_prior_to` has to go, the one in use with it.
fn[A] Session::on_new_id(
  self : Session[A],
  seq : UInt64,
  retire_prior_to : UInt64,
  cid : Bytes,
  token : Bytes,
  now : Int64,
) -> Unit {
  if retire_prior_to > seq {
    return self.close(
      frame_encoding_error, b"retire_prior_to past the sequence", now,
    )
  }
  if self.ids.offered.iter().all(entry => entry.0 != seq) &&
    seq > self.ids.peer_seq {
    self.ids.offered.push((seq, cid, token))
  }
  let kept = []
  for entry in self.ids.offered {
    if entry.0 < retire_prior_to {
      self.sender.queue_control(RetireConnectionId(entry.0))
    } else {
      kept.push(entry)
    }
  }
  self.ids.offered.clear()
  self.ids.offered.append(kept)
  if self.ids.peer_seq < retire_prior_to {
    ignore(self.next_peer_id())
  }
}

///|
/// Start sending to the next id the peer offered, and retire the one in use. False when it offered
/// none, in which case the connection goes on with the one it has (§9.5).
fn[A] Session::next_peer_id(self : Session[A]) -> Bool {
  guard self.ids.offered.length() > 0 else { return false }
  let (seq, cid, _) = self.ids.offered.remove(0)
  self.sender.queue_control(RetireConnectionId(self.ids.peer_seq))
  self.ids.peer_seq = seq
  self.peer_cid = cid
  true
}
