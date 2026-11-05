// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Multipath, first stage (draft-ietf-quic-multipath §3, §4): the frames and the state a
// connection keeps about its paths. A path is an id both ends know, the connection id used on
// it, and whether it has answered a challenge; the draft gives each path its own packet-number
// space and congestion state, which is the next stage rather than this one — what is here is
// everything the two ends have to agree on before that can be built, and it is what the
// transport parameter and the four frames carry.

///|
/// The largest path id a peer may name: it is folded into the packet nonce, which is twelve
/// bytes wide, so the id has to fit in the low 32 bits (draft-ietf-quic-multipath §3.1).
pub let max_path_id : UInt64 = 0xffff_ffffUL

///|
/// One path: the id both ends use for it, the connection id traffic on it is addressed by, and
/// what each end has said about it.
pub(all) struct PathState {
  id : UInt64
  mut dcid : Bytes
  mut validated : Bool
  /// The peer's latest word: true for PATH_AVAILABLE, false for PATH_BACKUP. A connection may
  /// send on a backup path, but should not while an available one is carrying traffic.
  mut available : Bool
  /// The highest status sequence number heard from the peer.
  mut heard : UInt64
  /// The highest status sequence number this end has sent.
  mut sent : UInt64
  mut abandoned : Bool
}

///|
/// The paths of one connection, path 0 being the one the handshake ran on.
pub struct Paths {
  paths : Map[UInt64, PathState]
  /// The largest path id the peer said it would accept, and the largest this end will accept.
  mut peer_max : UInt64
  local_max : UInt64
}

///|
/// A connection that has only the path its handshake ran on. `local_max` is what this end
/// advertises as `initial_max_path_id`: zero means multipath is not offered at all.
pub fn Paths::new(local_max~ : UInt64 = 0UL) -> Paths {
  let zero : PathState = {
    id: 0UL,
    dcid: b"",
    validated: true,
    available: true,
    heard: 0UL,
    sent: 0UL,
    abandoned: false,
  }
  { paths: Map([(0UL, zero)]), peer_max: 0UL, local_max, }
}

///|
/// The path with this id, if the connection has it.
pub fn Paths::get(self : Paths, id : UInt64) -> PathState? {
  self.paths.get(id)
}

///|
/// How many paths the connection has, path 0 among them.
pub fn Paths::count(self : Paths) -> Int32 {
  self.paths.length()
}

///|
/// The ids of the paths the connection has.
pub fn Paths::ids(self : Paths) -> Array[UInt64] {
  self.paths.keys().collect()
}

///|
/// The largest path id this end will open or accept.
pub fn Paths::local_max(self : Paths) -> UInt64 {
  self.local_max
}

///|
/// The largest path id the peer said it would accept.
pub fn Paths::peer_max(self : Paths) -> UInt64 {
  self.peer_max
}

///|
/// Whether `id` is a path id the peer may use without a new one being negotiated.
pub fn Paths::allowed(self : Paths, id : UInt64) -> Bool {
  id <= self.local_max
}

///|
/// Give the path `id` the connection id `dcid` and start it unvalidated: the first thing on it
/// is a PATH_CHALLENGE (draft-ietf-quic-multipath §3.2).
pub fn Paths::bind(self : Paths, id : UInt64, dcid : Bytes) -> Unit {
  match self.paths.get(id) {
    Some(path) => {
      path.dcid = dcid
      path.validated = false
    }
    None => {
      let path : PathState = {
        id,
        dcid,
        validated: false,
        available: true,
        heard: 0UL,
        sent: 0UL,
        abandoned: false,
      }
      self.paths[id] = path
    }
  }
}

///|
/// The lowest path id nobody is using, if the peer's limit leaves room for one. `None` means a
/// MAX_PATH_ID has to arrive before this connection can grow another path.
pub fn Paths::free(self : Paths) -> UInt64? {
  let mut id = 1UL
  while id <= self.peer_max {
    match self.paths.get(id) {
      Some(path) =>
        if !path.abandoned {
          id = id + 1UL
          continue
        }
      None => return Some(id)
    }
    id = id + 1UL
  }
  None
}

///|
/// The peer's MAX_PATH_ID: it may only rise, and it is never below what its
/// `initial_max_path_id` already said (draft-ietf-quic-multipath §4.5).
pub fn Paths::on_max_path_id(self : Paths, max : UInt64) -> Unit {
  if max > self.peer_max {
    self.peer_max = max
  }
}

///|
/// Take the peer's PATH_STATUS for `id`: a sequence number at or below one already heard is a
/// reordering, not news (draft-ietf-quic-multipath §4.4).
pub fn Paths::on_status(
  self : Paths,
  id : UInt64,
  seq : UInt64,
  available : Bool,
) -> Bool {
  guard self.paths.get(id) is Some(path) else { return false }
  if seq <= path.heard && path.heard > 0UL {
    return false
  }
  path.heard = seq
  path.available = available
  true
}

///|
/// Give up a path. Path 0 is the connection's and cannot go (draft-ietf-quic-multipath §3.1).
pub fn Paths::abandon(self : Paths, id : UInt64) -> Bool {
  guard id != 0UL else { return false }
  match self.paths.get(id) {
    Some(path) => {
      path.abandoned = true
      path.available = false
      true
    }
    None => false
  }
}

///|
/// The next status sequence number to put on a PATH_STATUS for any path: the two states share
/// one counter space across the connection (draft-ietf-quic-multipath §4.4).
pub fn Paths::next_status(self : Paths, id : UInt64) -> UInt64? {
  guard self.paths.get(id) is Some(path) else { return None }
  path.sent = path.sent + 1UL
  Some(path.sent)
}

///|
/// Whether the path has answered a challenge.
pub fn Paths::validated(self : Paths, id : UInt64) -> Bool {
  match self.paths.get(id) {
    Some(path) => path.validated
    None => false
  }
}

///|
/// The peer answered a challenge on `id`.
pub fn Paths::on_validated(self : Paths, id : UInt64) -> Unit {
  if self.paths.get(id) is Some(path) {
    path.validated = true
  }
}
