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
  /// The peer's connection id for this path: what this end addresses its datagrams to.
  mut dcid : Bytes
  /// This end's connection id for the path, which is how a packet that arrives is placed on it
  /// (draft-ietf-quic-multipath §1: a connection id belongs to exactly one path).
  mut lcid : Bytes
  mut validated : Bool
  /// The PATH_CHALLENGE this end sent on the path and has not had answered (RFC 9000 §8.2).
  mut challenge : Bytes
  /// The peer's latest word: true for PATH_AVAILABLE, false for PATH_BACKUP. A connection may
  /// send on a backup path, but should not while an available one is carrying traffic.
  mut available : Bool
  /// The highest connection-id sequence number the peer has offered for this path
  /// (draft-ietf-quic-multipath §3.2: each path numbers its ids on its own).
  mut peer_seq : UInt64
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
    lcid: b"",
    validated: true,
    challenge: b"",
    available: true,
    peer_seq: 0UL,
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
        lcid: b"",
        validated: false,
        challenge: b"",
        available: true,
        peer_seq: 0UL,
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
/// The next status sequence number to put on a PATH_STATUS for `id`: the two states share one
/// counter space for each path, and it only rises (draft-ietf-quic-multipath §4.3).
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

///|
/// The path a connection id belongs to, or 0 when no path has claimed it. Path 0's id is the
/// connection's own, which the table already routes by.
pub fn Paths::path_of(self : Paths, cid : Bytes) -> UInt64 {
  for id in self.paths.keys().collect() {
    guard self.paths.get(id) is Some(path) else { continue }
    if path.lcid == cid && cid.length() > 0 {
      return id
    }
  }
  0UL
}

///|
/// Give path `id` the connection id this end answers to on it (draft-ietf-quic-multipath §3.2).
/// A packet that arrives for that id belongs to this path and to its packet-number space.
pub fn Paths::bind_local(self : Paths, id : UInt64, cid : Bytes) -> Bool {
  match self.paths.get(id) {
    Some(path) => {
      path.lcid = cid
      true
    }
    None => false
  }
}

///|
/// The connection id this end answers to on path `id`, empty when it has none.
pub fn Paths::local_cid(self : Paths, id : UInt64) -> Bytes {
  match self.paths.get(id) {
    Some(path) => path.lcid
    None => b""
  }
}

///|
/// The connection id this end addresses path `id` by, empty when the path is not bound.
pub fn Paths::peer_cid(self : Paths, id : UInt64) -> Bytes {
  match self.paths.get(id) {
    Some(path) => path.dcid
    None => b""
  }
}

///|
/// Whether `id` is a path this end may open: the peer said it would maintain that many paths,
/// and this end is willing to as well (draft-ietf-quic-multipath §2.1).
pub fn Paths::openable(self : Paths, id : UInt64) -> Bool {
  id > 0UL && id <= self.peer_max && id <= self.local_max
}

///|
/// Begin proving path `id` with the eight-byte `nonce` (draft-ietf-quic-multipath §3.1): answers
/// with the challenge to put in a PATH_CHALLENGE, which goes out on the path itself.
pub fn Paths::start(self : Paths, id : UInt64, nonce : Bytes) -> Bytes {
  match self.paths.get(id) {
    Some(path) => {
      path.challenge = nonce
      path.validated = false
    }
    None => ()
  }
  nonce
}

///|
/// Whether `data` answers the challenge outstanding on path `id`. The comparison runs over every
/// byte rather than stopping at the first difference, so how long it takes says nothing about how
/// much of the value was right. A path with no challenge outstanding never proves.
pub fn Paths::prove(self : Paths, id : UInt64, data : Bytes) -> Bool {
  guard self.paths.get(id) is Some(path) else { return false }
  if path.challenge.length() == 0 || data.length() != path.challenge.length() {
    return false
  }
  let mut diff = 0
  for i = 0; i < data.length(); i = i + 1 {
    diff = diff | (data[i].to_int() ^ path.challenge[i].to_int())
  }
  if diff == 0 {
    path.validated = true
    path.challenge = b""
    true
  } else {
    false
  }
}

///|
/// Take a connection id the peer offered for `id` (draft-ietf-quic-multipath §4.4), which is what
/// this end addresses that path by from now on. An older sequence number than the one in use is a
/// reordering, not news.
pub fn Paths::on_peer_cid(
  self : Paths,
  id : UInt64,
  seq : UInt64,
  cid : Bytes,
) -> Bool {
  guard self.paths.get(id) is Some(path) else { return false }
  if seq < path.peer_seq {
    return false
  }
  path.peer_seq = seq
  path.dcid = cid
  true
}

///|
/// The peer gave up sequence number `seq` on path `id` (draft-ietf-quic-multipath §4.5). The id in
/// use on a path is the peer's to keep, so this only says it is no longer spare.
pub fn Paths::retire_peer_cid(self : Paths, id : UInt64, seq : UInt64) -> Bool {
  guard self.paths.get(id) is Some(path) else { return false }
  path.peer_seq = if seq + 1UL > path.peer_seq {
    seq + 1UL
  } else {
    path.peer_seq
  }
  true
}

///|
/// The path ids that are carrying traffic: everything bound and not given up.
pub fn Paths::open(self : Paths) -> Array[UInt64] {
  self.paths.iter().filter(e => !e.1.abandoned).map(e => e.0).collect()
}

// The second stage: each path numbers its packets on its own (draft-ietf-quic-multipath §2.3).
// A path's packets are sealed with a nonce that names the path (§2.4), acknowledged with a
// PATH_ACK (§4.1), lost and recovered separately (§5.4), and sent to that path's address. What
// stays on the connection is everything the two ends share: the streams, the flow control, and
// the scheduler that decides whose bytes go next.

///|
/// The sending state of path `path`, made the first time something is sent on it. Path 0's lane
/// shares the send loop's recovery state, so a connection that never opens a second path numbers,
/// paces and recovers exactly as it did before.
fn[A] Session::lane(self : Session[A], path : UInt64) -> Lane[A] {
  match self.lanes.get(path) {
    Some(lane) => lane
    None => {
      let lane = Lane::new(
        path,
        self.peer,
        self.core.conn.space_on(path, Level::Application),
        @recovery.State::new(
          policy=@recovery.Policy::new(
            datagram=self.cfg.max_datagram,
            ack_delay=self.cfg.max_ack_delay,
            granularity=self.cfg.granularity,
          ),
        ),
        self.cfg.max_datagram,
      )
      self.lanes[path] = lane
      lane
    }
  }
}

///|
/// The sending state of path `path`, or `None` before anything has been sent on it.
pub fn[A] Session::path_lane(self : Session[A], path : UInt64) -> Lane[A]? {
  self.lanes.get(path)
}

///|
/// Start a second path: give it `path`, address its datagrams to `peer` by the peer's `dcid`, and
/// answer to `lcid` on it (draft-ietf-quic-multipath §3.1). A PATH_CHALLENGE goes out on the path
/// at once, and the peer is told which connection id to use for it, so the two ends can tell the
/// path's packets from another's. Answers false when the peer offered no room for that path id, or
/// the handshake is not done.
pub fn[A] Session::add_path(
  self : Session[A],
  path : UInt64,
  peer : A,
  dcid : Bytes,
  lcid : Bytes,
  now : Int64,
  nonce~ : Bytes,
  token~ : Bytes,
) -> Bool {
  guard self.phase == Active && self.handshake_done() else { return false }
  guard self.paths.openable(path) else { return false }
  guard dcid.length() > 0 && lcid.length() > 0 && nonce.length() == 8 else {
    return false
  }
  self.paths.bind(path, dcid)
  ignore(self.paths.bind_local(path, lcid))
  ignore(self.paths.start(path, nonce))
  self.lane(path).rebind(peer)
  // §3.2: each path has a connection-id sequence number space of its own, starting at zero.
  self.sender.queue_control(
    PathNewConnectionId(
      path_id=path,
      seq=0UL,
      retire_prior_to=0UL,
      conn_id=lcid,
      reset_token=token,
    ),
  )
  self.send_on(path, [PathChallenge(nonce)], now)
}

///|
/// Put `frames` in one 1-RTT packet on `path`: numbered from that path's space, paced and gated by
/// that path's congestion window, and sealed with the nonce its id names (draft-ietf-quic-multipath
/// §2.4). Path 0 keeps the connection's own send loop, so its packets are numbered and recorded
/// there. Answers whether a packet went out.
pub fn[A] Session::send_on(
  self : Session[A],
  path : UInt64,
  frames : Array[@frame.Frame],
  now : Int64,
) -> Bool {
  guard self.app_tx is Some(keys) else { return false }
  guard frames.length() > 0 else { return false }
  if path == 0UL {
    self.send(Level::Application, frames)
    return true
  }
  let lane = self.lane(path)
  let payload = @packet.payload(frames)
  let size = (payload.length() + keys.suite.tag + 21 + self.cid.length()).to_int64()
  guard lane.send(now, frames, size) is Some(pn) else { return false }
  let dcid = self.paths.peer_cid(path)
  guard dcid.length() > 0 else { return false }
  let datagram = send_short(
    dcid,
    pn,
    4,
    frames,
    keys,
    key_phase=self.key_phase,
    path~,
  )
  self.lane_out.push((datagram, lane.peer()))
  true
}

///|
/// The next datagram on a path other than the connection's own, with the address it belongs on, or
/// `None` when no path has anything waiting. What a lost packet carried goes first, then a probe
/// the path owes.
pub fn[A] Session::poll_lane(self : Session[A], now : Int64) -> (Bytes, A)? {
  self.flush_lanes(now)
  guard self.lane_out.length() > 0 else { return None }
  Some(self.lane_out.remove(0))
}

///|
/// Put everything the further paths have waiting on the wire.
fn[A] Session::flush_lanes(self : Session[A], now : Int64) -> Unit {
  guard self.app_tx is Some(_) else { return }
  for path in self.lanes.keys().collect() {
    guard path != 0UL else { continue }
    guard self.lanes.get(path) is Some(lane) else { continue }
    guard !self.paths.get(path).unwrap().abandoned else { continue }
    while lane.due() is Some(frames) {
      guard self.send_on(path, frames, now) else { break }
    }
  }
}

///|
/// The probe timeouts of the further paths (RFC 9002 §6.2.4): a path whose timeout has come puts
/// its two oldest packets back in line, and the next `poll_lane` sends them. A path that has
/// nothing outstanding does nothing, so the timer costs a comparison per idle path.
fn[A] Session::tick_lanes(self : Session[A], now : Int64) -> Unit {
  for path in self.lanes.keys().collect() {
    guard path != 0UL else { continue }
    guard self.lanes.get(path) is Some(lane) else { continue }
    ignore(lane.on_pto(now))
  }
  self.flush_lanes(now)
}

///|
/// Act on an acknowledgement a path's peer sent for it. The connection's core keeps the path's
/// spacing of packet numbers; the lane keeps what the acknowledgement frees.
fn[A] Session::on_path_ack(
  self : Session[A],
  frame : @frame.Frame,
  path : UInt64,
  now : Int64,
) -> Unit {
  let lane = self.lane(path)
  lane.on_ack(frame, now, self.sender.ack_exponent) catch {
    _ => return self.close(frame_encoding_error, b"", now)
  }
}

///|
/// The acknowledgement owed on `path`: an ACK on the path the handshake ran on, a PATH_ACK on any
/// other (draft-ietf-quic-multipath §4.1), so the peer can tell which of its numbers is being
/// settled.
fn[A] Session::ack_on(
  self : Session[A],
  path : UInt64,
  delay : UInt64,
) -> @frame.Frame? {
  let space = self.core.conn.space_on(path, Level::Application)
  guard space.ack_pending() else { return None }
  let ack = space.build_ack(delay)
  if path == 0UL {
    return ack
  }
  match ack {
    Some(Ack(largest~, delay~, first_range~, ranges~)) =>
      Some(PathAck(path_id=path, largest~, delay~, first_range~, ranges~))
    Some(AckEcn(largest~, delay~, first_range~, ranges~, ect0~, ect1~, ce~)) =>
      Some(
        PathAckEcn(
          path_id=path,
          largest~,
          delay~,
          first_range~,
          ranges~,
          ect0~,
          ect1~,
          ce~,
        ),
      )
    _ => None
  }
}
