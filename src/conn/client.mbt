// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A client connection (RFC 9000 §7, §10; RFC 9001 §4, §6): the counterpart of `Server`. It
// drives moontls's QUIC client, splits the ClientHello across as many Initial packets as it
// needs, seals them with the Initial keys the connection ID alone yields, reassembles the
// server's flights per encryption level, and installs the keys each flight brings. It holds no
// socket and no clock: `poll_out`, `recv` and `tick` all take the time from the caller.
//
// Everything that can make a client stop making progress lives here: the probe timeout on the
// handshake's own CRYPTO streams, the anti-deadlock probe a client owes a server whose
// amplification budget is spent, Retry, version negotiation, and the closing and draining
// periods.

///|
/// The largest path id the client's own transport parameters offer, or 0 when they offer none.
/// A client declares `initial_max_path_id` in the block its caller passes, so the connection reads
/// its own declaration back rather than being told twice.
fn declared_paths(params : Bytes) -> UInt64 {
  match decode_opt(params[:]) {
    Some(block) =>
      match find(block[:], InitialMaxPathId) {
        Some(p) => p.as_int().unwrap_or(0UL)
        None => 0UL
      }
    None => 0UL
  }
}

///|
/// The frames one CRYPTO stream run may be split into, and what a packet spends on everything
/// but frames. An Initial packet's room is computed from the header that will actually carry it
/// rather than assumed: a Retry token makes the header longer, and a fixed room would then build
/// a packet past the 1200-byte floor RFC 9000 §14.1 sets, which is a packet a server drops.
fn crypto_room(
  dcid : Bytes,
  scid : Bytes,
  token : Bytes,
  handshake : Bool,
) -> Int32 {
  let token_field = if handshake {
    0
  } else {
    // The token's length varint (two bytes covers any token this library issues) and the token.
    2 + token.length()
  }
  let header = 1 +
    4 +
    1 +
    dcid.length() +
    1 +
    scid.length() +
    token_field +
    2 +
    4 +
    16
  let frame = 1 + 8 + 2
  let room = min_datagram - header - frame
  if room < 64 {
    64
  } else {
    room
  }
}

///|
/// A client connection mid-handshake.
pub struct Client {
  tls : @tls.Conn
  /// The id the first Initial was addressed to, which a Retry's tag is bound to (§17.2.5.2).
  original_dcid : Bytes
  scid : Bytes
  mut dcid : Bytes
  /// The id the server's first authenticated packet named, which every packet after it must
  /// come from (§7.2).
  mut server_scid : Bytes
  /// The token a Retry handed back, carried on every Initial from then on.
  mut token : Bytes
  /// The id a Retry named, which `retry_source_connection_id` has to match (§7.3).
  mut retry_scid : Bytes?
  mut retried : Bool
  /// The versions a Version Negotiation packet offered, empty when none arrived (§6.2).
  mut versions : Array[UInt32]
  mut initial_tx : @crypto.Keys
  mut initial_rx : @crypto.Keys
  mut hs_tx : @crypto.Keys?
  mut hs_rx : @crypto.Keys?
  mut app_tx : @crypto.Keys?
  mut app_rx : @crypto.Keys?
  mut suite : @crypto.Suite
  core : Conn
  /// The handshake's own CRYPTO streams, with what is in flight on each.
  priv initial_out : Outbox
  priv handshake_out : Outbox
  /// The next offset to write application-level CRYPTO at, which is a server's tickets.
  mut app_crypto_at : UInt64
  /// Initial keys go when the first Handshake packet does, Handshake keys on HANDSHAKE_DONE
  /// (RFC 9001 §4.9).
  mut initial_gone : Bool
  mut handshake_gone : Bool
  mut seen_server_cid : Bool
  /// 1-RTT and 0-RTT: the send loop, the receiving streams, and what the application is told.
  sender : Sender
  streams : @stream.Streams
  events : Array[Event]
  datagrams : Array[Bytes]
  mut key_phase : Bool
  mut rx_phase : Bool
  mut app_tx_secret : Bytes
  mut app_rx_secret : Bytes
  mut phase_start : Int64
  mut confirmed : Bool
  mut next_uni : UInt64
  /// The early keys a ticket brought, and whether the server took the data sent under them.
  mut zero_rtt_tx : @crypto.Keys?
  mut zero_sent : Bool
  mut zero_rejected : Bool
  mut reset_token : Bytes?
  offered_ids : Array[(UInt64, Bytes, Bytes)]
  mut dcid_seq : UInt64
  reset_tokens : Array[Bytes]
  mut phase : Phase
  mut close_at : Int64
  mut close_frame : @frame.Frame?
  mut close_level : Level
  mut last_rx : Int64
  mut last_tx : Int64
  mut idle_timeout : Int64
  /// The time an entry point was last called at, so a close raised while reading the handshake
  /// can date its closing period.
  mut at : Int64
  cfg : Config
  /// Probes the timers have decided to send, waiting for the next `poll_out`.
  priv probes : Array[Bytes]
  /// The name the ticket is filed under, and the store it is filed in, so this connection can
  /// remember what the next one needs to resume (RFC 9000 §7.4.1).
  host : String
  sessions : @tls.Sessions?
  wall : Int64
  /// The server's transport parameters exactly as they arrived, which is half of what is kept.
  mut peer_params : Bytes
  /// This connection's paths beyond the one it started on (draft-ietf-quic-multipath §3). A
  /// client holds no addresses — its caller owns the sockets — so a path is a number here, and
  /// `recv_on` says which one a datagram came in on.
  priv paths : Paths
  priv lanes : Map[UInt64, Lane[Unit]]
  /// Datagrams for the further paths, each tagged with the path it belongs on.
  priv lane_out : Array[(UInt64, Bytes)]
}

///|
/// A client for `server_name`, with `config` holding its roots and ALPN protocols. `dcid` is
/// the connection id the Initial keys derive from (RFC 9001 §5.2) and `scid` the one this
/// client calls itself; both are the caller's, so a test can make them reproducible.
pub fn Client::new(
  config : @tls.Client,
  server_name : String,
  params : Bytes,
  rand : (Int32) -> Bytes,
  dcid : Bytes,
  scid : Bytes,
  wall : Int64,
  cfg~ : Config = Config::default(),
  resumption? : Remembered,
) -> Client raise {
  let tls = @tls.Conn::quic_client(
    config,
    server_name,
    params~,
    rand~,
    now=wall,
  )
  let (tx, rx) = @crypto.initial(dcid[:])
  let core = Conn::new(false)
  // What early data may spend: the ticket's own parameters, unless Config overrules them
  // (RFC 9000 §7.4.1). A client with no ticket and no overrides has no credit, so early data
  // waits for the handshake instead of risking a flow-control error.
  let (early_data, early_bidi, early_uni, early_datagram) = early_credit(
    cfg, resumption,
  )
  let sender = Sender::new(
    early_data,
    if early_bidi < early_uni {
      early_bidi
    } else {
      early_uni
    },
    cfg.max_datagram,
    cfg.max_ack_delay,
    cfg.granularity,
    cfg.max_frame,
  )
  sender.sched.on_params(data=early_data, bidi=early_bidi, uni=early_uni)
  sender.on_peer_datagram(early_datagram)
  let client : Client = {
    tls,
    original_dcid: dcid,
    scid,
    dcid,
    server_scid: b"",
    token: b"",
    retry_scid: None,
    retried: false,
    versions: [],
    initial_tx: tx,
    initial_rx: rx,
    hs_tx: None,
    hs_rx: None,
    app_tx: None,
    app_rx: None,
    suite: @crypto.suite,
    core,
    initial_out: Outbox::new(),
    handshake_out: Outbox::new(),
    app_crypto_at: 0UL,
    initial_gone: false,
    handshake_gone: false,
    seen_server_cid: false,
    sender,
    streams: @stream.Streams::new(
      cfg.initial_max_data,
      cfg.initial_max_stream_data,
      server=false,
      bidi=@stream.Quota::new(cfg.streams_bidi),
      uni=@stream.Quota::new(cfg.streams_uni),
    ),
    events: [],
    datagrams: [],
    key_phase: false,
    rx_phase: false,
    app_tx_secret: b"",
    app_rx_secret: b"",
    phase_start: 0L,
    confirmed: false,
    next_uni: 0UL,
    zero_rtt_tx: None,
    zero_sent: false,
    zero_rejected: false,
    reset_token: None,
    offered_ids: [],
    dcid_seq: 0UL,
    reset_tokens: [],
    phase: Active,
    close_at: 0L,
    close_frame: None,
    close_level: Level::Initial,
    last_rx: 0L,
    last_tx: 0L,
    idle_timeout: cfg.idle_timeout,
    at: 0L,
    cfg,
    probes: [],
    host: server_name,
    sessions: config.sessions,
    wall,
    peer_params: b"",
    paths: Paths::new(local_max=declared_paths(params)),
    lanes: Map([
      (
        0UL,
        Lane::new(
          0UL,
          (),
          core.space(Application),
          sender.recovery,
          cfg.max_datagram,
        ),
      ),
    ]),
    lane_out: [],
  }
  match resumption {
    Some(session) => client.adopt_ticket(session)
    None => ()
  }
  client.absorb()
  client
}

///|
/// Do what the handshake asks: install the keys it derives now, and queue the bytes it wants
/// sent with the level they belong at.
fn Client::absorb(self : Client) -> Unit {
  for step in self.tls.steps() {
    match step {
      Send(level, data) =>
        match level {
          Initial => self.initial_out.write(data)
          Handshake => self.handshake_out.write(data)
          Application => self.queue_app_crypto(data)
        }
      Early(secret~, suite~) =>
        self.zero_rtt_tx = Some(
          @crypto.zero_rtt(secret[:], suite=suite_of(suite)),
        )
      Keys(level, client~, server~) => {
        if self.tls.suite() is Some(s) {
          self.suite = suite_of(s)
        }
        // A client writes under the client secret and reads under the server's.
        let tx = @crypto.Keys::of(client[:], suite=self.suite)
        let rx = @crypto.Keys::of(server[:], suite=self.suite)
        match level {
          Handshake => {
            self.hs_tx = Some(tx)
            self.hs_rx = Some(rx)
          }
          Application => {
            self.app_tx = Some(tx)
            self.app_rx = Some(rx)
            self.app_tx_secret = client
            self.app_rx_secret = server
          }
          Initial => ()
        }
      }
    }
  }
  self.adopt_peer_params()
  self.settle_zero_rtt()
}

///|
/// Queue post-handshake TLS bytes — a session ticket — as 1-RTT CRYPTO frames, so a lost one is
/// sent again (RFC 9001 §4.1.3).
fn Client::queue_app_crypto(self : Client, data : Bytes) -> Unit {
  let mut at = 0
  while at < data.length() {
    let end = if data.length() - at > app_crypto_chunk {
      at + app_crypto_chunk
    } else {
      data.length()
    }
    self.sender.queue_control(
      Crypto(offset=self.app_crypto_at, data=data[at:end].to_owned()),
    )
    self.app_crypto_at = self.app_crypto_at + (end - at).to_uint64()
    at = end
  }
}

///|
/// Take the server's transport parameters once EncryptedExtensions has brought them: the
/// flow-control credit that opens the send loop, the largest datagram it will take, and the
/// three connection ids RFC 9000 §7.3 holds the handshake to.
fn Client::adopt_peer_params(self : Client) -> Unit {
  guard self.tls.peer_params() is Some(raw) else { return }
  self.peer_params = raw
  self.reset_token = find(decode(raw[:]), StatelessResetToken).map(p => p.value) catch {
    _ => None
  }
  guard decode_opt(raw[:]) is Some(params) else {
    return self.close(transport_parameter_error, b"", self.at)
  }
  match params_fault(params[:], server=false) {
    Some(fault) => return self.close(fault.code, fault.reason, self.at)
    None => ()
  }
  // §7.3: the server confirms the id the client invented, the id a Retry named, and the id it
  // chose for itself. A handshake that does not add up is not this connection.
  if !same_param(params, OriginalDcid, self.original_dcid) {
    return self.close(transport_parameter_error, b"", self.at)
  }
  match self.retry_scid {
    Some(scid) =>
      if !same_param(params, RetryScid, scid) {
        return self.close(transport_parameter_error, b"", self.at)
      }
    None =>
      if find(params[:], RetryScid) is Some(_) {
        return self.close(transport_parameter_error, b"", self.at)
      }
  }
  if !same_param(params, InitialScid, self.server_scid) {
    return self.close(transport_parameter_error, b"", self.at)
  }
  let peer = Limits::read(params[:])
  // A stream this client opens is "remote" from the server's side of the ledger.
  self.sender.sched.on_params(
    data=peer.data,
    bidi=peer.stream_data_bidi_remote,
    uni=peer.stream_data_uni,
  )
  self.sender.on_max_data(peer.data)
  self.sender.on_peer_datagram(peer.datagram_frame)
  // draft-ietf-quic-multipath §2.1: the server's initial_max_path_id is a MAX_PATH_ID, and this
  // client may open a path up to it.
  match find(params[:], InitialMaxPathId) {
    Some(p) =>
      match p.as_int() {
        Some(max) => self.paths.on_max_path_id(max)
        None => ()
      }
    None => ()
  }
  self.sender.ack_exponent = peer.ack_delay_exponent.to_int()
  if find(params[:], MaxIdleTimeout) is Some(_) {
    self.idle_timeout = idle_timeout(
      self.cfg.idle_timeout,
      peer.idle_timeout.reinterpret_as_int64() * 1000L,
    )
  }
}

///|
/// Whether the parameter `kind` is present and worth `want`.
fn same_param(params : Array[Param], kind : Kind, want : Bytes) -> Bool {
  match find(params[:], kind) {
    Some(p) => p.value == want
    None => false
  }
}

///|
/// What becomes of the early data once the handshake has said (RFC 9000 §4.6.2). Taken, and the
/// early keys have done their work; refused, and everything still in flight has to go again
/// under the 1-RTT keys, which the send loop does once the contents are back in the queue.
fn Client::settle_zero_rtt(self : Client) -> Unit {
  guard self.zero_sent && self.tls.is_connected() && !self.zero_rejected else {
    return
  }
  if self.tls.early_accepted() {
    self.sender.requeue_all()
  } else {
    self.zero_rejected = true
    self.sender.requeue_all()
  }
  // RFC 9001 §4.9.3: the early keys are of no further use either way.
  self.zero_rtt_tx = None
}

///|
/// The datagrams to put on the wire: the queued CRYPTO bytes split so no Initial packet runs
/// past a datagram, each Initial padded to the 1200-byte floor (RFC 9000 §14.1), the early data
/// the send loop has ready, then 1-RTT traffic once the handshake is done.
pub fn Client::poll_out(self : Client, now : Int64) -> Array[Bytes] {
  self.at = now
  let out : Array[Bytes] = []
  match self.phase {
    Closing => {
      if now < self.close_at {
        match self.close_frame {
          Some(frame) => {
            let pn = self.core.next_packet_number(self.close_level)
            out.push(self.seal_level(self.close_level, pn, [frame]))
          }
          None => ()
        }
      }
      return out
    }
    Draining => return out
    Active => ()
  }
  if !self.initial_gone {
    // A post-quantum hello is more than one datagram, and each Initial is its own.
    while true {
      match self.handshake_packet(now, Level::Initial) {
        Some(packet) => out.push(packet)
        None => break
      }
    }
  }
  if !self.handshake_gone && self.hs_tx is Some(_) {
    while true {
      match self.handshake_packet(now, Level::Handshake) {
        Some(packet) => out.push(packet)
        None => break
      }
    }
    // RFC 9001 §4.9.1: the first Handshake packet is the last use of the Initial keys.
    self.initial_gone = true
    self.initial_out.clear()
  }
  for packet in self.probes {
    out.push(packet)
  }
  self.probes.clear()
  if !self.tls.is_connected() {
    self.zero_rtt_packets(now, out)
  }
  if self.tls.is_connected() {
    while true {
      let space = self.core.space(Level::Application)
      let ack = if space.ack_pending() { space.build_ack(0UL) } else { None }
      let next = self.sender.poll_send(now) catch { _ => None }
      match next {
        Some((pn, frames)) => {
          space.advance_past(pn)
          let all = match ack {
            Some(a) => [a, ..frames]
            None => frames
          }
          out.push(self.seal_app(pn, all))
        }
        None => {
          match ack {
            Some(a) => {
              // The send loop numbers this space too. A number used twice is a nonce used twice.
              let pn = space.next_packet_number()
              self.sender.advance_past(pn)
              out.push(self.seal_app(pn, [a]))
            }
            None => ()
          }
          break
        }
      }
    }
  }
  if out.length() > 0 {
    self.last_tx = now
  }
  out
}

///|
/// One Initial or Handshake packet: the ACK owed at that level and one run of CRYPTO, sealed
/// with the token a Retry left. An Initial datagram is padded to the floor whatever it carries,
/// because a server may not answer a smaller one.
fn Client::handshake_packet(
  self : Client,
  now : Int64,
  level : Level,
) -> Bytes? {
  let space = self.core.space(level)
  let frames : Array[@frame.Frame] = []
  if space.ack_pending() {
    if space.build_ack(0UL) is Some(ack) {
      frames.push(ack)
    }
  }
  let outbox = if level == Level::Initial {
    self.initial_out
  } else {
    self.handshake_out
  }
  let room = crypto_room(
    self.dcid,
    self.scid,
    self.token,
    level == Level::Handshake,
  )
  let run = outbox.take(room)
  if run is Some((at, size)) {
    frames.push(
      Crypto(offset=at.to_uint64(), data=outbox.bytes[at:at + size].to_owned()),
    )
  }
  guard frames.length() > 0 else { return None }
  let pn = self.core.next_packet_number(level)
  if run is Some(sent) {
    // What this packet carries goes out again when the probe timeout fires.
    outbox.flight[pn] = sent
    outbox.deadline = now + self.sender.recovery.pto()
  }
  Some(self.seal_level(level, pn, frames))
}

///|
/// A protected packet at `level` carrying `frames`. An Initial one is padded to the datagram
/// floor; a Handshake one is not, and a level whose keys are gone gives an empty packet.
fn Client::seal_level(
  self : Client,
  level : Level,
  pn : Int64,
  frames : Array[@frame.Frame],
) -> Bytes {
  match level {
    Initial => {
      let payload = @packet.payload(frames)
      let build = body => {
        seal_long(
          Initial,
          1U,
          self.dcid,
          self.scid,
          pn,
          4,
          body,
          self.initial_tx,
          token=self.token,
        )
      }
      pad(payload, build, min_datagram)
    }
    Handshake =>
      match self.hs_tx {
        Some(keys) =>
          send_long(Handshake, 1U, self.dcid, self.scid, pn, 4, frames, keys)
        None => b""
      }
    Application =>
      match self.app_tx {
        Some(keys) =>
          send_short(self.dcid, pn, 4, frames, keys, key_phase=self.key_phase)
        None => b""
      }
  }
}

///|
/// The 0-RTT packets the send loop has ready. Early data is only usable before the handshake
/// finishes, and only while a ticket's keys are in hand.
fn Client::zero_rtt_packets(
  self : Client,
  now : Int64,
  out : Array[Bytes],
) -> Unit {
  guard self.zero_rtt_tx is Some(keys) && !self.zero_rejected else { return }
  let space = self.core.space(Level::Application)
  while true {
    let next = self.sender.poll_send(now, zero=true) catch { _ => None }
    match next {
      Some((pn, frames)) => {
        space.advance_past(pn)
        out.push(send_zero_rtt(self.dcid, self.scid, pn, 4, frames, keys))
        self.zero_sent = true
      }
      None => break
    }
  }
}

///|
/// A protected 1-RTT packet carrying `frames`.
fn Client::seal_app(
  self : Client,
  pn : Int64,
  frames : Array[@frame.Frame],
) -> Bytes {
  match self.app_tx {
    Some(keys) =>
      send_short(self.dcid, pn, 4, frames, keys, key_phase=self.key_phase)
    None => b""
  }
}

///|
/// The highest level this client can send at.
fn Client::send_level(self : Client) -> Level {
  if self.app_tx is Some(_) {
    Level::Application
  } else if self.hs_tx is Some(_) {
    Level::Handshake
  } else {
    Level::Initial
  }
}

///|
/// Take a datagram from the server: split it into packets, unprotect each at the level its
/// header names, reassemble its CRYPTO stream, and drive the handshake with what becomes
/// contiguous. A server's first datagram may coalesce packets; the keys one brings are
/// installed before the next is read.
pub fn Client::recv(self : Client, datagram : Bytes, now : Int64) -> Unit raise {
  self.recv_on(0UL, datagram, now)
}

///|
/// Take a datagram that arrived on path `path`. A client has no address of its own — its caller
/// owns the sockets — so the path a datagram belongs to is something only the caller knows, and
/// it says so here (draft-ietf-quic-multipath §2.3). The path picks the packet-number space and
/// the nonce the packet was sealed with.
pub fn Client::recv_on(
  self : Client,
  path : UInt64,
  datagram : Bytes,
  now : Int64,
) -> Unit raise {
  self.at = now
  if self.phase == Draining {
    return
  }
  let mut at = 0
  while at < datagram.length() {
    let view = datagram[at:]
    guard view.length() > 0 else { break }
    if (view[0].to_int() & 0x80) == 0 {
      // 1-RTT: every Application packet runs to the end of the datagram.
      guard self.app_rx is Some(keys) else { break }
      let space = self.core.space_on(path, Level::Application)
      let opened = self.open_app(
        view.to_owned(),
        keys,
        space.largest_received(),
        path~,
      ) catch {
        _ => return self.close(frame_encoding_error, b"", now)
      }
      guard opened is Some((frames, pn)) else {
        // RFC 9000 §10.3.1: a packet that will not open may be the server saying it has forgotten
        // this connection. Only a packet that fails to open is compared, and it ends the
        // connection at once, since nothing more can come.
        if self.known_reset(view) {
          self.events.push(Closed(0UL))
        }
        break
      }
      if reserved_set(view.to_owned(), keys, 1 + self.scid.length(), short=true) {
        return self.close(protocol_violation, b"reserved bits set", now)
      }
      match
        frames_fault(
          Level::Application,
          frames,
          self.standing(Level::Application, path~),
        ) {
        Some(fault) => return self.close(fault.code, fault.reason, now)
        None => ()
      }
      // A PATH_ACK is judged against the path it names, not the path its packet came in on.
      match
        path_ack_fault(frames, p => {
          self.core.space_on(p, Level::Application).issued()
        }) {
        Some(fault) => return self.close(fault.code, fault.reason, now)
        None => ()
      }
      space.on_packet_received(pn, @packet.payload_elicits_ack(frames))
      self.on_app_frames(frames, now, path~)
      break
    }
    guard @packet.read_long(view) is Some((h, _)) else { break }
    if h.version == 0U {
      self.on_versions(view, h)
      break
    }
    if h.version != self.cfg.version {
      // RFC 9000 §6: a version this client did not offer is not this connection's business.
      break
    }
    if h.packet_type is Retry {
      // A Retry is a datagram of its own (RFC 9000 §17.2.5).
      self.on_retry(view.to_owned(), h)
      break
    }
    guard @packet.read_header(view) is Some((_, tail)) else { break }
    let size = tail.at + tail.length.to_int()
    guard size <= view.length() else { break }
    let packet = view[0:size].to_owned()
    at = at + size
    match h.packet_type {
      Initial => self.on_long(Level::Initial, h, packet, self.initial_rx, now)
      Handshake =>
        match self.hs_rx {
          Some(keys) => self.on_long(Level::Handshake, h, packet, keys, now)
          None => ()
        }
      _ => ()
    }
  }
}

///|
/// What a frame check on this client runs against.
fn Client::standing(
  self : Client,
  level : Level,
  path~ : UInt64 = 0UL,
) -> Standing {
  {
    server: false,
    streams: self.streams,
    sched: self.sender.sched,
    sent: self.core.space_on(path, level).issued(),
  }
}

///|
/// A Retry (RFC 9000 §17.2.5, RFC 9001 §5.8): check the tag over the id the first Initial used,
/// take the token, address the new id, derive the Initial keys again, and send the ClientHello
/// from the start — under packet numbers that carry on where they were. A second Retry is
/// ignored, and so is one whose tag does not add up.
fn Client::on_retry(self : Client, packet : Bytes, h : @packet.Long) -> Unit {
  guard !self.retried && !self.seen_server_cid else { return }
  guard @packet.read_retry(packet[:]) is Some((_, token, _)) else { return }
  guard @crypto.retry_ok(packet[:], self.original_dcid[:]) else { return }
  self.retried = true
  self.token = token
  self.dcid = h.scid
  self.retry_scid = Some(h.scid)
  self.server_scid = h.scid
  self.seen_server_cid = true
  let (tx, rx) = @crypto.initial(h.scid[:])
  self.initial_tx = tx
  self.initial_rx = rx
  // The ClientHello goes out again from offset zero; the packet numbers do not restart, since
  // they belong to the space, not to the attempt.
  self.initial_out.rewind()
}

///|
/// A Version Negotiation packet (RFC 9000 §6.2): the versions the server speaks. Only the first
/// packet of a connection may be one, and only addressed to this client's own id.
fn Client::on_versions(
  self : Client,
  packet : BytesView,
  h : @packet.Long,
) -> Unit {
  guard !self.seen_server_cid && h.dcid == self.scid else { return }
  match @packet.read_versions(packet[:]) {
    Some((dcid, scid, offered)) =>
      if dcid == self.scid && scid == self.dcid {
        self.versions = offered
      }
    None => ()
  }
}

///|
/// One long-header packet at `level`, under `keys`: check it against what a peer may send,
/// record its number, reassemble its CRYPTO bytes, feed the contiguous run to the handshake, and
/// do what it asks. The server's chosen id is adopted only here, from a packet that
/// authenticated (RFC 9000 §7.2).
fn Client::on_long(
  self : Client,
  level : Level,
  h : @packet.Long,
  packet : Bytes,
  keys : @crypto.Keys,
  now : Int64,
) -> Unit {
  let space = self.core.space(level)
  let opened : (Array[@frame.Frame], Int64)? = recv_long(
    packet,
    keys,
    largest=space.largest_received(),
  ) catch {
    _ => return self.close(frame_encoding_error, b"", now)
  }
  guard opened is Some((frames, pn)) else { return }
  if self.seen_server_cid && h.scid != self.server_scid {
    // RFC 9000 §7.2: after the first authenticated packet, another source id is another
    // connection's traffic.
    return
  }
  let at = match @packet.read_header(packet[:]) {
    Some((_, tail)) => tail.at
    None => return
  }
  if reserved_set(packet, keys, at, short=false) {
    return self.close(protocol_violation, b"reserved bits set", now)
  }
  guard !space.seen(pn) else { return }
  match frames_fault(level, frames, self.standing(level)) {
    Some(fault) => return self.close(fault.code, fault.reason, now)
    None => ()
  }
  if !self.seen_server_cid {
    self.dcid = h.scid
    self.server_scid = h.scid
    self.seen_server_cid = true
  }
  self.last_rx = now
  self.core.on_packet_received(level, pn, @packet.payload_elicits_ack(frames))
  let mut closing : UInt64? = None
  let ready = Buffer()
  for frame in frames {
    match frame {
      Crypto(offset~, data~) => {
        let contiguous = self.core.on_crypto_frame(level, offset, data) catch {
          _ => return self.close(crypto_buffer_exceeded, b"", now)
        }
        ready.write_bytes(contiguous)
      }
      ConnectionClose(error_code~, ..) => closing = Some(error_code)
      _ => ()
    }
  }
  if ready.length() > 0 {
    self.tls.crypto(tls_level(level), ready.to_bytes()[:]) catch {
      @alert.Alert(kind~, ..) =>
        return self.close(
          crypto_error + kind.code().to_uint64(),
          b"TLS alert",
          now,
        )
    }
  }
  self.absorb()
  match closing {
    Some(code) => {
      self.phase = Draining
      self.close_at = now + self.cfg.close_period
      self.events.push(Closed(code))
    }
    None => ()
  }
}

///|
/// A short-header packet's frames. One that will not open under the current keys may be the next
/// phase, and only a real packet opens under those (RFC 9001 §6.3). If the server moved first this
/// client follows it, since it may not keep writing the old phase once it has read the new one.
fn Client::open_app(
  self : Client,
  packet : Bytes,
  keys : @crypto.Keys,
  largest : Int64,
  path~ : UInt64 = 0UL,
) -> (Array[@frame.Frame], Int64)? raise @packet.Refused {
  let n = self.scid.length()
  let opened = recv_short(packet, n, keys, largest~, path~)
  guard opened is None && self.app_rx_secret.length() > 0 else { return opened }
  let (secret, next) = roll(self.app_rx_secret, keys, self.suite)
  let moved = recv_short(packet, n, next, largest~, path~)
  guard moved is Some(_) else { return None }
  self.app_rx = Some(next)
  self.app_rx_secret = secret
  self.rx_phase = !self.rx_phase
  if self.rx_phase != self.key_phase {
    self.next_write_phase()
  }
  moved
}

///|
fn Client::next_write_phase(self : Client) -> Unit {
  guard self.app_tx is Some(keys) else { return }
  let (secret, next) = roll(self.app_tx_secret, keys, self.suite)
  self.app_tx = Some(next)
  self.app_tx_secret = secret
  self.key_phase = !self.key_phase
  self.phase_start = self.sender.next_pn
}

///|
/// Whether a packet that would not open ends in a token one of this server's ids came with.
fn Client::known_reset(self : Client, packet : BytesView) -> Bool {
  (self.reset_token is Some(token) && is_stateless_reset(packet, token[:])) ||
  self.reset_tokens.iter().any(token => is_stateless_reset(packet, token[:]))
}

///|
/// An id from the server, for when this client wants a new one (RFC 9000 §5.1.2). Anything below
/// `retire_prior_to` has to go, the one in use with it.
fn Client::on_new_id(
  self : Client,
  seq : UInt64,
  retire_prior_to : UInt64,
  cid : Bytes,
  token : Bytes,
) -> Unit {
  if self.offered_ids.iter().all(entry => entry.0 != seq) && seq > self.dcid_seq {
    self.offered_ids.push((seq, cid, token))
    self.reset_tokens.push(token)
  }
  let kept = []
  for entry in self.offered_ids {
    if entry.0 < retire_prior_to {
      self.sender.queue_control(RetireConnectionId(entry.0))
    } else {
      kept.push(entry)
    }
  }
  self.offered_ids.clear()
  self.offered_ids.append(kept)
  if self.dcid_seq < retire_prior_to {
    ignore(self.next_cid())
  }
}

///|
/// Start addressing the server by the next id it offered, and retire the one in use. Do this before
/// sending from a new address on purpose, so the two paths cannot be linked (RFC 9000 §9.5). False
/// when it has offered none.
pub fn Client::next_cid(self : Client) -> Bool {
  guard self.offered_ids.length() > 0 else { return false }
  let (seq, cid, _) = self.offered_ids.remove(0)
  self.sender.queue_control(RetireConnectionId(self.dcid_seq))
  self.dcid_seq = seq
  self.dcid = cid
  true
}

///|
/// Move to the next key phase (RFC 9001 §6). The answer is false when it is not allowed yet: before
/// the handshake is confirmed, or before something written in the current phase has been
/// acknowledged, which is what stops an endpoint outrunning its peer's two sets of keys (§6.1, §6.2).
pub fn Client::update_keys(self : Client) -> Bool {
  guard self.confirmed &&
    self.rx_phase == self.key_phase &&
    self.sender.recovery.flight.largest_acked() >= self.phase_start else {
    return false
  }
  self.next_write_phase()
  true
}

///|
/// Whether the handshake has completed.
pub fn Client::is_connected(self : Client) -> Bool {
  self.tls.is_connected()
}

///|
/// Where this connection is in its lifecycle.
pub fn Client::phase(self : Client) -> Phase {
  self.phase
}

///|
/// The ALPN protocol the handshake settled on.
pub fn Client::alpn(self : Client) -> String? {
  self.tls.alpn()
}

///|
/// The TLS code of the cipher suite in force, 0 before one is chosen.
pub fn Client::suite_code(self : Client) -> Int32 {
  match self.tls.suite() {
    Some(suite) => suite.code()
    None => 0
  }
}

///|
/// The connection id the client addresses the server by — the server's, once it has named it.
pub fn Client::server_cid(self : Client) -> Bytes {
  self.dcid
}

///|
/// The versions a Version Negotiation packet offered, empty when none came. A non-empty answer
/// means this attempt is over: RFC 9000 §6.2 leaves the caller to start another with one of them.
pub fn Client::versions(self : Client) -> Array[UInt32] {
  self.versions.copy()
}

///|
/// Install the client's 0-RTT (early) keys (RFC 9001 §5.2) by hand. A client given a ticket and
/// `early=true` has them from its handshake already; this is for keys that came from elsewhere.
pub fn Client::install_zero_rtt(self : Client, keys : @crypto.Keys) -> Unit {
  self.zero_rtt_tx = Some(keys)
}

///|
/// Whether the server accepted the early data this client offered.
pub fn Client::early_accepted(self : Client) -> Bool {
  self.tls.early_accepted()
}

///|
/// Act on a 1-RTT packet's frames: acknowledgements to the send loop, stream data into the
/// reassembler, flow-control updates to the scheduler, and the rest to the application.
fn Client::on_app_frames(
  self : Client,
  frames : Array[@frame.Frame],
  now : Int64,
  path~ : UInt64 = 0UL,
) -> Unit raise {
  for frame in frames {
    match frame {
      Ack(largest~, ..) | AckEcn(largest~, ..) => {
        self.core.on_ack_received(
          Level::Application,
          largest.reinterpret_as_int64(),
        )
        self.sender.on_ack(frame, now)
      }
      // §4.1: an acknowledgement for another path settles that path's numbers, and leaves this
      // one's congestion state alone.
      PathAck(path_id~, ..) | PathAckEcn(path_id~, ..) =>
        self.on_path_ack(frame, path_id, now)
      Stream(id~, offset~, fin~, data~) => {
        self.streams.accept(id, offset, data, fin~)
        let event = Readable(id)
        if self.streams.streams.contains(id) && !self.events.contains(event) {
          self.events.push(event)
        }
      }
      // RFC 9001 §4.1.3: TLS goes on speaking at this level, and what it says is a ticket.
      Crypto(offset~, data~) => {
        let ready = self.core.on_crypto_frame(Level::Application, offset, data) catch {
          _ => return self.close(crypto_buffer_exceeded, b"", now)
        }
        if ready.length() > 0 {
          self.tls.crypto(Application, ready[:]) catch {
            @alert.Alert(kind~, ..) =>
              return self.close(
                crypto_error + kind.code().to_uint64(),
                b"TLS alert",
                now,
              )
          }
          self.absorb()
        }
      }
      HandshakeDone => {
        // RFC 9001 §4.9.2: the Handshake keys are done once the server says so.
        self.confirmed = true
        self.handshake_gone = true
        self.handshake_out.clear()
      }
      NewConnectionId(seq~, retire_prior_to~, conn_id~, reset_token~) =>
        self.on_new_id(seq, retire_prior_to, conn_id, reset_token)
      MaxData(v) => self.sender.on_max_data(v)
      MaxStreamData(id~, max~) => self.sender.on_max_stream_data(id, max)
      ResetStream(id~, error_code~, ..) =>
        self.events.push(Reset(id, error_code))
      StopSending(id~, error_code~) => self.events.push(Stopped(id, error_code))
      // The peer's side of the path bookkeeping (draft-ietf-quic-multipath §3, §4): the id to
      // address a further path by, the room it offers for more paths, and its word on each one.
      // They arrive before anything has been sent on the path they name, which is what they are
      // for — a path is opened on the id the peer gives for it, not the other way round.
      PathNewConnectionId(path_id~, seq~, conn_id~, ..) =>
        if path_id > self.paths.local_max() {
          return self.close(protocol_violation, b"a path never agreed", now)
        } else {
          ignore(self.paths.on_peer_cid(path_id, seq, conn_id))
        }
      PathRetireConnectionId(path_id~, seq~) =>
        ignore(self.paths.retire_peer_cid(path_id, seq))
      PathStatus(path_id~, seq~, available~) =>
        if path_id > self.paths.local_max() {
          return self.close(protocol_violation, b"a path never agreed", now)
        } else {
          ignore(self.paths.on_status(path_id, seq, available))
        }
      PathAbandon(path_id~, ..) => ignore(self.paths.abandon(path_id))
      MaxPathId(max~) => self.paths.on_max_path_id(max)
      // §4.7: a report that the peer has no more connection ids for a path, which this end acts
      // on by issuing one; nothing is owed back.
      PathCidsBlocked(..) => ()
      // A challenge is answered on the path it came from, and a path is proven once its own
      // challenge comes back unchanged (draft-ietf-quic-multipath §3.1).
      PathChallenge(data) =>
        if path == 0UL {
          self.sender.queue_control(PathResponse(data))
        } else {
          ignore(self.send_on(path, [PathResponse(data)], now))
        }
      PathResponse(data) =>
        if path != 0UL {
          ignore(self.paths.prove(path, data))
        }
      @frame.Datagram(data~) => {
        self.datagrams.push(data)
        if !self.events.contains(Event::Datagram) {
          self.events.push(Event::Datagram)
        }
      }
      ConnectionClose(error_code~, ..) => {
        self.phase = Draining
        self.close_at = now + self.cfg.close_period
        self.events.push(Closed(error_code))
        return
      }
      _ => ()
    }
  }
  // A path of its own is acknowledged on itself, in a packet that names it (§4.1).
  if path != 0UL && self.phase == Active {
    match self.ack_on(path, 0UL) {
      Some(ack) => ignore(self.send_on(path, [ack], now))
      None => ()
    }
  }
}

///|
/// Open a bidirectional stream this end initiates, without putting anything on it. A caller that
/// places a stream's frames on a path of its own choosing — `send_on` — has to say the stream
/// exists first: RFC 9000 §19.8 lets a peer answer only on a bidirectional stream this end opened,
/// and the send loop's record of having opened it is what that turns on. Answers false for a stream
/// this end may not initiate, which is a unidirectional one or the peer's own.
pub fn Client::open_stream(self : Client, id : UInt64) -> Bool {
  guard self.phase == Active else { return false }
  guard @stream.is_local(id, server=false) && @stream.is_bidi(id) else {
    return false
  }
  self.sender.sched.queue(id, 0UL)
  true
}

///|
/// Queue `data` on stream `id`, ending it after the data when `fin`. Before the handshake
/// finishes, data queued here leaves in 0-RTT packets when a ticket brought early keys, and the
/// send loop carries it over to 1-RTT if the server refuses them (RFC 9000 §4.6.2).
pub fn Client::write(
  self : Client,
  id : UInt64,
  data : Bytes,
  fin~ : Bool = false,
) -> Unit {
  self.sender.queue_stream(id, data)
  if fin {
    self.sender.queue_fin(id)
  }
}

///|
/// The bytes readable on stream `id` in order, emptied by the call; their flow-control credit
/// goes back to the server here.
pub fn Client::read(self : Client, id : UInt64) -> Bytes {
  let data = self.streams.read(id)
  if data.length() > 0 {
    if self.streams.max_data() is Some(max) {
      self.sender.queue_control(MaxData(max))
    }
    if self.streams.max_stream_data(id) is Some(max) {
      self.sender.queue_control(MaxStreamData(id~, max~))
    }
  }
  data
}

///|
/// Whether stream `id` has ended and every byte of it has been read.
pub fn Client::finished(self : Client, id : UInt64) -> Bool {
  self.streams.finished(id)
}

///|
/// A new unidirectional stream from this client (RFC 9000 §2.1).
pub fn Client::open_uni(self : Client) -> UInt64 {
  let id = self.next_uni * 4UL + 2UL
  self.next_uni = self.next_uni + 1UL
  id
}

///|
/// How many bytes written to stream `id` the server has not acknowledged.
pub fn Client::buffered(self : Client, id : UInt64) -> UInt64 {
  self.sender.buffered(id)
}

///|
/// What has happened on this connection since the last call, emptied by it.
pub fn Client::take_events(self : Client) -> Array[Event] {
  let out = self.events.copy()
  self.events.clear()
  out
}

///|
/// Queue an unreliable datagram (RFC 9221), answering whether the server will take it.
pub fn Client::send_datagram(self : Client, data : Bytes) -> Bool {
  self.sender.queue_datagram(data)
}

///|
/// The datagrams that arrived since the last call, emptied by it.
pub fn Client::take_datagrams(self : Client) -> Array[Bytes] {
  let out = self.datagrams.copy()
  self.datagrams.clear()
  out
}

///|
/// Run the timers at `now` (RFC 9002 §6.2): the probe timeout on each handshake level, the send
/// loop's own, the idle timeout, the closing period, and the probe a client owes a server it
/// cannot hear — the last of which is what keeps a handshake from wedging when the server's
/// amplification budget is spent (RFC 9002 §6.2.2.1).
pub fn Client::tick(self : Client, now : Int64) -> Unit {
  self.at = now
  match self.phase {
    Closing => if now >= self.close_at { self.phase = Draining }
    Draining => ()
    Active => {
      if self.idle_timeout > 0L && now - self.last_rx >= self.idle_timeout {
        return self.close(0UL, b"", now)
      }
      let pto = self.sender.recovery.pto()
      self.initial_out.tick(now, pto)
      self.handshake_out.tick(now, pto)
      self.tick_paths(now)
      let _ = self.sender.on_pto_timeout(now)
      if !self.tls.is_connected() &&
        now - self.last_tx >= pto &&
        self.initial_out.flight.length() == 0 &&
        self.handshake_out.flight.length() == 0 {
        // Nothing is in flight and the handshake is not moving: the server is waiting for
        // something it can answer, which a padded Initial with a PING gives it.
        self.last_tx = now
        self.probes.push(self.build_probe())
      }
    }
  }
}

///|
/// The datagrams to put on the wire for one more attempt at a deadlocked handshake: a PING in a
/// padded Initial, which a server with no amplification budget left can still answer.
pub fn Client::probe(self : Client, now : Int64) -> Array[Bytes] {
  self.at = now
  guard self.phase == Active && !self.tls.is_connected() else { return [] }
  [self.build_probe()]
}

///|
/// A padded Initial carrying a PING: the packet a client sends when the server can answer
/// nothing until something arrives (RFC 9002 §6.2.2.1).
fn Client::build_probe(self : Client) -> Bytes {
  let pn = self.core.next_packet_number(Level::Initial)
  let payload = @packet.payload([@frame.Ping])
  let build = body => {
    seal_long(
      Initial,
      1U,
      self.dcid,
      self.scid,
      pn,
      4,
      body,
      self.initial_tx,
      token=self.token,
    )
  }
  pad(payload, build, min_datagram)
}

///|
/// Close the connection (RFC 9000 §10.2), in the shape `Session::close` has. An application's
/// close before 1-RTT keys exist cannot name its own error code, so it goes as a transport
/// close carrying APPLICATION_ERROR instead (RFC 9000 §10.2.3).
pub fn Client::close(
  self : Client,
  error_code : UInt64,
  reason : Bytes,
  now : Int64,
  application~ : Bool = false,
) -> Unit {
  guard self.phase == Active else { return }
  self.at = now
  let level = self.send_level()
  let frame = if application && level == Level::Application {
    @frame.ConnectionClose(error_code~, frame_type=None, reason~)
  } else if application {
    @frame.ConnectionClose(
      error_code=application_error,
      frame_type=Some(0UL),
      reason~,
    )
  } else {
    @frame.ConnectionClose(error_code~, frame_type=Some(0UL), reason~)
  }
  self.phase = Closing
  self.close_frame = Some(frame)
  self.close_level = level
  self.close_at = now + self.cfg.close_period
  self.events.push(Closed(error_code))
}

///|
/// The sending state of path `path` on this client. Path 0's lane shares the send loop's recovery
/// state, so a connection that never opens a second path behaves as it did before.
fn Client::lane(self : Client, path : UInt64) -> Lane[Unit] {
  match self.lanes.get(path) {
    Some(lane) => lane
    None => {
      let lane = Lane::new(
        path,
        (),
        self.core.space_on(path, Level::Application),
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
pub fn Client::path_lane(self : Client, path : UInt64) -> Lane[Unit]? {
  self.lanes.get(path)
}

///|
/// This connection's paths, path 0 being the one the handshake ran on.
pub fn Client::paths(self : Client) -> Paths {
  self.paths
}

///|
/// Start a second path from this client (draft-ietf-quic-multipath §3.1): the caller names the
/// peer's connection id for it, the id this end will answer to on it, and eight bytes for the
/// PATH_CHALLENGE. The datagrams that follow are handed back by `poll_paths`, tagged with the
/// path they belong on, because which socket each goes out of is the caller's to know.
pub fn Client::add_path(
  self : Client,
  path : UInt64,
  dcid : Bytes,
  lcid : Bytes,
  now : Int64,
  nonce~ : Bytes,
  token~ : Bytes,
) -> Bool {
  guard self.phase == Active && self.tls.is_connected() else { return false }
  guard self.paths.openable(path) else { return false }
  guard dcid.length() > 0 && lcid.length() > 0 && nonce.length() == 8 else {
    return false
  }
  self.paths.bind(path, dcid)
  ignore(self.paths.bind_local(path, lcid))
  // The challenge is what proves the path, so it is remembered before the packet that carries it:
  // the answer is checked against what was sent, not against what can be recalled later.
  ignore(self.paths.start(path, nonce))
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
/// Put `frames` in one 1-RTT packet on `path`. Path 0 goes out the connection's own way and is
/// picked up by `poll_out`; any other path is numbered, paced and recovered by its own lane.
pub fn Client::send_on(
  self : Client,
  path : UInt64,
  frames : Array[@frame.Frame],
  now : Int64,
) -> Bool {
  guard self.app_tx is Some(keys) else { return false }
  guard frames.length() > 0 else { return false }
  if path == 0UL {
    for frame in frames {
      self.sender.queue_control(frame)
    }
    return true
  }
  let lane = self.lane(path)
  let dcid = self.paths.peer_cid(path)
  guard dcid.length() > 0 else { return false }
  let payload = @packet.payload(frames)
  let size = (payload.length() + keys.suite.tag + 21 + self.scid.length()).to_int64()
  guard lane.send(now, frames, size) is Some(pn) else { return false }
  let datagram = send_short(
    dcid,
    pn,
    4,
    frames,
    keys,
    key_phase=self.key_phase,
    path~,
  )
  self.lane_out.push((path, datagram))
  true
}

///|
/// The datagrams the further paths have ready, each with the path it belongs on: what a lost
/// packet carried, then a probe a path owes. A client's caller sends each on the socket that path
/// runs over.
pub fn Client::poll_paths(self : Client, now : Int64) -> Array[(UInt64, Bytes)] {
  let out : Array[(UInt64, Bytes)] = []
  if self.phase != Active || !self.tls.is_connected() {
    return out
  }
  for path in self.lanes.keys().collect() {
    guard path != 0UL else { continue }
    guard self.lanes.get(path) is Some(lane) else { continue }
    while lane.due() is Some(frames) {
      guard self.send_on(path, frames, now) else { break }
    }
  }
  out.append(self.lane_out)
  self.lane_out.clear()
  if out.length() > 0 {
    self.last_tx = now
  }
  out
}

///|
/// The probe timeouts of the further paths (RFC 9002 §6.2.4): a path whose timeout has come puts
/// its two oldest packets back in line for the next `poll_paths`.
fn Client::tick_paths(self : Client, now : Int64) -> Unit {
  for path in self.lanes.keys().collect() {
    guard path != 0UL else { continue }
    guard self.lanes.get(path) is Some(lane) else { continue }
    ignore(lane.on_pto(now))
  }
}

///|
/// Act on an acknowledgement for path `path` (draft-ietf-quic-multipath §4.1).
fn Client::on_path_ack(
  self : Client,
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
/// other, naming the path whose numbers it settles.
fn Client::ack_on(
  self : Client,
  path : UInt64,
  delay : UInt64,
) -> @frame.Frame? {
  let space = self.core.space_on(path, Level::Application)
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
