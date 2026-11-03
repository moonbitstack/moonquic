// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A client connection's handshake (RFC 9000 §7, RFC 9001 §4): the counterpart of `Server`.
// It drives moontls's QUIC client, splits the ClientHello across as many Initial packets as
// it needs — a post-quantum hello is over a kilobyte, past one datagram — seals them with
// the Initial keys the connection ID alone yields, reassembles the server's flights per
// encryption level, and installs the keys each flight brings. It holds no socket and no
// clock: `poll_out` and `recv` both take the time from the caller.

///|
/// The most CRYPTO bytes one Initial or Handshake packet carries. Every path must carry a
/// 1200-byte datagram (RFC 9000 §14); the header, packet number and AEAD tag take the rest,
/// with room to spare.
let crypto_room : Int32 = 1100

///|
/// A client connection mid-handshake.
pub struct Client {
  tls : @tls.Conn
  scid : Bytes
  mut dcid : Bytes
  initial_tx : @crypto.Keys
  initial_rx : @crypto.Keys
  mut hs_tx : @crypto.Keys?
  mut hs_rx : @crypto.Keys?
  mut app_tx : @crypto.Keys?
  mut app_rx : @crypto.Keys?
  mut suite : @crypto.Suite
  core : Conn
  /// The next CRYPTO offset to write at each level, 0 for Initial, 1 Handshake.
  offsets : Array[Int64]
  /// Bytes the handshake has asked to send, with the level and CRYPTO offset they start at.
  out : Array[(Level, Int64, Bytes)]
  mut seen_server_cid : Bool
  received : Array[@frame.Frame]
  /// 1-RTT: the send loop, the receiving streams, and what the application is told.
  sender : Sender
  streams : @stream.Streams
  events : Array[Event]
  datagrams : Array[Bytes]
  key_phase : Bool
  mut next_uni : UInt64
  /// The early keys a caller supplied for 0-RTT, and the frames waiting to go under them.
  mut zero_rtt_tx : @crypto.Keys?
  zero_frames : Array[@frame.Frame]
}

///|
/// The index of a TLS level in the per-level arrays, Initial 0 and Application 2.
fn level_index(level : @tls.Level) -> Int32 {
  match level {
    Initial => 0
    Handshake => 1
    Application => 2
  }
}

///|
/// The connection level a TLS level names.
fn ours_of(level : @tls.Level) -> Level {
  match level {
    Initial => Level::Initial
    Handshake => Level::Handshake
    Application => Level::Application
  }
}

///|
/// The CRYPTO runs a byte stream at `offset` splits into, each at most `crypto_room` long.
/// The first flight of a post-quantum hello is two, which is what this is for.
fn split_crypto(offset : Int64, data : Bytes) -> Array[(Int64, Bytes)] {
  let out : Array[(Int64, Bytes)] = []
  let mut at = 0
  while at < data.length() {
    let left = data.length() - at
    let take = if left > crypto_room { crypto_room } else { left }
    out.push((offset + at.to_int64(), data[at:at + take].to_owned()))
    at = at + take
  }
  out
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
  now : Int64,
  cfg~ : Config = Config::default(),
) -> Client raise {
  let tls = @tls.Conn::quic_client(config, server_name, params~, rand~, now~)
  let (tx, rx) = @crypto.initial(dcid[:])
  let client : Client = {
    tls,
    scid,
    dcid,
    initial_tx: tx,
    initial_rx: rx,
    hs_tx: None,
    hs_rx: None,
    app_tx: None,
    app_rx: None,
    suite: @crypto.suite,
    core: Conn::new(false),
    offsets: [0L, 0L, 0L],
    out: [],
    seen_server_cid: false,
    received: [],
    sender: Sender::new(
      0UL,
      0UL,
      cfg.max_datagram,
      cfg.max_ack_delay,
      cfg.granularity,
      cfg.max_frame,
    ),
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
    next_uni: 0UL,
    zero_rtt_tx: None,
    zero_frames: [],
  }
  client.absorb()
  client
}

///|
/// Do what the handshake asks: install the keys it derives now, and queue the bytes it wants
/// sent with the level and offset they belong at.
fn Client::absorb(self : Client) -> Unit {
  for step in self.tls.steps() {
    match step {
      Send(level, data) => {
        let at = level_index(level)
        let offset = self.offsets[at]
        self.out.push((ours_of(level), offset, data))
        self.offsets[at] = offset + data.length().to_int64()
      }
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
          }
          Initial => ()
        }
      }
    }
  }
  self.adopt_peer_params()
}

///|
/// Take the server's transport parameters once EncryptedExtensions has brought them: the
/// flow-control credit that opens the send loop, and the largest datagram it will take.
fn Client::adopt_peer_params(self : Client) -> Unit {
  guard self.tls.peer_params() is Some(raw) else { return }
  guard decode_opt(raw[:]) is Some(params) else { return }
  let peer = Limits::read(params[:])
  // A stream this client opens is "remote" from the server's side of the ledger.
  self.sender.sched.on_params(
    data=peer.data,
    bidi=peer.stream_data_bidi_remote,
    uni=peer.stream_data_uni,
  )
  self.sender.on_max_data(peer.data)
  self.sender.on_peer_datagram(peer.datagram_frame)
  self.sender.ack_exponent = peer.ack_delay_exponent.to_int()
}

///|
/// The datagrams to put on the wire: the queued CRYPTO bytes split so no Initial packet runs
/// past a datagram, each Initial padded to the 1200-byte floor (RFC 9000 §14.1). A client's
/// first flight is usually one datagram and a post-quantum hello is two.
pub fn Client::poll_out(self : Client, now : Int64) -> Array[Bytes] {
  ignore(now)
  let out : Array[Bytes] = []
  let queued = self.out.copy()
  self.out.clear()
  for entry in queued {
    let (level, offset, data) = entry
    for run in split_crypto(offset, data) {
      let (at, chunk) = run
      let pn = self.core.next_packet_number(level)
      let frame : @frame.Frame = Crypto(
        offset=at.reinterpret_as_uint64(),
        data=chunk,
      )
      let packet = match level {
        Level::Initial => {
          let payload = @packet.payload([frame])
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
              suite=self.suite,
            )
          }
          pad(payload, build, min_datagram)
        }
        Level::Handshake =>
          match self.hs_tx {
            Some(keys) =>
              send_long(
                Handshake,
                1U,
                self.dcid,
                self.scid,
                pn,
                4,
                [frame],
                keys,
                suite=self.suite,
              )
            None => b""
          }
        Level::Application => b""
      }
      if packet.length() > 0 {
        out.push(packet)
      }
    }
  }
  // 0-RTT goes before the handshake finishes: the client's early keys, the Application space.
  if self.zero_rtt_tx is Some(keys) &&
    !self.tls.is_connected() &&
    self.zero_frames.length() > 0 {
    let frames = self.zero_frames.copy()
    self.zero_frames.clear()
    let pn = self.core.next_packet_number(Level::Application)
    out.push(
      send_zero_rtt(self.dcid, self.scid, pn, 4, frames, keys, suite=self.suite),
    )
  }
  // 1-RTT: once the handshake is done, whatever the send loop has ready, with the ACK owed.
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
              let pn = space.next_packet_number()
              out.push(self.seal_app(pn, [a]))
            }
            None => ()
          }
          break
        }
      }
    }
  }
  out
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
      send_short(
        self.dcid,
        pn,
        4,
        frames,
        keys,
        key_phase=self.key_phase,
        suite=self.suite,
      )
    None => b""
  }
}

///|
/// Take a datagram from the server: split it into packets, unprotect each at the level its
/// header names, reassemble its CRYPTO stream, and drive the handshake with what becomes
/// contiguous. A server's first datagram may coalesce an Initial and a Handshake packet;
/// the keys the Initial brings are installed before the Handshake packet is read.
pub fn Client::recv(self : Client, datagram : Bytes, now : Int64) -> Unit raise {
  ignore(now)
  let mut at = 0
  while at < datagram.length() {
    let view = datagram[at:]
    guard view.length() > 0 else { break }
    if (view[0].to_int() & 0x80) == 0 {
      // 1-RTT: every Application packet runs to the end of the datagram.
      guard self.app_rx is Some(keys) else { break }
      let space = self.core.space(Level::Application)
      let opened = recv_short(
        view.to_owned(),
        self.scid.length(),
        keys,
        largest=space.largest_received(),
        suite=self.suite,
      ) catch {
        _ => None
      }
      guard opened is Some((frames, pn)) else { break }
      self.core.on_packet_received(
        Level::Application,
        pn,
        @packet.payload_elicits_ack(frames),
      )
      self.on_app_frames(frames, now)
      break
    }
    guard @packet.read_header(view) is Some((h, tail)) else { break }
    let size = tail.at + tail.length.to_int()
    guard size <= view.length() else { break }
    let packet = view[0:size].to_owned()
    at = at + size
    if !self.seen_server_cid {
      // The server names the connection id it wants addressed by in its first long header.
      self.dcid = h.scid
      self.seen_server_cid = true
    }
    match h.packet_type {
      Initial => self.on_long(Level::Initial, packet, self.initial_rx)
      Handshake =>
        match self.hs_rx {
          Some(keys) => self.on_long(Level::Handshake, packet, keys)
          None => ()
        }
      _ => ()
    }
  }
}

///|
/// One long-header packet at `level`, under `keys`: record its number, reassemble its CRYPTO
/// bytes, feed the contiguous run to the handshake, and do what it asks.
fn Client::on_long(
  self : Client,
  level : Level,
  packet : Bytes,
  keys : @crypto.Keys,
) -> Unit raise {
  let space = self.core.space(level)
  let opened = recv_long(
    packet,
    keys,
    largest=space.largest_received(),
    suite=self.suite,
  ) catch {
    _ => None
  }
  guard opened is Some((frames, pn)) else { return }
  self.core.on_packet_received(level, pn, @packet.payload_elicits_ack(frames))
  let ready = Buffer()
  for frame in frames {
    self.received.push(frame)
    match frame {
      Crypto(offset~, data~) => {
        let contiguous = self.core.on_crypto_frame(level, offset, data)
        ready.write_bytes(contiguous)
      }
      _ => ()
    }
  }
  if ready.length() > 0 {
    self.tls.crypto(tls_level(level), ready.to_bytes()[:])
  }
  self.absorb()
}

///|
/// Whether the handshake has completed.
pub fn Client::is_connected(self : Client) -> Bool {
  self.tls.is_connected()
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
/// Install the client's 0-RTT (early) keys (RFC 9001 §5.2). They are TLS's early traffic
/// secret expanded by `@crypto.zero_rtt`; this library has no handshake of its own to derive
/// one, so the caller supplies them.
pub fn Client::install_zero_rtt(self : Client, keys : @crypto.Keys) -> Unit {
  self.zero_rtt_tx = Some(keys)
}

///|
/// Queue frames to go out in a 0-RTT packet (RFC 9000 §12.5): STREAM, MAX_*, or any frame
/// 0-RTT permits. Answering when no early keys are installed, because there is nothing to
/// protect them with.
pub fn Client::send_zero_rtt(
  self : Client,
  frames : Array[@frame.Frame],
) -> Bool {
  guard self.zero_rtt_tx is Some(_) else { return false }
  for frame in frames {
    self.zero_frames.push(frame)
  }
  true
}

///|
/// Whether the server accepted the early data this client offered.
pub fn Client::early_accepted(self : Client) -> Bool {
  self.tls.early_accepted()
}

///|
/// The frames received so far, in order, for a caller reading the handshake's own traffic.
pub fn Client::frames(self : Client) -> Array[@frame.Frame] {
  self.received.copy()
}

///|
/// Act on a 1-RTT packet's frames: acknowledgements to the send loop, stream data into the
/// reassembler, flow-control updates to the scheduler, and the rest to the application.
fn Client::on_app_frames(
  self : Client,
  frames : Array[@frame.Frame],
  now : Int64,
) -> Unit raise {
  for frame in frames {
    self.received.push(frame)
    match frame {
      Ack(largest~, ..) | AckEcn(largest~, ..) => {
        self.core.on_ack_received(
          Level::Application,
          largest.reinterpret_as_int64(),
        )
        self.sender.on_ack(frame, now)
      }
      Stream(id~, offset~, fin~, data~) => {
        self.streams.accept(id, offset, data, fin~)
        let event = Readable(id)
        if self.streams.streams.contains(id) && !self.events.contains(event) {
          self.events.push(event)
        }
      }
      MaxData(v) => self.sender.on_max_data(v)
      MaxStreamData(id~, max~) => self.sender.on_max_stream_data(id, max)
      ResetStream(id~, error_code~, ..) =>
        self.events.push(Reset(id, error_code))
      StopSending(id~, error_code~) => self.events.push(Stopped(id, error_code))
      PathChallenge(data) => self.sender.queue_control(PathResponse(data))
      @frame.Datagram(data~) => {
        self.datagrams.push(data)
        if !self.events.contains(Event::Datagram) {
          self.events.push(Event::Datagram)
        }
      }
      ConnectionClose(error_code~, ..) => self.events.push(Closed(error_code))
      _ => ()
    }
  }
}

///|
/// Queue `data` on stream `id`, ending it after the data when `fin`.
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
