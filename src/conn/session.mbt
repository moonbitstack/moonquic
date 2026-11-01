// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A QUIC server's connection table and event loop (RFC 9000 §5.2, §8.1, §10, §14.1). Every
// piece below this file is a pure function — the packet protection, the frame codec, the
// handshake, the recovery loop — and none of them talk to each other. This is the driver that
// makes them a server: it demultiplexes a received datagram onto a connection by its
// Destination Connection ID, drives that connection's state machine at the encryption level
// its installed keys allow, fires the idle, probe and closing timers, and hands back the
// datagrams to put on the wire — padded to the Initial minimum, and withheld once an
// unvalidated peer's amplification budget is spent. It holds no socket and no clock: the peer
// address is a type parameter and every entry point takes `now`, so the tests drive it with a
// fake sink on an injected clock and `quic_serve.native.mbt` drives it with a UDP socket.
//
// Version negotiation, stateless reset, connection migration, path validation and coalesced
// packets (more than one QUIC packet in a datagram) are not implemented here.

///|
/// Where a connection is in its lifecycle (RFC 9000 §10.2): exchanging packets, closing —
/// this endpoint sent a CONNECTION_CLOSE and answers anything further with it — or draining,
/// where the peer closed and nothing more goes out.
pub(all) enum Phase {
  Active
  Closing
  Draining
} derive(Eq, Debug)

///|
/// The smallest a datagram carrying an ack-eliciting Initial packet may be (RFC 9000 §14.1).
pub let min_datagram : Int32 = 1200

///|
/// The anti-amplification factor (RFC 9000 §8.1): until it has validated a peer's address, a
/// server may send it at most this many times the bytes it has received from it.
pub let amplification : Int64 = 3L

///|
/// What a server gives each new connection: the QUIC version its long headers carry, the idle
/// timeout it advertises, how long a closing or draining connection lingers, and the datagram
/// size, timer tuning and flow-control credit the send loop starts from. Every duration is in
/// microseconds, the unit the recovery code measures in.
pub(all) struct Config {
  version : UInt32
  idle_timeout : Int64
  close_period : Int64
  max_datagram : Int64
  max_ack_delay : Int64
  granularity : Int64
  initial_max_data : UInt64
  initial_max_stream_data : UInt64
  max_frame : UInt64
  streams_bidi : UInt64
  streams_uni : UInt64
}

///|
/// CRYPTO_BUFFER_EXCEEDED, RFC 9000 §20.1.
let crypto_buffer_exceeded : UInt64 = 0x0dUL

///|
/// TRANSPORT_PARAMETER_ERROR, RFC 9000 §20.1.
let transport_parameter_error : UInt64 = 0x08UL

///|
/// The base of the CRYPTO_ERROR codes: a TLS alert closes a connection with this plus its
/// description (RFC 9001 §4.8).
let crypto_error : UInt64 = 0x0100UL

///|
/// The error code a bad STREAM or RESET_STREAM closes the connection with (RFC 9000 §20.1).
fn stream_error(e : @stream.Refused) -> UInt64 {
  match e {
    Exceeded(..) => 0x03UL
    Conflict(_) => 0x06UL
    Illegal(_) => 0x0aUL
  }
}

///|
/// QUIC version 1, a 30-second idle timeout, a 3-second closing period, 1200-byte datagrams,
/// a 25-millisecond ACK delay, a mebibyte of flow-control credit on the connection and on each
/// stream, and a hundred streams of each kind at a time, as HTTP/2 servers commonly allow.
pub fn Config::default() -> Config {
  {
    version: 1U,
    idle_timeout: 30_000_000L,
    close_period: 3_000_000L,
    max_datagram: 1200L,
    max_ack_delay: 25_000L,
    granularity: 1_000L,
    initial_max_data: 1_048_576UL,
    initial_max_stream_data: 1_048_576UL,
    max_frame: 1024UL,
    streams_bidi: 100UL,
    streams_uni: 100UL,
  }
}

///|
/// The idle timeout in force on a connection (RFC 9000 §10.1): the smaller of the two
/// endpoints' advertised `max_idle_timeout`s, where zero on either side means that end asks
/// for no limit at all.
pub fn idle_timeout(ours : Int64, theirs : Int64) -> Int64 {
  if ours <= 0L {
    theirs
  } else if theirs <= 0L {
    ours
  } else if ours < theirs {
    ours
  } else {
    theirs
  }
}

///|
/// Build a datagram from `payload`, padding the payload with PADDING frames until the built
/// datagram reaches `min` bytes (RFC 9000 §14.1). The header's Length field is a varint, so
/// growing the payload can grow the header too; re-measure rather than guess the overhead.
fn pad(payload : Bytes, build : (Bytes) -> Bytes, min : Int32) -> Bytes {
  let mut body = payload
  let mut datagram = build(body)
  while datagram.length() < min {
    body = @packet.pad(body, body.length() + min - datagram.length())
    datagram = build(body)
  }
  datagram
}

///|
/// One server-side connection: the peer it answers, the connection ids the two ends address
/// each other by, the handshake and send state machines it drives, and the counters the
/// amplification limit, the idle timer and the closing period are read from. `A` is the
/// peer-address type the enclosing `Endpoint` was built with.
pub struct Session[A] {
  peer : A
  cid : Bytes
  peer_cid : Bytes
  core : Server
  sender : Sender
  cfg : Config
  out : Array[Bytes]
  received : Array[(Level, @frame.Frame)]
  mut rx : Int64
  mut tx : Int64
  mut packets : Int32
  mut validated : Bool
  mut last_rx : Int64
  mut idle_timeout : Int64
  mut phase : Phase
  mut close_at : Int64
  mut close_frame : @frame.Frame?
  mut close_level : Level
  mut hs_rx : @crypto.Keys?
  mut hs_rx_secret : Bytes
  mut hs_tx : @crypto.Keys?
  mut app_rx : @crypto.Keys?
  mut app_tx : @crypto.Keys?
  priv tls : @tls.Conn?
  streams : @stream.Streams
  priv events : Array[Event]
  priv initial_out : Outbox
  priv handshake_out : Outbox
  priv mut suite : @crypto.Suite
  priv mut app_rx_secret : Bytes
  priv mut app_tx_secret : Bytes
  priv mut key_phase : Bool
  priv mut initial_gone : Bool
  priv mut handshake_gone : Bool
  priv mut confirmed : Bool
  priv mut next_uni : UInt64
}

///|
/// A connection for the peer at `peer` that addressed this server as `cid` and called itself
/// `peer_cid`. The server keeps the client's original Destination Connection ID as its own —
/// that is the id the Initial keys derive from (RFC 9001 §5.2), so reusing it keeps the
/// demultiplexing key and the key schedule talking about the same bytes.
fn[A] Session::new(
  peer : A,
  cid : Bytes,
  peer_cid : Bytes,
  cfg : Config,
  now : Int64,
  original~ : Bytes = cid,
  tls? : @tls.Conn,
) -> Session[A] {
  {
    peer,
    cid,
    peer_cid,
    core: Server::new(original),
    sender: Sender::new(
      cfg.initial_max_data,
      cfg.initial_max_stream_data,
      cfg.max_datagram,
      cfg.max_ack_delay,
      cfg.granularity,
      cfg.max_frame,
    ),
    cfg,
    out: [],
    received: [],
    rx: 0L,
    tx: 0L,
    packets: 0,
    validated: false,
    last_rx: now,
    idle_timeout: cfg.idle_timeout,
    phase: Active,
    close_at: 0L,
    close_frame: None,
    close_level: Level::Initial,
    hs_rx: None,
    hs_rx_secret: b"",
    hs_tx: None,
    app_rx: None,
    app_tx: None,
    tls,
    streams: @stream.Streams::new(
      cfg.initial_max_data,
      cfg.initial_max_stream_data,
      server=true,
      bidi=@stream.Quota::new(cfg.streams_bidi),
      uni=@stream.Quota::new(cfg.streams_uni),
    ),
    events: [],
    initial_out: Outbox::new(),
    handshake_out: Outbox::new(),
    suite: @crypto.suite,
    app_rx_secret: b"",
    app_tx_secret: b"",
    key_phase: false,
    initial_gone: false,
    handshake_gone: false,
    confirmed: false,
    next_uni: 0UL,
  }
}

///|
/// The peer this connection answers.
pub fn[A] Session::peer(self : Session[A]) -> A {
  self.peer
}

///|
/// The connection id the peer addresses this server by — the table's key.
pub fn[A] Session::cid(self : Session[A]) -> Bytes {
  self.cid
}

///|
/// Where this connection is in its lifecycle.
pub fn[A] Session::phase(self : Session[A]) -> Phase {
  self.phase
}

///|
/// The handshake state machine underneath, for a caller driving the TLS flights.
pub fn[A] Session::core(self : Session[A]) -> Server {
  self.core
}

///|
/// Bytes received from the peer, the numerator of the amplification limit.
pub fn[A] Session::rx_bytes(self : Session[A]) -> Int64 {
  self.rx
}

///|
/// Bytes sent to the peer, the quantity the amplification limit caps.
pub fn[A] Session::tx_bytes(self : Session[A]) -> Int64 {
  self.tx
}

///|
/// Datagrams received on this connection.
pub fn[A] Session::packets_received(self : Session[A]) -> Int32 {
  self.packets
}

///|
/// Whether the peer's address has been validated (RFC 9000 §8.1), which lifts the
/// amplification limit.
pub fn[A] Session::validated(self : Session[A]) -> Bool {
  self.validated
}

///|
/// The idle timeout in force, in microseconds; zero means none.
pub fn[A] Session::idle_timeout(self : Session[A]) -> Int64 {
  self.idle_timeout
}

///|
/// Datagrams built and waiting to go out — non-zero while the amplification limit or a closed
/// congestion window is holding them back.
pub fn[A] Session::pending(self : Session[A]) -> Int32 {
  self.out.length()
}

///|
/// The largest packet number the peer has acknowledged at `level`, or `None` before its first
/// ACK there.
pub fn[A] Session::largest_acked(self : Session[A], level : Level) -> Int64? {
  self.core.conn.space(level).largest_acked()
}

///|
/// Whether `n` more bytes may go to this peer: unrestricted once its address is validated,
/// otherwise at most three times what it has sent this server (RFC 9000 §8.1).
pub fn[A] Session::can_send(self : Session[A], n : Int32) -> Bool {
  self.validated || self.tx + n.to_int64() <= amplification * self.rx
}

///|
/// Install the Handshake-space keys, derived from the client's and this server's handshake
/// traffic secrets (RFC 9001 §5.1). Until they are installed, a Handshake packet cannot be
/// unprotected and is dropped; after, the connection reads and writes at that level. The
/// client's secret is kept so an arriving Finished can be verified against it.
pub fn[A] Session::install_handshake_keys(
  self : Session[A],
  client_secret : Bytes,
  server_secret : Bytes,
) -> Unit {
  self.hs_rx = Some(@crypto.Keys::of(client_secret[:], suite=self.suite))
  self.hs_rx_secret = client_secret
  self.hs_tx = Some(@crypto.Keys::of(server_secret[:], suite=self.suite))
}

///|
/// Install the Application-space (1-RTT) keys, derived from the two application traffic
/// secrets. Until they are installed, a short-header packet is dropped and the send loop has
/// nowhere to put stream data.
pub fn[A] Session::install_app_keys(
  self : Session[A],
  client_secret : Bytes,
  server_secret : Bytes,
) -> Unit {
  self.app_rx = Some(@crypto.Keys::of(client_secret[:], suite=self.suite))
  self.app_rx_secret = client_secret
  self.app_tx = Some(@crypto.Keys::of(server_secret[:], suite=self.suite))
  self.app_tx_secret = server_secret
}

///|
/// Apply the peer's transport parameters (RFC 9000 §18): the idle timer settles at the
/// smaller of the two ends' values, and the peer's initial flow-control credit opens the
/// connection-wide send window, which §18.2 says is a MAX_DATA arriving at once.
pub fn[A] Session::apply_peer_params(
  self : Session[A],
  params : Array[Param],
) -> Unit {
  let peer = Limits::read(params[:])
  // The idle timer settles at the smaller of the two ends' values; the parameter is in
  // milliseconds and the timers here are in microseconds.
  if find(params[:], MaxIdleTimeout) is Some(_) {
    self.idle_timeout = idle_timeout(
      self.cfg.idle_timeout,
      peer.idle_timeout.reinterpret_as_int64() * 1000L,
    )
  }
  // §18.2: the initial flow-control parameters are a MAX_DATA and a MAX_STREAM_DATA on
  // every stream, delivered the moment the handshake carries them.
  self.sender.on_max_data(peer.data)
}

///|
/// The highest encryption level this connection can send at — Application once its 1-RTT keys
/// are in, else Handshake, else Initial, which is always available.
pub fn[A] Session::send_level(self : Session[A]) -> Level {
  if self.app_tx is Some(_) {
    Level::Application
  } else if self.hs_tx is Some(_) {
    Level::Handshake
  } else {
    Level::Initial
  }
}

///|
/// Queue `frames` to go out at `level` on the next `poll_out`, numbered from that level's
/// packet-number space. An Initial packet carrying anything ack-eliciting takes its datagram
/// to the 1200-byte floor (RFC 9000 §14.1); a level whose keys are not installed drops the
/// frames, since there is nothing to protect them with.
pub fn[A] Session::send(
  self : Session[A],
  level : Level,
  frames : Array[@frame.Frame],
) -> Unit {
  let pn = self.core.conn.next_packet_number(level)
  if level == Level::Application {
    // The recovery loop numbers this space too; keep the two counters from colliding.
    self.sender.advance_past(pn)
  }
  self.emit(level, frames, pn)
}

///|
fn[A] Session::emit(
  self : Session[A],
  level : Level,
  frames : Array[@frame.Frame],
  pn : Int64,
) -> Unit {
  let payload = @packet.payload(frames)
  let build = p => self.seal(level, p, pn)
  self.out.push(
    if level == Level::Initial && @packet.payload_elicits_ack(frames) {
      pad(payload, build, min_datagram)
    } else {
      build(payload)
    },
  )
}

///|
/// A packet at `level` carrying `payload`, under that level's keys and cipher. A level without
/// keys gives an empty packet, which goes nowhere.
fn[A] Session::seal(
  self : Session[A],
  level : Level,
  payload : Bytes,
  pn : Int64,
) -> Bytes {
  match level {
    Initial =>
      seal_long(
        Initial,
        self.cfg.version,
        self.peer_cid,
        self.cid,
        pn,
        4,
        payload,
        self.core.reply_keys,
      )
    Handshake => {
      guard self.hs_tx is Some(k) else { return b"" }
      seal_long(
        Handshake,
        self.cfg.version,
        self.peer_cid,
        self.cid,
        pn,
        4,
        payload,
        k,
        suite=self.suite,
      )
    }
    Application => {
      guard self.app_tx is Some(k) else { return b"" }
      let pn_bytes = @packet.number(pn, None, size=4)
      let h : @packet.Short = {
        spin: false,
        key_phase: self.key_phase,
        pn_length: 4,
        dcid: self.peer_cid,
      }
      k.seal(h.header(pn_bytes[:])[:], payload[:], number=pn, suite=self.suite)
    }
  }
}

///|
/// Queue `bytes` to send on stream `id`; the send loop frames and paces them out through
/// `poll_out` once the Application keys are installed.
pub fn[A] Session::queue_stream(
  self : Session[A],
  id : UInt64,
  bytes : Bytes,
) -> Unit {
  self.sender.queue_stream(id, bytes)
}

///|
/// Take the frames received since the last call, each with the level it arrived at — where an
/// application layer reads its streams out of.
pub fn[A] Session::take_received(
  self : Session[A],
) -> Array[(Level, @frame.Frame)] {
  let out = self.received.copy()
  self.received.clear()
  out
}

///|
/// Close the connection (RFC 9000 §10.2): put a CONNECTION_CLOSE carrying `error_code` and
/// `reason` on the wire at the highest level with keys, drop whatever else was queued, and
/// enter the closing period — during which every packet the peer sends is answered with the
/// same CONNECTION_CLOSE, and at the end of which `tick` forgets the connection. Closing a
/// connection that is already closing or draining does nothing.
pub fn[A] Session::close(
  self : Session[A],
  error_code : UInt64,
  reason : Bytes,
  now : Int64,
  application~ : Bool = false,
) -> Unit {
  guard self.phase == Active else { return }
  // frame_type 0 names no triggering frame, which is what a close not provoked by one says. An
  // application's close has no frame type at all (RFC 9000 §19.19).
  let frame = @frame.ConnectionClose(
    error_code~,
    frame_type=if application { None } else { Some(0UL) },
    reason~,
  )
  self.phase = Closing
  self.events.push(Closed(error_code))
  self.close_frame = Some(frame)
  self.close_level = self.send_level()
  self.close_at = now + self.cfg.close_period
  self.out.clear()
  self.send(self.close_level, [frame])
}

///|
/// The next datagram to put on the wire, or `None` when nothing is queued, the amplification
/// budget is spent, or the connection is draining. Pulls a fresh packet out of the send loop
/// when the queue has run dry.
fn[A] Session::next_datagram(self : Session[A], now : Int64) -> Bytes? raise {
  guard self.phase != Draining else { return None }
  if self.out.length() == 0 {
    self.fill(now)
  }
  guard self.out.length() > 0 else { return None }
  let datagram = self.out[0]
  guard self.can_send(datagram.length()) else { return None }
  let _ = self.out.remove(0)
  self.tx = self.tx + datagram.length().to_int64()
  Some(datagram)
}

///|
/// Pull the next packet the send loop has ready — a retransmission or freshly scheduled stream
/// data — into the outbound queue (RFC 9002 §7).
fn[A] Session::fill(self : Session[A], now : Int64) -> Unit raise {
  guard self.phase == Active else { return }
  if self.tls is Some(_) {
    return self.assemble(now)
  }
  guard self.app_tx is Some(_) else { return }
  match self.sender.poll_send(now) {
    Some((pn, frames)) => {
      // The recovery loop assigned the number; keep the space's own counter past it.
      self.core.conn.space(Level::Application).advance_past(pn)
      self.emit(Level::Application, frames, pn)
    }
    None => ()
  }
}

///|
/// Take a datagram from this connection's peer at `now`: count it against the amplification
/// budget and the idle timer, unprotect it at whichever level its header names, and drive the
/// state machine with the frames inside.
fn[A] Session::on_datagram(
  self : Session[A],
  datagram : Bytes,
  now : Int64,
) -> Unit raise {
  self.rx = self.rx + datagram.length().to_int64()
  self.last_rx = now
  self.packets = self.packets + 1
  // A datagram may carry several packets, each long header giving its length; a short header
  // runs to the end (RFC 9000 §12.2).
  let mut at = 0
  while at < datagram.length() && self.phase != Draining {
    let view = datagram[at:]
    if (view[0].to_int() & 0x80) == 0 {
      self.on_app(view.to_owned(), now)
      break
    }
    guard @packet.read_header(view) is Some((h, tail)) else { break }
    let size = tail.at + tail.length.to_int()
    guard size <= view.length() else { break }
    let packet = view[0:size].to_owned()
    at = at + size
    match h.packet_type {
      @packet.Kind::Initial => self.on_initial(packet, now)
      @packet.Kind::Handshake => self.on_handshake(packet, now)
      // 0-RTT is not served, and a client sends no Retry.
      _ => ()
    }
  }
}

///|
fn[A] Session::on_initial(
  self : Session[A],
  datagram : Bytes,
  now : Int64,
) -> Unit raise {
  guard !self.initial_gone else { return }
  let space = self.core.conn.space(Level::Initial)
  let opened = recv_long(
    datagram,
    self.core.initial_keys,
    largest=space.largest_received(),
  ) catch {
    _ => None
  }
  // A datagram that does not authenticate is discarded, not an error: an endpoint cannot
  // tell a corrupted packet from an injected one (RFC 9000 §12.2).
  guard opened is Some((frames, pn)) else { return }
  match self.tls {
    Some(tls) => {
      guard !space.seen(pn) else { return }
      self.on_crypto(tls, Level::Initial, frames, pn, now)
    }
    None => {
      let _ = self.core.on_frames(Level::Initial, frames, pn)
      self.adopt_peer_params()
    }
  }
  self.on_frames(Level::Initial, frames, now)
}

///|
fn[A] Session::on_handshake(
  self : Session[A],
  datagram : Bytes,
  now : Int64,
) -> Unit raise {
  guard self.hs_rx is Some(keys) && !self.handshake_gone else { return }
  let space = self.core.conn.space(Level::Handshake)
  let opened = recv_long(
    datagram,
    keys,
    largest=space.largest_received(),
    suite=self.suite,
  ) catch {
    _ => None
  }
  guard opened is Some((frames, pn)) else { return }
  // A Handshake packet the peer could only have sent from the address it claims proves that
  // address, which lifts the amplification limit (RFC 9000 §8.1).
  self.validated = true
  match self.tls {
    Some(tls) => {
      guard !space.seen(pn) else { return }
      // RFC 9001 §4.9.1: a server is done with the Initial keys at its first Handshake packet.
      self.initial_gone = true
      self.initial_out.clear()
      self.on_crypto(tls, Level::Handshake, frames, pn, now)
    }
    None => {
      let _ = self.core.on_handshake_frames(frames, pn, self.hs_rx_secret)
    }
  }
  self.on_frames(Level::Handshake, frames, now)
}

///|
fn[A] Session::on_app(
  self : Session[A],
  datagram : Bytes,
  now : Int64,
) -> Unit raise {
  guard self.app_rx is Some(keys) else { return }
  // RFC 9001 §5.7: a server holds 1-RTT keys before the client is authenticated, and reads
  // nothing under them until the handshake is done.
  if self.tls is Some(tls) && !tls.is_connected() {
    return
  }
  let space = self.core.conn.space(Level::Application)
  let opened = self.open_app(datagram, keys, space.largest_received())
  guard opened is Some((frames, pn)) else { return }
  if self.tls is Some(_) && space.seen(pn) {
    return
  }
  self.core.conn.on_packet_received(
    Level::Application,
    pn,
    @packet.payload_elicits_ack(frames),
  )
  self.on_frames(Level::Application, frames, now)
}

///|
/// Act on the frames of a packet that arrived at `level`: feed acknowledgements to the
/// recovery loop, take a CONNECTION_CLOSE into the draining period, raise the send limit from
/// a MAX_DATA, and record the rest for the application layer. Then answer — an ACK if one is
/// owed (RFC 9000 §13.2.1), or this endpoint's CONNECTION_CLOSE again if it is closing
/// (§10.2.1).
fn[A] Session::on_frames(
  self : Session[A],
  level : Level,
  frames : Array[@frame.Frame],
  now : Int64,
) -> Unit raise {
  let live = self.tls is Some(_)
  for frame in frames {
    if !live {
      self.received.push((level, frame))
    }
    match frame {
      Ack(largest~, ..) | AckEcn(largest~, ..) => {
        self.core.conn.on_ack_received(level, largest.reinterpret_as_int64())
        match level {
          Application => self.sender.on_ack(frame, now)
          _ => self.outbox(level).on_ack(frame)
        }
      }
      ConnectionClose(error_code~, ..) => {
        self.phase = Draining
        self.close_at = now + self.cfg.close_period
        self.out.clear()
        self.events.push(Closed(error_code))
        return
      }
      MaxData(v) => self.sender.on_max_data(v)
      MaxStreamData(id~, max~) => self.sender.on_max_stream_data(id, max)
      Stream(id~, offset~, fin~, data~) if live =>
        self.on_stream(level, id, offset, data, fin, now)
      ResetStream(id~, error_code~, final_size~) if live => {
        self.streams.on_reset(id, final_size) catch {
          e => return self.close(stream_error(e), b"", now)
        }
        self.events.push(Reset(id, error_code))
      }
      StopSending(id~, error_code~) if live =>
        self.events.push(Stopped(id, error_code))
      PathChallenge(data) if live =>
        self.sender.queue_control(PathResponse(data))
      _ => ()
    }
  }
  if self.phase == Closing {
    match self.close_frame {
      Some(frame) => self.send(self.close_level, [frame])
      None => ()
    }
    return
  }
  // With a TLS server the datagram builder picks ACKs up, so they share a packet with what is
  // going out anyway.
  if !live && self.core.conn.space(level).ack_pending() {
    match self.core.conn.build_ack(level, 0UL) {
      Some(ack) => self.send(level, [ack])
      None => ()
    }
  }
}

///|
/// A STREAM frame: only 1-RTT packets may carry one here, 0-RTT not being served (RFC 9000 §12.5).
fn[A] Session::on_stream(
  self : Session[A],
  level : Level,
  id : UInt64,
  offset : UInt64,
  data : Bytes,
  fin : Bool,
  now : Int64,
) -> Unit {
  if level != Level::Application {
    return self.close(0x0aUL, b"STREAM outside 1-RTT", now)
  }
  self.streams.accept(id, offset, data, fin~) catch {
    e => return self.close(stream_error(e), b"", now)
  }
  // A frame for a stream already released was dropped above, and is no news.
  let event = Readable(id)
  if self.streams.streams.contains(id) && !self.events.contains(event) {
    self.events.push(event)
  }
}

///|
/// Read the peer's transport parameters off the ClientHello the handshake has taken in, once
/// there is one to read (RFC 9001 §8.2). A hello that does not decode leaves the defaults
/// standing.
fn[A] Session::adopt_peer_params(self : Session[A]) -> Unit {
  let hello = self.core.client_hello()
  guard hello.length() > 0 else { return }
  guard @msg.unframe(hello[:]) is Some((_, body)) else { return }
  guard @msg.read_hello(body[:]) is Some(ch) else { return }
  self.apply_peer_params(of_extensions(ch.extensions[:]))
}

///|
pub extend Phase with Debug::{to_repr}

///|
pub extend Phase with Eq::{not_equal, equal}
