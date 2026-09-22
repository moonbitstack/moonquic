// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A QUIC connection's numbering and handshake-input core (RFC 9000 §12.3, RFC 9001
// §4.1.3). A connection keeps three independent packet-number spaces — Initial,
// Handshake, and Application (1-RTT) — and a CRYPTO byte stream per encryption level,
// each ordered on its own. This skeleton routes a received packet's number to its space
// (for acknowledgement) and a received CRYPTO frame to its level's reassembler (yielding
// the contiguous TLS handshake bytes to feed the handshake), and hands out send-side
// packet numbers per space. It holds no keys or socket — the key schedule and the async
// UDP transport wrap this pure core.

///|
/// A QUIC encryption level / packet-number space (RFC 9001 §4.1.1). 0-RTT shares the
/// Application space, so the three long-lived spaces are Initial, Handshake, and
/// Application.
pub(all) enum Level {
  Initial
  Handshake
  Application
} derive(Eq, Debug)

///|
/// A QUIC connection's per-space numbering/ACK state and per-level CRYPTO streams.
pub struct Conn {
  is_server : Bool
  initial_space : @packet.Space
  handshake_space : @packet.Space
  application_space : @packet.Space
  initial_crypto : @stream.Assembler
  handshake_crypto : @stream.Assembler
  application_crypto : @stream.Assembler
}

///|
/// A fresh connection (client or server) with empty spaces and CRYPTO streams.
pub fn Conn::new(is_server : Bool) -> Conn {
  {
    is_server,
    initial_space: @packet.Space::new(),
    handshake_space: @packet.Space::new(),
    application_space: @packet.Space::new(),
    initial_crypto: @stream.Assembler::new(),
    handshake_crypto: @stream.Assembler::new(),
    application_crypto: @stream.Assembler::new(),
  }
}

///|
/// Whether this endpoint is the server.
pub fn Conn::is_server(self : Conn) -> Bool {
  self.is_server
}

///|
/// The packet-number space for `level`.
pub fn Conn::space(self : Conn, level : Level) -> @packet.Space {
  match level {
    Initial => self.initial_space
    Handshake => self.handshake_space
    Application => self.application_space
  }
}

///|
/// The CRYPTO reassembler for `level`.
pub fn Conn::crypto_stream(self : Conn, level : Level) -> @stream.Assembler {
  match level {
    Initial => self.initial_crypto
    Handshake => self.handshake_crypto
    Application => self.application_crypto
  }
}

///|
/// Allocate the next packet number to send at `level`.
pub fn Conn::next_packet_number(self : Conn, level : Level) -> Int64 {
  self.space(level).next_packet_number()
}

///|
/// Record that a packet numbered `pn` arrived at `level`; `ack_eliciting` marks one that
/// must be acknowledged.
pub fn Conn::on_packet_received(
  self : Conn,
  level : Level,
  pn : Int64,
  ack_eliciting : Bool,
) -> Unit {
  self.space(level).on_packet_received(pn, ack_eliciting)
}

///|
/// Record the peer's acknowledgement of up to `largest` at `level`.
pub fn Conn::on_ack_received(
  self : Conn,
  level : Level,
  largest : Int64,
) -> Unit {
  self.space(level).on_ack_received(largest)
}

///|
/// Build the ACK frame owed at `level`, or `None` if nothing has been received there.
pub fn Conn::build_ack(
  self : Conn,
  level : Level,
  ack_delay : UInt64,
) -> @frame.Frame? {
  self.space(level).build_ack(ack_delay)
}

///|
/// Feed a CRYPTO frame's `data` at `offset` and `level` into that level's handshake
/// stream, returning the newly contiguous TLS handshake bytes now readable (empty while
/// an earlier gap is still outstanding). CRYPTO streams carry no fin.
pub fn Conn::on_crypto_frame(
  self : Conn,
  level : Level,
  offset : UInt64,
  data : Bytes,
) -> Bytes raise @stream.Refused {
  let stream = self.crypto_stream(level)
  stream.insert(offset, data, fin=false)
  stream.read()
}

///|
pub extend Level with Debug::{to_repr}

///|
pub extend Level with Eq::{not_equal, equal}

// The QUIC send loop, assembled (RFC 9000 §13, RFC 9002): the deterministic core a connection
// drives to put stream data on the wire and recover from loss. It composes the stream scheduler
// (which stream sends how much, bounded by flow control), the loss-recovery state (RTT,
// congestion window, loss detection), and a record of which STREAM data each packet carried.
// `poll_send` yields the next packet — a retransmission first, else freshly scheduled data —
// charging the congestion window; `on_ack` clears acknowledged packets and re-queues the stream
// data of any the ACK reveals as lost. The async UDP transport is the thin glue over this: send
// what `poll_send` returns, feed received ACKs to `on_ack`.

///|
/// A connection's send state for one packet-number space.
pub struct Sender {
  sched : @stream.Scheduler
  recovery : @recovery.State
  data : Map[UInt64, Bytes]
  in_packet : Map[Int64, Array[@stream.Chunk]]
  retransmit : Array[@stream.Chunk]
  mut next_pn : Int64
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
    data: Map([]),
    in_packet: Map([]),
    retransmit: [],
    next_pn: 0L,
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
/// Queue `bytes` of application data to send on stream `id`.
pub fn Sender::queue_stream(self : Sender, id : UInt64, bytes : Bytes) -> Unit {
  self.data[id] = bytes
  self.sched.queue(id, bytes.length().to_uint64())
}

///|
/// Mark stream `id` finished.
pub fn Sender::queue_fin(self : Sender, id : UInt64) -> Unit {
  self.sched.queue_fin(id)
}

///|
/// Raise the connection-wide send limit from a received MAX_DATA frame.
pub fn Sender::on_max_data(self : Sender, new_max : UInt64) -> Unit {
  self.sched.on_max_data(new_max)
}

///|
fn Sender::materialize(self : Sender, send : @stream.Chunk) -> @frame.Frame {
  let full = match self.data.get(send.stream) {
    Some(b) => b
    None => b""
  }
  let off = send.offset.to_int()
  let len = send.length.to_int()
  Stream(
    id=send.stream,
    offset=send.offset,
    fin=send.fin,
    data=full[off:off + len].to_owned(),
  )
}

///|
/// The next packet to send at `now`, or `None` when the congestion window is closed or nothing
/// is queued (RFC 9002 §7). Retransmissions go first, then freshly scheduled stream data; the
/// packet is recorded in the recovery state and its stream sends remembered for retransmission.
pub fn Sender::poll_send(
  self : Sender,
  now : Int64,
) -> (Int64, Array[@frame.Frame])? raise {
  if self.recovery.can_send(1L) {
    let send = match self.retransmit.pop() {
      Some(x) => Some(x)
      None => self.sched.next()
    }
    match send {
      None => None
      Some(s) => {
        let pn = self.next_pn
        self.next_pn = self.next_pn + 1L
        let frame = self.materialize(s)
        self.recovery.on_sent(pn, at=now, size=s.length.reinterpret_as_int64())
        self.in_packet[pn] = [s]
        Some((pn, [frame]))
      }
    }
  } else {
    None
  }
}

///|
/// Process a received ACK `frame` at `now`: clear acknowledged packets from the recovery state
/// and re-queue the stream data of any packet the ACK reveals as lost, to be retransmitted by a
/// later `poll_send` (RFC 9002 §6). Raises on a malformed ACK.
pub fn Sender::on_ack(
  self : Sender,
  frame : @frame.Frame,
  now : Int64,
) -> Unit raise {
  let lost = self.recovery.on_ack(frame, now, ack_delay=0L)
  for pn in lost {
    match self.in_packet.get(pn) {
      Some(sends) =>
        for s in sends {
          self.retransmit.push(s)
        }
      None => ()
    }
  }
}

///|
/// Handle the probe timeout firing at `now` (RFC 9002 §6.2.4). If the PTO deadline has passed with
/// packets still outstanding, re-queue the oldest outstanding packet's stream data as a probe — a
/// later `poll_send` puts it back on the wire — and back off the timer for the next arming. Unlike
/// loss detection, this neither declares packets lost nor reduces the congestion window. Returns
/// whether a probe was armed.
pub fn Sender::on_pto_timeout(self : Sender, now : Int64) -> Bool {
  guard self.recovery.pto_deadline() is Some(deadline) else { return false }
  guard now >= deadline else { return false }
  let out = self.recovery.outstanding()
  guard out.length() > 0 else { return false }
  let mut oldest = out[0]
  for pn in out {
    if pn < oldest {
      oldest = pn
    }
  }
  match self.in_packet.get(oldest) {
    Some(sends) =>
      for s in sends {
        self.retransmit.push(s)
      }
    None => ()
  }
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

// A QUIC server connection's Initial-flight processing (RFC 9000 §7, RFC 9001 §5): it
// ties the Initial packet protection, the per-level CRYPTO reassembly, and the TLS 1.3
// handshake runner together. Receiving an Initial packet unprotects it with the keys
// derived from the client's connection id, records the packet number for acknowledgement,
// reassembles the CRYPTO stream, and drives the handshake with the contiguous handshake
// bytes. This is the pure connection core the async UDP transport wraps; feeding it a
// client's Initial packet advances the server handshake to RECVD_CH.

///|
/// A QUIC server connection mid-handshake: the Initial keys, the packet-number/CRYPTO
/// bookkeeping, and the TLS handshake it is driving.
pub struct Server {
  initial_keys : @crypto.Keys
  handshake : @hs.Handshake
  conn : Conn
}

///|
/// A server connection for a client whose Destination Connection ID is `dcid` (the
/// Initial secret and keys derive from it, RFC 9001 §5.2).
pub fn Server::new(dcid : Bytes) -> Server {
  {
    initial_keys: @crypto.initial(dcid[:]).0,
    handshake: @hs.Handshake::new(),
    conn: Conn::new(true),
  }
}

///|
/// The current TLS handshake state.
pub fn Server::handshake_state(self : Server) -> @hs.Server {
  self.handshake.state()
}

///|
/// The transcript hash over the handshake messages processed so far.
pub fn Server::transcript_hash(self : Server) -> Bytes {
  self.handshake.transcript()
}

///|
/// The raw ClientHello the connection received (empty before one arrives): the source a
/// server runs the ECDHE key_share from to derive its handshake secrets.
pub fn Server::client_hello(self : Server) -> Bytes {
  self.handshake.hello()
}

///|
/// Negotiate the ClientHello this connection received (RFC 8446 §4.1.1): the group and key
/// share to run the ECDHE with, and the signature scheme to sign the CertificateVerify under,
/// read off what the client offered. Raises the §6 alert for a ClientHello this build cannot
/// serve, and returns `Retry` when the answer is a HelloRetryRequest.
pub fn Server::negotiate(self : Server) -> @hs.Choice raise @alert.Alert {
  self.handshake.negotiate()
}

///|
/// Whether an ACK is owed in the Initial space.
pub fn Server::initial_ack_pending(self : Server) -> Bool {
  self.conn.space(Level::Initial).ack_pending()
}

///|
/// Build the server's ServerHello response: encode it, fold it into the transcript, and
/// protect it into an Initial packet addressed to `out_dcid` (the client's source
/// connection id) from `out_scid`, at Initial packet number `pn` (RFC 9001 §5.3). The
/// state stays at RECVD_CH — the server flight is not complete until the Handshake-space
/// messages (EncryptedExtensions, Certificate, CertificateVerify, Finished) are sent by
/// `send_handshake_flight`, which advances it to WAIT_FINISHED.
pub fn Server::send_server_hello(
  self : Server,
  server_hello : @msg.Server,
  out_dcid : Bytes,
  out_scid : Bytes,
  pn : Int64,
) -> Bytes {
  let sh_msg = @msg.server_hello(server_hello)
  self.handshake.sent(sh_msg[:])
  send_long(
    Initial,
    1U,
    out_dcid,
    out_scid,
    pn,
    4,
    [@frame.Crypto(offset=0, data=sh_msg)],
    self.initial_keys,
  )
}

///|
/// Send the server's Handshake-space flight (RFC 8446 §4, RFC 9001 §5): encode
/// EncryptedExtensions, Certificate, and CertificateVerify, fold them into the transcript
/// in order, compute the server Finished as `HMAC(finished_key, transcript hash through
/// CertificateVerify)` over `server_hs_secret`, fold the Finished too, and advance the
/// state past the whole flight (RECVD_CH → WAIT_FINISHED). The four messages form one
/// contiguous CRYPTO stream, protected into a Handshake packet with the handshake-space
/// keys `@crypto.Keys::of(server_hs_secret[:])`, addressed to `out_dcid` from `out_scid` at
/// Handshake packet number `pn`. `server_hs_secret` is the server handshake traffic secret
/// the key schedule derives once ECDHE completes.
pub fn Server::send_handshake_flight(
  self : Server,
  server_hs_secret : Bytes,
  encrypted_extensions : Bytes,
  certificate : Bytes,
  verify : (Bytes) -> Bytes,
  out_dcid : Bytes,
  out_scid : Bytes,
  pn : Int64,
) -> Bytes raise {
  let ee = @msg.frame(EncryptedExtensions, encrypted_extensions[:])
  let cert = @msg.frame(Certificate, certificate[:])
  self.handshake.sent(ee[:])
  self.handshake.sent(cert[:])
  // The body is built here rather than passed in, because §4.4.3 signs the transcript
  // as it stands at exactly this point: Certificate folded in, Finished not yet.
  let cv = @msg.frame(CertificateVerify, verify(self.handshake.transcript())[:])
  self.handshake.sent(cv[:])
  let verify_data = @keys.finished(
    server_hs_secret[:],
    self.handshake.transcript()[:],
  )
  let fin = @msg.frame(Finished, verify_data[:])
  self.handshake.sent(fin[:])
  self.handshake.sent_flight(client_cert=false)
  let crypto = join(join(join(ee, cert), cv), fin)
  send_long(
    Handshake,
    1U,
    out_dcid,
    out_scid,
    pn,
    4,
    [@frame.Crypto(offset=0, data=crypto)],
    @crypto.Keys::of(server_hs_secret[:]),
  )
}

///|
/// Drive an already-unprotected packet's `frames` at `level`, numbered `pn`: record the
/// packet for acknowledgement and feed its CRYPTO frames into that level's reassembler,
/// driving the handshake with whatever handshake bytes become contiguous. Returns the
/// handshake message types processed. A driver that unprotected the packet itself — because
/// it also wants the ACK and CONNECTION_CLOSE frames beside the CRYPTO — enters here rather
/// than through `receive_initial`.
pub fn Server::on_frames(
  self : Server,
  level : Level,
  frames : Array[@frame.Frame],
  pn : Int64,
) -> Array[@msg.Kind] raise {
  self.conn.on_packet_received(level, pn, @packet.payload_elicits_ack(frames))
  let processed : Array[@msg.Kind] = []
  for frame in frames {
    match frame {
      Crypto(offset~, data~) => {
        let contiguous = self.conn.on_crypto_frame(level, offset, data)
        if contiguous.length() > 0 {
          for msg_type in self.handshake.feed(contiguous) {
            processed.push(msg_type)
          }
        }
      }
      _ => ()
    }
  }
  processed
}

///|
/// Receive a client Initial packet: unprotect it, record its number for acknowledgement,
/// reassemble its CRYPTO frames, and drive the handshake with the contiguous handshake
/// bytes. Returns the handshake message types processed. Raises if the packet fails to
/// authenticate.
pub fn Server::receive_initial(
  self : Server,
  packet : Bytes,
) -> Array[@msg.Kind] raise {
  let (frames, pn) = match recv_long(packet, self.initial_keys) {
    Some(v) => v
    None => raise @packet.Malformed("Initial packet failed to authenticate")
  }
  self.on_frames(Level::Initial, frames, pn)
}

///|
/// Receive the client's Handshake-space flight — in this no-client-authentication path,
/// the client Finished (RFC 8446 §4.4.4): unprotect the Handshake packet with the client
/// handshake keys, reassemble its CRYPTO stream, verify the Finished `verify_data` against
/// `client_hs_secret` over the transcript through the server Finished, then fold it in to
/// advance the handshake to CONNECTED. Returns whether the handshake is now connected with
/// a Finished that authenticated. Raises if the packet fails to authenticate.
pub fn Server::receive_handshake(
  self : Server,
  packet : Bytes,
  client_hs_keys : @crypto.Keys,
  client_hs_secret : Bytes,
) -> Bool raise {
  let (frames, pn) = match recv_long(packet, client_hs_keys) {
    Some(v) => v
    None => raise @packet.Malformed("Handshake packet failed to authenticate")
  }
  self.on_handshake_frames(frames, pn, client_hs_secret)
}

///|
/// Drive the client's Handshake-space `frames`, numbered `pn`, already unprotected: record
/// the packet, reassemble its CRYPTO stream, verify any Finished in it against
/// `client_hs_secret` over the transcript as it stands, then fold the messages in. Returns
/// whether the handshake is now connected with a Finished that authenticated — the frame-level
/// half of `receive_handshake`, for a driver holding the decrypted packet.
pub fn Server::on_handshake_frames(
  self : Server,
  frames : Array[@frame.Frame],
  pn : Int64,
  client_hs_secret : Bytes,
) -> Bool raise {
  self.conn.on_packet_received(
    Level::Handshake,
    pn,
    @packet.payload_elicits_ack(frames),
  )
  let mut finished_ok = false
  for frame in frames {
    match frame {
      Crypto(offset~, data~) => {
        let contiguous = self.conn.on_crypto_frame(
          Level::Handshake,
          offset,
          data,
        )
        if contiguous.length() > 0 {
          // The Finished MACs the transcript as it stands now (through the server Finished),
          // so verify against the current hash before folding the client Finished in.
          let th = self.handshake.transcript()
          let view = contiguous[:]
          let mut off = 0
          for ;; {
            match @msg.unframe(view[off:]) {
              Some((t, body)) => {
                if t == @msg.Kind::Finished {
                  finished_ok = @keys.finished_ok(
                    client_hs_secret[:],
                    th[:],
                    body[:],
                  )
                }
                off = off + 4 + body.length()
              }
              None => break
            }
          }
          let _ = self.handshake.feed(contiguous)
        }
      }
      _ => ()
    }
  }
  self.handshake.is_connected() && finished_ok
}

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
pub let min_datagram : Int = 1200

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
  version : UInt
  idle_timeout : Int64
  close_period : Int64
  max_datagram : Int64
  max_ack_delay : Int64
  granularity : Int64
  initial_max_data : UInt64
  initial_max_stream_data : UInt64
  max_frame : UInt64
}

///|
/// QUIC version 1, a 30-second idle timeout, a 3-second closing period, 1200-byte datagrams,
/// a 25-millisecond ACK delay, and a mebibyte of flow-control credit on the connection and on
/// each stream.
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
fn pad(payload : Bytes, build : (Bytes) -> Bytes, min : Int) -> Bytes {
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
  mut packets : Int
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
) -> Session[A] {
  {
    peer,
    cid,
    peer_cid,
    core: Server::new(cid),
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
pub fn[A] Session::packets_received(self : Session[A]) -> Int {
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
pub fn[A] Session::pending(self : Session[A]) -> Int {
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
pub fn[A] Session::can_send(self : Session[A], n : Int) -> Bool {
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
  self.hs_rx = Some(@crypto.Keys::of(client_secret[:]))
  self.hs_rx_secret = client_secret
  self.hs_tx = Some(@crypto.Keys::of(server_secret[:]))
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
  self.app_rx = Some(@crypto.Keys::of(client_secret[:]))
  self.app_tx = Some(@crypto.Keys::of(server_secret[:]))
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
  let keys = match level {
    Initial => Some(self.core.initial_keys)
    Handshake => self.hs_tx
    Application => self.app_tx
  }
  guard keys is Some(k) else { return }
  let payload = @packet.payload(frames)
  let datagram = match level {
    Initial => {
      let build = p => {
        seal_long(
          Initial,
          self.cfg.version,
          self.peer_cid,
          self.cid,
          pn,
          4,
          p,
          k,
        )
      }
      if @packet.payload_elicits_ack(frames) {
        pad(payload, build, min_datagram)
      } else {
        build(payload)
      }
    }
    Handshake =>
      send_long(
        Handshake,
        self.cfg.version,
        self.peer_cid,
        self.cid,
        pn,
        4,
        frames,
        k,
      )
    Application => send_short(self.peer_cid, pn, 4, frames, k)
  }
  self.out.push(datagram)
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
) -> Unit {
  guard self.phase == Active else { return }
  // frame_type 0 names no triggering frame, which is what a close not provoked by one says.
  let frame = @frame.ConnectionClose(error_code~, frame_type=Some(0UL), reason~)
  self.phase = Closing
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
  guard self.phase != Draining else { return }
  match @packet.read_long(datagram[:]) {
    Some((h, _)) =>
      match h.packet_type {
        @packet.Kind::Initial => self.on_initial(datagram, now)
        @packet.Kind::Handshake => self.on_handshake(datagram, now)
        // 0-RTT and Retry are not served.
        _ => ()
      }
    None => self.on_app(datagram, now)
  }
}

///|
fn[A] Session::on_initial(
  self : Session[A],
  datagram : Bytes,
  now : Int64,
) -> Unit raise {
  let opened = recv_long(datagram, self.core.initial_keys) catch { _ => None }
  // A datagram that does not authenticate is discarded, not an error: an endpoint cannot
  // tell a corrupted packet from an injected one (RFC 9000 §12.2).
  guard opened is Some((frames, pn)) else { return }
  let _ = self.core.on_frames(Level::Initial, frames, pn)
  self.adopt_peer_params()
  self.on_frames(Level::Initial, frames, now)
}

///|
fn[A] Session::on_handshake(
  self : Session[A],
  datagram : Bytes,
  now : Int64,
) -> Unit raise {
  guard self.hs_rx is Some(keys) else { return }
  let opened = recv_long(datagram, keys) catch { _ => None }
  guard opened is Some((frames, pn)) else { return }
  // A Handshake packet the peer could only have sent from the address it claims proves that
  // address, which lifts the amplification limit (RFC 9000 §8.1).
  self.validated = true
  let _ = self.core.on_handshake_frames(frames, pn, self.hs_rx_secret)
  self.on_frames(Level::Handshake, frames, now)
}

///|
fn[A] Session::on_app(
  self : Session[A],
  datagram : Bytes,
  now : Int64,
) -> Unit raise {
  guard self.app_rx is Some(keys) else { return }
  let opened = recv_short(datagram, self.cid.length(), keys) catch { _ => None }
  guard opened is Some((frames, pn)) else { return }
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
  for frame in frames {
    self.received.push((level, frame))
    match frame {
      Ack(largest~, ..) | AckEcn(largest~, ..) => {
        self.core.conn.on_ack_received(level, largest.reinterpret_as_int64())
        if level == Level::Application {
          self.sender.on_ack(frame, now)
        }
      }
      ConnectionClose(..) => {
        self.phase = Draining
        self.close_at = now + self.cfg.close_period
        self.out.clear()
        return
      }
      MaxData(v) => self.sender.on_max_data(v)
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
  if self.core.conn.space(level).ack_pending() {
    match self.core.conn.build_ack(level, 0UL) {
      Some(ack) => self.send(level, [ack])
      None => ()
    }
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
/// A QUIC server: the connections it is holding, keyed by the connection id peers address
/// each by, and the settings a new one starts from. `A` is the peer-address type — a socket
/// address under the native event loop, whatever a test finds convenient under a fake sink.
pub struct Endpoint[A] {
  conns : Map[Bytes, Session[A]]
  cfg : Config
}

///|
/// A server holding no connections, handing `cfg` to each one it opens.
pub fn[A] Endpoint::new(cfg : Config) -> Endpoint[A] {
  { conns: Map([]), cfg, }
}

///|
/// How many connections the server is holding.
pub fn[A] Endpoint::count(self : Endpoint[A]) -> Int {
  self.conns.length()
}

///|
/// The connection ids the server is holding.
pub fn[A] Endpoint::conn_ids(self : Endpoint[A]) -> Array[Bytes] {
  self.conns.keys().collect()
}

///|
/// The connection `cid` addresses, or `None` if the server is not holding one.
pub fn[A] Endpoint::conn(self : Endpoint[A], cid : Bytes) -> Session[A]? {
  self.conns.get(cid)
}

///|
/// Take a datagram received at `now` from `from`: route it to the connection its Destination
/// Connection ID names, opening one when an Initial packet arrives for an id the server does
/// not hold, and drive that connection with it (RFC 9000 §5.2). A datagram naming no
/// connection is dropped — RFC 9000 §10.3's stateless reset is not implemented.
pub fn[A] Endpoint::recv(
  self : Endpoint[A],
  datagram : Bytes,
  from : A,
  now : Int64,
) -> Unit raise {
  guard datagram.length() > 0 else { return }
  match @packet.read_long(datagram[:]) {
    Some((h, _)) => {
      let conn = match self.conns.get(h.dcid) {
        Some(c) => c
        None => {
          guard h.packet_type is @packet.Kind::Initial else { return }
          let c = Session::new(from, h.dcid, h.scid, self.cfg, now)
          self.conns[h.dcid] = c
          c
        }
      }
      conn.on_datagram(datagram, now)
    }
    None => {
      guard self.lookup_short(datagram) is Some(conn) else { return }
      conn.on_datagram(datagram, now)
    }
  }
}

///|
/// The connection a short-header datagram belongs to. A short header carries no connection-id
/// length (RFC 9000 §17.3), so the only way back to the connection is to test the datagram
/// against the ids this server has issued.
fn[A] Endpoint::lookup_short(
  self : Endpoint[A],
  datagram : Bytes,
) -> Session[A]? {
  for cid in self.conns.keys().collect() {
    let n = cid.length()
    if datagram.length() >= 1 + n && datagram[1:1 + n].to_owned() == cid {
      return self.conns.get(cid)
    }
  }
  None
}

///|
/// The next datagram to put on the wire and the peer to send it to, or `None` when no
/// connection has one ready.
pub fn[A] Endpoint::poll_out(
  self : Endpoint[A],
  now : Int64,
) -> (Bytes, A)? raise {
  for cid in self.conns.keys().collect() {
    guard self.conns.get(cid) is Some(conn) else { continue }
    match conn.next_datagram(now) {
      Some(datagram) => return Some((datagram, conn.peer))
      None => ()
    }
  }
  None
}

///|
/// Close the connection `cid` addresses with `error_code` and `reason`, if the server holds
/// one (RFC 9000 §10.2).
pub fn[A] Endpoint::close(
  self : Endpoint[A],
  cid : Bytes,
  error_code : UInt64,
  reason : Bytes,
  now : Int64,
) -> Unit {
  match self.conns.get(cid) {
    Some(conn) => conn.close(error_code, reason, now)
    None => ()
  }
}

///|
/// Run the timers at `now`. An idle connection is forgotten without a CONNECTION_CLOSE, which
/// is what RFC 9000 §10.1 asks for; a closing or draining one is forgotten when its period
/// ends (§10.2); an active one whose probe timeout has come re-queues its oldest outstanding
/// packet, to go out on the next `poll_out` (RFC 9002 §6.2.4).
pub fn[A] Endpoint::tick(self : Endpoint[A], now : Int64) -> Unit {
  let expired : Array[Bytes] = []
  for cid in self.conns.keys().collect() {
    guard self.conns.get(cid) is Some(conn) else { continue }
    match conn.phase {
      Active =>
        if conn.idle_timeout > 0L && now - conn.last_rx >= conn.idle_timeout {
          expired.push(cid)
        } else {
          let _ = conn.sender.on_pto_timeout(now)
        }
      Closing | Draining => if now >= conn.close_at { expired.push(cid) }
    }
  }
  for cid in expired {
    self.conns.remove(cid)
  }
}

///|
pub extend Phase with Debug::{to_repr}

///|
pub extend Phase with Eq::{not_equal, equal}

///|
/// A protected long-header packet carrying `frames` at this level.
fn send_long(
  kind : @packet.Kind,
  version : UInt,
  dcid : Bytes,
  scid : Bytes,
  number : Int64,
  size : Int,
  frames : Array[@frame.Frame],
  keys : @crypto.Keys,
  token? : Bytes = b"",
) -> Bytes {
  seal_long(
    kind,
    version,
    dcid,
    scid,
    number,
    size,
    @packet.payload(frames),
    keys,
    token~,
  )
}

///|
/// The same from a payload already encoded, which is what padding an Initial to the
/// minimum datagram needs (RFC 9000 §14.1).
fn seal_long(
  kind : @packet.Kind,
  version : UInt,
  dcid : Bytes,
  scid : Bytes,
  number : Int64,
  size : Int,
  payload : Bytes,
  keys : @crypto.Keys,
  token? : Bytes = b"",
) -> Bytes {
  let pn = @packet.number(number, None, size~)
  let h : @packet.Long = {
    packet_type: kind,
    type_specific: 0,
    version,
    dcid,
    scid,
  }
  keys.seal(
    h.header(pn[:], payload=payload.length() + 16, token~)[:],
    payload[:],
    number~,
  )
}

///|
/// A protected 1-RTT packet carrying `frames`.
fn send_short(
  dcid : Bytes,
  number : Int64,
  size : Int,
  frames : Array[@frame.Frame],
  keys : @crypto.Keys,
  spin? : Bool = false,
  key_phase? : Bool = false,
) -> Bytes {
  let payload = @packet.payload(frames)
  let pn = @packet.number(number, None, size~)
  let h : @packet.Short = { spin, key_phase, pn_length: size, dcid, }
  keys.seal(h.header(pn[:])[:], payload[:], number~)
}

///|
/// The frames a protected long-header packet carries, and its packet number. `None` when
/// the tag does not match, which is a packet to drop rather than an error to report.
fn recv_long(
  packet : Bytes,
  keys : @crypto.Keys,
) -> (Array[@frame.Frame], Int64)? raise @packet.Refused {
  match keys.open(packet[:], largest=-1L) {
    Some((payload, pn)) => Some((@packet.read_payload(payload), pn))
    None => None
  }
}

///|
/// The same for a 1-RTT packet, whose connection-id length only the receiver knows.
fn recv_short(
  packet : Bytes,
  dcid_len : Int,
  keys : @crypto.Keys,
) -> (Array[@frame.Frame], Int64)? raise @packet.Refused {
  match keys.open(packet[:], largest=-1L, at=1 + dcid_len) {
    Some((payload, pn)) => Some((@packet.read_payload(payload), pn))
    None => None
  }
}

///|
/// A CertificateVerify body signed over the transcript as RFC 8446 §4.4.3 frames it.
///
/// This is the seam that keeps a signing key out of this library: a flight takes a
/// function from the transcript hash to a CertificateVerify body, and whoever holds the
/// key builds one with this.
pub fn signed(
  signer : &@spec.Signer,
  scheme? : Int = @ext.ecdsa_secp256r1_sha256,
) -> (Bytes) -> Bytes {
  th => {
    @msg.certificate_verify(
      signer.sign(@msg.signed(@msg.server_context, th[:])[:]),
      scheme,
    )
  }
}

///|
/// Two byte strings joined.
fn join(a : Bytes, b : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(a)
  buf.write_bytes(b)
  buf.to_bytes()
}
