// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What turns a connection with a TLS server into a real one (RFC 9001 §4): CRYPTO bytes go to
// `@tls.Conn`, and what it asks for comes back as keys to install and bytes to send. Datagrams are
// built here too, since a handshake needs several encryption levels in one datagram and loses
// nothing to the padding rule that way (RFC 9000 §12.2, §14.1).

///|
/// One level's outgoing CRYPTO stream, and what is in flight on it.
priv struct Outbox {
  mut bytes : Bytes
  mut next : Int32
  lost : Array[(Int32, Int32)]
  flight : Map[Int64, (Int32, Int32)]
  mut deadline : Int64
  mut backoff : Int32
}

///|
fn Outbox::new() -> Outbox {
  { bytes: b"", next: 0, lost: [], flight: Map([]), deadline: 0L, backoff: 0, }
}

///|
fn Outbox::write(self : Outbox, data : Bytes) -> Unit {
  self.bytes = join(self.bytes, data)
}

///|
/// The next run of at most `room` bytes to put in a CRYPTO frame: something lost, else something new.
fn Outbox::take(self : Outbox, room : Int32) -> (Int32, Int32)? {
  guard room > 0 else { return None }
  match self.lost.pop() {
    Some((at, size)) => {
      if size > room {
        self.lost.push((at + room, size - room))
      }
      Some((at, if size > room { room } else { size }))
    }
    None => {
      let left = self.bytes.length() - self.next
      guard left > 0 else { return None }
      let size = if left > room { room } else { left }
      let at = self.next
      self.next = self.next + size
      Some((at, size))
    }
  }
}

///|
/// The ranges a packet at this level acknowledges no longer need resending.
fn Outbox::on_ack(self : Outbox, frame : @frame.Frame) -> Unit raise {
  let acked = frame.acked()
  for pn in self.flight.keys().collect() {
    let number = pn.reinterpret_as_uint64()
    if acked.iter().any(r => number >= r.0 && number <= r.1) {
      self.flight.remove(pn)
    }
  }
  if self.flight.length() == 0 {
    self.backoff = 0
  }
}

///|
/// A probe timeout for this level (RFC 9002 §6.2.4): everything in flight goes out again, and the
/// timer doubles.
fn Outbox::tick(self : Outbox, now : Int64, pto : Int64) -> Unit {
  guard self.flight.length() > 0 && now >= self.deadline else { return }
  for run in self.flight.values() {
    self.lost.push(run)
  }
  self.flight.clear()
  self.backoff = self.backoff + 1
  self.deadline = now + (pto << self.backoff)
}

///|
/// Send the stream from the start again, keeping what was written: what a Retry needs, since the
/// ClientHello has to go out under the new Initial keys at offset zero (RFC 9000 §17.2.5.3).
fn Outbox::rewind(self : Outbox) -> Unit {
  self.next = 0
  self.lost.clear()
  self.flight.clear()
  self.backoff = 0
}

///|
fn Outbox::clear(self : Outbox) -> Unit {
  self.bytes = b""
  self.next = 0
  self.lost.clear()
  self.flight.clear()
}

///|
/// The `@crypto.Suite` a TLS cipher suite names.
fn suite_of(suite : @record.Suite) -> @crypto.Suite {
  match suite {
    Aes128Gcm => @crypto.suite
    Aes256Gcm => @crypto.aes256
    ChaCha20Poly1305 => @crypto.chacha20
  }
}

///|
fn tls_level(level : Level) -> @tls.Level {
  match level {
    Initial => Initial
    Handshake => Handshake
    Application => Application
  }
}

///|
/// The transport parameters this server declares for a connection (RFC 9000 §18.2).
fn declared(
  cfg : Config,
  original : Bytes,
  cid : Bytes,
  token : Bytes,
  retry~ : Bytes?,
) -> Bytes {
  let limits = Limits::new(
    idle_timeout=(cfg.idle_timeout / 1000L).reinterpret_as_uint64(),
    data=cfg.initial_max_data,
    stream_data_bidi_local=cfg.initial_max_stream_data,
    stream_data_bidi_remote=cfg.initial_max_stream_data,
    stream_data_uni=cfg.initial_max_stream_data,
    streams_bidi=cfg.streams_bidi,
    streams_uni=cfg.streams_uni,
    max_ack_delay=(cfg.max_ack_delay / 1000L).reinterpret_as_uint64(),
    datagram_frame=cfg.max_datagram_frame_size,
  )
  let params = limits.params()
  params.push({ kind: OriginalDcid, value: original, })
  params.push({ kind: InitialScid, value: cid, })
  if cfg.max_path_id > 0UL {
    // draft-ietf-quic-multipath §3: offering a second path is this parameter and nothing else.
    params.push(Param::int(InitialMaxPathId, cfg.max_path_id))
  }
  // §7.3: after a Retry the client checks that this is the id the Retry named.
  match retry {
    Some(retry) => params.push({ kind: RetryScid, value: retry, })
    None => ()
  }
  // Without this a reset this endpoint sends means nothing to the peer (RFC 9000 §10.3).
  params.push({ kind: StatelessResetToken, value: token, })
  encode(params[:])
}

///|
/// How much of an application-level CRYPTO run goes in one frame: small enough to share a packet.
let app_crypto_chunk : Int32 = 1000

///|
/// What TLS says after the handshake, which is a server's tickets (RFC 9001 §4.1.3). It goes in
/// 1-RTT packets as control frames, so a lost one is sent again, and not through the handshake's
/// outbox, which is thrown away the moment the handshake is confirmed.
fn[A] Session::send_app_crypto(self : Session[A], data : Bytes) -> Unit {
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
fn[A] Session::outbox(self : Session[A], level : Level) -> Outbox {
  match level {
    Initial => self.initial_out
    _ => self.handshake_out
  }
}

///|
/// Feed a packet's CRYPTO frames to the handshake and do what it asks. An alert closes the
/// connection with the matching CRYPTO_ERROR (RFC 9001 §4.8).
fn[A] Session::on_crypto(
  self : Session[A],
  tls : @tls.Conn,
  level : Level,
  frames : Array[@frame.Frame],
  pn : Int64,
  now : Int64,
) -> Unit {
  self.core.conn.on_packet_received(
    level,
    pn,
    @packet.payload_elicits_ack(frames),
  )
  self.feed_crypto(tls, level, frames, now)
}

///|
/// Give a packet's CRYPTO bytes to the handshake and do what it asks, without touching the
/// packet-number space: the 1-RTT messages a connection reads after the handshake — a key
/// update, a ticket — arrive in packets already accounted for.
fn[A] Session::feed_crypto(
  self : Session[A],
  tls : @tls.Conn,
  level : Level,
  frames : Array[@frame.Frame],
  now : Int64,
) -> Unit {
  for frame in frames {
    guard frame is Crypto(offset~, data~) else { continue }
    let ready = self.core.conn.on_crypto_frame(level, offset, data) catch {
      _ => return self.close(crypto_buffer_exceeded, b"", now)
    }
    guard ready.length() > 0 else { continue }
    tls.crypto(tls_level(level), ready[:]) catch {
      @alert.Alert(kind~, ..) =>
        return self.close(
          crypto_error + kind.code().to_uint64(),
          b"TLS alert",
          now,
        )
    }
  }
  for step in tls.steps() {
    match step {
      Send(Initial, data) => self.initial_out.write(data)
      Send(Handshake, data) => self.handshake_out.write(data)
      Send(Application, data) => self.send_app_crypto(data)
      Keys(Handshake, client~, server~) => {
        if tls.suite() is Some(suite) {
          self.suite = suite_of(suite)
        }
        self.adopt_declared(tls, now)
        self.install_handshake_keys(client, server)
      }
      Keys(Application, client~, server~) =>
        self.install_app_keys(client, server)
      Keys(_, ..) => ()
      Early(secret~, suite~) =>
        self.install_zero_rtt(
          @crypto.zero_rtt(secret[:], suite=suite_of(suite)),
        )
    }
  }
  if tls.is_connected() && !self.confirmed {
    self.confirmed = true
    self.handshake_gone = true
    self.handshake_out.clear()
    self.sender.queue_control(HandshakeDone)
    self.events.push(Connected)
  }
}

///|
/// Take the client's transport parameters from the handshake, holding them to the connection id
/// it actually used (RFC 9000 §7.3).
fn[A] Session::adopt_declared(
  self : Session[A],
  tls : @tls.Conn,
  now : Int64,
) -> Unit {
  guard tls.peer_params() is Some(raw) else { return }
  guard decode_opt(raw[:]) is Some(params) else {
    return self.close(transport_parameter_error, b"", now)
  }
  match params_fault(params[:], server=true) {
    Some(fault) => return self.close(fault.code, fault.reason, now)
    None => ()
  }
  match find(params[:], InitialScid) {
    Some(p) if p.value == self.peer_cid => ()
    _ => return self.close(transport_parameter_error, b"", now)
  }
  self.apply_peer_params(params)
  let peer = Limits::read(params[:])
  self.ids.limit = peer.active_connection_ids
  // The peer's limits name streams by who opened them, so what limits a response on a stream the
  // client opened is the client's bidi_local (RFC 9000 §18.2).
  self.sender.sched.on_params(
    data=peer.data,
    bidi=peer.stream_data_bidi_local,
    uni=peer.stream_data_uni,
  )
  self.sender.ack_exponent = peer.ack_delay_exponent.to_int()
}

///|
/// The bytes a packet at `level` spends on anything but frames, with the Length field and the
/// packet number at the widest this connection writes them.
fn[A] Session::overhead(self : Session[A], level : Level) -> Int32 {
  match level {
    Initial => 31 + self.peer_cid.length() + self.cid.length()
    Handshake => 30 + self.peer_cid.length() + self.cid.length()
    Application => 21 + self.peer_cid.length()
  }
}

///|
/// Build a datagram for a connection with a TLS server: the handshake levels' ACKs and CRYPTO in
/// one coalesced datagram, or a 1-RTT packet alone (RFC 9000 §12.2).
fn[A] Session::assemble(self : Session[A], now : Int64) -> Unit raise {
  let limit = self.cfg.max_datagram.to_int()
  let planned : Array[(Level, Bytes, Int64)] = []
  let mut used = 0
  let mut floor = false
  for level in [Level::Initial, Level::Handshake] {
    if (level == Level::Initial && self.initial_gone) ||
      (level == Level::Handshake && (self.handshake_gone || self.hs_tx is None)) {
      continue
    }
    let frames : Array[@frame.Frame] = []
    let cost = self.overhead(level)
    let mut room = limit - used - cost
    let space = self.core.conn.space(level)
    if space.ack_pending() && space.build_ack(0UL) is Some(ack) {
      frames.push(ack)
      room = room - @frame.encode(ack).length()
    }
    let outbox = self.outbox(level)
    // One byte of type, four of offset, two of length.
    let run = outbox.take(room - 7)
    if run is Some((at, size)) {
      let data = outbox.bytes[at:at + size].to_owned()
      frames.push(Crypto(offset=at.to_uint64(), data~))
    }
    guard frames.length() > 0 else { continue }
    let pn = self.core.conn.next_packet_number(level)
    if run is Some(sent) {
      outbox.flight[pn] = sent
      outbox.deadline = now + (self.sender.recovery.pto() << outbox.backoff)
    }
    let payload = @packet.payload(frames)
    // An Initial datagram is padded to the 1200-byte floor even when it carries only an
    // ACK: RFC 9000 §14.1 requires it of ack-eliciting ones and permits it of the rest, and
    // a peer that cannot yet answer a split hello still expects a full-size first datagram.
    floor = floor || level == Level::Initial
    used = used + payload.length() + cost
    planned.push((level, payload, pn))
    // One encryption level per datagram. A Handshake packet cannot be read until the
    // ServerHello is whole, and the keys come from it; coalescing the two lets a large
    // post-quantum ServerHello hand the peer a packet it has no keys for.
    break
  }
  guard planned.length() > 0 else { return self.next_app_packet(now) }
  let datagram = Buffer()
  for i, packet in planned {
    let (level, payload, pn) = packet
    let build = (body : Bytes) => self.seal(level, body, pn)
    if i == planned.length() - 1 && floor {
      datagram.write_bytes(
        pad(payload, build, min_datagram - datagram.length()),
      )
    } else {
      datagram.write_bytes(build(payload))
    }
  }
  self.out.push(datagram.to_bytes())
}

///|
/// A 1-RTT packet: whatever the send loop has ready, with the ACK owed.
fn[A] Session::next_app_packet(self : Session[A], now : Int64) -> Unit raise {
  guard self.app_tx is Some(_) else { return }
  let space = self.core.conn.space(Level::Application)
  let ack = if space.ack_pending() { space.build_ack(0UL) } else { None }
  match self.sender.poll_send(now) {
    Some((pn, frames)) => {
      space.advance_past(pn)
      match ack {
        Some(a) if @frame.encode(a).length() <= control_room =>
          self.emit(Level::Application, [a, ..frames], pn)
        Some(a) => {
          self.emit(Level::Application, frames, pn)
          self.send(Level::Application, [a])
        }
        None => self.emit(Level::Application, frames, pn)
      }
    }
    None => if ack is Some(a) { self.send(Level::Application, [a]) }
  }
}

///|
/// One direction's next key phase (RFC 9001 §6.1): the secret after this one and its keys. The
/// header-protection key is the one thing that does not change.
fn roll(
  secret : Bytes,
  keys : @crypto.Keys,
  suite : @crypto.Suite,
) -> (Bytes, @crypto.Keys) {
  let (next, rolled) = @crypto.next(secret[:], suite~)
  (next, { ..rolled, hp: keys.hp, })
}

///|
/// A short-header packet's frames. One that does not open under the current keys may be the first
/// under the next phase (RFC 9001 §6): only a real packet opens under those, so one that does
/// settles it, and the keys in both directions move on. The header-protection key stays.
fn[A] Session::open_app(
  self : Session[A],
  packet : Bytes,
  keys : @crypto.Keys,
  largest : Int64,
) -> (Array[@frame.Frame], Int64)? raise @packet.Refused {
  let n = self.cid.length()
  let opened = recv_short(packet, n, keys, largest~)
  guard opened is None && self.app_rx_secret.length() > 0 else { return opened }
  let (rx_secret, next) = roll(self.app_rx_secret, keys, self.suite)
  let moved = recv_short(packet, n, next, largest~)
  guard moved is Some(_) && self.app_tx is Some(tx) else { return None }
  let (tx_secret, written) = roll(self.app_tx_secret, tx, self.suite)
  self.app_rx = Some(next)
  self.app_rx_secret = rx_secret
  self.app_tx = Some(written)
  self.app_tx_secret = tx_secret
  self.key_phase = !self.key_phase
  moved
}
