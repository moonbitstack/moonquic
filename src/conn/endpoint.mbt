// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A QUIC server: the connections it is holding, keyed by the connection id peers address
/// each by, and the settings a new one starts from. `A` is the peer-address type — a socket
/// address under the native event loop, whatever a test finds convenient under a fake sink.
pub struct Endpoint[A] {
  conns : Map[Bytes, Session[A]]
  cfg : Config
  priv tls : @tls.Server?
  priv rand : (Int32) -> Bytes
  priv issue : () -> Bytes
  priv aliases : Map[Bytes, Bytes]
  priv stateless : Array[(Bytes, A)]
  priv busy : Array[Session[A]]
  priv reset_key : Bytes
}

///|
/// How long a connection id this server issues is. A fixed length is what lets a short header,
/// which does not say how long its id is, be read at all (RFC 9000 §5.2).
pub let cid_size : Int32 = 8

///|
/// A server holding no connections, handing `cfg` to each one it opens.
pub fn[A] Endpoint::new(cfg : Config) -> Endpoint[A] {
  {
    conns: Map([]),
    cfg,
    tls: None,
    rand: n => Bytes::make(n, 0),
    issue: () => Bytes::make(cid_size, 0),
    aliases: Map([]),
    stateless: [],
    busy: [],
    reset_key: Bytes::make(32, 0),
  }
}

///|
/// A server that runs the TLS handshake itself: `tls` holds its certificate chain, key and ALPN
/// protocols, and `rand` is the source of its handshake randomness.
///
/// `cid` makes the connection ids this server issues, `cid_size` bytes each; by default they are
/// drawn from `rand`. A server behind something that routes datagrams by connection id (several
/// processes on one port, or a load balancer in the manner of QUIC-LB) puts its own number in
/// them here. An id that is not `cid_size` bytes, or that is already in use, is drawn again.
pub fn[A] Endpoint::server(
  cfg : Config,
  tls : @tls.Server,
  rand~ : (Int32) -> Bytes,
  cid? : () -> Bytes,
) -> Endpoint[A] {
  {
    conns: Map([]),
    cfg,
    tls: Some(tls),
    rand,
    issue: match cid {
      Some(f) => f
      None => () => rand(cid_size)
    },
    aliases: Map([]),
    stateless: [],
    busy: [],
    reset_key: rand(32),
  }
}

///|
/// The connection a long header's Destination Connection ID names: the id this server issued, or,
/// until the client has heard it, the id the client made up.
fn[A] Endpoint::find(self : Endpoint[A], cid : Bytes) -> Session[A]? {
  match self.conns.get(cid) {
    Some(c) => Some(c)
    None =>
      match self.aliases.get(cid) {
        Some(own) => self.conns.get(own)
        None => None
      }
  }
}

///|
/// A new connection for a client's first Initial.
fn[A] Endpoint::open(
  self : Endpoint[A],
  h : @packet.Long,
  from : A,
  size : Int32,
  now : Int64,
  wall : Int64?,
) -> Session[A]? {
  match self.tls {
    None => {
      let c = Session::new(from, h.dcid, h.scid, self.cfg, now)
      self.conns[h.dcid] = c
      Some(c)
    }
    Some(config) => {
      // RFC 9000 §14.1: a client's first datagram is at least this big, which is what keeps a
      // spoofed Initial from buying more than it costs.
      guard size >= min_datagram else { return None }
      let cid = self.fresh_cid()
      let tls = @tls.Conn::quic_server(
        config,
        params=declared(self.cfg, h.dcid, cid, reset_token(self.reset_key, cid)),
        rand=self.rand,
        now?=wall,
      )
      let c = Session::new(
        from,
        cid,
        h.scid,
        self.cfg,
        now,
        original=h.dcid,
        tls~,
      )
      self.conns[cid] = c
      self.aliases[h.dcid] = cid
      Some(c)
    }
  }
}

///|
/// An id for a new connection: the size a short header is read with, and not one already held.
fn[A] Endpoint::fresh_cid(self : Endpoint[A]) -> Bytes {
  for _ in 0..<16 {
    let cid = (self.issue)()
    if cid.length() == cid_size &&
      !self.conns.contains(cid) &&
      !self.aliases.contains(cid) {
      return cid
    }
  }
  abort("the connection id source keeps giving ids that cannot be used")
}

///|
/// How many connections the server is holding.
pub fn[A] Endpoint::count(self : Endpoint[A]) -> Int32 {
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
///
/// `now` is the timers' clock, in microseconds. `wall` is the time in seconds since the Unix epoch
/// that tickets and client certificates are judged at, a different clock: left out, this endpoint
/// neither issues nor takes a ticket.
pub fn[A : Eq] Endpoint::recv(
  self : Endpoint[A],
  datagram : Bytes,
  from : A,
  now : Int64,
  wall? : Int64,
) -> Unit raise {
  guard datagram.length() > 0 else { return }
  let conn = match @packet.read_long(datagram[:]) {
    Some((h, _)) => {
      if h.version != self.cfg.version {
        return self.negotiate(h, from, datagram.length())
      }
      match self.find(h.dcid) {
        Some(c) => c
        None => {
          guard h.packet_type is @packet.Kind::Initial else { return }
          guard self.open(h, from, datagram.length(), now, wall) is Some(c) else {
            return
          }
          c
        }
      }
    }
    None =>
      match self.lookup_short(datagram) {
        Some(c) => c
        // A short header naming no connection is answered with a stateless reset, so the
        // peer learns the connection is gone rather than waiting out its idle timer.
        None => return self.reset_unknown(datagram, from)
      }
  }
  conn.on_datagram(datagram, from, (self.rand)(8), now)
  self.supply_ids(conn)
  self.note(conn)
}

///|
/// Keep a connection's peer in spare ids, and forget the ones it retired (RFC 9000 §5.1.1). An id
/// is the endpoint's to make, since it has to be unique across every connection here.
fn[A] Endpoint::supply_ids(self : Endpoint[A], conn : Session[A]) -> Unit {
  guard self.tls is Some(_) else { return }
  for cid in conn.ids.take_retired() {
    self.aliases.remove(cid)
  }
  while conn.owes_id() {
    let cid = self.fresh_cid()
    self.aliases[cid] = conn.cid
    conn.issue_id(cid, reset_token(self.reset_key, cid))
  }
}

///|
/// Answer a short-header datagram that names no connection with a stateless reset (RFC 9000
/// §10.3): a packet whose last sixteen bytes are the token this endpoint would have given for
/// that connection id. A datagram too short to be one, or one that does not look like a short
/// header, is dropped.
fn[A] Endpoint::reset_unknown(
  self : Endpoint[A],
  datagram : Bytes,
  from : A,
) -> Unit {
  guard datagram.length() >= 21 && self.reset_key.length() >= 16 else { return }
  guard (datagram[0].to_int() & 0x80) == 0 else { return }
  guard datagram.length() >= 1 + cid_size else { return }
  let cid = datagram[1:1 + cid_size].to_owned()
  let token = reset_token(self.reset_key, cid)
  self.stateless.push((stateless_reset(token, self.rand), from))
}

///|
/// Offer the versions this server speaks to a client that asked for another (RFC 9000 §6.1). The
/// packet is answered only when as big as a client's first, so it amplifies nothing.
fn[A] Endpoint::negotiate(
  self : Endpoint[A],
  h : @packet.Long,
  from : A,
  size : Int32,
) -> Unit {
  guard size >= min_datagram && h.version != 0U else { return }
  self.stateless.push(
    (@packet.versions(dcid=h.scid, scid=h.dcid, [self.cfg.version][:]), from),
  )
}

///|
fn[A] Endpoint::note(self : Endpoint[A], conn : Session[A]) -> Unit {
  if conn.events.length() > 0 &&
    !self.busy.iter().any(c => physical_equal(c, conn)) {
    self.busy.push(conn)
  }
}

///|
/// The connections with something to tell their application, each once, emptied by the call.
pub fn[A] Endpoint::take_busy(self : Endpoint[A]) -> Array[Session[A]] {
  let out = self.busy.copy()
  self.busy.clear()
  out
}

///|
/// The connection a short-header datagram belongs to. A short header carries no connection-id
/// length (RFC 9000 §17.3), so the only way back to the connection is to test the datagram
/// against the ids this server has issued.
fn[A] Endpoint::lookup_short(
  self : Endpoint[A],
  datagram : Bytes,
) -> Session[A]? {
  if self.tls is Some(_) {
    guard datagram.length() >= 1 + cid_size else { return None }
    return self.find(datagram[1:1 + cid_size].to_owned())
  }
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
  if self.stateless.length() > 0 {
    return Some(self.stateless.remove(0))
  }
  for cid in self.conns.keys().collect() {
    guard self.conns.get(cid) is Some(conn) else { continue }
    if conn.probes.length() > 0 {
      return Some(conn.probes.remove(0))
    }
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
    Some(conn) => {
      conn.close(error_code, reason, now)
      self.note(conn)
    }
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
          conn.events.push(Closed(0UL))
          self.note(conn)
          expired.push(cid)
        } else {
          let _ = conn.sender.on_pto_timeout(now)
          conn.tick_path(now)
          let pto = conn.sender.recovery.pto()
          conn.initial_out.tick(now, pto)
          conn.handshake_out.tick(now, pto)
        }
      Closing | Draining => if now >= conn.close_at { expired.push(cid) }
    }
  }
  for cid in expired {
    self.conns.remove(cid)
  }
  if expired.length() > 0 {
    let dead = self.aliases
      .iter()
      .filter(a => !self.conns.contains(a.1))
      .map(a => a.0)
      .collect()
    for id in dead {
      self.aliases.remove(id)
    }
  }
}
