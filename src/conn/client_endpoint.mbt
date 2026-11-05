// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Many client connections on one socket (RFC 9000 §5.2): a datagram names the connection it
// belongs to in its Destination Connection ID, and that is the whole of the routing. A short
// header names this endpoint — the id the client called itself — and a long one names the
// server, which is either the id the client invented before the server answered or the one the
// server chose. Both are held in one table, so a datagram costs a lookup rather than a search
// through every connection.

///|
/// A set of client connections sharing an id space. It holds no socket: `recv` takes what a
/// socket read, `poll_out` gives back what to write, and `tick` runs every connection's timers.
pub struct ClientEndpoint {
  conns : Map[Bytes, Client]
  /// Every id that names a connection as a key of `conns`: the client's own, and the server's
  /// for each connection both before and after the handshake names it.
  ids : Map[Bytes, Bytes]
  cfg : Config
  rand : (Int32) -> Bytes
}

///|
/// An endpoint that holds no connections yet. `rand` is where a connection's own id comes from
/// when the caller does not pick one.
pub fn ClientEndpoint::new(
  cfg : Config,
  rand~ : (Int32) -> Bytes,
) -> ClientEndpoint {
  { conns: Map([]), ids: Map([]), cfg, rand, }
}

///|
/// Start a connection to `server_name`, answering the id this endpoint knows it by. `scid` is
/// the id this client calls itself; left out, it is drawn from `rand`. `dcid` is what the first
/// Initial is addressed to; left out, it is drawn too, since nothing has named it yet.
pub fn ClientEndpoint::connect(
  self : ClientEndpoint,
  config : @tls.Client,
  server_name : String,
  params : Bytes,
  wall : Int64,
  dcid? : Bytes,
  scid? : Bytes,
  cfg? : Config,
) -> Bytes raise {
  let own = match scid {
    Some(id) => id
    None => {
      let mut id = (self.rand)(cid_size)
      while self.conns.contains(id) || self.ids.contains(id) {
        id = (self.rand)(cid_size)
      }
      id
    }
  }
  let target = match dcid {
    Some(id) => id
    None => (self.rand)(cid_size)
  }
  // The transport parameters have to name the id this client just took, or the server cannot
  // hold the handshake to it (RFC 9000 §7.3). The block is read back and the parameter added
  // when the caller did not write it, so a caller need not know the id in advance.
  let block = decode(params[:])
  if find(block[:], InitialScid) is None {
    block.push({ kind: InitialScid, value: own, })
  }
  let client = Client::new(
    config,
    server_name,
    encode(block[:]),
    self.rand,
    target,
    own,
    wall,
    cfg=match cfg {
      Some(cfg) => cfg
      None => self.cfg
    },
  )
  self.conns[own] = client
  self.resync()
  own
}

///|
/// Put every id that names a connection into the table: the client's own, and the server's both
/// before the handshake (the id the client invented) and after (the one the server chose).
fn ClientEndpoint::resync(self : ClientEndpoint) -> Unit {
  self.ids.clear()
  for entry in self.conns {
    let (own, client) = entry
    self.ids[own] = own
    self.ids[client.original_dcid] = own
    if client.seen_server_cid {
      self.ids[client.dcid] = own
    }
  }
}

///|
/// The connection a received datagram belongs to, if any.
fn ClientEndpoint::route(self : ClientEndpoint, datagram : Bytes) -> Client? {
  guard datagram.length() > 0 else { return None }
  if (datagram[0].to_int() & 0x80) == 0 {
    guard datagram.length() >= 1 + cid_size else { return None }
    let id = datagram[1:1 + cid_size].to_owned()
    return match self.ids.get(id) {
      Some(own) => self.conns.get(own)
      None => None
    }
  }
  guard @packet.read_long(datagram[:]) is Some((h, _)) else { return None }
  match self.ids.get(h.dcid) {
    Some(own) => self.conns.get(own)
    None => None
  }
}

///|
/// Take a datagram from any of this endpoint's servers and hand it to the connection its
/// Destination Connection ID names. One that names nothing here is dropped: another endpoint's
/// traffic is not this one's to answer.
pub fn ClientEndpoint::recv(
  self : ClientEndpoint,
  datagram : Bytes,
  now : Int64,
) -> Unit raise {
  match self.route(datagram) {
    Some(client) => {
      client.recv(datagram, now)
      self.resync()
    }
    None => ()
  }
}

///|
/// Every datagram every connection has ready, in connection order. A caller loops until it is
/// empty, sending each to the address it connected to.
pub fn ClientEndpoint::poll_out(
  self : ClientEndpoint,
  now : Int64,
) -> Array[Bytes] {
  let out : Array[Bytes] = []
  for entry in self.conns {
    let (_, client) = entry
    for datagram in client.poll_out(now) {
      out.push(datagram)
    }
  }
  self.resync()
  out
}

///|
/// Run every connection's timers.
pub fn ClientEndpoint::tick(self : ClientEndpoint, now : Int64) -> Unit {
  for entry in self.conns {
    let (_, client) = entry
    client.tick(now)
  }
}

///|
/// A connection by the id `connect` answered.
pub fn ClientEndpoint::client(self : ClientEndpoint, id : Bytes) -> Client? {
  self.conns.get(id)
}

///|
/// The ids of the connections this endpoint holds.
pub fn ClientEndpoint::ids(self : ClientEndpoint) -> Array[Bytes] {
  self.conns.keys().collect()
}

///|
/// How many connections this endpoint holds.
pub fn ClientEndpoint::count(self : ClientEndpoint) -> Int32 {
  self.conns.length()
}

///|
/// Forget a connection, as after it has closed and drained.
pub fn ClientEndpoint::remove(self : ClientEndpoint, id : Bytes) -> Unit {
  self.conns.remove(id)
  self.resync()
}
