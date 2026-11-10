// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A multipath connection: the handshake's path, then a second one opened from a second socket
// (draft-ietf-quic-multipath §3.1). The peer offers a connection id for the new path on its own
// initiative; the path is challenged and validated on itself, and then carries its own traffic,
// numbered, acknowledged and recovered in its own packet-number space.

///|
async fn multipath(
  socket : @udp.Socket,
  to : @socket.Addr,
  host : String,
  options : Map[String, String],
  payload : String,
) -> Unit {
  let scid = entropy(8)
  let client = @conn.Client::new(
    tls_client(options),
    host,
    params(scid, paths=1UL),
    entropy,
    entropy(8),
    scid,
    wall(),
  ) catch {
    e => return fail("the client did not start: \{e}")
  }
  let link = Link::new(socket, to, client)
  link.handshake()
  println("peer_max_path \{(client.paths().peer_max()).to_string()}")
  // A request on the handshake's path: the answer proves path 0 carries application data, and the
  // peer's reply is what brings its connection ids for the further path.
  let request = @utf8.encode(payload)
  client.write(0UL, request, fin=true)
  let first = exchange(link, 0UL, 300)
  println("path0_stream_bytes \{(first.length()).to_string()}")
  println("path0_answer \{@utf8.decode(first)}")
  let mut idle = 0
  while idle < 200 && client.paths().peer_cid(1UL).length() == 0 {
    if link.turn() {
      idle = 0
    } else {
      idle += 1
    }
    ignore(client.read(0UL))
  }
  let peer_cid = client.paths().peer_cid(1UL)
  if peer_cid.length() == 0 {
    return fail("the peer offered no connection id for a second path")
  }
  println("path1_cid \{hex(peer_cid)}")
  // The second path's own socket. The address opposite it does not change; the port it leaves
  // from does, which is what makes it a path and not the same path twice.
  let second = @udp.bind(host="127.0.0.1", port=0)
  link.wires[1UL] = (second, to)
  let nonce = entropy(8)
  guard client.add_path(
    1UL,
    peer_cid,
    entropy(8),
    now(),
    nonce~,
    token=entropy(16),
  ) else {
    return fail("the connection would not open a second path")
  }
  // The challenge goes out on path 1; the answer comes back on path 1, and only then is the path
  // this end's to send on.
  let mut idle = 0
  while idle < 300 && !client.paths().validated(1UL) {
    if link.turn() || link.turn_on(1UL) {
      idle = 0
    } else {
      idle += 1
    }
  }
  println("path1_validated \{(client.paths().validated(1UL)).to_string()}")
  // Application data on the new path: a stream of its own, written as one frame so that it leaves
  // where the caller says rather than where the connection's own send loop would put it.
  ignore(client.open_stream(4UL))
  ignore(
    client.send_on(
      1UL,
      [@frame.Stream(id=4UL, offset=0UL, fin=true, data=request)],
      now(),
    ),
  )
  let on_path_one = exchange_on(link, 4UL, 300)
  println("path1_stream_bytes \{(on_path_one.length()).to_string()}")
  println("path1_answer \{@utf8.decode(on_path_one)}")
  // The last packet on the path needs a turn or two more for the peer's acknowledgement to land.
  let lane = client.path_lane(1UL).unwrap()
  let mut idle = 0
  while idle < 100 && lane.in_flight() > 0 {
    if link.turn() || link.turn_on(1UL) {
      idle = 0
    } else {
      idle += 1
    }
  }
  println("path1_sent \{(link.count_sent(1UL)).to_string()}")
  println("path1_received \{(link.count_received(1UL)).to_string()}")
  println("path0_sent \{(link.count_sent(0UL)).to_string()}")
  println("path0_received \{(link.count_received(0UL)).to_string()}")
  // Nothing of this end's is left on the path: the peer settled it with a PATH_ACK naming path 1,
  // which a plain ACK of the connection's space would not have done.
  println("path1_in_flight \{(lane.in_flight()).to_string()}")
  // A closing handshake, so the peer writes out its own view of the run.
  client.close(0UL, b"bye", now(), application=true)
  link.flush()
  let mut idle = 0
  while idle < 20 {
    if link.turn() {
      idle = 0
    } else {
      idle += 1
    }
  }
  socket.close()
  second.close()
}

///|
/// Read stream `id` until the peer ends it, or the turns run out. A stream this end only wrote on
/// reports itself ended until the peer says something on it, so the answer's first byte is what
/// makes the question worth asking.
async fn exchange(link : Link, id : UInt64, rounds : Int32) -> Bytes {
  let answer = Buffer()
  let mut idle = 0
  while idle < rounds && !(answer.length() > 0 && link.client.finished(id)) {
    if link.turn() {
      idle = 0
    } else {
      idle += 1
    }
    let arrived = link.client.read(id)
    if arrived.length() > 0 {
      answer.write_bytes(arrived)
    }
  }
  answer.to_bytes()
}

///|
/// The same, on a further path: both sockets are polled, because either may carry the answer.
async fn exchange_on(link : Link, id : UInt64, rounds : Int32) -> Bytes {
  let answer = Buffer()
  let mut idle = 0
  while idle < rounds && !(answer.length() > 0 && link.client.finished(id)) {
    if link.turn() || link.turn_on(1UL) {
      idle = 0
    } else {
      idle += 1
    }
    let arrived = link.client.read(id)
    if arrived.length() > 0 {
      answer.write_bytes(arrived)
    }
  }
  answer.to_bytes()
}

///|
fn Link::count_sent(self : Link, path : UInt64) -> Int64 {
  self.sent.get(path).unwrap_or(0L)
}

///|
fn Link::count_received(self : Link, path : UInt64) -> Int64 {
  self.received.get(path).unwrap_or(0L)
}
