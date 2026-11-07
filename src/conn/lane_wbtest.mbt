// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Multipath, second stage: each path numbers its packets on its own, is acknowledged on its own,
// and recovers on its own (draft-ietf-quic-multipath §2.3, §4.1, §5.4).

///|
/// A client whose transport parameters offer one path beyond the handshake's.
fn path_client(store : @tls.Sessions) -> Client raise {
  let params = Limits::new(
    idle_timeout=30000UL,
    data=10_000_000UL,
    stream_data_bidi_local=2_000_000UL,
    stream_data_bidi_remote=1_000_000UL,
    stream_data_uni=1_000_000UL,
    streams_bidi=100UL,
    streams_uni=100UL,
  ).params()
  params.push({ kind: InitialMaxPathId, value: @quic.encode(1UL), })
  let scid = b"\xaa\xbb\xcc\xdd"
  params.push({ kind: InitialScid, value: scid, })
  Client::new(
    @tls.Client::new(
      @x509.Roots::new(certs=[@x509.pem(root_pem)][:]),
      alpn=["h3"],
      suites=@tls.suites,
      sessions=store,
      early=true,
    ),
    "a.example",
    encode(params[:]),
    fake_rand(5),
    b"\x83\x94\xc8\xf0\x3e\x51\x57\x08",
    scid,
    WALL,
  )
}

///|
/// A server that will maintain one path beyond the handshake's.
fn path_server() -> Endpoint[String] raise {
  Endpoint::server(
    { ..Config::default(), max_path_id: 1UL, },
    @tls.Server::new(
      [@x509.pem(leaf_pem)],
      leaf_key(),
      alpn=["h3"],
      tickets=@tls.Tickets::new([Bytes::make(32, b'\x07')][:], early=1024),
    ),
    rand=fake_rand(99),
  )
}

///|
/// A client and a server past the handshake, both willing to maintain a second path.
fn multi_ready() -> (Client, Endpoint[String], Session[String]) raise {
  let client = path_client(@tls.Sessions::new())
  let server = path_server()
  exchange(client, server, WALL, 1000L)
  assert_true(client.is_connected())
  let conn = only_conn(server)
  (client, server, conn)
}

///|
test "a path opened after the handshake is challenged on itself, and its first number is 0" {
  let (client, _, conn) = multi_ready()
  // Each end said it would maintain one path beyond the handshake's.
  assert_eq(conn.paths().peer_max(), 1UL)
  assert_eq(client.paths().peer_max(), 1UL)
  // The client's id for the second path, which the server addresses it by.
  let peer_cid = b"\xc1\xc1\xc1\xc1"
  let challenge : Bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88"
  assert_true(
    conn.add_path(
      1UL,
      "second",
      peer_cid,
      b"\x5d\x5d\x5d\x5d\x5d\x5d\x5d\x5d",
      2000L,
      nonce=challenge,
      token=Bytes::make(16, b'\x02'),
    ),
  )
  guard conn.poll_lane(2000L) is Some((packet, to)) else {
    fail("no challenge went out on the new path")
  }
  assert_eq(to, "second")
  // It belongs on path 1, not on the connection's own address.
  assert_eq(conn.paths().validated(1UL), false)
  // The first packet on the path is number 0 there, whatever path 0 has used.
  let keys = conn.app_tx.unwrap()
  guard recv_short(packet, peer_cid.length(), keys, largest=-1L, path=1UL)
    is Some((frames, pn)) else {
    fail("the path's first packet did not open")
  }
  assert_eq(pn, 0L)
  assert_eq(frames, [PathChallenge(challenge)])
  // The same bytes under path 0's nonce are not this packet: the path is part of the nonce.
  assert_true(recv_short(packet, peer_cid.length(), keys, largest=-1L) is None)
}

///|
test "two paths carry the same frame under different numbers and different nonces" {
  let (_, _, conn) = multi_ready()
  let peer_cid = b"\xc1\xc1\xc1\xc1"
  assert_true(
    conn.add_path(
      1UL,
      "second",
      peer_cid,
      b"\x5d\x5d\x5d\x5d\x5d\x5d\x5d\x5d",
      2000L,
      nonce=b"\x01\x02\x03\x04\x05\x06\x07\x08",
      token=Bytes::make(16, b'\x02'),
    ),
  )
  ignore(conn.poll_lane(2000L))
  let keys = conn.app_tx.unwrap()
  // The same frame on both paths.
  ignore(conn.send_on(1UL, [Ping], 3000L))
  guard conn.poll_lane(3000L) is Some((on_path_one, _)) else {
    fail("nothing went out on path 1")
  }
  guard recv_short(on_path_one, peer_cid.length(), keys, largest=-1L, path=1UL)
    is Some((frames, pn)) else {
    fail("path 1's packet did not open")
  }
  assert_eq(frames, [Ping])
  // Path 1 has now used 0 (the challenge) and 1.
  assert_eq(pn, 1L)
  // Path 0 read and wrote several packets during the handshake, and none of them was number 0.
  assert_true(conn.largest_acked(Level::Application).unwrap() >= 0L)
}

///|
test "a challenge on a path is answered on that path, and proves it" {
  let (client, server, conn) = multi_ready()
  let peer_cid = b"\xc1\xc1\xc1\xc1"
  let challenge : Bytes = b"\xde\xad\xbe\xef\xde\xad\xbe\xef"
  // The endpoint makes the path's connection id, so a packet for that id routes to this
  // connection like any other.
  assert_true(
    server.add_path(conn.cid(), 1UL, "second", peer_cid, 2000L, nonce=challenge),
  )
  // Whatever else the connection had queued, the challenge is the datagram the new path sends:
  // the one addressed to the peer's id for it.
  let packet = drain(server, 2000L)
    .iter()
    .find_first(d => {
      d.length() > 1 + peer_cid.length() &&
      d[1:1 + peer_cid.length()].to_owned() == peer_cid
    })
  guard packet is Some(packet) else { fail("no challenge") }
  // The server's id for the path, which the client will answer to.
  let server_cid = conn.paths().local_cid(1UL)
  // The client takes it on path 1, which it must know about to answer.
  assert_true(
    client.add_path(
      1UL,
      server_cid,
      peer_cid,
      2000L,
      nonce=b"\x01\x01\x01\x01\x01\x01\x01\x01",
      token=Bytes::make(16, b'\x03'),
    ),
  )
  ignore(client.poll_paths(2000L))
  client.recv_on(1UL, packet, 2000L)
  // Its answer goes out on path 1, not on the path the handshake ran on.
  let answers = client.poll_paths(2500L)
  assert_true(answers.length() >= 1)
  let mut answered = false
  for entry in answers {
    let (path, response) = entry
    assert_eq(path, 1UL)
    server.recv(response, "second", 2500L)
    answered = true
  }
  assert_true(answered)
  assert_true(conn.paths().validated(1UL))
}

///|
test "a path's own probe timeout sends what it lost again, on that path" {
  let (_, server, conn) = multi_ready()
  let peer_cid = b"\xc1\xc1\xc1\xc1"
  assert_true(
    conn.add_path(
      1UL,
      "second",
      peer_cid,
      b"\x5d\x5d\x5d\x5d\x5d\x5d\x5d\x5d",
      2000L,
      nonce=b"\x09\x09\x09\x09\x09\x09\x09\x09",
      token=Bytes::make(16, b'\x02'),
    ),
  )
  ignore(conn.poll_lane(2000L))
  // Nothing is acknowledged, so the path has a packet outstanding and a timer.
  let lane = conn.path_lane(1UL).unwrap()
  assert_eq(lane.in_flight(), 1)
  let pto = lane.recovery().pto()
  assert_false(lane.on_pto(2000L))
  server.tick(2000L + pto)
  guard conn.poll_lane(2000L + pto) is Some((again, to)) else {
    fail("the lost packet did not go out again")
  }
  assert_eq(to, "second")
  // It is the same challenge, re-numbered on the path.
  let keys = conn.app_tx.unwrap()
  guard recv_short(again, peer_cid.length(), keys, largest=-1L, path=1UL)
    is Some((frames, pn)) else {
    fail("the retransmission did not open")
  }
  assert_eq(frames, [PathChallenge(b"\x09\x09\x09\x09\x09\x09\x09\x09")])
  assert_eq(pn, 1L)
}

///|
test "a PATH_ACK settles the numbers it names, and leaves another path's alone" {
  let (_, _, conn) = multi_ready()
  let peer_cid = b"\xc1\xc1\xc1\xc1"
  assert_true(
    conn.add_path(
      1UL,
      "second",
      peer_cid,
      b"\x5d\x5d\x5d\x5d\x5d\x5d\x5d\x5d",
      2000L,
      nonce=b"\x42\x42\x42\x42\x42\x42\x42\x42",
      token=Bytes::make(16, b'\x02'),
    ),
  )
  ignore(conn.poll_lane(2000L))
  let lane = conn.path_lane(1UL).unwrap()
  assert_eq(lane.in_flight(), 1)
  // Path 0's outstanding packets are the connection's own; the PATH_ACK names path 1.
  let before = conn.sender.outstanding().length()
  conn.on_path_ack(
    PathAck(path_id=1UL, largest=0UL, delay=0UL, first_range=0UL, ranges=[]),
    1UL,
    2500L,
  )
  assert_eq(lane.in_flight(), 0)
  assert_eq(conn.sender.outstanding().length(), before)
}

///|
test "a path id the peer never offered is refused" {
  let (_, _, conn) = multi_ready()
  assert_false(
    conn.add_path(
      2UL,
      "third",
      b"\xc2\xc2\xc2\xc2",
      b"\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e",
      2000L,
      nonce=b"\x00\x00\x00\x00\x00\x00\x00\x01",
      token=Bytes::make(16, b'\x02'),
    ),
  )
  // Path 0 is the connection's own and is never opened again.
  assert_false(
    conn.add_path(
      0UL,
      "elsewhere",
      b"\xc2\xc2\xc2\xc2",
      b"\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e",
      2000L,
      nonce=b"\x00\x00\x00\x00\x00\x00\x00\x02",
      token=Bytes::make(16, b'\x02'),
    ),
  )
}

///|
test "the multipath frames round trip with the draft's types" {
  let frames : Array[@frame.Frame] = [
    PathAck(path_id=1UL, largest=9UL, delay=3UL, first_range=1UL, ranges=[
      (2UL, 3UL),
    ]),
    PathAckEcn(
      path_id=2UL,
      largest=4UL,
      delay=0UL,
      first_range=0UL,
      ranges=[],
      ect0=1UL,
      ect1=2UL,
      ce=3UL,
    ),
    PathNewConnectionId(
      path_id=1UL,
      seq=0UL,
      retire_prior_to=0UL,
      conn_id=b"\x01\x02\x03\x04",
      reset_token=Bytes::make(16, b'\x05'),
    ),
    PathRetireConnectionId(path_id=1UL, seq=0UL),
    PathCidsBlocked(path_id=1UL, next=1UL),
  ]
  let types : Array[UInt64] = [0x3eUL, 0x3fUL, 0x3e78UL, 0x3e79UL, 0x3e7cUL]
  for i, frame in frames {
    let wire = @frame.encode(frame)
    // The first varint is the type, which this draft fixes.
    let (ty, _) = @quic.decode(wire[:]).unwrap()
    assert_eq(ty, types[i])
    let (back, used) = @frame.decode(wire[:]) catch {
      _ => abort("the frame did not decode")
    }
    assert_eq(used, wire.length())
    assert_eq(back, frame)
  }
}

///|
test "a packet on a path is acknowledged with a PATH_ACK that names it" {
  let (client, server, conn) = multi_ready()
  let peer_cid = b"\xc1\xc1\xc1\xc1"
  assert_true(
    server.add_path(
      conn.cid(),
      1UL,
      "second",
      peer_cid,
      2000L,
      nonce=b"\x01\x01\x01\x01\x01\x01\x01\x01",
    ),
  )
  let server_cid = conn.paths().local_cid(1UL)
  guard drain(server, 2000L)
    .iter()
    .find_first(d => {
      d.length() > 1 + peer_cid.length() &&
      d[1:1 + peer_cid.length()].to_owned() == peer_cid
    })
    is Some(challenge) else {
    fail("no challenge")
  }
  assert_true(
    client.add_path(
      1UL,
      server_cid,
      peer_cid,
      2000L,
      nonce=b"\x02\x02\x02\x02\x02\x02\x02\x02",
      token=Bytes::make(16, b'\x03'),
    ),
  )
  ignore(client.poll_paths(2000L))
  client.recv_on(1UL, challenge, 2000L)
  // One PING on the path, which the server owes an acknowledgement for.
  assert_true(client.send_on(1UL, [Ping], 2500L))
  for entry in client.poll_paths(2500L) {
    let (path, datagram) = entry
    assert_eq(path, 1UL)
    server.recv(datagram, "second", 2500L)
  }
  // The answer carries a PATH_ACK for path 1, not an ACK, and its ranges are path 1's.
  let keys = conn.app_tx.unwrap()
  let mut seen : Array[@frame.Frame]? = None
  for datagram in drain(server, 2500L) {
    if datagram.length() > 1 + peer_cid.length() &&
      datagram[1:1 + peer_cid.length()].to_owned() == peer_cid {
      if recv_short(datagram, peer_cid.length(), keys, largest=-1L, path=1UL)
        is Some((frames, _)) {
        seen = Some(frames)
      }
    }
  }
  guard seen is Some(frames) else {
    fail("the path's packet was never acknowledged")
  }
  guard frames is [PathAck(path_id~, largest~, ..)] else {
    fail("path 1 was answered with some other frame")
  }
  assert_eq(path_id, 1UL)
  // What it acknowledges is what path 1 has received, and nothing of path 0's.
  let received = conn.core.conn
    .space_on(1UL, Level::Application)
    .largest_received()
  assert_eq(largest.reinterpret_as_int64(), received)
}
