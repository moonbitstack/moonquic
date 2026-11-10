// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Multipath, first stage: the frames round trip, and a connection's path state follows what the
// peer says about it (draft-ietf-quic-multipath §3, §4).

///|
test "the multipath frames round trip" {
  let frames : Array[@frame.Frame] = [
    PathAbandon(path_id=1UL, error_code=0UL),
    PathStatus(path_id=2UL, seq=7UL, available=false),
    PathStatus(path_id=3UL, seq=8UL, available=true),
    MaxPathId(max=4UL),
    PathsBlocked(max=5UL),
  ]
  for frame in frames {
    let wire = @frame.encode(frame)
    let (back, used) = @frame.decode(wire[:]) catch {
      _ => abort("the frame did not decode")
    }
    assert_eq(used, wire.length())
    assert_eq(back, frame)
  }
}

///|
test "a connection starts with path 0 and no room for another" {
  let paths = Paths::new()
  assert_eq(paths.count(), 1)
  assert_true(paths.get(0UL) is Some(_))
  assert_true(paths.free() is None)
  assert_eq(paths.allowed(1UL), false)
}

///|
test "an offered path id makes room for one path, and MAX_PATH_ID makes room for more" {
  let paths = Paths::new(local_max=2UL)
  // Nothing may be opened until the peer has said what it will accept.
  assert_true(paths.free() is None)
  paths.on_max_path_id(2UL)
  assert_eq(paths.free(), Some(1UL))
  paths.on_max_path_id(3UL)
  assert_eq(paths.peer_max(), 3UL)
  // A limit only rises.
  paths.on_max_path_id(1UL)
  assert_eq(paths.peer_max(), 3UL)
}

///|
test "a bound path starts unvalidated and becomes valid when it answers" {
  let paths = Paths::new(local_max=1UL)
  paths.bind(1UL, b"path-one")
  assert_false(paths.validated(1UL))
  paths.on_validated(1UL)
  assert_true(paths.validated(1UL))
}

///|
test "a status that arrives out of order changes nothing" {
  let paths = Paths::new(local_max=1UL)
  paths.bind(1UL, b"path-one")
  assert_true(paths.on_status(1UL, 2UL, false))
  assert_false(paths.get(1UL).unwrap().available)
  // An older sequence number is a reordering of the one already applied.
  assert_false(paths.on_status(1UL, 1UL, true))
  assert_false(paths.get(1UL).unwrap().available)
  assert_true(paths.on_status(1UL, 3UL, true))
  assert_true(paths.get(1UL).unwrap().available)
}

///|
test "path 0 cannot be given up, and any other path can" {
  let paths = Paths::new(local_max=1UL)
  paths.bind(1UL, b"path-one")
  assert_false(paths.abandon(0UL))
  assert_true(paths.abandon(1UL))
  assert_true(paths.get(1UL).unwrap().abandoned)
}

///|
test "a connection advertises the paths it will accept, and a peer cannot abandon path 0" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server : Endpoint[String] = Endpoint::server(
    { ..Config::default(), max_path_id: 2UL, },
    @tls.Server::new([@x509.pem(leaf_pem)], leaf_key(), alpn=["h3"]),
    rand=fake_rand(99),
  )
  exchange(client, server, WALL, 1000L)
  let conn = only_conn(server)
  assert_eq(conn.paths().local_max(), 2UL)
  assert_eq(conn.paths().count(), 1)
  // A PATH_STATUS for a path this end never offered is a protocol violation.
  let bad = inject(
    server,
    client,
    [PathStatus(path_id=9UL, seq=1UL, available=true)],
    500L,
    2000L,
  )
  assert_eq(closed_with(bad), protocol_violation)
}

///|
test "a peer's MAX_PATH_ID and PATH_STATUS reach the connection's path state" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = plain_server()
  exchange(client, server, WALL, 1000L)
  let conn = inject(
    server,
    client,
    [MaxPathId(max=3UL), PathStatus(path_id=0UL, seq=1UL, available=false)],
    500L,
    2000L,
  )
  // Path 0 is the handshake's path, so it is always there to be given a status.
  assert_eq(conn.paths().peer_max(), 3UL)
  assert_false(conn.paths().get(0UL).unwrap().available)
}

///|
test "abandoning path 0 closes the connection" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = plain_server()
  exchange(client, server, WALL, 1000L)
  let conn = inject(
    server,
    client,
    [PathAbandon(path_id=0UL, error_code=0UL)],
    500L,
    2000L,
  )
  assert_eq(closed_with(conn), protocol_violation)
}

///|
test "a connection id the peer offers for a path opens that path, before anything is sent on it" {
  let paths = Paths::new(local_max=1UL)
  // The peer has said it will maintain one path beyond the handshake's.
  paths.on_max_path_id(1UL)
  // Nothing is known about path 1 yet: no address, no local id, no challenge.
  assert_true(paths.get(1UL) is None)
  // The peer's PATH_NEW_CONNECTION_ID is what makes it openable.
  assert_true(paths.on_peer_cid(1UL, 0UL, b"\x01\x02\x03\x04"))
  assert_eq(paths.peer_cid(1UL), b"\x01\x02\x03\x04")
  assert_eq(paths.count(), 2)
  // A later id for the same path takes over, and an older one is a reordering.
  assert_true(paths.on_peer_cid(1UL, 1UL, b"\x05\x05\x05\x05"))
  assert_eq(paths.peer_cid(1UL), b"\x05\x05\x05\x05")
  assert_false(paths.on_peer_cid(1UL, 0UL, b"\x01\x02\x03\x04"))
  assert_eq(paths.peer_cid(1UL), b"\x05\x05\x05\x05")
  // A path neither end offered is still refused.
  assert_false(paths.on_peer_cid(2UL, 0UL, b"\x06\x06\x06\x06"))
  assert_false(paths.on_peer_cid(1UL, 2UL, b""))
}

///|
test "a peer's connection id for a further path reaches a connection, and that path opens on it" {
  let (client, _, conn) = multi_ready()
  let peer_cid = b"\x77\x66\x55\x44\x33\x22\x11\x00"
  // What a peer does after the handshake: name the further path, and the id to use on it.
  let packet = send_short(
    client.scid,
    1000L,
    4,
    [
      PathNewConnectionId(
        path_id=1UL,
        seq=0UL,
        retire_prior_to=0UL,
        conn_id=peer_cid,
        reset_token=Bytes::make(16, b'\x09'),
      ),
    ],
    conn.app_tx.unwrap(),
  )
  client.recv(packet, 2000L)
  // The path did not exist before the frame; the id it named is now what the path is addressed by.
  assert_eq(client.paths().peer_cid(1UL), peer_cid)
  assert_true(client.paths().openable(1UL))
}

///|
test "a path a client opens is proven by the answer to the challenge it sent" {
  let (client, _, conn) = multi_ready()
  let peer_cid = b"\xc1\xc1\xc1\xc1"
  // A short header is read with the length of this end's own id, so the path's id is that long.
  let own_cid = b"\x5d\x5d\x5d\x5d"
  let nonce : Bytes = b"\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"
  assert_true(
    client.add_path(
      1UL,
      peer_cid,
      own_cid,
      2000L,
      nonce~,
      token=Bytes::make(16, b'\x02'),
    ),
  )
  // The peer answers the challenge on the path itself, addressing this end by the id it gave.
  // The path is part of the nonce (draft §2.4), so the answer is protected as path 1's.
  let packet = send_short(
    own_cid,
    0L,
    4,
    [PathResponse(nonce)],
    conn.app_tx.unwrap(),
    path=1UL,
  )
  client.recv_on(1UL, packet, 2500L)
  assert_true(client.paths().validated(1UL))
}
