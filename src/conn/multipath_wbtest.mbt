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
