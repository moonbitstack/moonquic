// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The library client's handshake: a first flight that splits across Initial packets when the
// hello is large, the server reassembling that flight, and a full handshake against a real
// certificate.

///|
fn make_client(alpn~ : Array[String] = ["h3"]) -> Client raise {
  let dcid = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
  let scid = b"\xaa\xbb\xcc\xdd"
  let params = Limits::new(
    idle_timeout=30000UL,
    data=10_000_000UL,
    stream_data_bidi_local=2_000_000UL,
    stream_data_bidi_remote=1_000_000UL,
    stream_data_uni=1_000_000UL,
    streams_bidi=100UL,
    streams_uni=100UL,
  ).params()
  params.push({ kind: InitialScid, value: scid, })
  let config = @tls.Client::new(
    @x509.Roots::new(certs=[@x509.pem(root_pem)][:]),
    alpn~,
    suites=@tls.suites,
  )
  Client::new(
    config,
    "a.example",
    encode(params[:]),
    fake_rand(5),
    dcid,
    scid,
    1767225600L,
  )
}

///|
test "a long CRYPTO stream leaves in runs sized for the packet that carries it" {
  let out = Outbox::new()
  out.write(Bytes::make(1600, 0))
  let room = crypto_room(
    b"\x83\x94\xc8\xf0\x3e\x51\x57\x08", b"\xaa\xbb\xcc\xdd", b"", false,
  )
  // Each run is at most the room one datagram leaves, and the next starts where it ended.
  assert_eq(out.take(room), Some((0, room)))
  assert_eq(out.take(room), Some((room, 1600 - room)))
  assert_eq(out.take(room), None)
  // A stream shorter than one packet is one run.
  let small = Outbox::new()
  small.write(Bytes::make(100, 0))
  assert_eq(small.take(room), Some((0, 100)))
}

///|
test "the real post-quantum hello takes more than one Initial packet" {
  let client = make_client()
  let packets = client.poll_out(0L)
  // The default hello now carries an X25519MLKEM768 share and is over a kilobyte.
  assert_eq(packets.length() >= 2, true)
  for packet in packets {
    assert_eq(packet.length() <= 1200, true)
    // Every one is a long header, not a 1-RTT packet.
    assert_eq((packet[0].to_int() & 0x80) != 0, true)
  }
}

///|
test "streams run both ways over the client's 1-RTT path" {
  let server = new_server()
  let client = make_client()
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L)
  }
  for datagram in drain(server, 1000L) {
    client.recv(datagram, 1000L)
  }
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L)
  }
  assert_true(client.is_connected())
  let conn = only_conn(server)
  conn.take_events() |> ignore
  // Client to server.
  client.write(0UL, b"hello", fin=true)
  for datagram in client.poll_out(2000L) {
    server.recv(datagram, from, 2000L)
  }
  assert_eq(conn.take_events(), [Readable(0UL)])
  assert_eq(conn.read(0UL), b"hello")
  // Server to client.
  conn.write(0UL, b"reply", fin=true)
  for datagram in drain(server, 2000L) {
    client.recv(datagram, 2000L)
  }
  assert_eq(client.take_events().contains(Readable(0UL)), true)
  assert_eq(client.read(0UL), b"reply")
}

///|
test "a first flight larger than a datagram splits into several Initial packets" {
  let client = make_client()
  // Stand in for the post-quantum hello: 1600 bytes of CRYPTO, past one packet.
  client.initial_out.clear()
  client.initial_out.write(Bytes::make(1600, b'c'))
  let packets = client.poll_out(0L)
  assert_eq(packets.length(), 2)
  for packet in packets {
    // Padded to the 1200-byte floor, and never past it.
    assert_eq(packet.length() <= 1200, true)
    assert_eq(packet.length() >= 1200, true)
  }
}

///|
test "the server reassembles a hello that arrived in two Initial packets" {
  let conn = Conn::new(true)
  let first = Bytes::makei(1100, i => (i & 0xff).to_byte())
  let second = Bytes::makei(500, i => ((i + 7) & 0xff).to_byte())
  // Out of order: the later run first leaves a gap, so nothing is contiguous yet.
  assert_eq(conn.on_crypto_frame(Level::Initial, 1100UL, second).length(), 0)
  let whole = conn.on_crypto_frame(Level::Initial, 0UL, first)
  assert_eq(whole.length(), 1600)
  let want = Buffer()
  want.write_bytes(first)
  want.write_bytes(second)
  assert_eq(whole, want.to_bytes())
}

///|
test "a client completes the handshake against the server" {
  let server = new_server()
  let client = make_client()
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L)
  }
  for datagram in drain(server, 1000L) {
    client.recv(datagram, 1000L)
  }
  assert_true(client.is_connected())
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L)
  }
  let conn = only_conn(server)
  assert_eq(conn.take_events(), [Connected])
  assert_eq(client.alpn(), Some("h3"))
}

///|
const WALL : Int64 = 1767225600L

///|
/// A client that keeps its tickets in `store` and may offer 0-RTT.
fn resuming_client(store : @tls.Sessions, wall : Int64) -> Client raise {
  let params = Limits::new(
    idle_timeout=30000UL,
    data=10_000_000UL,
    stream_data_bidi_local=2_000_000UL,
    stream_data_bidi_remote=1_000_000UL,
    stream_data_uni=1_000_000UL,
    streams_bidi=100UL,
    streams_uni=100UL,
  ).params()
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
    wall,
    // What the last connection left: 0-RTT data may spend this before the handshake's
    // parameters arrive (RFC 9000 §7.4.1).
    cfg={
      ..Config::default(),
      zero_rtt_data: 1_000_000UL,
      zero_rtt_stream_data: 1_000_000UL,
    },
  )
}

///|
/// An endpoint that seals tickets under one key and allows 0-RTT under them.
fn resuming_server() -> Endpoint[String] raise {
  Endpoint::server(
    Config::default(),
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
/// Run a client against an endpoint until neither has anything left to say.
fn exchange(
  client : Client,
  server : Endpoint[String],
  wall : Int64,
  now : Int64,
) -> Unit raise {
  for _ in 0..<8 {
    for datagram in client.poll_out(now) {
      server.recv(datagram, from, now, wall~)
    }
    for datagram in drain(server, now) {
      client.recv(datagram, now)
    }
  }
}

///|
test "a server's ticket reaches the client over 1-RTT" {
  let store = @tls.Sessions::new()
  let client = resuming_client(store, WALL)
  let server = resuming_server()
  exchange(client, server, WALL, 1000L)
  assert_true(client.is_connected())
  assert_true(store.length() > 0)
}

///|
test "an endpoint given no wall clock issues no ticket" {
  let store = @tls.Sessions::new()
  let client = resuming_client(store, WALL)
  let server = resuming_server()
  for _ in 0..<8 {
    for datagram in client.poll_out(1000L) {
      server.recv(datagram, from, 1000L)
    }
    for datagram in drain(server, 1000L) {
      client.recv(datagram, 1000L)
    }
  }
  assert_true(client.is_connected())
  assert_eq(store.length(), 0)
}

///|
test "0-RTT: a stream written before the handshake arrives, and the server said yes" {
  let store = @tls.Sessions::new()
  let first = resuming_client(store, WALL)
  exchange(first, resuming_server(), WALL, 1000L)
  assert_true(store.length() > 0)
  // The second connection, five seconds later, on the same two clocks.
  let wall = WALL + 5L
  let client = resuming_client(store, wall)
  let server = resuming_server()
  // The early keys came out of the handshake with no help from the caller.
  client.write(0UL, b"early", fin=true)
  for datagram in client.poll_out(2000L) {
    server.recv(datagram, from, 2000L, wall~)
  }
  // The server holds the stream before it has seen the client's Finished.
  let conn = only_conn(server)
  assert_false(client.is_connected())
  assert_eq(conn.read(0UL), b"early")
  exchange(client, server, wall, 2000L)
  assert_true(client.is_connected())
  assert_true(client.early_accepted())
}

///|
test "0-RTT: a client with no ticket keeps early data back for the handshake" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  client.write(0UL, b"early", fin=true)
  for packet in client.poll_out(1000L) {
    // Nothing may carry a STREAM frame but a 0-RTT or 1-RTT packet, and with neither key
    // there is no such packet.
    assert_false(
      (packet[0].to_int() & 0x80) != 0 && (packet[0].to_int() & 0x30) == 0x10,
    )
  }
  assert_false(client.is_connected())
}

///|
test "a server names the token its resets end with, and a client closes on one" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = resuming_server()
  exchange(client, server, WALL, 1000L)
  assert_true(client.is_connected())
  ignore(client.take_events())
  let cid = client.server_cid()
  guard client.reset_token is Some(token) else {
    fail("no stateless_reset_token in the transport parameters")
  }
  assert_eq(token, reset_token(server.reset_key, cid))
  // The server has forgotten the connection; a short header for it draws a reset.
  server.conns.remove(cid)
  let junk = Buffer()
  junk.write_byte(b'\x40')
  junk.write_bytes(cid)
  junk.write_bytes(Bytes::make(32, b'\x11'))
  server.recv(junk.to_bytes(), from, 2000L)
  guard server.poll_out(2000L) is Some((reset, _)) else { fail("no reset") }
  client.recv(reset, 2000L)
  assert_true(client.take_events().contains(Closed(0UL)))
}

///|
test "a packet that will not open and does not end in the token closes nothing" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  exchange(client, resuming_server(), WALL, 1000L)
  ignore(client.take_events())
  client.recv(Bytes::make(40, b'\x41'), 2000L)
  assert_false(client.take_events().contains(Closed(0UL)))
}

///|
/// A client and a server past the handshake, with something sent and acknowledged both ways.
fn talking() -> (Client, Endpoint[String], Session[String]) raise {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = resuming_server()
  exchange(client, server, WALL, 1000L)
  assert_true(client.is_connected())
  let conn = only_conn(server)
  client.write(0UL, b"first", fin=true)
  exchange(client, server, WALL, 2000L)
  assert_eq(conn.read(0UL), b"first")
  conn.write(0UL, b"back", fin=true)
  exchange(client, server, WALL, 3000L)
  assert_eq(client.read(0UL), b"back")
  (client, server, conn)
}

///|
test "a key update a client starts moves both ways, and data still flows" {
  let (client, server, conn) = talking()
  assert_true(client.update_keys())
  assert_true(client.key_phase)
  client.write(4UL, b"second", fin=true)
  exchange(client, server, WALL, 4000L)
  assert_eq(conn.read(4UL), b"second")
  assert_true(conn.key_phase)
  conn.write(4UL, b"again", fin=true)
  exchange(client, server, WALL, 5000L)
  assert_eq(client.read(4UL), b"again")
  assert_true(client.rx_phase)
}

///|
test "a key update waits for confirmation, and for the last one to be acknowledged" {
  let early = resuming_client(@tls.Sessions::new(), WALL)
  assert_false(early.update_keys())
  // Confirmed, with nothing written yet in this phase to have been acknowledged.
  exchange(early, resuming_server(), WALL, 1000L)
  assert_true(early.confirmed)
  assert_false(early.update_keys())
  let (client, server, _) = talking()
  assert_true(client.update_keys())
  // Nothing in the new phase has been written, let alone acknowledged.
  assert_false(client.update_keys())
  client.write(4UL, b"x", fin=true)
  exchange(client, server, WALL, 4000L)
  assert_true(client.update_keys())
}

///|
test "a client follows a key update the server starts" {
  let (client, server, conn) = talking()
  // The client opens the stream first: a peer may only send on a bidirectional stream this end
  // created (RFC 9000 §19.8), and the next part of this test is the server sending on it.
  client.write(4UL, b"open", fin=false)
  for datagram in client.poll_out(4000L) {
    server.recv(datagram, from, 4000L, wall=WALL)
  }
  ignore(conn.read(4UL))
  let (secret, written) = roll(
    conn.app_tx_secret,
    conn.app_tx.unwrap(),
    conn.suite,
  )
  conn.app_tx = Some(written)
  conn.app_tx_secret = secret
  conn.key_phase = !conn.key_phase
  conn.write(4UL, b"moved", fin=true)
  for datagram in drain(server, 4000L) {
    client.recv(datagram, 4000L)
  }
  assert_eq(client.read(4UL), b"moved")
  // It has read the new phase, so it writes the new phase.
  assert_true(client.key_phase)
  client.write(8UL, b"followed", fin=true)
  exchange(client, server, WALL, 5000L)
  assert_eq(conn.read(8UL), b"followed")
}

///|
test "no packet number is used twice, whichever path through the client numbered it" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = resuming_server()
  exchange(client, server, WALL, 1000L)
  // The handshake left only acknowledgements in this space, numbered outside the send loop.
  let conn = only_conn(server)
  client.write(0UL, b"first", fin=true)
  for datagram in client.poll_out(2000L) {
    server.recv(datagram, from, 2000L, wall=WALL)
  }
  assert_eq(conn.read(0UL), b"first")
}

///|
test "a server offers spare ids up to what the client takes, and the client can move to one" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = resuming_server()
  exchange(client, server, WALL, 1000L)
  // This client's limit is RFC 9000's default of 2: the handshake's id and one more.
  assert_eq(client.offered_ids.length(), 1)
  let (seq, spare, token) = client.offered_ids[0]
  assert_eq(seq, 1UL)
  assert_eq(token, reset_token(server.reset_key, spare))
  let conn = only_conn(server)
  assert_true(client.next_cid())
  assert_eq(client.dcid, spare)
  client.write(0UL, b"on a new id", fin=true)
  exchange(client, server, WALL, 2000L)
  assert_eq(conn.read(0UL), b"on a new id")
}

///|
test "a retired id is forgotten, and the client is given another" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = resuming_server()
  exchange(client, server, WALL, 1000L)
  let conn = only_conn(server)
  let (_, first, _) = client.offered_ids[0]
  assert_true(client.next_cid())
  client.write(0UL, b"a", fin=true)
  exchange(client, server, WALL, 2000L)
  // The handshake's id went back with that, and its place was filled.
  assert_true(client.offered_ids.length() >= 1)
  assert_true(client.next_cid())
  client.write(4UL, b"b", fin=true)
  exchange(client, server, WALL, 3000L)
  assert_eq(conn.read(4UL), b"b")
  // Now the first spare has been retired too, and nothing routes to it.
  assert_false(server.aliases.contains(first))
}

///|
test "retiring an id never issued closes the connection" {
  let server = resuming_server()
  let client = resuming_client(@tls.Sessions::new(), WALL)
  exchange(client, server, WALL, 1000L)
  let conn = only_conn(server)
  conn.on_retire_id(99UL, 2000L)
  assert_true(conn.phase is Closing)
}

///|
test "a server with one id to a connection offers no spares" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server : Endpoint[String] = Endpoint::server(
    { ..Config::default(), connection_ids: 1UL, },
    @tls.Server::new(
      [@x509.pem(leaf_pem)],
      leaf_key(),
      alpn=["h3"],
      tickets=@tls.Tickets::new([Bytes::make(32, b'\x07')][:], early=1024),
    ),
    rand=fake_rand(99),
  )
  exchange(client, server, WALL, 1000L)
  assert_true(client.is_connected())
  assert_eq(client.offered_ids.length(), 0)
  assert_false(client.next_cid())
}

///|
test "a reset for a spare id closes the client too" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = resuming_server()
  exchange(client, server, WALL, 1000L)
  ignore(client.take_events())
  let (_, _, token) = client.offered_ids[0]
  let noise = Bytes::make(30, b'\x41')
  let reset = Buffer()
  reset.write_bytes(noise)
  reset.write_bytes(token)
  client.recv(reset.to_bytes(), 2000L)
  assert_true(client.take_events().contains(Closed(0UL)))
}
