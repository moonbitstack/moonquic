// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Resumption: what a client keeps from one connection, and what the next one may spend before the
// handshake answers (RFC 9000 §7.4.1).

///|
/// A client that resumes from `kept`: no Config overrides, so everything its early data may spend
/// comes out of the ticket.
fn resumed_client(
  kept : Remembered,
  store : @tls.Sessions,
  wall : Int64,
  cfg~ : Config = Config::default(),
) -> Client raise {
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
    cfg~,
    resumption=kept,
  )
}

///|
/// A connection that got a ticket, and what it kept for the next one.
fn kept_ticket() -> (@tls.Sessions, Remembered) raise {
  let store = @tls.Sessions::new()
  let client = resuming_client(store, WALL)
  let server = resuming_server()
  exchange(client, server, WALL, 1000L)
  assert_true(client.is_connected())
  guard client.remembered() is Some(kept) else { fail("no ticket to keep") }
  (store, kept)
}

///|
test "a ticket is kept with the transport parameters it was issued under" {
  let (_, kept) = kept_ticket()
  let params = decode(kept.params[:])
  let limits = Limits::read(params[:])
  // The server's own defaults: a mebibyte of credit on the connection and on each stream.
  assert_eq(limits.data, 1_048_576UL)
  assert_eq(limits.stream_data_bidi_remote, 1_048_576UL)
  assert_eq(limits.stream_data_uni, 1_048_576UL)
  // The parameters are the block as it arrived, not a reading of it, so nothing is lost between
  // one connection and the next.
  assert_true(find(params[:], InitialScid) is Some(_))
}

///|
test "0-RTT: a kept ticket's limits carry early data with no Config override at all" {
  let (store, kept) = kept_ticket()
  let wall = WALL + 5L
  let client = resumed_client(kept, store, wall)
  let server = resuming_server()
  client.write(0UL, b"early", fin=true)
  for datagram in client.poll_out(2000L) {
    server.recv(datagram, from, 2000L, wall~)
  }
  // The server has the stream before it has seen the client's Finished: the credit came from the
  // remembered parameters, since Config says nothing.
  let conn = only_conn(server)
  assert_false(client.is_connected())
  assert_eq(conn.read(0UL), b"early")
  exchange(client, server, wall, 2000L)
  assert_true(client.is_connected())
  assert_true(client.early_accepted())
}

///|
test "0-RTT: Config's credit overrules the remembered one, in both directions" {
  let (store, kept) = kept_ticket()
  let wall = WALL + 5L
  // Four bytes of credit cannot carry five bytes of data, whatever the ticket remembered.
  let client = resumed_client(kept, store, wall, cfg={
    ..Config::default(),
    zero_rtt_data: 4UL,
    zero_rtt_stream_data: 4UL,
  })
  let server = resuming_server()
  client.write(0UL, b"early", fin=true)
  for datagram in client.poll_out(2000L) {
    server.recv(datagram, from, 2000L, wall~)
  }
  // Four of the five bytes: exactly the credit the override left, and no more.
  let conn = only_conn(server)
  assert_eq(conn.read(0UL), b"earl")
  // Held back, not dropped: the handshake's own parameters let it out.
  exchange(client, server, wall, 2000L)
  assert_true(client.is_connected())
  assert_eq(conn.read(0UL), b"y")
}

///|
test "0-RTT: a client with a ticket and no remembered parameters sends nothing early" {
  let (store, kept) = kept_ticket()
  let wall = WALL + 5L
  // The same ticket, but the parameters lost: nothing says what early data may spend, so it waits.
  let lost : Remembered = { ..kept, params: b"", }
  let client = resumed_client(lost, store, wall)
  let server = resuming_server()
  client.write(0UL, b"early", fin=true)
  for datagram in client.poll_out(2000L) {
    server.recv(datagram, from, 2000L, wall~)
  }
  assert_eq(only_conn(server).read(0UL), b"")
  exchange(client, server, wall, 2000L)
  assert_eq(only_conn(server).read(0UL), b"early")
}

///|
test "a ticket offered by a connection the handshake did not finish is not kept" {
  let store = @tls.Sessions::new()
  let client = resuming_client(store, WALL)
  // One flight only: no handshake, no ticket, nothing to remember.
  ignore(client.poll_out(1000L))
  assert_false(client.is_connected())
  assert_true(client.remembered() is None)
}
