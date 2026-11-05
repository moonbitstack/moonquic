// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The client's timers and its two recovery paths: a handshake packet that went missing, and a
// 0-RTT packet the server never saw. The server here is the real one, so what is dropped is
// dropped on the wire rather than in a record.

///|
/// A server that runs the handshake, with 0-RTT allowed under one ticket key.
fn plain_server() -> Endpoint[String] raise {
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
test "a dropped first flight goes out again when the probe timeout fires" {
  let client = make_client()
  let server = plain_server()
  let first = client.poll_out(1000L)
  assert_true(first.length() >= 1)
  // The whole first flight is lost.
  client.tick(1000L + client.sender.recovery.pto())
  let second = client.poll_out(1000L + client.sender.recovery.pto())
  assert_true(second.length() >= first.length())
  for datagram in second {
    assert_true(datagram.length() >= 1200)
    server.recv(datagram, from, 1000L)
  }
  for datagram in drain(server, 1000L) {
    client.recv(datagram, 1000L)
  }
  assert_true(client.is_connected())
}

///|
test "a client with nothing in flight probes, so a server out of budget can answer" {
  let client = make_client()
  // Drain the first flight against nothing: every byte is now in flight, so this only checks
  // that a probe is not sent while something is.
  ignore(client.poll_out(1000L))
  assert_eq(client.probe(1000L).length(), 1)
  // A probe is a full-size Initial, so a server that spent its amplification budget on
  // nothing still owes an answer to it.
  let probe = client.probe(1000L)[0]
  assert_eq(probe.length() >= 1200, true)
  assert_eq((probe[0].to_int() & 0x80) != 0, true)
}

///|
test "an idle client closes itself" {
  let client = make_client()
  let deadline = client.idle_timeout
  client.tick(deadline - 1L)
  assert_eq(client.phase(), Phase::Active)
  client.tick(deadline)
  assert_eq(client.phase(), Phase::Closing)
  assert_eq(client.take_events(), [Closed(0UL)])
}

///|
test "a close before 1-RTT keys goes as a transport close with APPLICATION_ERROR" {
  let client = make_client()
  client.close(7UL, b"done", 1000L, application=true)
  assert_eq(client.phase(), Phase::Closing)
  let out = client.poll_out(1000L)
  assert_eq(out.length(), 1)
  // Open the packet under the Initial keys to read what it carries.
  // The client seals with the client's own Initial keys, so those are the ones that open it.
  let (frames, _) = recv_long(out[0], client.initial_tx, largest=-1L).unwrap()
  match frames[0] {
    ConnectionClose(error_code~, frame_type~, ..) => {
      assert_eq(error_code, application_error)
      assert_eq(frame_type, Some(0UL))
    }
    _ => fail("not a CONNECTION_CLOSE")
  }
}

///|
test "an Initial from the server draws an ACK in the client's next Initial" {
  let client = make_client()
  let server = plain_server()
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L, wall=WALL)
  }
  let answer = drain(server, 1000L)
  assert_true(answer.length() > 0)
  client.recv(answer[0], 1000L)
  let again = client.poll_out(1000L)
  let mut acked = false
  for datagram in again {
    if (datagram[0].to_int() & 0x80) != 0 &&
      ((datagram[0].to_int() >> 4) & 0x3) == 0 {
      let (frames, _) = recv_long(datagram, client.initial_tx, largest=-1L).unwrap()
      if frames.iter().any(f => f is Ack(..)) {
        acked = true
      }
    }
  }
  assert_true(acked)
}

///|
test "a version negotiation names the versions it offers and stops this attempt" {
  let client = make_client()
  let packet = @packet.versions(dcid=client.scid, scid=client.dcid, [2U, 1U][:])
  client.recv(packet, 1000L)
  assert_eq(client.versions(), [2U, 1U])
  assert_false(client.is_connected())
}

///|
test "a Retry moves the client to the server's id and the handshake completes" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server : Endpoint[String] = Endpoint::server(
    { ..Config::default(), retry: true, },
    @tls.Server::new([@x509.pem(leaf_pem)], leaf_key(), alpn=["h3"]),
    rand=fake_rand(99),
    address=_ => b"peer",
  )
  let before = client.dcid
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L, wall=WALL)
  }
  guard server.poll_out(1000L) is Some((retry, to)) else {
    fail("the server did not retry")
  }
  assert_eq(to, from)
  assert_eq((retry[0].to_int() >> 4) & 0x03, 3)
  client.recv(retry, 1000L)
  assert_true(client.retried)
  assert_true(client.dcid != before)
  assert_eq(client.token.length() > 0, true)
  exchange(client, server, WALL, 2000L)
  assert_true(client.is_connected())
  // The connection the server keeps is the one the Retry named.
  assert_eq(server.count(), 1)
  assert_eq(client.server_cid(), only_conn(server).cid())
}

///|
test "a second Retry is ignored" {
  let client = make_client()
  let server : Endpoint[String] = Endpoint::server(
    { ..Config::default(), retry: true, },
    @tls.Server::new([@x509.pem(leaf_pem)], leaf_key(), alpn=["h3"]),
    rand=fake_rand(99),
  )
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L, wall=WALL)
  }
  guard server.poll_out(1000L) is Some((retry, _)) else { fail("no retry") }
  client.recv(retry, 1000L)
  let after = client.dcid
  client.recv(retry, 1000L)
  assert_eq(client.dcid, after)
}

///|
test "a Retry whose tag does not match changes nothing" {
  let client = make_client()
  let server : Endpoint[String] = Endpoint::server(
    { ..Config::default(), retry: true, },
    @tls.Server::new([@x509.pem(leaf_pem)], leaf_key(), alpn=["h3"]),
    rand=fake_rand(99),
  )
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L, wall=WALL)
  }
  guard server.poll_out(1000L) is Some((retry, _)) else { fail("no retry") }
  let buf = Buffer()
  buf.write_bytes(retry[0:retry.length() - 1])
  buf.write_byte((retry[retry.length() - 1].to_int() ^ 1).to_byte())
  let tampered = buf.to_bytes()
  let before = client.dcid
  client.recv(tampered, 1000L)
  assert_false(client.retried)
  assert_eq(client.dcid, before)
}

///|
test "a 0-RTT packet the server never saw goes out again" {
  let store = @tls.Sessions::new()
  let first = resuming_client(store, WALL)
  exchange(first, plain_server(), WALL, 1000L)
  assert_true(store.length() > 0)
  let wall = WALL + 5L
  let client = resuming_client(store, wall)
  let server = plain_server()
  client.write(0UL, b"early", fin=true)
  let flight = client.poll_out(2000L)
  // Everything the client had to say on its first attempt is lost.
  guard flight.length() > 0 else { fail("nothing to send") }
  client.tick(2000L + client.sender.recovery.pto())
  for datagram in client.poll_out(2000L + client.sender.recovery.pto()) {
    server.recv(datagram, from, 2000L, wall~)
  }
  let conn = only_conn(server)
  assert_eq(conn.read(0UL), b"early")
}
