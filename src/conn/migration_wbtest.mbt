// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Connection migration and stateless reset at the server's edge (RFC 9000 §9, §10.3), driven
// through the real handshake harness.

///|
test "a packet from a new address is challenged, and the answer proves the path" {
  let server = new_server()
  let client = Peer::new()
  connect(client, server)
  let conn = only_conn(server)
  conn.take_events() |> ignore
  server.take_busy() |> ignore
  // The same connection, now sending from another address.
  server.recv(client.packet(Application, [Ping]), "moved", 3000L)
  let mut challenge = b""
  for datagram in drain(server, 3000L) {
    client.receive(datagram)
  }
  for frame in client.frames {
    match frame {
      PathChallenge(data) => challenge = data
      _ => ()
    }
  }
  assert_eq(challenge.length(), 8)
  assert_eq(conn.path_validated(), false)
  // The peer echoes the challenge from the new address; the path is proven.
  server.recv(
    client.packet(Application, [PathResponse(challenge)]),
    "moved",
    3001L,
  )
  assert_eq(conn.path_validated(), true)
}

///|
test "a short-header datagram for no connection draws a stateless reset" {
  let server = new_server()
  let junk = Buffer()
  junk.write_byte(b'\x40')
  junk.write_bytes(Bytes::make(20, 0))
  server.recv(junk.to_bytes(), from, 1000L)
  let out = drain(server, 1000L)
  assert_eq(out.length(), 1)
  // Short-header form, and the 21-byte floor.
  assert_eq(out[0][0].to_int() & 0x80, 0)
  assert_eq(out[0].length(), 21)
  assert_eq(server.count(), 0)
}

///|
/// A server and a client past the handshake, with everything so far read and sent.
fn settled() -> (Endpoint[String], Peer, Session[String]) raise {
  let server = new_server()
  let client = Peer::new()
  connect(client, server)
  let conn = only_conn(server)
  conn.take_events() |> ignore
  server.take_busy() |> ignore
  ignore(drain(server, 2000L))
  (server, client, conn)
}

///|
/// Every datagram ready to go, with where it is going.
fn sent(server : Endpoint[String], now : Int64) -> Array[(Bytes, String)] raise {
  let out = []
  while server.poll_out(now) is Some(item) {
    out.push(item)
  }
  out
}

///|
test "a packet that does not authenticate moves nothing, whatever connection id it names" {
  let (server, client, conn) = settled()
  // The genuine header bytes, a corrupted body: anyone on the path can write this.
  let packet = client.packet(Application, [Ping])
  let forged = Bytes::makei(packet.length(), i => {
    if i == packet.length() - 1 {
      (packet[i].to_int() ^ 1).to_byte()
    } else {
      packet[i]
    }
  })
  server.recv(forged, "attacker", 3000L)
  assert_eq(conn.peer(), from)
  assert_false(sent(server, 3000L).iter().any(item => item.1 == "attacker"))
}

///|
test "a probe is answered where it came from, and the connection stays" {
  let (server, client, conn) = settled()
  let challenge = b"12345678"
  server.recv(
    client.packet(Application, [PathChallenge(challenge)]),
    "probe",
    3000L,
  )
  assert_eq(conn.peer(), from)
  let out = sent(server, 3000L)
  let answers = out.filter(item => item.1 == "probe")
  assert_eq(answers.length(), 1)
  // Three times what the probe sent is the most an unproven address may get (§8.1).
  client.receive(answers[0].0)
  assert_true(
    client.frames
    .iter()
    .any(frame => frame is PathResponse(data) && data == challenge),
  )
}

///|
test "a reordered packet from where the peer was does not move it back" {
  let (server, client, conn) = settled()
  let older = client.packet(Application, [Ping])
  let newer = client.packet(Application, [Ping])
  server.recv(newer, from, 3000L)
  server.recv(older, "old", 3001L)
  assert_eq(conn.peer(), from)
}

///|
test "a real packet from a new address moves the connection, on a budget until it answers" {
  let (server, client, conn) = settled()
  conn.write(0UL, Bytes::make(40000, b'x'))
  let packet = client.packet(Application, [Ping])
  server.recv(packet, "moved", 3000L)
  assert_eq(conn.peer(), "moved")
  assert_false(conn.validated())
  let out = sent(server, 3000L)
  assert_true(out.iter().all(item => item.1 == "moved"))
  let total = out.fold(init=0, (sum, item) => sum + item.0.length())
  assert_true(total > 0)
  assert_true(total.to_int64() <= amplification * packet.length().to_int64())
}

///|
test "a challenge fills a full-size datagram when the budget allows it" {
  let (server, client, conn) = settled()
  server.recv(client.packet(Application, [Ping, Padding(1200)]), "moved", 3000L)
  assert_eq(conn.peer(), "moved")
  let out = sent(server, 3000L)
  assert_true(out[0].0.length() >= min_datagram)
}

///|
test "an answer proves the path, and the window and round trip start over" {
  let (server, client, conn) = settled()
  conn.sender.recovery.rtt().sample(50000L, ack_delay=0L)
  server.recv(client.packet(Application, [Ping]), "moved", 3000L)
  let mut challenge = b""
  for item in sent(server, 3000L) {
    client.receive(item.0)
  }
  for frame in client.frames {
    if frame is PathChallenge(data) {
      challenge = data
    }
  }
  server.recv(
    client.packet(Application, [PathResponse(challenge)]),
    "moved",
    3100L,
  )
  assert_true(conn.path_validated())
  assert_true(conn.validated())
  assert_false(conn.sender.recovery.rtt().sampled)
  // The budget is gone once the address has proven itself.
  conn.write(0UL, Bytes::make(40000, b'x'))
  let total = sent(server, 3200L).fold(init=0, (sum, item) => {
    sum + item.0.length()
  })
  assert_true(total > 3000)
}

///|
test "a path that never answers is given up, and the connection goes back" {
  let (server, client, conn) = settled()
  // Padded, so the budget has room to ask again.
  server.recv(client.packet(Application, [Ping, Padding(1200)]), "moved", 3000L)
  assert_eq(conn.peer(), "moved")
  ignore(sent(server, 3000L))
  let pto = conn.sender.recovery.pto()
  // One timeout on: asked again, still there.
  server.tick(3000L + pto)
  assert_eq(conn.peer(), "moved")
  client.frames.clear()
  let again = sent(server, 3000L + pto)
  assert_true(again.iter().any(item => item.1 == "moved"))
  for item in again {
    client.receive(item.0)
  }
  assert_true(client.frames.iter().any(frame => frame is PathChallenge(_)))
  server.tick(3000L + path_timeouts * pto)
  assert_eq(conn.peer(), from)
  assert_true(conn.validated())
}

///|
test "a packet that does not authenticate does not keep a dead connection alive" {
  let (server, client, conn) = settled()
  let packet = client.packet(Application, [Ping])
  let forged = Bytes::makei(packet.length(), i => {
    if i == packet.length() - 1 {
      (packet[i].to_int() ^ 1).to_byte()
    } else {
      packet[i]
    }
  })
  let before = conn.last_rx
  server.recv(forged, from, before + 1000L)
  assert_eq(conn.last_rx, before)
}

///|
test "a peer that moves with a new id gets a new id back, and one that keeps its id does not" {
  let (server, client, conn) = settled()
  let original = conn.peer_cid
  let theirs = Bytes::makei(original.length(), i => (0x71 + i).to_byte())
  server.recv(
    client.packet(Application, [
      NewConnectionId(
        seq=1UL,
        retire_prior_to=0UL,
        conn_id=theirs,
        reset_token=Bytes::make(16, b'\x09'),
      ),
    ]),
    from,
    3000L,
  )
  // A NAT rebinding: same id, new address.
  server.recv(client.packet(Application, [Ping]), "rebound", 3100L)
  assert_eq(conn.peer(), "rebound")
  assert_eq(conn.peer_cid, original)
  // On purpose: a new id, from a new address.
  guard conn.ids.issued.values().collect() is [spare, ..] else {
    fail("no spare id issued")
  }
  client.dcid = spare
  server.recv(client.packet(Application, [Ping]), "chosen", 3200L)
  assert_eq(conn.peer(), "chosen")
  assert_eq(conn.peer_cid, theirs)
  client.frames.clear()
  for item in sent(server, 3200L) {
    client.receive(item.0)
  }
  assert_true(
    client.frames.iter().any(frame => frame is RetireConnectionId(0UL)),
  )
}

///|
test "retire_prior_to retires what it names, the id in use with it" {
  let (server, client, conn) = settled()
  let newer = b"\x81\x82\x83\x84\x85\x86\x87\x88"
  server.recv(
    client.packet(Application, [
      NewConnectionId(
        seq=2UL,
        retire_prior_to=2UL,
        conn_id=newer,
        reset_token=Bytes::make(16, b'\x09'),
      ),
    ]),
    from,
    3000L,
  )
  assert_eq(conn.peer_cid, newer)
  // retire_prior_to may not pass the frame's own number (RFC 9000 §19.15).
  server.recv(
    client.packet(Application, [
      NewConnectionId(
        seq=3UL,
        retire_prior_to=9UL,
        conn_id=newer,
        reset_token=Bytes::make(16, b'\x09'),
      ),
    ]),
    from,
    3100L,
  )
  assert_true(conn.phase is Closing)
}
