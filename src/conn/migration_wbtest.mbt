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
