// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Several connections on one socket: one endpoint's datagrams are told apart by the connection
// id they carry, and nothing else has to be true of them — they may be in the handshake, past
// it, or closing all at once.

///|
fn endpoint_params() -> Bytes {
  let params = Limits::new(
    idle_timeout=30000UL,
    data=10_000_000UL,
    stream_data_bidi_local=2_000_000UL,
    stream_data_bidi_remote=1_000_000UL,
    stream_data_uni=1_000_000UL,
    streams_bidi=100UL,
    streams_uni=100UL,
  ).params()
  encode(params[:])
}

///|
fn endpoint_client() -> @tls.Client raise {
  @tls.Client::new(
    @x509.Roots::new(certs=[@x509.pem(root_pem)][:]),
    alpn=["h3"],
    suites=@tls.suites,
  )
}

///|
test "two connections on one endpoint handshake and carry streams apart" {
  let server = plain_server()
  let endpoint : ClientEndpoint = ClientEndpoint::new(
    Config::default(),
    rand=fake_rand(11),
  )
  let a = endpoint.connect(
    endpoint_client(),
    "a.example",
    endpoint_params(),
    WALL,
  )
  let b = endpoint.connect(
    endpoint_client(),
    "a.example",
    endpoint_params(),
    WALL,
  )
  assert_true(a != b)
  assert_eq(endpoint.count(), 2)
  for _ in 0..<8 {
    for datagram in endpoint.poll_out(1000L) {
      server.recv(datagram, from, 1000L, wall=WALL)
    }
    for datagram in drain(server, 1000L) {
      endpoint.recv(datagram, 1000L)
    }
  }
  let first = endpoint.client(a).unwrap()
  let second = endpoint.client(b).unwrap()
  assert_true(first.is_connected())
  assert_true(second.is_connected())
  assert_eq(server.count(), 2)
  // One stream each, and each answer comes back on the connection it belongs to.
  first.write(0UL, b"from a", fin=true)
  second.write(0UL, b"from b", fin=true)
  for datagram in endpoint.poll_out(2000L) {
    server.recv(datagram, from, 2000L, wall=WALL)
  }
  for datagram in drain(server, 2000L) {
    endpoint.recv(datagram, 2000L)
  }
  let seen : Array[Bytes] = []
  for cid in server.conn_ids() {
    guard server.conn(cid) is Some(conn) else { continue }
    let data = conn.read(0UL)
    if data.length() > 0 {
      seen.push(data)
    }
  }
  assert_eq(seen.length(), 2)
  assert_true(seen.contains(b"from a"))
  assert_true(seen.contains(b"from b"))
}

///|
test "a datagram that names no connection here is dropped" {
  let server = plain_server()
  let endpoint : ClientEndpoint = ClientEndpoint::new(
    Config::default(),
    rand=fake_rand(12),
  )
  let id = endpoint.connect(
    endpoint_client(),
    "a.example",
    endpoint_params(),
    WALL,
  )
  ignore(id)
  let junk = Buffer()
  junk.write_byte(b'\x40')
  junk.write_bytes(Bytes::make(cid_size, b'\x55'))
  junk.write_bytes(Bytes::make(40, b'\x11'))
  endpoint.recv(junk.to_bytes(), 1000L)
  assert_eq(endpoint.count(), 1)
  assert_false(endpoint.client(id).unwrap().is_connected())
  ignore(server)
}

///|
test "a connection can be forgotten once it has closed" {
  let endpoint : ClientEndpoint = ClientEndpoint::new(
    Config::default(),
    rand=fake_rand(13),
  )
  let id = endpoint.connect(
    endpoint_client(),
    "a.example",
    endpoint_params(),
    WALL,
  )
  let client = endpoint.client(id).unwrap()
  client.close(0UL, b"", 1000L)
  endpoint.remove(id)
  assert_eq(endpoint.count(), 0)
  assert_true(endpoint.client(id) is None)
}
