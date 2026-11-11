// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// QUIC version 2 (RFC 9369) and version negotiation (RFC 9368), end to end: a connection that
// speaks version 2 from its first flight, a server that offers it to a client that did not ask,
// and a client that answers that offer. The vectors that say the constants are right are in
// `crypto`; what is checked here is that the two halves of this library agree with each other
// about which version a packet carries.

///|
/// A client that offers `versions`, in that order.
fn versioned_client(
  versions : Array[UInt32],
  rand_seed : Int32,
) -> Client raise {
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
  Client::new(
    @tls.Client::new(
      @x509.Roots::new(certs=[@x509.pem(root_pem)][:]),
      alpn=["h3"],
      suites=@tls.suites,
    ),
    "a.example",
    encode(params[:]),
    fake_rand(rand_seed),
    dcid,
    scid,
    1767225600L,
    cfg={ ..Config::default(), versions, },
  )
}

///|
/// A server that speaks `versions`, in that order.
fn versioned_server(versions : Array[UInt32]) -> Endpoint[String] raise {
  Endpoint::server(
    { ..Config::default(), versions, },
    tls_server(),
    rand=fake_rand(99),
  )
}

///|
/// The version the long header at the front of `packet` carries.
fn version_of(packet : Bytes) -> UInt32 {
  @packet.read_long(packet[:]).unwrap().0.version
}

///|
test "a version 2 connection completes a handshake and carries a stream" {
  let server = versioned_server([@packet.version2])
  let client = versioned_client([@packet.version2], 5)
  exchange(client, server, 1767225600L, 1000L)
  assert_true(client.is_connected())
  // Every packet the client put on the wire was a version 2 long header.
  for packet in client.poll_out(1000L) {
    if (packet[0].to_int() & 0x80) != 0 {
      assert_eq(version_of(packet), @packet.version2)
    }
  }
  let conn = only_conn(server)
  assert_eq(conn.version, @packet.version2)
  conn.take_events() |> ignore
  client.write(0UL, b"over version two", fin=true)
  for datagram in client.poll_out(2000L) {
    server.recv(datagram, from, 2000L)
  }
  assert_eq(conn.take_events(), [Readable(0UL)])
  assert_eq(conn.read(0UL), b"over version two")
  conn.write(0UL, b"and back", fin=true)
  for datagram in drain(server, 2000L) {
    client.recv(datagram, 2000L)
  }
  assert_eq(client.read(0UL), b"and back")
}

///|
test "an unimplemented version gets the list this server speaks" {
  let server = versioned_server([@packet.version1, @packet.version2])
  let client = versioned_client([@packet.version2], 11)
  // A first flight in the version 2 draft codepoint, which no endpoint speaks.
  let h : @packet.Long = {
    packet_type: @packet.Kind::Initial,
    type_specific: 0,
    version: 0x709a50c4U,
    dcid: b"\x01\x02\x03\x04\x05\x06\x07\x08",
    scid: b"\x09\x0a",
  }
  let head = h.header(b"\x00"[:], payload=1200)
  let datagram = Buffer()
  datagram.write_bytes(head)
  datagram.write_bytes(Bytes::make(1200, 0))
  server.recv(datagram.to_bytes(), from, 1000L)
  assert_eq(server.count(), 0)
  let answers = drain(server, 1000L)
  assert_eq(answers.length(), 1)
  let (dcid, scid, versions) = @packet.read_versions(answers[0][:]).unwrap()
  assert_eq(dcid, h.scid)
  assert_eq(scid, h.dcid)
  // Both, in this server's own order of preference.
  assert_eq(versions, [@packet.version1, @packet.version2])
  // The client is untouched by a packet it never received.
  assert_false(client.is_connected())
}

///|
test "a version negotiation moves the client to a version both ends speak" {
  // The client would take either, and prefers version 1; the server speaks only version 2. One
  // round trip of Version Negotiation, then the handshake runs in version 2 (RFC 9368 §2.1).
  let server = versioned_server([@packet.version2])
  let client = versioned_client([@packet.version1, @packet.version2], 5)
  for datagram in client.poll_out(1000L) {
    assert_eq(version_of(datagram), @packet.version1)
    server.recv(datagram, from, 1000L)
  }
  // One Version Negotiation packet per first-flight datagram, which RFC 9000 §6.1 allows; the
  // client acts on the first and discards the rest (§6.2).
  let answers = drain(server, 1000L)
  assert_true(answers.length() >= 1)
  // A Version Negotiation packet names version zero and lists what the server speaks.
  assert_eq(answers[0][1].to_int(), 0)
  assert_eq(server.count(), 0)
  for datagram in answers {
    client.recv(datagram, 1000L)
  }
  assert_eq(client.versions(), [@packet.version2])
  // The restarted first flight is a version 2 one, from the same connection id.
  let restarted = client.poll_out(1000L)
  assert_eq(restarted.length() >= 1, true)
  for datagram in restarted {
    assert_eq(version_of(datagram), @packet.version2)
    server.recv(datagram, from, 1000L)
  }
  for _ in 0..<8 {
    for datagram in drain(server, 1000L) {
      client.recv(datagram, 1000L)
    }
    for datagram in client.poll_out(1000L) {
      server.recv(datagram, from, 1000L)
    }
  }
  assert_true(client.is_connected())
  assert_eq(only_conn(server).version, @packet.version2)
}

///|
test "a version negotiation the client cannot satisfy leaves it where it was" {
  let client = versioned_client([@packet.version2], 5)
  // A list that names only version 1, which this client does not offer.
  let packet = @packet.versions(
    dcid=client.scid,
    scid=client.dcid,
    [@packet.version1][:],
  )
  client.recv(packet, 1000L)
  assert_eq(client.versions(), [@packet.version1])
  assert_false(client.is_connected())
}

///|
test "a version negotiation that repeats the version sent is not an answer" {
  let client = versioned_client([@packet.version1, @packet.version2], 5)
  let packet = @packet.versions(
    dcid=client.scid,
    scid=client.dcid,
    [@packet.version1, @packet.version2][:],
  )
  // RFC 9000 §6.2: a Version Negotiation packet that lists the version the client chose is
  // discarded — the list is there to read, but nothing is negotiated and the first flight stays
  // where it was.
  client.recv(packet, 1000L)
  assert_eq(client.versions(), [@packet.version1, @packet.version2])
  assert_false(client.is_connected())
  for datagram in client.poll_out(1000L) {
    assert_eq(version_of(datagram), @packet.version1)
  }
}

///|
test "a version_information parameter carries a version and the ones beside it" {
  let param = version_information(
    @packet.version2,
    [@packet.version1, @packet.version2][:],
  )
  assert_eq(param.kind, VersionInformation)
  assert_eq(param.kind.code(), 0x11UL)
  assert_eq(
    read_version_information(param.value[:]),
    Some((@packet.version2, [@packet.version1, @packet.version2])),
  )
  // A value that is not a whole number of versions is not one, and a connection that reads one
  // closes (RFC 9368 §4).
  assert_eq(read_version_information(b"\x00\x00\x00"[:]), None)
  assert_eq(read_version_information(b""[:]), None)
  // And it survives the block it travels in.
  let block = encode([param, Param::int(MaxIdleTimeout, 30_000UL)])
  assert_eq(find(decode(block[:]), VersionInformation), Some(param))
}
