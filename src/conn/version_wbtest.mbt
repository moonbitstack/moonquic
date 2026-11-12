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

///|
/// Drive a handshake in which the client has already sent its first flight, keeping both clocks
/// the way `exchange` does, and answer how many rounds it took.
fn complete(
  client : Client,
  server : Endpoint[String],
  wall : Int64,
  now : Int64,
) -> Unit raise {
  for _ in 0..<8 {
    for datagram in drain(server, now) {
      client.recv(datagram, now)
    }
    for datagram in client.poll_out(now) {
      server.recv(datagram, from, now, wall~)
    }
  }
}

///|
/// A ClientHello carrying exactly the transport parameter block it is given. Used to hold the
/// first-flight reader to the four outcomes RFC 9368 §4 names, without running a handshake.
fn hello_with(params : Bytes) -> Bytes {
  let extensions : Array[@ext.Ext] = [
    { kind: @ext.QuicTransportParameters, data: params, },
  ]
  let hello : @msg.Hello = {
    version: 0x0303,
    random: Bytes::make(32, b'\x00'),
    session_id: b"",
    cookie: b"",
    suites: [0x1301],
    compression: b"\x00",
    extensions,
  }
  // `msg::hello` already frames the message; framing it again would put a handshake header
  // where the ClientHello body belongs.
  @msg.hello(hello)
}

///|
/// A client whose first flight is version 1 but whose own `version_information` names another
/// Chosen Version. §4 makes that a version negotiation error, and §2.3 says a server reads the
/// parameter before it starts the handshake, so the connection never reaches EncryptedExtensions.
fn lying_client(chosen : UInt32) -> Client raise {
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
  params.push(
    version_information(chosen, [@packet.version1, @packet.version2][:]),
  )
  Client::new(
    @tls.Client::new(
      @x509.Roots::new(certs=[@x509.pem(root_pem)][:]),
      alpn=["h3"],
      suites=@tls.suites,
    ),
    "a.example",
    encode(params[:]),
    fake_rand(7),
    dcid,
    scid,
    1767225600L,
    cfg={ ..Config::default(), versions: [@packet.version1, @packet.version2], },
  )
}

///|
test "a server converts a first flight into the version it prefers, without a negotiation packet" {
  // The client sends its first flight in version 1 and says it would take version 2; the server
  // speaks both but prefers version 2. RFC 9368 §2.3: it selects version 2, converts the first
  // flight, and answers in version 2. There is no Version Negotiation packet and no restart.
  let server = versioned_server([@packet.version2, @packet.version1])
  let client = versioned_client([@packet.version1, @packet.version2], 5)
  let wall = 1767225600L
  let first = client.poll_out(1000L)
  assert_true(first.length() > 0)
  for datagram in first {
    assert_eq(version_of(datagram), @packet.version1)
    server.recv(datagram, from, 1000L, wall~)
  }
  complete(client, server, wall, 1000L)
  assert_true(client.is_connected())
  assert_eq(client.version, @packet.version2)
  assert_eq(client.versions(), [])
  assert_eq(only_conn(server).version, @packet.version2)
  assert_eq(server.count(), 1)
  // Everything the server answered with after the first-flight ACK is a version 2 long header,
  // and the stream still goes both ways under the negotiated version's labels.
  let conn = only_conn(server)
  conn.take_events() |> ignore
  client.write(0UL, b"converted", fin=true)
  for datagram in client.poll_out(2000L) {
    server.recv(datagram, from, 2000L, wall~)
  }
  let conn = only_conn(server)
  assert_eq(conn.take_events(), [Readable(0UL)])
  assert_eq(conn.read(0UL), b"converted")
  conn.write(0UL, b"and back", fin=true)
  for datagram in drain(server, 2000L) {
    assert_true(
      (datagram[0].to_int() & 0x80) == 0 ||
      version_of(datagram) == @packet.version2,
    )
    client.recv(datagram, 2000L)
  }
  assert_eq(client.read(0UL), b"and back")
}

///|
test "a server whose first preference is the client's Chosen Version does not convert" {
  let server = versioned_server([@packet.version1, @packet.version2])
  let client = versioned_client([@packet.version1, @packet.version2], 5)
  let wall = 1767225600L
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L, wall~)
  }
  complete(client, server, wall, 1000L)
  assert_true(client.is_connected())
  assert_eq(client.version, @packet.version1)
  assert_eq(only_conn(server).version, @packet.version1)
}

///|
test "a client that offers only its Chosen Version disables compatible negotiation" {
  // RFC 9368 §2.3: the server may only select from the client's Available Versions.
  let server = versioned_server([@packet.version2, @packet.version1])
  let client = versioned_client([@packet.version1], 5)
  let wall = 1767225600L
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L, wall~)
  }
  complete(client, server, wall, 1000L)
  assert_true(client.is_connected())
  assert_eq(client.version, @packet.version1)
  assert_eq(only_conn(server).version, @packet.version1)
}

///|
test "a server closes when a client's Chosen Version is not the version its flight used" {
  let server = versioned_server([@packet.version1, @packet.version2])
  let client = lying_client(@packet.version2)
  let wall = 1767225600L
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L, wall~)
  }
  complete(client, server, wall, 1000L)
  assert_false(client.is_connected())
  let conn = only_conn(server)
  assert_eq(conn.phase, Closing)
  assert_eq(conn.take_events(), [Closed(version_negotiation_error)])
}

///|
test "the first-flight reader names all four outcomes RFC 9368 §4 asks for" {
  let client = versioned_client([@packet.version1, @packet.version2], 5)
  let hello = client.initial_out.bytes
  guard client_version_information(hello[:]) is Present(chosen, available) else {
    fail("a real ClientHello should carry version_information")
  }
  assert_eq(chosen, @packet.version1)
  assert_eq(available, [@packet.version1, @packet.version2])
  // A ClientHello split across Initial packets is not an answer yet.
  guard client_version_information(hello[:100]) is Incomplete else {
    fail("a partial ClientHello is incomplete")
  }
  let good = hello_with(
    encode([
      version_information(
        @packet.version2,
        [@packet.version1, @packet.version2][:],
      ),
    ]),
  )
  guard client_version_information(good[:]) is Present(c, a) else {
    fail("a crafted hello should carry version_information")
  }
  assert_eq(c, @packet.version2)
  assert_eq(a, [@packet.version1, @packet.version2])
  let malformed = hello_with(
    encode([{ kind: VersionInformation, value: b"\x00\x00\x00", }]),
  )
  guard client_version_information(malformed[:]) is Malformed else {
    fail("a three-byte version list is malformed")
  }
  let absent = hello_with(encode([Param::int(MaxIdleTimeout, 30_000UL)]))
  guard client_version_information(absent[:]) is Absent else {
    fail("a hello without the parameter is absent, not malformed")
  }
}

///|
test "the negotiated version is the first compatible one in the server's own order" {
  let both = Config::default()
  let v1 = @packet.version1
  let v2 = @packet.version2
  let prefer2 : Config = { ..both, versions: [v2, v1], }
  assert_eq(choose_version(both, v1, [v1, v2]), v1)
  assert_eq(choose_version(prefer2, v1, [v1, v2]), v2)
  assert_eq(choose_version(prefer2, v2, [v2]), v2)
  // A client that offers only its Chosen Version: the identity transformation.
  assert_eq(choose_version(prefer2, v1, [v1]), v1)
  // A version neither end speaks is not assumed compatible (§2.2).
  assert_eq(choose_version(prefer2, v1, [0x709a50c4U]), v1)
  assert_eq(compatible(v1, v2), true)
  assert_eq(compatible(v2, v1), true)
  assert_eq(compatible(v1, 0x709a50c4U), false)
}

///|
test "version zero in a version_information parameter is a parsing failure" {
  assert_eq(read_version_information(b"\x00\x00\x00\x00"[:]), None)
  assert_eq(
    read_version_information(b"\x00\x00\x00\x01\x00\x00\x00\x00"[:]),
    None,
  )
}

///|
test "a converted server re-derives both directions' Initial keys" {
  // RFC 9368 §2.3: after converting a first flight, the handshake completes in the Negotiated
  // Version. That means the keys of *both* directions, not only the server's replies.
  let dcid = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
  let s = Server::new(dcid, version=@packet.version1)
  let v2 = @crypto.Version::of(@packet.version2).unwrap()
  let (want_rx, want_tx) = @crypto.initial(dcid[:], version=v2)
  s.convert_to(@packet.version2)
  assert_eq(s.initial_keys, want_rx)
  assert_eq(s.reply_keys, want_tx)
  assert_eq(s.version, @packet.version2)
  // The identity transformation leaves everything where it was.
  s.convert_to(@packet.version2)
  assert_eq(s.initial_keys, want_rx)
  assert_eq(s.reply_keys, want_tx)
}

///|
test "a converted server still opens Initial packets in both versions" {
  // §2.3 explicitly allows a server to answer the first packet in the client's Chosen Version
  // before switching. A client that has not seen that answer can therefore still be sending
  // version 1 Initials, while everything after the switch is protected under version 2.
  let server = versioned_server([@packet.version2, @packet.version1])
  let client = versioned_client([@packet.version1, @packet.version2], 5)
  let wall = 1767225600L
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L, wall~)
  }
  let conn = only_conn(server)
  assert_eq(conn.version, @packet.version2)
  // Consume the ACK the first flight earned, so the next assertion is about our own packets.
  drain(server, 1000L) |> ignore
  let dcid = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
  let (v1_tx, _) = @crypto.initial(
    dcid[:],
    version=@crypto.Version::of(@packet.version1).unwrap(),
  )
  let (v2_tx, _) = @crypto.initial(
    dcid[:],
    version=@crypto.Version::of(@packet.version2).unwrap(),
  )
  let in_v1 = send_long(
    @packet.Kind::Initial,
    @packet.version1,
    conn.cid(),
    client.scid,
    10L,
    4,
    [@frame.Ping],
    v1_tx,
  )
  let in_v2 = send_long(
    @packet.Kind::Initial,
    @packet.version2,
    conn.cid(),
    client.scid,
    11L,
    4,
    [@frame.Ping],
    v2_tx,
  )
  server.recv(in_v1, from, 1000L, wall~)
  assert_true(only_conn(server).core().initial_ack_pending())
  drain(server, 1000L) |> ignore
  server.recv(in_v2, from, 1000L, wall~)
  assert_true(only_conn(server).core().initial_ack_pending())
  assert_eq(only_conn(server).phase, Active)
}
