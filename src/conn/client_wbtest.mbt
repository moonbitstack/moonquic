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
test "the splitter runs a long CRYPTO stream across packets at their offsets" {
  let runs = split_crypto(0L, Bytes::make(1600, 0))
  assert_eq(runs.length(), 2)
  assert_eq(runs[0].0, 0L)
  assert_eq(runs[0].1.length(), 1100)
  assert_eq(runs[1].0, 1100L)
  assert_eq(runs[1].1.length(), 500)
  // A stream shorter than one packet is one run.
  assert_eq(split_crypto(7L, Bytes::make(100, 0)).length(), 1)
}

///|
test "a first flight larger than a datagram splits into several Initial packets" {
  let client = make_client()
  // Stand in for the post-quantum hello: 1600 bytes of CRYPTO, past one packet.
  client.out.clear()
  client.offsets[0] = 1600L
  client.out.push((Level::Initial, 0L, Bytes::make(1600, b'c')))
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
