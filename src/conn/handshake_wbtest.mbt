// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A real TLS 1.3 handshake against `Endpoint::server`: the client below is moontls's QUIC client
// over packets built with this library's own sealing functions.

///|
let leaf_pem : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBUDCB96ADAgECAhRjYY5dHAd3VQ3tyPL7/3le5Fvm+TAKBggqhkjOPQQDAjAT
  #|MREwDwYDVQQDDAh0bHMgcm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00MDAxMDEwMDAw
  #|MDBaMA8xDTALBgNVBAMMBHAyNTYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ6
  #|y11wYOg06UWDk0waEosabR4QPHrtYFiqwUcCXo2B1LS7Eq9399CS6M4iIqK1mo03
  #|iNp/ZYu76deRCF96VH1Xoy0wKzAUBgNVHREEDTALgglhLmV4YW1wbGUwEwYDVR0l
  #|BAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAwRQIgZKc+Qk2H/NenjER8IGYl
  #|3XUX4v2Og5H2y8s3QfRMMu4CIQDL4Z0K1TBRZRCDpjeXoaACuBWI9dC/U7xDzPLo
  #|O7ftvA==
  #|-----END CERTIFICATE-----

///|
let root_pem : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBOTCB4aADAgECAhRBoRNE2qUhDT7gsQZp87k7rG4hgDAKBggqhkjOPQQDAjAT
  #|MREwDwYDVQQDDAh0bHMgcm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00MDAxMDEwMDAw
  #|MDBaMBMxETAPBgNVBAMMCHRscyByb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
  #|QgAE5Tl/MQGIDlEsYL0ooTHgwuwyddUOWA6mFhw0nIvogBVN7hCiqZpjzIe/+gTL
  #|2jmlCKKRFhyE8qTPTVCgAZCxh6MTMBEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO
  #|PQQDAgNHADBEAiAgWUh++JxjgLIuoat2eRS1EqNd+a7uozNrXSBWIQ9zZQIgGLI6
  #|Ec2yYljzZQ8wjbUjJnL/NRzS5dZ4+HZsSF/DXKY=
  #|-----END CERTIFICATE-----

///|
/// A counter's bytes: distinct, reproducible, and no business of a real server.
fn fake_rand(seed : Int32) -> (Int32) -> Bytes {
  let state = Ref(seed)
  n => {
    Bytes::makei(n, i => {
      state.val = state.val * 31 + i + 7
      (state.val & 0xff).to_byte()
    })
  }
}

///|
/// The key `p256_leaf` was issued for; test material, in the open on purpose.
fn leaf_key() -> @x509.PrivateKey raise {
  @x509.PrivateKey::pem(
    (
      #|-----BEGIN PRIVATE KEY-----
      #|MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkd9OIQmt6ZJz2WUh
      #|D/+AZp/or4McQbJfSAhmjgVReCKhRANCAAQ6y11wYOg06UWDk0waEosabR4QPHrt
      #|YFiqwUcCXo2B1LS7Eq9399CS6M4iIqK1mo03iNp/ZYu76deRCF96VH1X
      #|-----END PRIVATE KEY-----
    ),
  )
}

///|
fn tls_server(alpn~ : Array[String] = ["h3"]) -> @tls.Server raise {
  @tls.Server::new([@x509.pem(leaf_pem)], leaf_key(), alpn~)
}

///|
priv struct Peer {
  tls : @tls.Conn
  original : Bytes
  scid : Bytes
  mut dcid : Bytes
  initial_tx : @crypto.Keys
  initial_rx : @crypto.Keys
  mut hs_tx : @crypto.Keys?
  mut hs_rx : @crypto.Keys?
  mut app_tx : @crypto.Keys?
  mut app_rx : @crypto.Keys?
  mut app_tx_secret : Bytes
  mut key_phase : Bool
  mut suite : @crypto.Suite
  spaces : Array[@packet.Space]
  crypto : Array[@stream.Assembler]
  stream_data : Map[UInt64, Buffer]
  finished : Array[UInt64]
  frames : Array[@frame.Frame]
  mut server_cid_seen : Bool
  queued : Array[Bytes]
  offsets : Array[UInt64]
}

///|
fn Peer::new(
  alpn~ : Array[String] = ["h3"],
  suites? : Array[@record.Suite],
) -> Peer raise {
  let original = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
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
    suites=suites.unwrap_or(@tls.suites),
  )
  let tls = @tls.Conn::quic_client(
    config,
    "a.example",
    params=encode(params[:]),
    rand=fake_rand(5),
    now=1767225600L,
  )
  let (tx, rx) = @crypto.initial(original[:])
  {
    tls,
    original,
    scid,
    dcid: original,
    initial_tx: tx,
    initial_rx: rx,
    hs_tx: None,
    hs_rx: None,
    app_tx: None,
    app_rx: None,
    app_tx_secret: b"",
    key_phase: false,
    suite: @crypto.suite,
    spaces: [@packet.Space::new(), @packet.Space::new(), @packet.Space::new()],
    crypto: [
      @stream.Assembler::new(),
      @stream.Assembler::new(),
      @stream.Assembler::new(),
    ],
    stream_data: Map([]),
    finished: [],
    frames: [],
    server_cid_seen: false,
    queued: [],
    offsets: [0UL, 0UL, 0UL],
  }
}

///|
fn index(level : @tls.Level) -> Int32 {
  match level {
    Initial => 0
    Handshake => 1
    Application => 2
  }
}

///|
fn Peer::packet(
  self : Peer,
  level : @tls.Level,
  frames : Array[@frame.Frame],
) -> Bytes {
  let pn = self.spaces[index(level)].next_packet_number()
  match level {
    Initial => {
      let payload = @packet.payload(frames)
      pad(
        payload,
        p => {
          seal_long(
            Initial,
            1U,
            self.dcid,
            self.scid,
            pn,
            4,
            p,
            self.initial_tx,
          )
        },
        1200,
      )
    }
    Handshake =>
      send_long(
        Handshake,
        1U,
        self.dcid,
        self.scid,
        pn,
        4,
        frames,
        self.hs_tx.unwrap(),
        suite=self.suite,
      )
    Application =>
      send_short(
        self.dcid,
        pn,
        4,
        frames,
        self.app_tx.unwrap(),
        key_phase=self.key_phase,
        suite=self.suite,
      )
  }
}

///|
/// Do what the handshake asks: install keys now, and hold datagrams for `flush`. The keys cannot
/// wait, because the packet after this one in a datagram may need them.
fn Peer::absorb(self : Peer) -> Unit {
  let out = self.queued
  let offsets = self.offsets
  for step in self.tls.steps() {
    match step {
      Send(level, data) => {
        let at = index(level)
        out.push(self.packet(level, [Crypto(offset=offsets[at], data~)]))
        offsets[at] = offsets[at] + data.length().to_uint64()
      }
      Keys(level, client~, server~) => {
        if self.tls.suite() is Some(s) {
          self.suite = suite_of(s)
        }
        let tx = @crypto.Keys::of(client[:], suite=self.suite)
        let rx = @crypto.Keys::of(server[:], suite=self.suite)
        match level {
          Handshake => {
            self.hs_tx = Some(tx)
            self.hs_rx = Some(rx)
          }
          Application => {
            self.app_tx = Some(tx)
            self.app_rx = Some(rx)
            self.app_tx_secret = client
          }
          Initial => ()
        }
      }
    }
  }
}

///|
/// The datagrams answering what the handshake has queued.
fn Peer::flush(self : Peer) -> Array[Bytes] {
  self.absorb()
  let out = self.queued.copy()
  self.queued.clear()
  out
}

///|
fn Peer::on_frames(
  self : Peer,
  level : @tls.Level,
  frames : Array[@frame.Frame],
  pn : Int64,
) -> Unit raise {
  let at = index(level)
  self.spaces[at].on_packet_received(pn, @packet.payload_elicits_ack(frames))
  for frame in frames {
    self.frames.push(frame)
    match frame {
      Crypto(offset~, data~) => {
        self.crypto[at].insert(offset, data, fin=false)
        let ready = self.crypto[at].read()
        if ready.length() > 0 {
          self.tls.crypto(level, ready[:])
          self.absorb()
        }
      }
      Stream(id~, offset~, fin~, data~) => {
        let buffer = match self.stream_data.get(id) {
          Some(b) => b
          None => {
            let b = Buffer()
            self.stream_data[id] = b
            b
          }
        }
        assert_eq(offset, buffer.length().to_uint64())
        buffer.write_bytes(data)
        if fin {
          self.finished.push(id)
        }
      }
      _ => ()
    }
  }
}

///|
fn[T] must(value : T?, what : String) -> T raise {
  match value {
    Some(v) => v
    None => fail("expected " + what)
  }
}

///|
/// Take a datagram from the server, packet by packet.
fn Peer::receive(self : Peer, datagram : Bytes) -> Unit raise {
  let mut at = 0
  while at < datagram.length() {
    let view = datagram[at:]
    if (view[0].to_int() & 0x80) == 0 {
      let keys = must(self.app_rx, "1-RTT keys")
      let largest = self.spaces[2].largest_received()
      let (frames, pn) = must(
        recv_short(
          view.to_owned(),
          self.scid.length(),
          keys,
          largest~,
          suite=self.suite,
        ),
        "a 1-RTT packet that opens",
      )
      self.on_frames(Application, frames, pn)
      return
    }
    let (h, tail) = must(@packet.read_header(view), "a long header")
    let size = tail.at + tail.length.to_int()
    let packet = view[0:size].to_owned()
    at = at + size
    if !self.server_cid_seen {
      self.dcid = h.scid
      self.server_cid_seen = true
    }
    match h.packet_type {
      Initial => {
        let largest = self.spaces[0].largest_received()
        let (frames, pn) = must(
          recv_long(packet, self.initial_rx, largest~),
          "an Initial that opens",
        )
        self.on_frames(Initial, frames, pn)
      }
      Handshake => {
        let largest = self.spaces[1].largest_received()
        let (frames, pn) = must(
          recv_long(
            packet,
            must(self.hs_rx, "Handshake keys"),
            largest~,
            suite=self.suite,
          ),
          "a Handshake packet that opens",
        )
        self.on_frames(Handshake, frames, pn)
      }
      _ => ()
    }
  }
}

///|
fn Peer::ack(self : Peer, level : @tls.Level) -> Bytes? {
  let space = self.spaces[index(level)]
  guard space.ack_pending() && space.build_ack(0UL) is Some(frame) else {
    return None
  }
  Some(self.packet(level, [frame]))
}

///|
let from : String = "peer"

///|
/// Every datagram the server has ready, in order.
fn drain(server : Endpoint[String], now : Int64) -> Array[Bytes] raise {
  let out : Array[Bytes] = []
  while server.poll_out(now) is Some((datagram, _)) {
    out.push(datagram)
  }
  out
}

///|
fn only_conn(server : Endpoint[String]) -> Session[String] {
  assert_only(server.conns.values().collect())
}

///|
fn[A] assert_only(all : Array[A]) -> A {
  guard all is [one] else { abort("expected one connection") }
  one
}

///|
/// Run a handshake to the end. The client's last flight goes out as one datagram, its Finished
/// and a 1-RTT PING coalesced, as real clients do.
fn connect(
  client : Peer,
  server : Endpoint[String],
  now~ : Int64 = 1000L,
) -> Unit raise {
  for hello in client.flush() {
    server.recv(hello, from, now)
  }
  for datagram in drain(server, now) {
    client.receive(datagram)
  }
  let flight = client.flush()
  assert_eq(flight.length(), 1)
  let datagram = Buffer()
  datagram.write_bytes(flight[0])
  datagram.write_bytes(client.packet(Application, [Ping]))
  server.recv(datagram.to_bytes(), from, now)
}

///|
fn new_server(cfg? : Config) -> Endpoint[String] raise {
  Endpoint::server(
    cfg.unwrap_or(Config::default()),
    tls_server(),
    rand=fake_rand(99),
  )
}

///|
test "a client completes the handshake against a real certificate" {
  let server = new_server()
  let client = Peer::new()
  connect(client, server)
  let conn = only_conn(server)
  assert_true(client.tls.is_connected())
  assert_eq(conn.take_events(), [Connected])
  assert_eq(conn.alpn(), Some("h3"))
  assert_eq(conn.server_name(), Some("a.example"))
  assert_true(conn.validated())
  assert_eq(client.dcid, conn.cid())
  assert_true(client.dcid != client.original)
  for datagram in drain(server, 2000L) {
    client.receive(datagram)
  }
  assert_true(client.frames.contains(HandshakeDone))
}

///|
test "every cipher suite reaches 1-RTT" {
  for
    suite in [
      @record.Suite::Aes128Gcm,
      @record.Suite::Aes256Gcm,
      @record.Suite::ChaCha20Poly1305,
    ] {
    let server = new_server()
    let client = Peer::new(suites=[suite])
    connect(client, server)
    let conn = only_conn(server)
    assert_eq(conn.take_events(), [Connected])
    assert_eq(client.tls.suite(), Some(suite))
    conn.write(0UL, b"over", fin=true)
    for datagram in drain(server, 2000L) {
      client.receive(datagram)
    }
    assert_eq(client.finished, [0UL])
  }
}

///|
test "the server's first datagram is padded and within three times what arrived" {
  let server = new_server()
  let client = Peer::new()
  let hello = client.flush()
  server.recv(hello[0], from, 1000L)
  let sent = drain(server, 1000L)
  assert_true(sent.length() > 0)
  assert_true(sent[0].length() >= 1200)
  let total = sent.fold(init=0, (sum, d) => sum + d.length())
  assert_true(total <= 3 * hello[0].length())
}

///|
test "a stream goes both ways, with its credit coming back as the application reads" {
  let cfg = { ..Config::default(), initial_max_stream_data: 4096UL, }
  let server = new_server(cfg~)
  let client = Peer::new()
  connect(client, server)
  let conn = only_conn(server)
  conn.take_events() |> ignore
  let body = Bytes::make(4000, b'x')
  server.recv(
    client.packet(Application, [Stream(id=0UL, offset=0UL, fin=true, data=body)]),
    from,
    2000L,
  )
  assert_eq(conn.take_events(), [Readable(0UL)])
  assert_false(conn.finished(0UL))
  assert_eq(conn.read(0UL).length(), 4000)
  assert_true(conn.finished(0UL))
  let before = client.frames.length()
  for datagram in drain(server, 2000L) {
    client.receive(datagram)
  }
  assert_true(
    client.frames[before:].iter().any(f => f is MaxStreamData(id=0UL, ..)),
  )
}

///|
test "a response spanning many datagrams arrives whole and leaves nothing held" {
  let server = new_server()
  let client = Peer::new()
  connect(client, server)
  let conn = only_conn(server)
  let body = Bytes::makei(20000, i => (i & 0xff).to_byte())
  conn.write(0UL, body[:8000].to_owned())
  conn.write(0UL, body[8000:].to_owned(), fin=true)
  let mut now = 2000L
  for _ in 0..<200 {
    if client.finished.length() > 0 {
      break
    }
    for datagram in drain(server, now) {
      assert_true(datagram.length() <= 1200)
      client.receive(datagram)
    }
    if client.ack(Application) is Some(ack) {
      server.recv(ack, from, now)
    }
    now = now + 1000L
  }
  assert_eq(client.finished, [0UL])
  assert_eq(client.stream_data[0].to_bytes(), body)
  if client.ack(Application) is Some(ack) {
    server.recv(ack, from, now)
  }
  assert_eq(conn.buffered(0UL), 0UL)
}

///|
test "a lost handshake flight goes out again when the probe timer fires" {
  let server = new_server()
  let client = Peer::new()
  for hello in client.flush() {
    server.recv(hello, from, 1000L)
  }
  let first = drain(server, 1000L)
  assert_true(first.length() > 0)
  assert_eq(drain(server, 1000L).length(), 0)
  let later = 2_000_000L
  server.tick(later)
  for datagram in drain(server, later) {
    client.receive(datagram)
  }
  let flight = client.flush()
  server.recv(flight[0], from, later)
  assert_true(client.tls.is_connected())
  assert_eq(only_conn(server).take_events(), [Connected])
}

///|
test "the client moving to the next key phase moves the server too" {
  let server = new_server()
  let client = Peer::new()
  connect(client, server)
  let conn = only_conn(server)
  conn.take_events() |> ignore
  let (secret, rolled) = @crypto.next(
    client.app_tx_secret[:],
    suite=client.suite,
  )
  client.app_tx = Some({ ..rolled, hp: client.app_tx.unwrap().hp, })
  client.app_tx_secret = secret
  client.key_phase = true
  server.recv(
    client.packet(Application, [
      Stream(id=0UL, offset=0UL, fin=true, data=b"after"),
    ]),
    from,
    2000L,
  )
  assert_eq(conn.take_events(), [Readable(0UL)])
  assert_eq(conn.read(0UL), b"after")
}

///|
test "a client with no protocol in common is closed with the TLS alert's code" {
  let server = new_server()
  let client = Peer::new(alpn=["other"])
  for hello in client.flush() {
    server.recv(hello, from, 1000L)
  }
  let conn = only_conn(server)
  assert_eq(conn.take_events(), [Closed(0x178UL)])
  assert_eq(conn.phase(), Closing)
  for datagram in drain(server, 1000L) {
    client.receive(datagram)
  }
  assert_true(
    client.frames.iter().any(f => f is ConnectionClose(error_code=0x178UL, ..)),
  )
}

///|
test "an Initial in a datagram under 1200 bytes opens nothing" {
  let server = new_server()
  let client = Peer::new()
  let frames : Array[@frame.Frame] = [Ping]
  let short = send_long(
    Initial,
    1U,
    client.dcid,
    client.scid,
    0L,
    4,
    frames,
    client.initial_tx,
  )
  server.recv(short, from, 1000L)
  assert_eq(server.count(), 0)
}

///|
test "an unknown version is answered with the versions this server speaks" {
  let server = new_server()
  let h : @packet.Long = {
    packet_type: Initial,
    type_specific: 0,
    version: 0x0a0a0a0aU,
    dcid: b"\x01\x02\x03\x04\x05\x06\x07\x08",
    scid: b"\x09\x0a",
  }
  let head = h.header(b"\x00"[:], payload=1200)
  let datagram = Buffer()
  datagram.write_bytes(head)
  datagram.write_bytes(Bytes::make(1200, 0))
  server.recv(datagram.to_bytes(), from, 1000L)
  assert_eq(server.count(), 0)
  let answer = drain(server, 1000L)
  assert_eq(answer.length(), 1)
  let (dcid, scid, versions) = @packet.read_versions(answer[0][:]).unwrap()
  assert_eq(dcid, h.scid)
  assert_eq(scid, h.dcid)
  assert_eq(versions, [1U])
}

///|
test "an idle connection is gone, and its application is told" {
  let server = new_server()
  let client = Peer::new()
  connect(client, server)
  let conn = only_conn(server)
  conn.take_events() |> ignore
  server.take_busy() |> ignore
  server.tick(60_000_000L)
  assert_eq(server.count(), 0)
  assert_eq(conn.take_events(), [Closed(0UL)])
  assert_eq(server.take_busy().length(), 1)
}

///|
test "a window lost whole still gets a probe out, past the closed window" {
  let s = Sender::new(1_000_000UL, 1_000_000UL, 1200L, 25000L, 1000L, 1000UL)
  s.queue_stream(0UL, Bytes::make(100000, b'z'))
  let mut sent = 0
  while s.poll_send(1000L) is Some(_) {
    sent = sent + 1
  }
  assert_true(sent > 0)
  assert_eq(s.poll_send(1000L), None)
  assert_true(s.on_pto_timeout(10_000_000L))
  let (_, frames) = s.poll_send(10_000_000L).unwrap()
  assert_true(frames[0] is Stream(offset=0UL, ..))
}

///|
test "a probe with nothing to resend is a PING" {
  let s = Sender::new(1_000_000UL, 1_000_000UL, 1200L, 25000L, 1000L, 1000UL)
  s.queue_stream(0UL, b"hello")
  let (first, _) = s.poll_send(1000L).unwrap()
  assert_true(s.on_pto_timeout(10_000_000L))
  let (_, again) = s.poll_send(10_000_000L).unwrap()
  assert_true(again[0] is Stream(offset=0UL, ..))
  let (_, ping) = s.poll_send(10_000_000L).unwrap()
  assert_eq(ping, [Ping])
  assert_true(first >= 0L)
}

///|
test "stream data written in two goes is sent as one run, and released as it is acknowledged" {
  let s = Sender::new(1_000_000UL, 1_000_000UL, 1200L, 25000L, 1000L, 4UL)
  s.queue_stream(0UL, b"abc")
  s.queue_stream(0UL, b"defgh")
  s.queue_fin(0UL)
  let got = Buffer()
  let mut largest = 0L
  while s.poll_send(1000L) is Some((pn, frames)) {
    largest = pn
    guard frames[0] is Stream(offset~, data~, ..) else { fail("not a stream") }
    assert_eq(offset, got.length().to_uint64())
    got.write_bytes(data)
  }
  assert_eq(got.to_bytes(), b"abcdefgh")
  assert_eq(s.buffered(0UL), 8UL)
  let ack : @frame.Frame = Ack(
    largest=largest.reinterpret_as_uint64(),
    delay=0UL,
    first_range=largest.reinterpret_as_uint64(),
    ranges=[],
  )
  s.on_ack(ack, 2000L)
  assert_eq(s.buffered(0UL), 0UL)
}

///|
test "abandoning a stream resets it and drops what was queued" {
  let s = Sender::new(1_000_000UL, 1_000_000UL, 1200L, 25000L, 1000L, 4UL)
  s.queue_stream(0UL, b"abcdefgh")
  let _ = s.poll_send(1000L)
  s.abandon(0UL, 7UL)
  let (_, frames) = s.poll_send(1000L).unwrap()
  assert_eq(frames, [ResetStream(id=0UL, error_code=7UL, final_size=8UL)])
  assert_eq(s.poll_send(1000L), None)
}
