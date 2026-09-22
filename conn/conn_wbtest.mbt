// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A hex string as bytes, and back.
fn qv_hexb(h : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < h.length(); i = i + 2 {
    buf.write_byte(
      ((qv_nibble(h[i].to_int()) << 4) | qv_nibble(h[i + 1].to_int())).to_byte(),
    )
  }
  buf.to_bytes()
}

///|
fn qv_nibble(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    0
  }
}

///|
fn qv_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}

///|
/// Where the packet number starts in a received Initial packet.
fn pn_offset(packet : Bytes) -> Int raise @packet.Refused {
  guard @packet.read_header(packet[:]) is Some((_, tail)) else {
    raise @packet.Malformed("the Initial packet's header does not parse")
  }
  tail.at
}

// The transport parameters, the packet-number spaces and CRYPTO streams, the send
// loop, the server handshake, and the connection table — RFC 9000 §7, §12.3, §18.

///|
test "transport parameters encode to the RFC 9000 §18 (id, length, value) form" {
  let params : Array[Param] = [
    Param::int(MaxData, 1048576UL),
    Param::int(MaxStreamsBidi, 100UL),
    // initial_source_connection_id carries raw bytes, not a varint.
    { kind: InitialScid, value: qv_hexb("8394c8f03e515708"), },
  ]
  // id 04 len 04 value 80100000 (varint 1048576); id 08 len 02 value 4064 (100);
  // id 0f len 08 value = the 8-byte connection id.
  assert_eq(qv_hex(encode(params)), "040480100000080240640f088394c8f03e515708")
}

///|
test "transport parameters round-trip and integer values read back" {
  let params : Array[Param] = [
    Param::int(MaxIdleTimeout, 30000UL),
    Param::int(ActiveConnectionIdLimit, 8UL),
    Param::int(MaxUdpPayload, 1472UL),
  ]
  let encoded = encode(params)
  match decode(encoded[:]) {
    Some(got) => {
      assert_eq(got.length(), 3)
      assert_eq(got[0].kind, MaxIdleTimeout)
      assert_eq(Param::as_int(got[0]), Some(30000UL))
      assert_eq(Param::as_int(got[2]), Some(1472UL))
    }
    None => fail("transport params should decode")
  }
}

///|
test "a truncated transport-parameter block decodes to None" {
  // id 04, length 04, but only two value bytes supplied.
  assert_eq(decode(qv_hexb("04048010")[:]) is None, true)
}

///|
test "conn: packet-number spaces are independent" {
  let c = Conn::new(false)
  assert_eq(c.is_server(), false)
  // Send numbers advance per space.
  assert_eq(c.next_packet_number(Level::Initial), 0)
  assert_eq(c.next_packet_number(Level::Initial), 1)
  assert_eq(c.next_packet_number(Level::Handshake), 0)
  assert_eq(c.next_packet_number(Level::Application), 0)
}

///|
test "conn: a received packet is acknowledged only in its own space" {
  let c = Conn::new(true)
  c.on_packet_received(Level::Initial, 0, true)
  c.on_packet_received(Level::Initial, 1, true)
  // Initial owes an ACK covering 0..1; Handshake has received nothing.
  match c.build_ack(Level::Initial, 0) {
    Some(Ack(largest~, first_range~, ..)) => {
      assert_eq(largest, 1)
      assert_eq(first_range, 1)
    }
    _ => abort("expected an Initial ACK")
  }
  assert_eq(c.build_ack(Level::Handshake, 0), None)
}

///|
test "conn: the largest acknowledged is tracked per space" {
  let c = Conn::new(false)
  c.on_ack_received(Level::Handshake, 7)
  assert_eq(c.space(Level::Handshake).largest_acked(), Some(7))
  assert_eq(c.space(Level::Initial).largest_acked(), None)
}

///|
test "conn: CRYPTO frames reassemble per level, out of order" {
  let c = Conn::new(false)
  // Initial CRYPTO: the tail arrives first, then the head fills the gap.
  assert_eq(c.on_crypto_frame(Level::Initial, 3, b"def"), b"")
  assert_eq(c.on_crypto_frame(Level::Initial, 0, b"abc"), b"abcdef")
  // Handshake CRYPTO is a separate stream, still at offset 0.
  assert_eq(c.on_crypto_frame(Level::Handshake, 0, b"TLS"), b"TLS")
  // The Initial stream continues from where it left off.
  assert_eq(c.on_crypto_frame(Level::Initial, 6, b"ghi"), b"ghi")
}

///|
test "conn: a CRYPTO gap holds back later handshake bytes" {
  let c = Conn::new(true)
  assert_eq(c.on_crypto_frame(Level::Handshake, 2, b"cd"), b"")
  assert_eq(c.on_crypto_frame(Level::Handshake, 0, b"ab"), b"abcd")
}

///|
test "Initial packet: protect then parse recovers the frames with derived keys" {
  let dcid = qv_hexb("8394c8f03e515708")
  let scid = qv_hexb("0102030405")
  let keys = @crypto.initial(dcid[:]).0
  let frames : Array[@frame.Frame] = [
    @frame.Crypto(offset=0, data=b"CLIENTHELLO-bytes"),
    @frame.Ping,
  ]
  let packet = send_long(Initial, 1U, dcid, scid, 2, 4, frames, keys)
  // The receiver shares the Initial keys (derived from the same DCID).
  match recv_long(packet, keys) {
    Some((recovered, pn)) => {
      assert_eq(pn, 2)
      assert_eq(recovered, frames)
    }
    None => abort("Initial packet failed to authenticate")
  }
}

///|
test "Initial packet: the packet-number offset lands after the length field" {
  let dcid = qv_hexb("8394c8f03e515708")
  let scid = qv_hexb("0102030405")
  let keys = @crypto.initial(dcid[:]).0
  let packet = send_long(Initial, 1U, dcid, scid, 0, 4, [@frame.Ping], keys)
  // 1 (first byte) + 4 (version) + 1 + 8 (DCID) + 1 + 5 (SCID) + 1 (token len 0) +
  // 1 (length varint: value 21 fits one byte) = 22.
  assert_eq(pn_offset(packet), 22)
}

///|
test "Initial packet: tampering breaks authentication" {
  let dcid = qv_hexb("8394c8f03e515708")
  let keys = @crypto.initial(dcid[:]).0
  let packet = send_long(
    Initial,
    1U,
    dcid,
    b"",
    1,
    4,
    [@frame.Crypto(offset=0, data=b"hello")],
    keys,
  )
  // Flip the last byte of the ciphertext so the AEAD tag no longer verifies.
  let buf = Buffer()
  for i = 0; i < packet.length(); i = i + 1 {
    if i == packet.length() - 1 {
      buf.write_byte((packet[i].to_int() ^ 0xff).to_byte())
    } else {
      buf.write_byte(packet[i])
    }
  }
  assert_eq(recv_long(buf.to_bytes(), keys), None)
}

///|
fn sender_poll(s : Sender, now : Int64) -> (Int64, Array[@frame.Frame]) raise {
  match s.poll_send(now) {
    Some(p) => p
    None => abort("expected a packet to send")
  }
}

///|
test "sender: schedules queued stream data into packets and an ACK clears them" {
  let s = Sender::new(100000UL, 100000UL, 1200L, 25000L, 1000L, 8UL)
  s.queue_stream(0UL, b"abcdefghij") // 10 bytes, max frame 8 → 8 then 2
  s.queue_fin(0UL)
  let (pn0, f0) = sender_poll(s, 0L)
  assert_eq(pn0, 0L)
  match f0[0] {
    Stream(id~, offset~, fin~, data~) => {
      assert_eq(id, 0UL)
      assert_eq(offset, 0UL)
      assert_eq(fin, false)
      assert_eq(data, b"abcdefgh")
    }
    _ => abort("expected a STREAM frame")
  }
  let (pn1, f1) = sender_poll(s, 1L)
  assert_eq(pn1, 1L)
  match f1[0] {
    Stream(offset~, fin~, data~, ..) => {
      assert_eq(offset, 8UL)
      assert_eq(fin, true) // FIN rides the draining frame
      assert_eq(data, b"ij")
    }
    _ => abort("expected a STREAM frame")
  }
  // Nothing more to send.
  match s.poll_send(2L) {
    None => ()
    Some(_) => abort("expected the streams drained")
  }
  // An ACK for packets 0 and 1 clears the outstanding set.
  let ack : @frame.Frame = Ack(largest=1UL, delay=0UL, first_range=1UL, ranges=[])
  s.on_ack(ack, 10L)
  assert_eq(s.outstanding(), [])
}

///|
test "sender: a probe timeout re-queues the oldest outstanding packet's data" {
  let s = Sender::new(100000UL, 100000UL, 1200L, 25000L, 1000L, 8UL)
  s.queue_stream(0UL, b"0123") // 4 bytes → one packet
  let (pn0, _) = sender_poll(s, 0L)
  assert_eq(pn0, 0L)
  // Nothing new is queued before the timeout fires.
  match s.poll_send(1L) {
    None => ()
    Some(_) => abort("expected nothing queued before the probe timeout")
  }
  // The probe timer is armed; firing it before the deadline is a no-op.
  guard s.recovery.pto_deadline() is Some(deadline) else {
    abort("expected the probe timer armed")
  }
  assert_eq(s.on_pto_timeout(deadline - 1L), false)
  assert_eq(s.recovery.pto_count(), 0)
  // At the deadline the oldest outstanding packet's data is re-queued and the timer backs off.
  assert_eq(s.on_pto_timeout(deadline), true)
  assert_eq(s.recovery.pto_count(), 1)
  // A later poll_send puts the probe on the wire as a new packet carrying the same stream data.
  let (pn1, f1) = sender_poll(s, deadline + 1L)
  assert_eq(pn1, 1L)
  match f1[0] {
    Stream(id~, offset~, data~, ..) => {
      assert_eq(id, 0UL)
      assert_eq(offset, 0UL)
      assert_eq(data, b"0123")
    }
    _ => abort("expected the probe to carry the stream data")
  }
  // A probe does not clear the original: both packets are now outstanding.
  assert_eq(s.outstanding().length(), 2)
}

///|
test "sender: a lost packet's stream data is re-queued and retransmitted" {
  let s = Sender::new(100000UL, 100000UL, 1200L, 25000L, 1000L, 4UL)
  s.queue_stream(0UL, b"0123456789abcdefghij") // 20 bytes, max frame 4 → five packets 0..4
  for i = 0; i < 5; i = i + 1 {
    let _ = sender_poll(s, i.to_int64())
  }
  assert_eq(s.outstanding().length(), 5)
  // Acknowledge only [2,4]; 0 and 1 are three-plus before the largest → lost, and re-queued.
  let ack : @frame.Frame = Ack(largest=4UL, delay=0UL, first_range=2UL, ranges=[])
  s.on_ack(ack, 10L)
  assert_eq(s.outstanding(), [])
  // The next packet retransmits a lost chunk (offset 4, the "4567" bytes) as a new packet.
  let (pn5, f5) = sender_poll(s, 20L)
  assert_eq(pn5, 5L)
  match f5[0] {
    Stream(id~, offset~, data~, ..) => {
      assert_eq(id, 0UL)
      assert_eq(offset, 4UL)
      assert_eq(data, b"4567")
    }
    _ => abort("expected a retransmitted STREAM frame")
  }
  // The other lost chunk (offset 0) retransmits next.
  let (pn6, f6) = sender_poll(s, 21L)
  assert_eq(pn6, 6L)
  match f6[0] {
    Stream(offset~, data~, ..) => {
      assert_eq(offset, 0UL)
      assert_eq(data, b"0123")
    }
    _ => abort("expected a retransmitted STREAM frame")
  }
}

///|
/// The Initial packet keys a client uses toward a server, both derived from `dcid`.
fn client_initial_keys(dcid : Bytes) -> @crypto.Keys {
  @crypto.initial(dcid[:]).0
}

///|
test "server conn: a ClientHello in one Initial packet reaches RECVD_CH" {
  let dcid = qv_hexb("8394c8f03e515708")
  let keys = client_initial_keys(dcid)
  let ch = @msg.frame(ClientHello, b"clienthello-body"[:])
  let packet = send_long(
    Initial,
    1U,
    dcid,
    b"",
    0,
    4,
    [@frame.Crypto(offset=0, data=ch)],
    keys,
  )
  let server = Server::new(dcid)
  assert_eq(server.receive_initial(packet), [ClientHello])
  assert_eq(server.handshake_state(), RecvdClientHello)
  // The ack-eliciting Initial owes an ACK.
  assert_eq(server.initial_ack_pending(), true)
}

///|
test "server conn: a ClientHello split across two Initial packets reassembles" {
  let dcid = qv_hexb("0001020304050607")
  let keys = client_initial_keys(dcid)
  let ch = @msg.frame(ClientHello, b"a-longer-clienthello-body"[:])
  let first = ch[0:15].to_owned()
  let rest = ch[15:ch.length()].to_owned()
  let packet1 = send_long(
    Initial,
    1U,
    dcid,
    b"",
    0,
    4,
    [@frame.Crypto(offset=0, data=first)],
    keys,
  )
  let packet2 = send_long(
    Initial,
    1U,
    dcid,
    b"",
    1,
    4,
    [@frame.Crypto(offset=15, data=rest)],
    keys,
  )
  let server = Server::new(dcid)
  // The first packet delivers only a partial handshake message: nothing processed yet.
  assert_eq(server.receive_initial(packet1), [])
  assert_eq(server.handshake_state(), Start)
  // The second packet completes it.
  assert_eq(server.receive_initial(packet2), [ClientHello])
  assert_eq(server.handshake_state(), RecvdClientHello)
}

///|
test "server conn: send_server_hello produces a ServerHello the client can decode" {
  let dcid = qv_hexb("8394c8f03e515708")
  let keys = client_initial_keys(dcid)
  // The client sends its ClientHello; the server receives it.
  let ch_packet = send_long(
    Initial,
    1U,
    dcid,
    b"",
    0,
    4,
    [@frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"ch"[:]))],
    keys,
  )
  let server = Server::new(dcid)
  let _ = server.receive_initial(ch_packet)
  assert_eq(server.handshake_state(), RecvdClientHello)
  // The server builds and protects its ServerHello.
  let sh = @msg.Server::{
    random: Bytes::make(32, b'\xab'),
    session_id: b"",
    suite: 0x1301,
    extensions: [],
  }
  let sh_packet = server.send_server_hello(sh, b"", b"\x01\x02\x03\x04", 0)
  // ServerHello alone does not complete the flight; the state stays at RECVD_CH until the
  // Handshake-space messages are sent.
  assert_eq(server.handshake_state(), RecvdClientHello)
  // The client (sharing the Initial keys) receives it and decodes the ServerHello.
  let decoded = match recv_long(sh_packet, keys) {
    Some((frames, _)) => {
      let mut result : @msg.Server? = None
      for frame in frames {
        match frame {
          Crypto(data~, ..) =>
            match @msg.unframe(data[:]) {
              Some((ServerHello, body)) =>
                result = @msg.read_server_hello(body[:])
              _ => ()
            }
          _ => ()
        }
      }
      result
    }
    None => abort("ServerHello Initial packet failed to authenticate")
  }
  match decoded {
    Some(d) => assert_eq(d, sh)
    None => abort("expected a ServerHello CRYPTO frame")
  }
}

///|
test "server conn: send_handshake_flight emits EE/Cert/CertVerify/Finished the client authenticates" {
  let dcid = qv_hexb("8394c8f03e515708")
  let initial_keys = client_initial_keys(dcid)
  let server = Server::new(dcid)
  // Client sends its ClientHello; the server receives it, then sends its ServerHello.
  let ch = @msg.frame(ClientHello, b"ch"[:])
  let ch_packet = send_long(
    Initial,
    1U,
    dcid,
    b"",
    0,
    4,
    [@frame.Crypto(offset=0, data=ch)],
    initial_keys,
  )
  let _ = server.receive_initial(ch_packet)
  let sh = @msg.Server::{
    random: Bytes::make(32, b'\xcd'),
    session_id: b"",
    suite: 0x1301,
    extensions: [],
  }
  let _ = server.send_server_hello(sh, b"", b"\x0a\x0b\x0c\x0d", 0)
  let sh_msg = @msg.server_hello(sh)
  // The server sends its Handshake-space flight (a real 32-byte server handshake secret).
  let secret = qv_hexb(
    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
  )
  let ee_body = b"encrypted-extensions"
  let cert_body = b"the-server-certificate"
  let cv_body = b"the-certificate-verify-signature"
  let hs_packet = server.send_handshake_flight(
    secret,
    ee_body,
    cert_body,
    _ => cv_body,
    b"",
    b"\x0a\x0b\x0c\x0d",
    0,
  )
  // With the whole flight sent, the server now waits for the client's Finished.
  assert_eq(server.handshake_state(), WaitFinished)
  // The client opens the Handshake packet with the same handshake-space keys and splits the
  // CRYPTO stream back into the four handshake messages.
  let hs_keys = @crypto.Keys::of(secret)
  let msgs = match recv_long(hs_packet, hs_keys) {
    Some((frames, _)) => {
      let mut crypto = b""
      for frame in frames {
        match frame {
          Crypto(data~, ..) => crypto = join(crypto, data)
          _ => ()
        }
      }
      let out : Array[(@msg.Kind, Bytes)] = []
      let view = crypto[:]
      let mut off = 0
      for ;; {
        match @msg.unframe(view[off:]) {
          Some((t, body)) => {
            out.push((t, body))
            off = off + 4 + body.length()
          }
          None => break
        }
      }
      out
    }
    None => abort("Handshake flight failed to authenticate")
  }
  // The four handshake messages, in order.
  assert_eq(msgs.length(), 4)
  assert_eq(msgs[0].0, @msg.Kind::EncryptedExtensions) // EncryptedExtensions
  assert_eq(msgs[1].0, @msg.Kind::Certificate) // Certificate
  assert_eq(msgs[2].0, @msg.Kind::CertificateVerify) // CertificateVerify
  assert_eq(msgs[3].0, @msg.Kind::Finished) // Finished
  // The Finished verify_data is the MAC over the transcript CH..SH..EE..Cert..CertVerify.
  let ee = @msg.frame(EncryptedExtensions, ee_body[:])
  let cert = @msg.frame(Certificate, cert_body[:])
  let cv = @msg.frame(CertificateVerify, cv_body[:])
  let transcript = join(join(join(join(ch, sh_msg), ee), cert), cv)
  let expected = @keys.finished(secret[:], @keys.digest.hash(transcript[:]))
  assert_eq(msgs[3].1, expected)
}

///|
test "server conn: receive_handshake verifies the client Finished and reaches CONNECTED" {
  let dcid = qv_hexb("8394c8f03e515708")
  let initial_keys = client_initial_keys(dcid)
  let server = Server::new(dcid)
  // Drive the server through ClientHello, ServerHello, and its Handshake flight.
  let ch = @msg.frame(ClientHello, b"ch"[:])
  let ch_packet = send_long(
    Initial,
    1U,
    dcid,
    b"",
    0,
    4,
    [@frame.Crypto(offset=0, data=ch)],
    initial_keys,
  )
  let _ = server.receive_initial(ch_packet)
  let sh = @msg.Server::{
    random: Bytes::make(32, b'\xcd'),
    session_id: b"",
    suite: 0x1301,
    extensions: [],
  }
  let _ = server.send_server_hello(sh, b"", b"\x0a\x0b\x0c\x0d", 0)
  let sh_msg = @msg.server_hello(sh)
  let server_secret = qv_hexb(
    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
  )
  let ee_body = b"encrypted-extensions"
  let cert_body = b"the-server-certificate"
  let cv_body = b"the-certificate-verify-signature"
  let _ = server.send_handshake_flight(
    server_secret,
    ee_body,
    cert_body,
    _ => cv_body,
    b"",
    b"\x0a\x0b\x0c\x0d",
    0,
  )
  assert_eq(server.handshake_state(), WaitFinished)
  // Reconstruct the transcript the server holds, through its own Finished, so the client
  // can compute its Finished over the same bytes.
  let ee = @msg.frame(EncryptedExtensions, ee_body[:])
  let cert = @msg.frame(Certificate, cert_body[:])
  let cv = @msg.frame(CertificateVerify, cv_body[:])
  let through_cv = join(join(join(join(ch, sh_msg), ee), cert), cv)
  let server_fin = @msg.frame(
    Finished,
    @keys.finished(server_secret[:], @keys.digest.hash(through_cv[:])),
  )
  let through_server_fin = join(through_cv, server_fin)
  // The client Finished MACs the transcript through the server Finished with the client
  // handshake secret; it travels in a Handshake packet protected with the client keys.
  let client_secret = qv_hexb(
    "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
  )
  let client_fin = @msg.frame(
    Finished,
    @keys.finished(client_secret[:], @keys.digest.hash(through_server_fin[:])),
  )
  let client_keys = @crypto.Keys::of(client_secret)
  let fin_packet = send_long(
    Handshake,
    1U,
    b"",
    b"",
    0,
    4,
    [@frame.Crypto(offset=0, data=client_fin)],
    client_keys,
  )
  assert_eq(
    server.receive_handshake(fin_packet, client_keys, client_secret),
    true,
  )
  assert_eq(server.handshake_state(), Connected)
}

///|
test "server conn: receive_handshake rejects a Finished with the wrong verify_data" {
  let dcid = qv_hexb("8394c8f03e515708")
  let initial_keys = client_initial_keys(dcid)
  let server = Server::new(dcid)
  let ch = @msg.frame(ClientHello, b"ch"[:])
  let ch_packet = send_long(
    Initial,
    1U,
    dcid,
    b"",
    0,
    4,
    [@frame.Crypto(offset=0, data=ch)],
    initial_keys,
  )
  let _ = server.receive_initial(ch_packet)
  let sh = @msg.Server::{
    random: Bytes::make(32, b'\xcd'),
    session_id: b"",
    suite: 0x1301,
    extensions: [],
  }
  let _ = server.send_server_hello(sh, b"", b"\x0a\x0b\x0c\x0d", 0)
  let server_secret = qv_hexb(
    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
  )
  let _ = server.send_handshake_flight(
    server_secret,
    b"ee",
    b"cert",
    _ => b"cv",
    b"",
    b"\x0a\x0b\x0c\x0d",
    0,
  )
  // A Finished whose verify_data is garbage does not authenticate: receive_handshake
  // returns false even though the message advances the state.
  let client_secret = qv_hexb(
    "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
  )
  let bad_fin = @msg.frame(Finished, Bytes::make(32, b'\x00')[:])
  let client_keys = @crypto.Keys::of(client_secret)
  let fin_packet = send_long(
    Handshake,
    1U,
    b"",
    b"",
    0,
    4,
    [@frame.Crypto(offset=0, data=bad_fin)],
    client_keys,
  )
  assert_eq(
    server.receive_handshake(fin_packet, client_keys, client_secret),
    false,
  )
}

///|
test "server conn: a tampered Initial packet is rejected" {
  let dcid = qv_hexb("8394c8f03e515708")
  let keys = client_initial_keys(dcid)
  let packet = send_long(
    Initial,
    1U,
    dcid,
    b"",
    0,
    4,
    [@frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"ch"[:]))],
    keys,
  )
  let buf = Buffer()
  for i = 0; i < packet.length(); i = i + 1 {
    if i == packet.length() - 1 {
      buf.write_byte((packet[i].to_int() ^ 0xff).to_byte())
    } else {
      buf.write_byte(packet[i])
    }
  }
  let server = Server::new(dcid)
  let rejected = try {
    let _ = server.receive_initial(buf.to_bytes())
    false
  } catch {
    _ => true
  }
  assert_eq(rejected, true)
}

///|
/// A client Initial datagram addressed to `dcid` from `scid`, carrying `frames` at packet
/// number `pn` under the Initial keys the DCID derives (RFC 9001 §5.2). Padded to the 1200
/// bytes a client's first flight has to reach unless `pad` says otherwise.
fn qs_initial(
  dcid : Bytes,
  scid : Bytes,
  pn : Int64,
  frames : Array[@frame.Frame],
  fill? : Bool = true,
) -> Bytes {
  let keys = client_initial_keys(dcid)
  let payload = @packet.payload(frames)
  let build = p => seal_long(Initial, 1U, dcid, scid, pn, 4, p, keys)
  if fill {
    pad(payload, build, min_datagram)
  } else {
    build(payload)
  }
}

///|
fn[A] qs_conn(server : Endpoint[A], cid : Bytes) -> Session[A] {
  match server.conn(cid) {
    Some(c) => c
    None => abort("the server is holding no connection for that id")
  }
}

///|
fn[A] qs_next(server : Endpoint[A], now? : Int64 = 0L) -> Bytes raise {
  match server.poll_out(now) {
    Some((datagram, _)) => datagram
    None => abort("the server had no datagram ready")
  }
}

///|
/// Everything the server will send at `now`, as `(datagrams, bytes)`.
fn[A] qs_drain(server : Endpoint[A], now? : Int64 = 0L) -> (Int, Int) raise {
  let mut count = 0
  let mut bytes = 0
  for ;; {
    match server.poll_out(now) {
      Some((datagram, _)) => {
        count = count + 1
        bytes = bytes + datagram.length()
      }
      None => break
    }
  }
  (count, bytes)
}

///|
/// The packet number a protected 1-RTT packet carries.
fn qs_short_pn(
  packet : Bytes,
  dcid_len : Int,
  keys : @crypto.Keys,
) -> Int64 raise {
  match recv_short(packet, dcid_len, keys) {
    Some((_, pn)) => pn
    None => abort("the 1-RTT packet did not authenticate")
  }
}

///|
fn qs_open(packet : Bytes, cid : Bytes) -> Array[@frame.Frame] raise {
  match recv_long(packet, client_initial_keys(cid)) {
    Some((frames, _)) => frames
    None => abort("the server's Initial packet did not authenticate")
  }
}

///|
test "quic serve: two datagrams for different connection ids reach different connections (RFC 9000 §5.2)" {
  let server : Endpoint[String] = Endpoint::new(Config::default())
  let cid_a = qv_hexb("8394c8f03e515708")
  let cid_b = qv_hexb("1122334455667788")
  let hello_a = @msg.frame(ClientHello, b"emm"[:])
  let hello_b = @msg.frame(ClientHello, b"hhh"[:])
  server.recv(
    qs_initial(cid_a, b"\xaa", 0L, [@frame.Crypto(offset=0, data=hello_a)]),
    "client-a",
    0L,
  )
  server.recv(
    qs_initial(cid_b, b"\xbb", 0L, [@frame.Crypto(offset=0, data=hello_b)]),
    "client-b",
    0L,
  )
  server.recv(qs_initial(cid_a, b"\xaa", 1L, [@frame.Ping]), "client-a", 0L)
  assert_eq(server.count(), 2)
  let a = qs_conn(server, cid_a)
  let b = qs_conn(server, cid_b)
  assert_eq(a.peer(), "client-a")
  assert_eq(b.peer(), "client-b")
  assert_eq(a.packets_received(), 2)
  assert_eq(b.packets_received(), 1)
  // Each connection reassembled its own CRYPTO stream, not the other's.
  assert_eq(a.core().client_hello(), hello_a)
  assert_eq(b.core().client_hello(), hello_b)
}

///|
test "quic serve: an ack-eliciting Initial datagram is padded to 1200 bytes (RFC 9000 §14.1)" {
  let server : Endpoint[String] = Endpoint::new(Config::default())
  let cid = qv_hexb("8394c8f03e515708")
  server.recv(
    qs_initial(cid, b"\xaa", 0L, [
      @frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"emm"[:])),
    ]),
    "peer",
    0L,
  )
  let conn = qs_conn(server, cid)
  // The ACK the server owes is not ack-eliciting, so §14.1 does not ask it to be padded.
  let ack = qs_next(server)
  assert_eq(ack.length() < min_datagram, true)
  let server_hello = @msg.frame(ServerHello, b"serverhello"[:])
  conn.send(Level::Initial, [@frame.Crypto(offset=0, data=server_hello)])
  let flight = qs_next(server)
  assert_eq(flight.length() >= min_datagram, true)
  // Padded to the floor, not past it — the length varint growing is the only slack.
  assert_eq(flight.length() <= min_datagram + 4, true)
  // The padding rides inside the protected payload, so the packet still opens.
  assert_eq(qs_open(flight, cid)[0], @frame.Crypto(offset=0, data=server_hello))
}

///|
test "quic serve: a server sends at most 3x what it received before the address is validated (RFC 9000 §8.1)" {
  let server : Endpoint[String] = Endpoint::new(Config::default())
  let cid = qv_hexb("8394c8f03e515708")
  let first = qs_initial(cid, b"\xaa", 0L, [
    @frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"emm"[:])),
  ])
  server.recv(first, "peer", 0L)
  let conn = qs_conn(server, cid)
  let budget = 3 * first.length()
  // Far more than the budget: each of these is padded to 1200 bytes.
  for _i = 0; _i < 8; _i = _i + 1 {
    conn.send(Level::Initial, [
      Crypto(
        offset=0,
        data=@msg.frame(ServerHello, b"serverhello-many-bytes"[:]),
      ),
    ])
  }
  let (count, sent) = qs_drain(server)
  assert_eq(count > 0, true)
  assert_eq(sent <= budget, true)
  assert_eq(conn.validated(), false)
  // It stopped because of the limit, not because the queue ran dry.
  assert_eq(conn.pending() > 0, true)
  // A Handshake packet proves the address, and the rest goes out.
  let secret = Bytes::make(32, b'\x23')
  conn.install_handshake_keys(secret, secret)
  server.recv(
    send_long(
      Handshake,
      1U,
      cid,
      b"\xaa",
      0L,
      4,
      [@frame.Ping],
      @crypto.Keys::of(secret),
    ),
    "peer",
    0L,
  )
  assert_eq(conn.validated(), true)
  let (more_count, more) = qs_drain(server)
  assert_eq(more_count > 0, true)
  assert_eq(sent + more > budget, true)
}

///|
test "quic serve: an idle connection times out on the injected clock (RFC 9000 §10.1)" {
  let server : Endpoint[String] = Endpoint::new(Config::default())
  let cid = qv_hexb("8394c8f03e515708")
  server.recv(
    qs_initial(cid, b"\xaa", 0L, [
      @frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"emm"[:])),
    ]),
    "peer",
    1_000L,
  )
  let conn = qs_conn(server, cid)
  // The server advertises 30 s; the peer asks for 100 ms, and the smaller one wins.
  conn.apply_peer_params([Param::int(MaxIdleTimeout, 100UL)])
  assert_eq(conn.idle_timeout(), 100_000L)
  server.tick(1_000L + 99_999L)
  assert_eq(server.count(), 1)
  server.tick(1_000L + 100_000L)
  assert_eq(server.count(), 0)
}

///|
test "quic serve: closing a connection puts CONNECTION_CLOSE on the wire (RFC 9000 §10.2)" {
  let cfg = Config::default()
  let server : Endpoint[String] = Endpoint::new(cfg)
  let cid = qv_hexb("8394c8f03e515708")
  server.recv(
    qs_initial(cid, b"\xaa", 0L, [
      @frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"emm"[:])),
    ]),
    "peer",
    0L,
  )
  let _ = qs_drain(server)
  server.close(cid, 0x0cUL, b"qwq", 0L)
  let conn = qs_conn(server, cid)
  assert_eq(conn.phase(), Closing)
  let closed = qs_next(server)
  assert_eq(
    qs_open(closed, cid).contains(
      ConnectionClose(error_code=0x0cUL, frame_type=Some(0UL), reason=b"qwq"),
    ),
    true,
  )
  // §10.2.1: a packet arriving in the closing state is answered with the same frame.
  server.recv(qs_initial(cid, b"\xaa", 1L, [@frame.Ping]), "peer", 0L)
  assert_eq(
    qs_open(qs_next(server), cid).contains(
      ConnectionClose(error_code=0x0cUL, frame_type=Some(0UL), reason=b"qwq"),
    ),
    true,
  )
  // §10.2: the closing period ends, and the connection is gone.
  server.tick(cfg.close_period)
  assert_eq(server.count(), 0)
}

///|
test "quic serve: an ECN-enabled peer's ACK_ECN advances the acknowledged number (RFC 9000 §19.3.2)" {
  let server : Endpoint[String] = Endpoint::new(Config::default())
  let cid = qv_hexb("8394c8f03e515708")
  server.recv(
    qs_initial(cid, b"\xaa", 0L, [
      AckEcn(
        largest=7UL,
        delay=0UL,
        first_range=0UL,
        ranges=[],
        ect0=66UL,
        ect1=6UL,
        ce=1UL,
      ),
      @frame.Ping,
    ]),
    "peer",
    0L,
  )
  let conn = qs_conn(server, cid)
  assert_eq(conn.largest_acked(Level::Initial), Some(7L))
}

///|
test "quic serve: queued stream data leaves as a protected 1-RTT packet (RFC 9002 §7)" {
  let server : Endpoint[String] = Endpoint::new(Config::default())
  let cid = qv_hexb("8394c8f03e515708")
  let scid = b"\xaa\xbb"
  server.recv(
    qs_initial(cid, scid, 0L, [
      @frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"emm"[:])),
    ]),
    "peer",
    0L,
  )
  let conn = qs_conn(server, cid)
  let app_secret = Bytes::make(32, b'\x66')
  conn.install_app_keys(app_secret, app_secret)
  conn.queue_stream(0UL, b"heke1228")
  let _ = qs_next(server) // the Initial ACK first
  let packet = qs_next(server)
  let frames = match
    recv_short(packet, scid.length(), @crypto.Keys::of(app_secret)) {
    Some((frames, _)) => frames
    None => abort("the 1-RTT packet did not authenticate")
  }
  assert_eq(frames, [Stream(id=0UL, offset=0UL, fin=false, data=b"heke1228")])
}

///|
test "quic serve: the probe timeout re-queues an unacknowledged packet (RFC 9002 §6.2.4)" {
  let server : Endpoint[String] = Endpoint::new(Config::default())
  let cid = qv_hexb("8394c8f03e515708")
  let scid = b"\xaa\xbb"
  server.recv(
    qs_initial(cid, scid, 0L, [
      @frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"emm"[:])),
    ]),
    "peer",
    0L,
  )
  let conn = qs_conn(server, cid)
  let app_secret = Bytes::make(32, b'\x66')
  conn.install_app_keys(app_secret, app_secret)
  conn.queue_stream(0UL, b"lfanke")
  let _ = qs_drain(server)
  assert_eq(server.poll_out(0L) is None, true)
  // Well past the initial probe timeout, well inside the 30-second idle timeout.
  let later = 1_000_000L
  server.tick(later)
  let probe = qs_next(server, now=later)
  let frames = match
    recv_short(probe, scid.length(), @crypto.Keys::of(app_secret)) {
    Some((frames, _)) => frames
    None => abort("the probe packet did not authenticate")
  }
  assert_eq(frames, [Stream(id=0UL, offset=0UL, fin=false, data=b"lfanke")])
}

///|
test "quic serve: a short-header datagram is demultiplexed by the id it carries (RFC 9000 §17.3)" {
  let server : Endpoint[String] = Endpoint::new(Config::default())
  let cid = qv_hexb("8394c8f03e515708")
  server.recv(
    qs_initial(cid, b"\xaa\xbb", 0L, [
      @frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"emm"[:])),
    ]),
    "peer",
    0L,
  )
  let conn = qs_conn(server, cid)
  let app_secret = Bytes::make(32, b'\x66')
  conn.install_app_keys(app_secret, app_secret)
  let _ = conn.take_received()
  // A short header carries no connection-id length, so the only route back to the connection
  // is matching the bytes after the first against the ids the server issued.
  let data : @frame.Frame = Stream(id=4UL, offset=0UL, fin=true, data=b"qwq")
  server.recv(
    send_short(cid, 0L, 4, [data], @crypto.Keys::of(app_secret)),
    "peer",
    0L,
  )
  assert_eq(conn.packets_received(), 2)
  assert_eq(conn.take_received(), [(Level::Application, data)])
}

///|
test "quic serve: the send loop and the connection number one Application space between them (RFC 9000 §12.3)" {
  let server : Endpoint[String] = Endpoint::new(Config::default())
  let cid = qv_hexb("8394c8f03e515708")
  let scid = b"\xaa\xbb"
  server.recv(
    qs_initial(cid, scid, 0L, [
      @frame.Crypto(offset=0, data=@msg.frame(ClientHello, b"emm"[:])),
    ]),
    "peer",
    0L,
  )
  let conn = qs_conn(server, cid)
  let app_secret = Bytes::make(32, b'\x66')
  let app_keys = @crypto.Keys::of(app_secret)
  conn.install_app_keys(app_secret, app_secret)
  let _ = qs_next(server) // the Initial ACK
  // Reusing a packet number in one space would repeat an AEAD nonce, so the connection's own
  // packets and the send loop's have to advance the same counter.
  conn.send(Level::Application, [@frame.Ping])
  let first = qs_next(server)
  conn.queue_stream(0UL, b"heke1228")
  let second = qs_next(server)
  conn.send(Level::Application, [@frame.Ping])
  let third = qs_next(server)
  assert_eq(qs_short_pn(first, scid.length(), app_keys), 0L)
  assert_eq(qs_short_pn(second, scid.length(), app_keys), 1L)
  assert_eq(qs_short_pn(third, scid.length(), app_keys), 2L)
}

///|
test "every identifier RFC 9000 §18.2 defines round-trips through its code" {
  let named : Array[Kind] = [
    OriginalDcid,
    MaxIdleTimeout,
    StatelessResetToken,
    MaxUdpPayload,
    MaxData,
    MaxStreamDataBidiLocal,
    MaxStreamDataBidiRemote,
    MaxStreamDataUni,
    MaxStreamsBidi,
    MaxStreamsUni,
    AckDelayExponent,
    MaxAckDelay,
    DisableActiveMigration,
    PreferredAddress,
    ActiveConnectionIdLimit,
    InitialScid,
    RetryScid,
    MaxDatagramFrameSize,
  ]
  for kind in named {
    assert_eq(Kind::of(kind.code()), kind)
  }
  // The codes are §18.2's, 0x00 through 0x10, plus RFC 9221's 0x20.
  assert_eq(named.map(k => k.code()), [
    0UL, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 32,
  ])
  // Anything else survives intact rather than being dropped.
  assert_eq(Kind::of(0x1234), Other(0x1234))
  assert_eq(Kind::of(0x1234).code(), 0x1234UL)
}

///|
test "only a server may send four of them (§18.2)" {
  assert_eq(OriginalDcid.server_only(), true)
  assert_eq(PreferredAddress.server_only(), true)
  assert_eq(RetryScid.server_only(), true)
  assert_eq(StatelessResetToken.server_only(), true)
  assert_eq(MaxData.server_only(), false)
  assert_eq(InitialScid.server_only(), false)
}

///|
test "an absent parameter reads as RFC 9000 §18.2's default" {
  let empty = Limits::read([][:])
  assert_eq(empty, limits)
  assert_eq(empty.udp_payload, 65527UL)
  assert_eq(empty.ack_delay_exponent, 3UL)
  assert_eq(empty.max_ack_delay, 25UL)
  assert_eq(empty.active_connection_ids, 2UL)
  assert_eq(empty.data, 0UL)
  assert_eq(empty.migration, true)
}

///|
test "the limits a block sets, and the block those limits amount to" {
  let mine = Limits::new(
    idle_timeout=30000,
    data=1048576,
    stream_data_bidi_remote=65536,
    streams_bidi=100,
    migration=false,
  )
  let block = mine.params()
  // Only what differs from the default is written, so a handshake carries no filler.
  assert_eq(block.length(), 5)
  assert_eq(Limits::read(block[:]), mine)
  // And through the wire form as well.
  guard decode(encode(block[:])[:]) is Some(back) else {
    fail("a block this library wrote should read back")
  }
  assert_eq(Limits::read(back[:]), mine)
  assert_eq(find(back[:], MaxData).unwrap().as_int(), Some(1048576UL))
  assert_eq(find(back[:], MaxStreamsUni), None)
}

///|
test "a block rides in the TLS extension RFC 9001 §8.2 makes mandatory" {
  let mine = Limits::new(data=4096, streams_uni=3)
  let e = extension(mine.params()[:])
  assert_eq(e.kind, QuicTransportParameters)
  let hello : Array[@ext.Ext] = [
    { kind: SupportedVersions, data: b"\x02\x03\x04", },
    e,
  ]
  assert_eq(Limits::read(of_extensions(hello[:])[:]), mine)
  // A hello without the extension leaves every default standing, which is what an
  // endpoint assumes when the block is missing.
  assert_eq(of_extensions([hello[0]][:]).length(), 0)
  assert_eq(Limits::read(of_extensions([hello[0]][:])[:]), limits)
}

///|
test "a truncated block reads as nothing rather than as half of itself" {
  let good = encode(
    [Param::int(MaxData, 1000000), Param::int(MaxStreamsBidi, 8)][:],
  )
  assert_eq(decode(good[:]).unwrap().length(), 2)
  for cut = 1; cut < good.length(); cut = cut + 1 {
    let short = good[0:cut].to_owned()
    match decode(short[:]) {
      Some(params) =>
        // A prefix that happens to end on a parameter boundary is a valid shorter
        // block; anything else must not parse.
        assert_eq(encode(params[:]).length(), cut)
      None => ()
    }
  }
}

///|
test "a flag parameter carries no value, and an integer one carries exactly a varint" {
  let flag = Param::flag(DisableActiveMigration)
  assert_eq(flag.value.length(), 0)
  assert_eq(flag.as_int(), None)
  assert_eq(Param::int(MaxAckDelay, 100).as_int(), Some(100UL))
  // Trailing bytes after the varint are not an integer parameter.
  let junk : Param = { kind: MaxAckDelay, value: b"\x40\x64\x00", }
  assert_eq(junk.as_int(), None)
}
