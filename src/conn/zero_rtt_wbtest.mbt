// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// 0-RTT at the transport layer (RFC 9000 §12.5, RFC 9001 §5.2): the early traffic secret
// expands to packet keys, a 0-RTT packet seals and opens under them, and a server takes its
// frames once those keys are installed.

///|
test "a 0-rtt packet seals and opens under the early keys" {
  let secret = Bytes::make(32, 5)
  let keys = @crypto.zero_rtt(secret[:])
  let dcid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
  let scid = b"\x09\x0a\x0b\x0c"
  let frames : Array[@frame.Frame] = [
    Stream(id=0UL, offset=0UL, fin=false, data=b"early"),
  ]
  let packet = send_zero_rtt(dcid, scid, 0L, 4, frames, keys)
  match @packet.read_long(packet[:]) {
    Some((h, _)) => assert_eq(h.packet_type, @packet.Kind::ZeroRtt)
    None => abort("a 0-rtt packet is not a long header")
  }
  match recv_long(packet, keys, largest=-1L) {
    Some((got, pn)) => {
      assert_eq(pn, 0L)
      assert_eq(got, frames)
    }
    None => abort("the 0-rtt packet did not open")
  }
}

///|
test "a server takes a 0-rtt datagram under the early keys" {
  let secret = Bytes::make(32, 5)
  let keys = @crypto.zero_rtt(secret[:])
  let cfg = { ..Config::default(), max_datagram_frame_size: 1200UL, }
  let cid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
  let peer_cid = b"\x09\x0a\x0b\x0c"
  let conn : Session[String] = Session::new("peer", cid, peer_cid, cfg, 0L)
  conn.install_zero_rtt(keys)
  let frames : Array[@frame.Frame] = [@frame.Datagram(data=b"early")]
  // The client addresses the server's id and calls itself the peer's.
  let packet = send_zero_rtt(cid, peer_cid, 0L, 4, frames, keys)
  conn.on_datagram(packet, "peer", b"nonce", 0L)
  assert_eq(conn.take_datagrams(), [b"early"])
}

///|
test "without early keys a 0-rtt packet is dropped, not a connection error" {
  let secret = Bytes::make(32, 5)
  let keys = @crypto.zero_rtt(secret[:])
  let cid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
  let peer_cid = b"\x09\x0a\x0b\x0c"
  let conn : Session[String] = Session::new(
    "peer",
    cid,
    peer_cid,
    Config::default(),
    0L,
  )
  // No install_zero_rtt: the packet cannot be opened and is dropped.
  let frames : Array[@frame.Frame] = [@frame.Datagram(data=b"early")]
  let packet = send_zero_rtt(cid, peer_cid, 0L, 4, frames, keys)
  conn.on_datagram(packet, "peer", b"nonce", 0L)
  assert_eq(conn.take_datagrams().length(), 0)
}
