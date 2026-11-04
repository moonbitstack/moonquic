// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A protected long-header packet carrying `frames` at this level.
///
/// The three lines it stands for — build the header, seal the payload, protect the
/// header — are worth writing out once to see, and worth not writing out every time
/// after that. `@packet.Long::header` and `@crypto.Keys::seal` are still there for a
/// sender that wants the pieces.
pub fn send_long(
  kind : @packet.Kind,
  version : UInt32,
  dcid : Bytes,
  scid : Bytes,
  number : Int64,
  size : Int32,
  frames : Array[@frame.Frame],
  keys : @crypto.Keys,
  token~ : Bytes = b"",
) -> Bytes {
  seal_long(
    kind,
    version,
    dcid,
    scid,
    number,
    size,
    @packet.payload(frames),
    keys,
    token~,
  )
}

///|
/// The same from a payload already encoded, which is what padding an Initial to the
/// minimum datagram needs (RFC 9000 §14.1).
pub fn seal_long(
  kind : @packet.Kind,
  version : UInt32,
  dcid : Bytes,
  scid : Bytes,
  number : Int64,
  size : Int32,
  payload : Bytes,
  keys : @crypto.Keys,
  token~ : Bytes = b"",
) -> Bytes {
  let pn = @packet.number(number, None, size~)
  let h : @packet.Long = {
    packet_type: kind,
    type_specific: 0,
    version,
    dcid,
    scid,
  }
  keys.seal(
    h.header(pn[:], payload=payload.length() + keys.suite.tag, token~)[:],
    payload[:],
    number~,
  )
}

///|
/// A protected 1-RTT packet carrying `frames`.
pub fn send_short(
  dcid : Bytes,
  number : Int64,
  size : Int32,
  frames : Array[@frame.Frame],
  keys : @crypto.Keys,
  spin~ : Bool = false,
  key_phase~ : Bool = false,
) -> Bytes {
  let payload = @packet.payload(frames)
  let pn = @packet.number(number, None, size~)
  let h : @packet.Short = { spin, key_phase, pn_length: size, dcid, }
  keys.seal(h.header(pn[:])[:], payload[:], number~)
}

///|
/// A protected 0-RTT packet carrying `frames` (RFC 9001 §5.2): a long header of the 0-RTT
/// type, no Initial token, the client's early keys, and the Application packet-number space.
pub fn send_zero_rtt(
  dcid : Bytes,
  scid : Bytes,
  number : Int64,
  size : Int32,
  frames : Array[@frame.Frame],
  keys : @crypto.Keys,
) -> Bytes {
  send_long(ZeroRtt, 1U, dcid, scid, number, size, frames, keys)
}

///|
/// The frames a protected long-header packet carries, and its packet number, expanded against
/// `largest`, the largest number received in its space. `None` when the tag does not match,
/// which is a packet to drop rather than an error to report.
pub fn recv_long(
  packet : Bytes,
  keys : @crypto.Keys,
  largest~ : Int64 = -1L,
) -> (Array[@frame.Frame], Int64)? raise @packet.Refused {
  match keys.open(packet[:], largest~) {
    Some((payload, pn)) => Some((@packet.read_payload(payload), pn))
    None => None
  }
}

///|
/// The same for a 1-RTT packet, whose connection-id length only the receiver knows.
pub fn recv_short(
  packet : Bytes,
  dcid_len : Int32,
  keys : @crypto.Keys,
  largest~ : Int64 = -1L,
) -> (Array[@frame.Frame], Int64)? raise @packet.Refused {
  match keys.open(packet[:], largest~, at=1 + dcid_len) {
    Some((payload, pn)) => Some((@packet.read_payload(payload), pn))
    None => None
  }
}

///|
/// A CertificateVerify body signed over the transcript as RFC 8446 §4.4.3 frames it.
///
/// This is the seam that keeps a signing key out of this library: a flight takes a
/// function from the transcript hash to a CertificateVerify body, and whoever holds the
/// key builds one with this.
pub fn signed(
  signer : &@spec.Signer,
  scheme~ : Int32 = @ext.ecdsa_secp256r1_sha256,
) -> (Bytes) -> Bytes {
  th => {
    @msg.certificate_verify(
      signer.sign(@msg.signed(@msg.server_context, th[:])[:]),
      scheme,
    )
  }
}

///|
/// Two byte strings joined.
fn join(a : Bytes, b : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(a)
  buf.write_bytes(b)
  buf.to_bytes()
}
