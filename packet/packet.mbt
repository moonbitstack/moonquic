// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// QUIC long packet headers (RFC 9000 §17.2). Long headers carry the handshake
// packets (Initial, 0-RTT, Handshake, Retry): they are fully self-describing —
// version, and length-prefixed destination and source connection IDs — which is
// the version-independent invariant RFC 8999 pins down. The third QUIC brick,
// on top of the varint and packet-number primitives.

///|
/// The four long-header packet types (RFC 9000 §17.2), in the encoding of the
/// first byte's type bits: Initial 0, 0-RTT 1, Handshake 2, Retry 3.
pub(all) enum Kind {
  Initial
  ZeroRtt
  Handshake
  Retry
} derive(Eq, Debug)

///|
/// A long packet header's invariant fields: its type, the type-specific low four
/// bits of the first byte (the packet-number length for Initial/Handshake/0-RTT,
/// unused by Retry), the 32-bit version, and the destination and source connection
/// IDs.
pub(all) struct Long {
  packet_type : Kind
  type_specific : Int
  version : UInt
  dcid : Bytes
  scid : Bytes
} derive(Eq, Debug)

///|
/// The first byte's 2-bit type code for a packet type.
fn code_of(t : Kind) -> Int {
  match t {
    Initial => 0
    ZeroRtt => 1
    Handshake => 2
    Retry => 3
  }
}

///|
/// Encode a long header: first byte (`1` header-form, `1` fixed bit, 2-bit type,
/// 4 type-specific bits), the version big-endian, then each connection ID prefixed
/// by its one-byte length.
pub fn encode_long(h : Long) -> Bytes {
  let first = 0xc0 | (code_of(h.packet_type) << 4) | (h.type_specific & 0x0f)
  let buf = Buffer()
  buf.write_byte(first.to_byte())
  @fixed.write_u32(buf, h.version)
  buf.write_byte(h.dcid.length().to_byte())
  buf.write_bytes(h.dcid[:])
  buf.write_byte(h.scid.length().to_byte())
  buf.write_bytes(h.scid[:])
  buf.to_bytes()
}

///|
/// Parse a long header at the start of `b`, returning it and the number of bytes it
/// occupied, or `None` if the first byte is not a long header or `b` is truncated
/// before the header ends.
pub fn read_long(b : BytesView) -> (Long, Int)? {
  if b.length() < 5 {
    return None
  }
  let first = b[0].to_int()
  // Header form is the high bit; a long header has it set.
  if (first & 0x80) == 0 {
    return None
  }
  let packet_type = match (first >> 4) & 0x03 {
    0 => Kind::Initial
    1 => ZeroRtt
    2 => Kind::Handshake
    _ => Retry
  }
  let type_specific = first & 0x0f
  guard @fixed.read_u32(b, at=1) is Some(version) else { return None }
  let mut off = 5
  if b.length() < off + 1 {
    return None
  }
  let dcil = b[off].to_int()
  off = off + 1
  if b.length() < off + dcil {
    return None
  }
  let dcid = b[off:off + dcil].to_owned()
  off = off + dcil
  if b.length() < off + 1 {
    return None
  }
  let scil = b[off].to_int()
  off = off + 1
  if b.length() < off + scil {
    return None
  }
  let scid = b[off:off + scil].to_owned()
  off = off + scil
  Some(({ packet_type, type_specific, version, dcid, scid, }, off))
}

///|
pub extend Long with Debug::{to_repr}

///|
pub extend Long with Eq::{not_equal, equal}

///|
pub extend Kind with Debug::{to_repr}

///|
pub extend Kind with Eq::{not_equal, equal}

// The version-specific part of a long header (RFC 9000 §17.2). The invariant part above
// is all RFC 8999 pins down; version 1 continues with the Initial token, the Length
// covering the packet number and payload, and the packet number itself. Retry and
// Version Negotiation end differently and get their own pair.

///|
/// What follows a long header's invariant part in an Initial, 0-RTT or Handshake packet:
/// the Initial token (empty for the two types that carry none), the Length field covering
/// the packet number and the payload, and where in the packet the packet number starts.
pub(all) struct Tail {
  token : Bytes
  length : UInt64
  at : Int
} derive(Eq, Debug)

///|
/// The header a protected packet is sealed under: the invariant header, the Initial
/// token, the Length covering the packet number and `payload` bytes, then `number`.
///
/// `number` is the truncated packet number already encoded, so the first byte's low bits
/// follow from its length and the truncation is decided once, where `number` is built.
/// `payload` counts the sealed payload, AEAD tag included, because that is what a
/// receiver subtracts from Length to find where the payload ends.
///
/// A `token` on a type that carries none is written anyway: only Initial has the field,
/// so passing one elsewhere is a caller's error rather than something to paper over.
pub fn Long::header(
  self : Long,
  number : BytesView,
  payload~ : Int,
  token? : Bytes = b"",
) -> Bytes {
  let h = self
  let first = 0xc0 |
    (code_of(h.packet_type) << 4) |
    ((number.length() - 1) & 0x03)
  let buf = Buffer()
  buf.write_byte(first.to_byte())
  @fixed.write_u32(buf, h.version)
  buf.write_byte(h.dcid.length().to_byte())
  buf.write_bytes(h.dcid[:])
  buf.write_byte(h.scid.length().to_byte())
  buf.write_bytes(h.scid[:])
  if h.packet_type is Initial {
    buf.write_bytes(@quic.encode(token.length().to_uint64())[:])
    buf.write_bytes(token[:])
  }
  buf.write_bytes(@quic.encode((number.length() + payload).to_uint64())[:])
  buf.write_bytes(number)
  buf.to_bytes()
}

///|
/// The tail following the invariant header that ended `at` bytes into `b`.
///
/// `None` when the packet is truncated inside the token or the length field, or when
/// `h` is a Retry — a Retry has no Length and no packet number, so `read_retry` reads it.
pub fn read_tail(h : Long, b : BytesView, at : Int) -> Tail? {
  if h.packet_type is Retry {
    return None
  }
  let mut off = at
  let mut token = b""
  if h.packet_type is Initial {
    guard @quic.decode(b[off:]) is Some((n, used)) else { return None }
    off = off + used
    let n = n.to_int()
    if n < 0 || b.length() < off + n {
      return None
    }
    token = b[off:off + n].to_owned()
    off = off + n
  }
  guard @quic.decode(b[off:]) is Some((length, used)) else { return None }
  Some({ token, length, at: off + used, })
}

///|
/// A long header and its tail in one read, for the common case of taking a packet
/// apart from the front.
pub fn read_header(b : BytesView) -> (Long, Tail)? {
  guard read_long(b) is Some((h, at)) else { return None }
  match read_tail(h, b, at) {
    Some(tail) => Some((h, tail))
    None => None
  }
}

///|
/// A Retry packet (RFC 9000 §17.2.5): the invariant header, the retry token, and the
/// 16-byte integrity tag that binds the packet to the original connection ID.
pub fn retry(h : Long, token~ : Bytes, tag~ : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(encode_long(h)[:])
  buf.write_bytes(token[:])
  buf.write_bytes(tag[:])
  buf.to_bytes()
}

///|
/// A Retry packet's header, token and integrity tag. Everything after the invariant
/// header is the token save the trailing 16 bytes, so a packet shorter than that, or
/// one that is not a Retry, reads as `None`.
pub fn read_retry(b : BytesView) -> (Long, Bytes, Bytes)? {
  guard read_long(b) is Some((h, at)) else { return None }
  guard h.packet_type is Retry else { return None }
  if b.length() < at + 16 {
    return None
  }
  let split = b.length() - 16
  Some((h, b[at:split].to_owned(), b[split:].to_owned()))
}

///|
/// A Version Negotiation packet (RFC 9000 §17.2.1): version zero and the versions the
/// server will speak, with the connection IDs swapped from the packet that provoked it.
///
/// `first` is the whole first byte. The RFC leaves every bit but the header form
/// arbitrary and asks a server to vary them, so it is the caller's to choose; the
/// default sets the form bit alone.
pub fn versions(
  dcid~ : Bytes,
  scid~ : Bytes,
  offered : ArrayView[UInt],
  first? : Int = 0x80,
) -> Bytes {
  let buf = Buffer()
  buf.write_byte((first | 0x80).to_byte())
  buf.write_byte(b'\x00')
  buf.write_byte(b'\x00')
  buf.write_byte(b'\x00')
  buf.write_byte(b'\x00')
  buf.write_byte(dcid.length().to_byte())
  buf.write_bytes(dcid[:])
  buf.write_byte(scid.length().to_byte())
  buf.write_bytes(scid[:])
  for v in offered {
    @fixed.write_u32(buf, v)
  }
  buf.to_bytes()
}

///|
/// The connection IDs and offered versions a Version Negotiation packet carries.
///
/// `None` unless the version field is zero, which is what marks the packet, and unless
/// the version list is a whole number of four-byte versions.
pub fn read_versions(b : BytesView) -> (Bytes, Bytes, Array[UInt])? {
  guard read_long(b) is Some((h, at)) else { return None }
  if h.version != 0 {
    return None
  }
  let rest = b.length() - at
  if rest < 0 || rest % 4 != 0 {
    return None
  }
  let offered : Array[UInt] = []
  for i = at; i < b.length(); i = i + 4 {
    guard @fixed.read_u32(b, at=i) is Some(v) else { break }
    offered.push(v)
  }
  Some((h.dcid, h.scid, offered))
}

///|
pub extend Tail with Debug::{to_repr}

///|
pub extend Tail with Eq::{not_equal, equal}

// QUIC packet numbers (RFC 9000 §17.1). A packet number is a 62-bit integer sent
// truncated to 1–4 bytes: the sender emits the fewest bytes that let the peer
// recover the full number given the largest it has seen. Signed Int64 arithmetic
// mirrors the RFC's unbounded integers (the decode window arithmetic goes negative
// for small numbers, which UInt64 would wrap).

///|
/// The number of significant bits in `n` (`n > 0`).
fn bit_length(n : Int64) -> Int {
  let mut c = 0
  let mut x = n
  while x > 0L {
    c = c + 1
    x = x >> 1
  }
  c
}

///|
/// The number of bytes (1–4) needed to encode `full_pn` given the largest packet
/// number the peer has acknowledged (RFC 9000 §17.1 / A.2): enough bytes to cover
/// twice the number of unacknowledged packets, so wraparound is unambiguous. With
/// no acknowledgement yet, the count is `full_pn + 1`.
pub fn number_size(full_pn : Int64, largest_acked : Int64?) -> Int {
  let num_unacked = match largest_acked {
    Some(la) => full_pn - la
    None => full_pn + 1L
  }
  let min_bits = if num_unacked <= 0L { 1 } else { bit_length(num_unacked) }
  let nb = (min_bits + 7) / 8
  if nb < 1 {
    1
  } else if nb > 4 {
    4
  } else {
    nb
  }
}

///|
/// Encode `full_pn` as its truncated big-endian packet number, using the shortest
/// length that is unambiguous given `largest_acked` (RFC 9000 A.2).
///
/// `size` writes that many bytes instead. A sender that has already decided how long
/// its packet numbers are — a handshake that fixes four, a test with a vector to
/// match — says so rather than having the length inferred back.
pub fn number(full_pn : Int64, largest_acked : Int64?, size? : Int) -> Bytes {
  let nb = match size {
    Some(n) => n
    None => number_size(full_pn, largest_acked)
  }
  let buf = Buffer()
  for i = nb - 1; i >= 0; i = i - 1 {
    buf.write_byte((full_pn >> (i * 8)).to_byte())
  }
  buf.to_bytes()
}

///|
/// Recover the full packet number from a `truncated_pn` of `pn_nbits` bits, given
/// the largest full packet number already received (RFC 9000 A.3): pick the value
/// congruent to `truncated_pn` that is closest to the next expected number,
/// resolving wraparound with the half-window rule.
pub fn read_number(
  largest_pn : Int64,
  truncated_pn : Int64,
  pn_nbits : Int,
) -> Int64 {
  let expected = largest_pn + 1L
  let pn_win = 1L << pn_nbits
  let pn_hwin = pn_win >> 1
  let pn_mask = pn_win - 1L
  let candidate = (expected & pn_mask.lnot()) | truncated_pn
  if candidate <= expected - pn_hwin && candidate < (1L << 62) - pn_win {
    candidate + pn_win
  } else if candidate > expected + pn_hwin && candidate >= pn_win {
    candidate - pn_win
  } else {
    candidate
  }
}

// A QUIC packet-number space (RFC 9000 §12.3): the Initial, Handshake, and Application
// spaces each number their packets independently, track which packet numbers arrived so
// they can be acknowledged, remember the largest number the peer has acknowledged, and
// note when an ack-eliciting packet is owed an ACK. This is the per-space bookkeeping
// the connection state machine composes; it holds no keys or sockets, only the numbering
// and acknowledgement state, so it is pure and testable on its own.

///|
/// One packet-number space's send/receive numbering and acknowledgement state.
pub struct Space {
  mut next_pn : Int64
  received : @frame.Seen
  mut largest_acked : Int64?
  mut ack_eliciting_pending : Bool
}

///|
/// A fresh space: next packet number 0, nothing received or acknowledged.
pub fn Space::new() -> Space {
  {
    next_pn: 0,
    received: @frame.Seen::new(),
    largest_acked: None,
    ack_eliciting_pending: false,
  }
}

///|
/// Allocate the next packet number to send, advancing the counter.
pub fn Space::next_packet_number(self : Space) -> Int64 {
  let pn = self.next_pn
  self.next_pn = self.next_pn + 1L
  pn
}

///|
/// Skip the send counter past `pn`, so a packet another sender numbered in this space — the
/// recovery loop's, which keeps its own counter — is not handed out again here. A `pn` this
/// space is already past leaves it alone.
pub fn Space::advance_past(self : Space, pn : Int64) -> Unit {
  if pn >= self.next_pn {
    self.next_pn = pn + 1L
  }
}

///|
/// The largest packet number the peer has acknowledged, or `None`.
pub fn Space::largest_acked(self : Space) -> Int64? {
  self.largest_acked
}

///|
/// Record that packet number `pn` arrived. `ack_eliciting` marks a packet that must be
/// acknowledged (RFC 9000 §13.2.1); a pure-ACK packet is recorded but does not itself
/// oblige a new ACK.
pub fn Space::on_packet_received(
  self : Space,
  pn : Int64,
  ack_eliciting : Bool,
) -> Unit {
  self.received.add(pn.reinterpret_as_uint64())
  if ack_eliciting {
    self.ack_eliciting_pending = true
  }
}

///|
/// Record that the peer acknowledged up to `largest`, advancing the high-water mark
/// (an older ACK never lowers it).
pub fn Space::on_ack_received(self : Space, largest : Int64) -> Unit {
  match self.largest_acked {
    Some(current) => if largest > current { self.largest_acked = Some(largest) }
    None => self.largest_acked = Some(largest)
  }
}

///|
/// Whether an ACK is owed — an ack-eliciting packet has arrived since the last ACK was
/// built.
pub fn Space::ack_pending(self : Space) -> Bool {
  self.ack_eliciting_pending
}

///|
/// Build the ACK frame acknowledging everything received so far with the given
/// `ack_delay`, and clear the pending flag. `None` when nothing has been received.
pub fn Space::build_ack(self : Space, ack_delay : UInt64) -> @frame.Frame? {
  match self.received.fields() {
    Some((largest, first_range, pairs)) => {
      self.ack_eliciting_pending = false
      Some(Ack(largest~, delay=ack_delay, first_range~, ranges=pairs))
    }
    None => None
  }
}

// QUIC short packet headers (RFC 9000 §17.3) — the 1-RTT header that carries every
// packet once the handshake is done. Unlike a long header it does not carry the
// connection-ID lengths on the wire (the receiver already knows how long its own
// connection IDs are), so parsing takes the expected destination-CID length. The
// fifth QUIC brick, completing header parsing alongside the long header.

///|
/// A short header's fields: the latency spin bit, the key-phase bit, the
/// packet-number length (1–4 bytes, from the low two bits of the first byte plus
/// one), and the destination connection ID.
pub(all) struct Short {
  spin : Bool
  key_phase : Bool
  pn_length : Int
  dcid : Bytes
} derive(Eq, Debug)

///|
/// Encode a short header: first byte (`0` header-form, `1` fixed bit, spin, two
/// reserved zero bits, key phase, and the 2-bit packet-number length minus one),
/// then the destination connection ID with no length prefix. The (protected)
/// packet number follows, encoded separately.
pub fn encode_short(h : Short) -> Bytes {
  let first = 0x40 |
    (if h.spin { 0x20 } else { 0 }) |
    (if h.key_phase { 0x04 } else { 0 }) |
    ((h.pn_length - 1) & 0x03)
  let buf = Buffer()
  buf.write_byte(first.to_byte())
  buf.write_bytes(h.dcid[:])
  buf.to_bytes()
}

///|
/// Parse a short header at the start of `b`, given the length of the destination
/// connection ID this endpoint issued. Returns the header and the bytes consumed
/// (first byte plus the connection ID), or `None` if the first byte is a long
/// header or `b` is shorter than that.
pub fn read_short(b : BytesView, dcid_len : Int) -> (Short, Int)? {
  if b.length() < 1 + dcid_len {
    return None
  }
  let first = b[0].to_int()
  // Header form is the high bit; a short header has it clear.
  if (first & 0x80) != 0 {
    return None
  }
  let spin = (first & 0x20) != 0
  let key_phase = (first & 0x04) != 0
  let pn_length = (first & 0x03) + 1
  let dcid = b[1:1 + dcid_len].to_owned()
  Some(({ spin, key_phase, pn_length, dcid, }, 1 + dcid_len))
}

///|
/// The header a protected 1-RTT packet is sealed under (RFC 9000 §17.3): the first
/// byte, the destination connection ID, and the packet number.
///
/// As on the long side the first byte's low bits come from `number`, so `pn_length`
/// on the struct is what a reader found rather than something a writer must agree
/// with. A short header has no length field: the payload runs to the end of the
/// datagram.
pub fn Short::header(self : Short, number : BytesView) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(encode_short({ ..self, pn_length: number.length(), })[:])
  buf.write_bytes(number)
  buf.to_bytes()
}

///|
pub extend Short with Debug::{to_repr}

///|
pub extend Short with Eq::{not_equal, equal}

// A QUIC packet payload (RFC 9000 §12.4) is a sequence of frames. This assembles a
// frame list into the payload that goes under AEAD protection, parses a decrypted
// payload back into its frames, pads a payload out to a minimum size with PADDING, and
// classifies whether a payload is ack-eliciting (RFC 9000 §13.2.1). It sits between the
// single-frame codec and the packet-protection layer; pure bytes in and out.

///|
/// A truncated or unparsable frame in a packet payload.
pub(all) suberror Refused {
  Malformed(String)
} derive(Eq)

///|
pub extend Refused with Eq::{not_equal, equal}

///|
/// A refused payload prints as the fault it is, so a dropped packet names its reason.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Malformed(m) => logger.write_string("Malformed(" + m + ")")
  }
}

///|
pub extend Refused with Show::{to_string, output}

///|
/// Encode a list of frames into a packet payload — their wire encodings concatenated.
pub fn payload(frames : Array[@frame.Frame]) -> Bytes {
  let buf = Buffer()
  for frame in frames {
    buf.write_bytes(@frame.encode(frame))
  }
  buf.to_bytes()
}

///|
/// Parse a decrypted packet payload into its frames, consuming the whole payload. A
/// frame that does not parse, or that consumes no bytes, is a payload error.
pub fn read_payload(payload : Bytes) -> Array[@frame.Frame] raise Refused {
  let frames : Array[@frame.Frame] = []
  let view = payload[:]
  let mut off = 0
  while off < view.length() {
    match @frame.decode(view[off:]) {
      Some((frame, consumed)) => {
        if consumed <= 0 {
          raise Malformed("frame consumed no bytes")
        }
        frames.push(frame)
        off += consumed
      }
      None => raise Malformed("truncated or unknown frame in payload")
    }
  }
  frames
}

///|
/// Whether a payload's frames make the packet ack-eliciting — true if any frame is.
pub fn payload_elicits_ack(frames : Array[@frame.Frame]) -> Bool {
  for frame in frames {
    if @frame.elicits_ack(frame) {
      return true
    }
  }
  false
}

///|
/// Pad `payload` out to at least `min_size` bytes with PADDING frames (zero octets); a
/// payload already that long is returned unchanged (RFC 9000 §14.1 — an Initial packet's
/// payload is padded so the datagram reaches the 1200-byte minimum).
pub fn pad(payload : Bytes, min_size : Int) -> Bytes {
  if payload.length() >= min_size {
    return payload
  }
  let buf = Buffer()
  buf.write_bytes(payload)
  for _i = payload.length(); _i < min_size; _i = _i + 1 {
    buf.write_byte(0)
  }
  buf.to_bytes()
}
