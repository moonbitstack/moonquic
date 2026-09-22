// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// QUIC frames (RFC 9000 §19) — the content carried inside a packet's payload. Each
// frame starts with a varint type; its fields are varints too, except the fixed-width
// connection-ID tokens and path-validation data. This covers the full §19 frame set:
// PADDING/PING/ACK/ACK_ECN, CRYPTO and STREAM, the flow-control family (MAX_*, *_BLOCKED),
// the stream-control frames (RESET_STREAM/STOP_SENDING), connection management
// (NEW_CONNECTION_ID/RETIRE_CONNECTION_ID/NEW_TOKEN), path validation
// (PATH_CHALLENGE/PATH_RESPONSE), and the lifecycle frames
// (HANDSHAKE_DONE/CONNECTION_CLOSE).

///|
/// A decoded QUIC frame. `Padding` collapses a run of zero bytes to its length;
/// `Stream` carries application data on a stream, with a byte `offset` and a `fin`
/// flag marking the end of the stream (RFC 9000 §19.8).
pub(all) enum Frame {
  Padding(Int)
  Ping
  Crypto(offset~ : UInt64, data~ : Bytes)
  Stream(id~ : UInt64, offset~ : UInt64, fin~ : Bool, data~ : Bytes)
  Ack(
    largest~ : UInt64,
    delay~ : UInt64,
    first_range~ : UInt64,
    ranges~ : Array[(UInt64, UInt64)]
  )
  // ACK_ECN (0x03) repeats the ACK body, then the ECT(0), ECT(1) and CE counts the peer
  // has seen on this path (RFC 9000 §19.3.2).
  AckEcn(
    largest~ : UInt64,
    delay~ : UInt64,
    first_range~ : UInt64,
    ranges~ : Array[(UInt64, UInt64)],
    ect0~ : UInt64,
    ect1~ : UInt64,
    ce~ : UInt64
  )
  ResetStream(id~ : UInt64, error_code~ : UInt64, final_size~ : UInt64)
  StopSending(id~ : UInt64, error_code~ : UInt64)
  NewToken(token~ : Bytes)
  MaxData(UInt64)
  MaxStreamData(id~ : UInt64, max~ : UInt64)
  // `bidi` selects the 0x12/0x16 (bidirectional) vs 0x13/0x17 (unidirectional) type.
  MaxStreams(bidi~ : Bool, max~ : UInt64)
  DataBlocked(UInt64)
  StreamDataBlocked(id~ : UInt64, max~ : UInt64)
  StreamsBlocked(bidi~ : Bool, max~ : UInt64)
  NewConnectionId(
    seq~ : UInt64,
    retire_prior_to~ : UInt64,
    conn_id~ : Bytes,
    reset_token~ : Bytes
  )
  RetireConnectionId(UInt64)
  PathChallenge(Bytes)
  PathResponse(Bytes)
  HandshakeDone
  // `frame_type` is `Some` for a transport-error close (0x1c) and `None` for an
  // application-error close (0x1d), which omits the triggering frame type.
  ConnectionClose(error_code~ : UInt64, frame_type~ : UInt64?, reason~ : Bytes)
} derive(Eq, Debug)

///|
/// Write an ACK frame's body — Largest Acknowledged, ACK Delay, the range count, First ACK
/// Range, then the `(Gap, ACK Range Length)` pairs. ACK and ACK_ECN share it; ACK_ECN adds
/// its counts after.
fn write_ack(
  buf : Buffer,
  largest : UInt64,
  delay : UInt64,
  first_range : UInt64,
  ranges : Array[(UInt64, UInt64)],
) -> Unit {
  buf.write_bytes(@varint.encode(largest)[:])
  buf.write_bytes(@varint.encode(delay)[:])
  buf.write_bytes(@varint.encode(ranges.length().to_uint64())[:])
  buf.write_bytes(@varint.encode(first_range)[:])
  for r in ranges {
    let (gap, len) = r
    buf.write_bytes(@varint.encode(gap)[:])
    buf.write_bytes(@varint.encode(len)[:])
  }
}

///|
/// Encode a frame to its wire bytes.
pub fn encode(f : Frame) -> Bytes {
  let buf = Buffer()
  match f {
    Padding(n) =>
      for _i = 0; _i < n; _i = _i + 1 {
        buf.write_byte(b'\x00')
      }
    Ping => buf.write_bytes(@varint.encode(1UL)[:])
    Crypto(offset~, data~) => {
      buf.write_bytes(@varint.encode(6UL)[:])
      buf.write_bytes(@varint.encode(offset)[:])
      buf.write_bytes(@varint.encode(data.length().to_uint64())[:])
      buf.write_bytes(data[:])
    }
    Stream(id~, offset~, fin~, data~) => {
      // Always emit with the OFF and LEN bits set (0x0e) so the frame is
      // self-delimiting; the FIN bit rides the low bit.
      let type_byte = 0x0e | (if fin { 1 } else { 0 })
      buf.write_bytes(@varint.encode(type_byte.to_uint64())[:])
      buf.write_bytes(@varint.encode(id)[:])
      buf.write_bytes(@varint.encode(offset)[:])
      buf.write_bytes(@varint.encode(data.length().to_uint64())[:])
      buf.write_bytes(data[:])
    }
    Ack(largest~, delay~, first_range~, ranges~) => {
      buf.write_bytes(@varint.encode(2UL)[:])
      write_ack(buf, largest, delay, first_range, ranges)
    }
    AckEcn(largest~, delay~, first_range~, ranges~, ect0~, ect1~, ce~) => {
      buf.write_bytes(@varint.encode(3UL)[:])
      write_ack(buf, largest, delay, first_range, ranges)
      buf.write_bytes(@varint.encode(ect0)[:])
      buf.write_bytes(@varint.encode(ect1)[:])
      buf.write_bytes(@varint.encode(ce)[:])
    }
    ResetStream(id~, error_code~, final_size~) => {
      buf.write_bytes(@varint.encode(4UL)[:])
      buf.write_bytes(@varint.encode(id)[:])
      buf.write_bytes(@varint.encode(error_code)[:])
      buf.write_bytes(@varint.encode(final_size)[:])
    }
    StopSending(id~, error_code~) => {
      buf.write_bytes(@varint.encode(5UL)[:])
      buf.write_bytes(@varint.encode(id)[:])
      buf.write_bytes(@varint.encode(error_code)[:])
    }
    NewToken(token~) => {
      buf.write_bytes(@varint.encode(7UL)[:])
      buf.write_bytes(@varint.encode(token.length().to_uint64())[:])
      buf.write_bytes(token[:])
    }
    MaxData(v) => {
      buf.write_bytes(@varint.encode(0x10UL)[:])
      buf.write_bytes(@varint.encode(v)[:])
    }
    MaxStreamData(id~, max~) => {
      buf.write_bytes(@varint.encode(0x11UL)[:])
      buf.write_bytes(@varint.encode(id)[:])
      buf.write_bytes(@varint.encode(max)[:])
    }
    MaxStreams(bidi~, max~) => {
      buf.write_bytes(@varint.encode(if bidi { 0x12UL } else { 0x13UL })[:])
      buf.write_bytes(@varint.encode(max)[:])
    }
    DataBlocked(v) => {
      buf.write_bytes(@varint.encode(0x14UL)[:])
      buf.write_bytes(@varint.encode(v)[:])
    }
    StreamDataBlocked(id~, max~) => {
      buf.write_bytes(@varint.encode(0x15UL)[:])
      buf.write_bytes(@varint.encode(id)[:])
      buf.write_bytes(@varint.encode(max)[:])
    }
    StreamsBlocked(bidi~, max~) => {
      buf.write_bytes(@varint.encode(if bidi { 0x16UL } else { 0x17UL })[:])
      buf.write_bytes(@varint.encode(max)[:])
    }
    NewConnectionId(seq~, retire_prior_to~, conn_id~, reset_token~) => {
      buf.write_bytes(@varint.encode(0x18UL)[:])
      buf.write_bytes(@varint.encode(seq)[:])
      buf.write_bytes(@varint.encode(retire_prior_to)[:])
      buf.write_byte(conn_id.length().to_byte())
      buf.write_bytes(conn_id[:])
      buf.write_bytes(reset_token[:])
    }
    RetireConnectionId(seq) => {
      buf.write_bytes(@varint.encode(0x19UL)[:])
      buf.write_bytes(@varint.encode(seq)[:])
    }
    PathChallenge(data) => {
      buf.write_bytes(@varint.encode(0x1aUL)[:])
      buf.write_bytes(data[:])
    }
    PathResponse(data) => {
      buf.write_bytes(@varint.encode(0x1bUL)[:])
      buf.write_bytes(data[:])
    }
    HandshakeDone => buf.write_bytes(@varint.encode(0x1eUL)[:])
    ConnectionClose(error_code~, frame_type~, reason~) => {
      match frame_type {
        Some(ft) => {
          buf.write_bytes(@varint.encode(0x1cUL)[:])
          buf.write_bytes(@varint.encode(error_code)[:])
          buf.write_bytes(@varint.encode(ft)[:])
        }
        None => {
          buf.write_bytes(@varint.encode(0x1dUL)[:])
          buf.write_bytes(@varint.encode(error_code)[:])
        }
      }
      buf.write_bytes(@varint.encode(reason.length().to_uint64())[:])
      buf.write_bytes(reason[:])
    }
  }
  buf.to_bytes()
}

///|
/// Parse an ACK frame's body starting at `start` in `b` — Largest Acknowledged, ACK Delay,
/// the range count, First ACK Range, then that many `(Gap, ACK Range Length)` pairs — with
/// the offset just past it. ACK (0x02) ends there; ACK_ECN (0x03) reads its three counts on.
fn read_ack(
  b : BytesView,
  start : Int,
) -> (UInt64, UInt64, UInt64, Array[(UInt64, UInt64)], Int)? {
  let mut off = start
  guard @varint.decode(b[off:]) is Some((largest, l1)) else { return None }
  off = off + l1
  guard @varint.decode(b[off:]) is Some((delay, l2)) else { return None }
  off = off + l2
  guard @varint.decode(b[off:]) is Some((count, l3)) else { return None }
  off = off + l3
  guard @varint.decode(b[off:]) is Some((first_range, l4)) else { return None }
  off = off + l4
  let ranges : Array[(UInt64, UInt64)] = []
  for _i = 0; _i < count.to_int(); _i = _i + 1 {
    guard @varint.decode(b[off:]) is Some((gap, lg)) else { return None }
    off = off + lg
    guard @varint.decode(b[off:]) is Some((rlen, lr)) else { return None }
    off = off + lr
    ranges.push((gap, rlen))
  }
  Some((largest, delay, first_range, ranges, off))
}

///|
/// Read one frame at the start of `b`, returning it and the bytes it occupied, or
/// `None` on a truncated frame or a type this brick does not yet decode. A PADDING
/// frame absorbs the whole run of leading zero bytes.
pub fn decode(b : BytesView) -> (Frame, Int)? {
  guard @varint.decode(b) is Some((ftype, tlen)) else { return None }
  match ftype {
    0UL => {
      let mut n = 0
      while n < b.length() && b[n].to_int() == 0 {
        n = n + 1
      }
      Some((Padding(n), n))
    }
    1UL => Some((Ping, tlen))
    2UL => {
      guard read_ack(b, tlen)
        is Some((largest, delay, first_range, ranges, off)) else {
        return None
      }
      Some((Ack(largest~, delay~, first_range~, ranges~), off))
    }
    3UL => {
      guard read_ack(b, tlen)
        is Some((largest, delay, first_range, ranges, body_end)) else {
        return None
      }
      let mut off = body_end
      guard @varint.decode(b[off:]) is Some((ect0, l1)) else { return None }
      off = off + l1
      guard @varint.decode(b[off:]) is Some((ect1, l2)) else { return None }
      off = off + l2
      guard @varint.decode(b[off:]) is Some((ce, l3)) else { return None }
      off = off + l3
      Some(
        (
          AckEcn(largest~, delay~, first_range~, ranges~, ect0~, ect1~, ce~),
          off,
        ),
      )
    }
    6UL => {
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((offset, olen)) else { return None }
      off = off + olen
      guard @varint.decode(b[off:]) is Some((length, llen)) else { return None }
      off = off + llen
      let dlen = length.to_int()
      if b.length() < off + dlen {
        return None
      }
      let data = b[off:off + dlen].to_owned()
      off = off + dlen
      Some((Crypto(offset~, data~), off))
    }
    ty if ty >= 8UL && ty <= 15UL => {
      let ti = ty.to_int()
      let has_off = (ti & 0x04) != 0
      let has_len = (ti & 0x02) != 0
      let fin = (ti & 0x01) != 0
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((id, ilen)) else { return None }
      off = off + ilen
      let mut offset = 0UL
      if has_off {
        guard @varint.decode(b[off:]) is Some((o, olen)) else { return None }
        offset = o
        off = off + olen
      }
      let data = if has_len {
        guard @varint.decode(b[off:]) is Some((length, llen)) else {
          return None
        }
        off = off + llen
        let dlen = length.to_int()
        if b.length() < off + dlen {
          return None
        }
        let d = b[off:off + dlen].to_owned()
        off = off + dlen
        d
      } else {
        // No length field: the stream data runs to the end of the buffer.
        let d = b[off:].to_owned()
        off = b.length()
        d
      }
      Some((Stream(id~, offset~, fin~, data~), off))
    }
    4UL => {
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((id, l1)) else { return None }
      off = off + l1
      guard @varint.decode(b[off:]) is Some((error_code, l2)) else {
        return None
      }
      off = off + l2
      guard @varint.decode(b[off:]) is Some((final_size, l3)) else {
        return None
      }
      off = off + l3
      Some((ResetStream(id~, error_code~, final_size~), off))
    }
    5UL => {
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((id, l1)) else { return None }
      off = off + l1
      guard @varint.decode(b[off:]) is Some((error_code, l2)) else {
        return None
      }
      off = off + l2
      Some((StopSending(id~, error_code~), off))
    }
    7UL => {
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((length, ll)) else { return None }
      off = off + ll
      let n = length.to_int()
      if b.length() < off + n {
        return None
      }
      let token = b[off:off + n].to_owned()
      off = off + n
      Some((NewToken(token~), off))
    }
    0x10UL => {
      guard @varint.decode(b[tlen:]) is Some((v, vl)) else { return None }
      Some((MaxData(v), tlen + vl))
    }
    0x11UL => {
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((id, l1)) else { return None }
      off = off + l1
      guard @varint.decode(b[off:]) is Some((max, l2)) else { return None }
      off = off + l2
      Some((MaxStreamData(id~, max~), off))
    }
    ty if ty == 0x12UL || ty == 0x13UL => {
      guard @varint.decode(b[tlen:]) is Some((max, vl)) else { return None }
      Some((MaxStreams(bidi=ty == 0x12UL, max~), tlen + vl))
    }
    0x14UL => {
      guard @varint.decode(b[tlen:]) is Some((v, vl)) else { return None }
      Some((DataBlocked(v), tlen + vl))
    }
    0x15UL => {
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((id, l1)) else { return None }
      off = off + l1
      guard @varint.decode(b[off:]) is Some((max, l2)) else { return None }
      off = off + l2
      Some((StreamDataBlocked(id~, max~), off))
    }
    ty if ty == 0x16UL || ty == 0x17UL => {
      guard @varint.decode(b[tlen:]) is Some((max, vl)) else { return None }
      Some((StreamsBlocked(bidi=ty == 0x16UL, max~), tlen + vl))
    }
    0x18UL => {
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((seq, l1)) else { return None }
      off = off + l1
      guard @varint.decode(b[off:]) is Some((retire_prior_to, l2)) else {
        return None
      }
      off = off + l2
      if b.length() < off + 1 {
        return None
      }
      let cid_len = b[off].to_int()
      off = off + 1
      if b.length() < off + cid_len + 16 {
        return None
      }
      let conn_id = b[off:off + cid_len].to_owned()
      off = off + cid_len
      let reset_token = b[off:off + 16].to_owned()
      off = off + 16
      Some(
        (NewConnectionId(seq~, retire_prior_to~, conn_id~, reset_token~), off),
      )
    }
    0x19UL => {
      guard @varint.decode(b[tlen:]) is Some((seq, vl)) else { return None }
      Some((RetireConnectionId(seq), tlen + vl))
    }
    0x1aUL => {
      if b.length() < tlen + 8 {
        return None
      }
      Some((PathChallenge(b[tlen:tlen + 8].to_owned()), tlen + 8))
    }
    0x1bUL => {
      if b.length() < tlen + 8 {
        return None
      }
      Some((PathResponse(b[tlen:tlen + 8].to_owned()), tlen + 8))
    }
    0x1eUL => Some((HandshakeDone, tlen))
    0x1cUL => {
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((error_code, l1)) else {
        return None
      }
      off = off + l1
      guard @varint.decode(b[off:]) is Some((ft, l2)) else { return None }
      off = off + l2
      guard @varint.decode(b[off:]) is Some((rlen, l3)) else { return None }
      off = off + l3
      let n = rlen.to_int()
      if b.length() < off + n {
        return None
      }
      let reason = b[off:off + n].to_owned()
      off = off + n
      Some((ConnectionClose(error_code~, frame_type=Some(ft), reason~), off))
    }
    0x1dUL => {
      let mut off = tlen
      guard @varint.decode(b[off:]) is Some((error_code, l1)) else {
        return None
      }
      off = off + l1
      guard @varint.decode(b[off:]) is Some((rlen, l2)) else { return None }
      off = off + l2
      let n = rlen.to_int()
      if b.length() < off + n {
        return None
      }
      let reason = b[off:off + n].to_owned()
      off = off + n
      Some((ConnectionClose(error_code~, frame_type=None, reason~), off))
    }
    _ => None
  }
}

///|
/// Whether a single frame is ack-eliciting (RFC 9000 §13.2.1): every frame except
/// PADDING, ACK, ACK_ECN, and CONNECTION_CLOSE obliges the peer to acknowledge the packet.
pub fn elicits_ack(frame : Frame) -> Bool {
  match frame {
    Padding(_) | Ack(..) | AckEcn(..) | ConnectionClose(..) => false
    _ => true
  }
}

///|
pub extend Frame with Debug::{to_repr}

///|
pub extend Frame with Eq::{not_equal, equal}

// The ACK frame's range encoding (RFC 9000 §19.3.1). A receiver records which packet
// numbers arrived; an ACK reports them as the Largest Acknowledged, the First ACK Range,
// and a descending list of (Gap, ACK Range Length) pairs. Both directions live here
// because both are the frame's encoding; what to do with an acknowledgement is loss
// recovery's business.

///|
/// A malformed ACK frame: its fields do not describe a packet-number set.
pub(all) suberror Refused {
  Malformed(String)
} derive(Eq)

///|
pub extend Refused with Eq::{not_equal, equal}

///|
/// Refused ACKs print as the fault they are.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Malformed(m) => logger.write_string("Malformed(" + m + ")")
  }
}

///|
/// The packet numbers seen, held as ascending, non-overlapping, non-adjacent inclusive
/// runs `[lo, hi]`.
pub struct Seen {
  mut runs : Array[(UInt64, UInt64)]
}

///|
/// An empty set: nothing received yet.
pub fn Seen::new() -> Seen {
  { runs: [], }
}

///|
/// Whether nothing has been received.
pub fn Seen::is_empty(self : Seen) -> Bool {
  self.runs.length() == 0
}

///|
/// The largest packet number received, or `None` when empty.
pub fn Seen::largest(self : Seen) -> UInt64? {
  if self.runs.length() == 0 {
    None
  } else {
    Some(self.runs[self.runs.length() - 1].1)
  }
}

///|
/// Whether packet number `pn` has been received.
pub fn Seen::contains(self : Seen, pn : UInt64) -> Bool {
  for run in self.runs {
    if pn >= run.0 && pn <= run.1 {
      return true
    }
  }
  false
}

///|
/// The packet numbers as ascending inclusive ranges.
pub fn Seen::ranges(self : Seen) -> Array[(UInt64, UInt64)] {
  self.runs.copy()
}

///|
/// Record that packet number `pn` arrived. Out-of-order and duplicate numbers are
/// absorbed: the runs stay ascending and disjoint however they come in.
pub fn Seen::add(self : Seen, pn : UInt64) -> Unit {
  self.runs.push((pn, pn))
  self.runs = coalesce(self.runs)
}

///|
/// The ACK frame fields for the current set: the Largest Acknowledged, the First ACK
/// Range (how many contiguous packets below the largest are acked), and the descending
/// `(Gap, ACK Range Length)` list. `None` when nothing has been received.
pub fn Seen::fields(self : Seen) -> (UInt64, UInt64, Array[(UInt64, UInt64)])? {
  let n = self.runs.length()
  if n == 0 {
    return None
  }
  let (top_lo, top_hi) = self.runs[n - 1]
  let largest = top_hi
  let first_range = top_hi - top_lo
  let pairs : Array[(UInt64, UInt64)] = []
  // Walk down from the second-highest run, encoding each relative to the smallest of
  // the run above it.
  let mut prev_smallest = top_lo
  for i = n - 2; i >= 0; i = i - 1 {
    let (lo, hi) = self.runs[i]
    // Largest of this run = prev_smallest - Gap - 2  ->  Gap = prev_smallest - hi - 2.
    let gap = prev_smallest - hi - 2
    let length = hi - lo
    pairs.push((gap, length))
    prev_smallest = lo
  }
  Some((largest, first_range, pairs))
}

///|
/// The set an ACK frame's fields describe, the inverse of `fields`.
pub fn Seen::read(
  largest : UInt64,
  first_range : UInt64,
  pairs : Array[(UInt64, UInt64)],
) -> Seen raise Refused {
  let out : Array[(UInt64, UInt64)] = []
  if first_range > largest {
    raise Malformed("First ACK Range larger than Largest Acknowledged")
  }
  let mut smallest = largest - first_range
  out.push((smallest, largest))
  for pair in pairs {
    let (gap, length) = pair
    // Largest of the next run = smallest - Gap - 2.
    if smallest < gap + 2 {
      raise Malformed("ACK gap underflows the packet-number space")
    }
    let hi = smallest - gap - 2
    if length > hi {
      raise Malformed("ACK Range Length underflows")
    }
    let lo = hi - length
    out.push((lo, hi))
    smallest = lo
  }
  { runs: out.rev(), }
}

///|
/// The packet numbers an ACK or ACK_ECN frame acknowledges, as ascending inclusive
/// ranges; empty for every other frame.
pub fn Frame::acked(self : Frame) -> Array[(UInt64, UInt64)] raise Refused {
  match self {
    Ack(largest~, first_range~, ranges~, ..)
    | AckEcn(largest~, first_range~, ranges~, ..) =>
      Seen::read(largest, first_range, ranges).ranges()
    _ => []
  }
}

///|
/// Sort runs by low bound and merge any that overlap or sit next to each other
/// (`lo <= hi_prev + 1`), yielding ascending, non-overlapping, non-adjacent runs.
fn coalesce(runs : Array[(UInt64, UInt64)]) -> Array[(UInt64, UInt64)] {
  let sorted = runs.copy()
  sorted.sort_by((a, b) => a.0.compare(b.0))
  let out : Array[(UInt64, UInt64)] = []
  for run in sorted {
    let (lo, hi) = run
    if out.length() == 0 {
      out.push((lo, hi))
      continue
    }
    let (last_lo, last_hi) = out[out.length() - 1]
    if lo <= last_hi + 1 {
      if hi > last_hi {
        out[out.length() - 1] = (last_lo, hi)
      }
    } else {
      out.push((lo, hi))
    }
  }
  out
}

///|
pub extend Refused with Show::{to_string, output}
