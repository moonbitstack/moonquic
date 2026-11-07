// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What a peer may put in a packet, and what it may not (RFC 9000 §12.4, §13.1, §18.2, §19).
// A connection that reads a frame it should not have is expected to close, not to drop the
// packet: dropping hides the fault from both ends and leaves the peer waiting. Each check
// answers the error code and the reason, so the close reads the same wherever it is raised.

///|
/// A peer's departure from the protocol: the error code to close with, and what it did.
priv struct Fault {
  code : UInt64
  reason : Bytes
}

///|
/// The largest stream count a peer may name: a stream ID has 62 bits, two of them saying who
/// opened it and whether it is bidirectional (RFC 9000 §4.6, §19.11).
let max_streams : UInt64 = 1UL << 60

///|
/// The largest acknowledgement delay exponent, and the smallest maximum acknowledgement
/// delay, that RFC 9000 §18.2 permits a peer to declare.
let max_ack_exponent : UInt64 = 20UL

///|
let max_ack_delay : UInt64 = 1UL << 14

///|
/// The smallest `max_udp_payload_size` RFC 9000 §18.2 permits.
let min_udp_payload : UInt64 = 1200UL

///|
/// The longest connection ID a transport parameter may carry (RFC 9000 §18.2).
let max_cid : Int32 = 20

///|
/// What a frame check needs to know about the connection it arrived on: which end this is, the
/// streams a peer may already have, the ones this end opened, and how far the packet-number
/// space has been used.
priv struct Standing {
  server : Bool
  streams : @stream.Streams
  sched : @stream.Scheduler
  sent : Int64
}

///|
/// Whether RFC 9000 §12.4's Table 3 lets a packet at `level` carry `frame`.
fn permitted(level : Level, frame : @frame.Frame) -> Bool {
  match level {
    Initial | Handshake =>
      frame
      is (Padding(_)
      | Ping
      | Crypto(..)
      | Ack(..)
      | AckEcn(..)
      | ConnectionClose(..))
    Application => true
  }
}

///|
/// Whether a frame may go in a 0-RTT packet (RFC 9000 §12.4's Table 3). CRYPTO is the one a
/// client tests with: early data carries no handshake bytes (RFC 9001 §8.3).
fn permitted_zero_rtt(frame : @frame.Frame) -> Bool {
  !(frame
  is (Ack(..)
  | AckEcn(..)
  | Crypto(..)
  | NewToken(..)
  | RetireConnectionId(_)
  | HandshakeDone))
}

///|
/// The fault in a frame that is well formed but not allowed here, if any. Structural faults
/// that the codec already refuses — a truncated frame, an unknown type — are the caller's to
/// raise as FRAME_ENCODING_ERROR before this runs.
fn frame_fault(
  level : Level,
  frame : @frame.Frame,
  standing : Standing,
) -> Fault? {
  guard permitted(level, frame) else {
    return Some({
      code: protocol_violation,
      reason: b"frame outside its level",
    })
  }
  match frame {
    Ack(largest~, first_range~, ranges~, ..)
    | AckEcn(largest~, first_range~, ranges~, ..)
    | PathAck(largest~, first_range~, ranges~, ..)
    | PathAckEcn(largest~, first_range~, ranges~, ..) => {
      // RFC 9000 §19.3.1: a range that would start below packet number 0 is a frame this
      // endpoint cannot have written. `Seen::read` raises for exactly those.
      let _ = @frame.Seen::read(largest, first_range, ranges) catch {
        _ =>
          return Some({
            code: frame_encoding_error,
            reason: b"an acknowledgement range below packet 0",
          })
      }
      // RFC 9000 §13.1: acknowledging a packet that was never sent is a protocol violation.
      if largest.reinterpret_as_int64() >= standing.sent {
        return Some({
          code: protocol_violation,
          reason: b"acknowledged a packet never sent",
        })
      }
      None
    }
    MaxStreams(bidi=_, max~) =>
      if max > max_streams {
        Some({
          code: frame_encoding_error,
          reason: b"MAX_STREAMS past the stream-number space",
        })
      } else {
        None
      }
    StreamsBlocked(bidi=_, max~) =>
      if max > max_streams {
        Some({
          code: stream_limit_error,
          reason: b"STREAMS_BLOCKED past the stream-number space",
        })
      } else {
        None
      }
    NewConnectionId(seq~, retire_prior_to~, conn_id~, reset_token~) =>
      if conn_id.length() == 0 {
        Some({
          code: frame_encoding_error,
          reason: b"NEW_CONNECTION_ID with no id",
        })
      } else if retire_prior_to > seq {
        Some({
          code: frame_encoding_error,
          reason: b"retire_prior_to past the sequence number",
        })
      } else if reset_token.length() != 16 {
        Some({
          code: frame_encoding_error,
          reason: b"NEW_CONNECTION_ID with a short reset token",
        })
      } else {
        None
      }
    PathNewConnectionId(
      path_id~,
      seq~,
      retire_prior_to~,
      conn_id~,
      reset_token~
    ) =>
      // §4.4: the same rules NEW_CONNECTION_ID has, per path.
      if path_id > max_path_id {
        Some({ code: protocol_violation, reason: b"a path id past 2^32-1", })
      } else if conn_id.length() == 0 {
        Some({
          code: frame_encoding_error,
          reason: b"PATH_NEW_CONNECTION_ID with no id",
        })
      } else if retire_prior_to > seq {
        Some({
          code: frame_encoding_error,
          reason: b"retire_prior_to past the sequence number",
        })
      } else if reset_token.length() != 16 {
        Some({
          code: frame_encoding_error,
          reason: b"PATH_NEW_CONNECTION_ID with a short reset token",
        })
      } else {
        None
      }
    PathRetireConnectionId(path_id~, ..) =>
      if path_id > max_path_id {
        Some({ code: protocol_violation, reason: b"a path id past 2^32-1", })
      } else {
        None
      }
    PathCidsBlocked(path_id~, ..) =>
      if path_id > max_path_id {
        Some({ code: protocol_violation, reason: b"a path id past 2^32-1", })
      } else {
        None
      }
    PathAbandon(path_id~, ..) =>
      // §3.1 of the draft: the handshake's path is the connection's, and giving it up is not
      // something a peer can ask for.
      if path_id == 0UL {
        Some({ code: protocol_violation, reason: b"abandoned path 0", })
      } else {
        None
      }
    MaxPathId(max~) | PathsBlocked(max~) =>
      if max > max_path_id {
        Some({ code: protocol_violation, reason: b"a path id past 2^32-1", })
      } else {
        None
      }
    NewToken(_) | HandshakeDone =>
      // RFC 9000 §19.7, §19.20: only a server sends these.
      if standing.server {
        Some({
          code: protocol_violation,
          reason: b"a frame only a server sends",
        })
      } else {
        None
      }
    Stream(id~, ..) =>
      // §19.8: a peer's STREAM on a stream this end opened is only allowed on a bidirectional
      // one this end has already created — a unidirectional one it never writes on, and a
      // bidirectional one does not exist for the peer until this end opens it.
      if @stream.is_local(id, server=standing.server) &&
        (!@stream.is_bidi(id) || !standing.sched.opened(id)) {
        Some({ code: stream_state_error, reason: b"STREAM on a local stream", })
      } else {
        stream_limit(id, standing)
      }
    ResetStream(id~, ..) =>
      // §19.4: the sender of a stream resets it, so a unidirectional stream this end opened
      // cannot be, while a bidirectional one has a sending side at either end.
      if @stream.is_local(id, server=standing.server) && !@stream.is_bidi(id) {
        Some({
          code: stream_state_error,
          reason: b"RESET_STREAM on a local stream",
        })
      } else {
        None
      }
    StopSending(id~, ..)
    | MaxStreamData(id~, ..)
    | StreamDataBlocked(id~, ..) =>
      // §19.5, §19.10, §19.13: these name a stream this end sends on, and one that exists.
      if !@stream.is_writable(id, server=standing.server) {
        Some({
          code: stream_state_error,
          reason: b"a frame for a stream we cannot send on",
        })
      } else if !standing.sched.opened(id) && !standing.streams.contains(id) {
        Some({
          code: stream_state_error,
          reason: b"a frame for a stream that does not exist",
        })
      } else {
        None
      }
    _ => None
  }
}

///|
/// Whether a STREAM frame names a stream the peer may still open (RFC 9000 §4.6). A count above
/// the limit this end advertised is STREAM_LIMIT_ERROR, not flow control: the frame never got as
/// far as a limit on bytes.
fn stream_limit(id : UInt64, standing : Standing) -> Fault? {
  if standing.streams.contains(id) {
    return None
  }
  let bidi = @stream.is_bidi(id)
  if @stream.sequence(id) + 1UL > standing.streams.limit(bidi~) {
    Some({
      code: stream_limit_error,
      reason: b"a stream past the limit this end advertised",
    })
  } else {
    None
  }
}

///|
/// The first fault among a packet's frames, or `None` when they are all allowed.
fn frames_fault(
  level : Level,
  frames : Array[@frame.Frame],
  standing : Standing,
) -> Fault? {
  if frames.length() == 0 {
    // RFC 9000 §12.4: a packet has to carry something.
    return Some({
      code: protocol_violation,
      reason: b"a packet with no frames",
    })
  }
  for frame in frames {
    if frame_fault(level, frame, standing) is Some(fault) {
      return Some(fault)
    }
  }
  None
}

///|
/// The first fault in a 0-RTT packet's frames.
fn zero_rtt_fault(frames : Array[@frame.Frame]) -> Fault? {
  if frames.length() == 0 {
    return Some({
      code: protocol_violation,
      reason: b"a packet with no frames",
    })
  }
  for frame in frames {
    if !permitted_zero_rtt(frame) {
      return Some({
        code: protocol_violation,
        reason: b"frame not allowed in 0-RTT",
      })
    }
  }
  None
}

///|
/// Whether the reserved bits of a packet that has just been opened are set (RFC 9000 §17.2.2,
/// §17.3.1). The check runs on the unprotected first byte, so only a packet that authenticated
/// can fail it.
fn reserved_set(
  packet : Bytes,
  keys : @crypto.Keys,
  at : Int32,
  short~ : Bool,
) -> Bool {
  let (plain, _) = keys.unprotect(packet[:], at~)
  let bits = if short { 0x18 } else { 0x0c }
  (plain[0].to_int() & bits) != 0
}

///|
/// The fault in a peer's transport parameters (RFC 9000 §7.4, §18.2). `server` says which end is
/// reading: a client must not declare a server's parameters, and both ends are held to the same
/// value bounds.
fn params_fault(params : ArrayView[Param], server~ : Bool) -> Fault? {
  let seen : Array[Kind] = []
  for param in params {
    if seen.contains(param.kind) {
      return Some({
        code: transport_parameter_error,
        reason: b"a transport parameter declared twice",
      })
    }
    seen.push(param.kind)
    if server && param.kind.server_only() {
      return Some({
        code: transport_parameter_error,
        reason: b"a client declared a server's parameter",
      })
    }
    if param.kind == StatelessResetToken && param.value.length() != 16 {
      return Some({
        code: transport_parameter_error,
        reason: b"a stateless reset token that is not 16 bytes",
      })
    }
    if param.kind == PreferredAddress && param.value.length() < 41 {
      return Some({
        code: transport_parameter_error,
        reason: b"a preferred address too short to hold one",
      })
    }
    match param.kind {
      OriginalDcid | InitialScid | RetryScid =>
        if param.value.length() > max_cid {
          return Some({
            code: transport_parameter_error,
            reason: b"a connection id longer than 20 bytes",
          })
        }
      MaxIdleTimeout
      | MaxUdpPayload
      | MaxData
      | MaxStreamDataBidiLocal
      | MaxStreamDataBidiRemote
      | MaxStreamDataUni
      | MaxStreamsBidi
      | MaxStreamsUni
      | AckDelayExponent
      | MaxAckDelay
      | ActiveConnectionIdLimit
      | MaxDatagramFrameSize
      | InitialMaxPathId => {
        let value = match param.as_int() {
          Some(value) => value
          None =>
            return Some({
              code: transport_parameter_error,
              reason: b"a parameter whose value is not a varint",
            })
        }
        let fault = match param.kind {
          MaxUdpPayload if value < min_udp_payload =>
            Some(b"max_udp_payload_size below 1200")
          AckDelayExponent if value > max_ack_exponent =>
            Some(b"ack_delay_exponent above 20")
          MaxAckDelay if value >= max_ack_delay =>
            Some(b"max_ack_delay at or above 2^14")
          MaxStreamsBidi | MaxStreamsUni if value > max_streams =>
            Some(b"a stream count past the stream-number space")
          ActiveConnectionIdLimit if value < 2UL =>
            Some(b"active_connection_id_limit below two")
          InitialMaxPathId if value > max_path_id =>
            Some(b"initial_max_path_id past 2^32-1")
          _ => None
        }
        if fault is Some(reason) {
          return Some({ code: transport_parameter_error, reason, })
        }
      }
      _ => ()
    }
  }
  None
}
