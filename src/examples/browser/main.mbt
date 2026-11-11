// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The bridge the documentation site imports in the browser. Every entry point takes and answers
// plain JavaScript strings holding JSON, so the page never learns how MoonBit lays a value out.
//
// Everything here is this library's own code: the packet is sealed by `@crypto`, laid out by
// `@packet`, read back by `@frame`, and the transport parameters are the block `@conn` declares.
// The page shows what the library prints and nothing else.

///|
/// The connection IDs the demonstration packet uses, both fixed so the page shows the same bytes
/// on every visit.
let demo_dcid : Bytes = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"

///|
let demo_scid : Bytes = b"\xaa\xbb\xcc\xdd"

///|
/// Hex, lower case, two digits a byte.
fn hex(bytes : BytesView) -> String {
  let digits : Array[String] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
  ]
  let out = StringBuilder()
  for b in bytes {
    let v = b.to_int()
    out.write_string(digits[(v >> 4) & 15])
    out.write_string(digits[v & 15])
  }
  out.to_string()
}

///|
/// `s` as a JSON string literal.
fn q(s : StringView) -> String {
  let out = StringBuilder()
  out.write_char('"')
  for c in s {
    if c == '"' {
      out.write_string("\\\"")
    } else if c == '\\' {
      out.write_string("\\\\")
    } else if c == '\n' {
      out.write_string("\\n")
    } else if c.to_int() < 0x20 {
      out.write_string("\\u00")
      out.write_string(((c.to_int() >> 4) & 0xf).to_string())
      out.write_string((c.to_int() & 0xf).to_string())
    } else {
      out.write_char(c)
    }
  }
  out.write_char('"')
  out.to_string()
}

///|
/// A field of the packet: what it is, which bytes it occupies, and what the bytes say.
fn field(
  name : StringView,
  from : Int32,
  to : Int32,
  value : StringView,
  note : StringView,
) -> String {
  "{\"name\":" +
  q(name) +
  ",\"from\":" +
  from.to_string() +
  ",\"to\":" +
  to.to_string() +
  ",\"value\":" +
  q(value) +
  ",\"note\":" +
  q(note) +
  "}"
}

///|
/// The name a frame is known by.
fn frame_name(frame : @frame.Frame) -> String {
  match frame {
    Padding(_) => "PADDING"
    Ping => "PING"
    Crypto(..) => "CRYPTO"
    Stream(..) => "STREAM"
    Datagram(_) => "DATAGRAM"
    Ack(..) => "ACK"
    AckEcn(..) => "ACK_ECN"
    ResetStream(..) => "RESET_STREAM"
    StopSending(..) => "STOP_SENDING"
    NewToken(_) => "NEW_TOKEN"
    MaxData(_) => "MAX_DATA"
    MaxStreamData(..) => "MAX_STREAM_DATA"
    MaxStreams(..) => "MAX_STREAMS"
    DataBlocked(_) => "DATA_BLOCKED"
    StreamDataBlocked(..) => "STREAM_DATA_BLOCKED"
    StreamsBlocked(..) => "STREAMS_BLOCKED"
    NewConnectionId(..) => "NEW_CONNECTION_ID"
    RetireConnectionId(_) => "RETIRE_CONNECTION_ID"
    PathChallenge(_) => "PATH_CHALLENGE"
    PathResponse(_) => "PATH_RESPONSE"
    HandshakeDone => "HANDSHAKE_DONE"
    ConnectionClose(..) => "CONNECTION_CLOSE"
    PathAck(..) => "PATH_ACK"
    PathAckEcn(..) => "PATH_ACK_ECN"
    PathAbandon(..) => "PATH_ABANDON"
    PathStatus(..) => "PATH_STATUS"
    PathNewConnectionId(..) => "PATH_NEW_CONNECTION_ID"
    PathRetireConnectionId(..) => "PATH_RETIRE_CONNECTION_ID"
    MaxPathId(..) => "MAX_PATH_ID"
    PathsBlocked(..) => "PATHS_BLOCKED"
    PathCidsBlocked(..) => "PATH_CIDS_BLOCKED"
  }
}

///|
/// What a frame says, as a short line for the reader.
fn frame_detail(frame : @frame.Frame) -> String {
  match frame {
    Padding(n) => "\{n} bytes of zero"
    Ping => "no body"
    Crypto(offset~, data~) => "offset \{offset}, \{data.length()} bytes"
    Stream(id~, offset~, data~, ..) =>
      "stream \{id}, offset \{offset}, \{data.length()} bytes"
    Datagram(data~) => "\{data.length()} bytes, never retransmitted"
    Ack(largest~, first_range~, ranges~, ..)
    | AckEcn(largest~, first_range~, ranges~, ..) =>
      "largest \{largest}, first range \{first_range}, \{ranges.length()} more"
    PathAck(path_id~, largest~, ..) => "path \{path_id}, largest \{largest}"
    MaxData(v) => "\{v} bytes on the connection"
    MaxStreamData(id~, max~) => "stream \{id} up to \{max}"
    MaxStreams(max~, ..) => "\{max} streams"
    NewConnectionId(seq~, conn_id~, ..) => "sequence \{seq}, id \{hex(conn_id)}"
    PathStatus(path_id~, seq~, available~) =>
      "path \{path_id}, sequence \{seq}, \{if available { "available" } else { "backup" }}"
    MaxPathId(max~) => "\{max} paths"
    _ => "no body read here"
  }
}

///|
/// The demonstration packet: a client's first Initial, a PING in it, padded to the 1200-byte
/// datagram floor the way RFC 9000 §14.1 requires. It is sealed with the Initial keys the
/// destination connection id alone yields, so the page can show real ciphertext rather than a
/// diagram of one.
fn initial_packet() -> Bytes {
  let (client, _) = @crypto.initial(demo_dcid[:])
  let body = @packet.payload([@frame.Ping])
  let seal = padded => {
    @conn.seal_long(
      @packet.Kind::Initial,
      1U,
      demo_dcid,
      demo_scid,
      0L,
      4,
      padded,
      client,
    )
  }
  // RFC 9000 §14.1: an ack-eliciting Initial takes its datagram to 1200 bytes, and the padding is
  // PADDING frames inside the payload, so the header's Length field grows with it. Padding to the
  // exact deficit and re-measuring converges in two rounds; the Length varint can widen by two
  // bytes on the way, which is what the second round pays for.
  let mut target = body.length()
  let mut packet = seal(body)
  for _round = 0; _round < 4; _round = _round + 1 {
    if packet.length() == @conn.min_datagram {
      break
    }
    target = target + (@conn.min_datagram - packet.length())
    packet = seal(@packet.pad(body, target))
  }
  packet
}

///|
/// The packet, its header field by field, and the frames inside it: everything the page needs to
/// draw a card whose holes are its bytes.
#export_name("initial")
pub fn initial() -> String {
  let packet = initial_packet()
  let out = StringBuilder()
  out.write_string("{\"hex\":")
  out.write_string(q(hex(packet[:])))
  out.write_string(",\"length\":")
  out.write_string(packet.length().to_string())
  out.write_string(",\"dcid\":")
  out.write_string(q(hex(demo_dcid[:])))
  out.write_string(",\"scid\":")
  out.write_string(q(hex(demo_scid[:])))
  out.write_string(",\"pn\":0,\"fields\":[")
  match @packet.read_header(packet[:]) {
    Some((_, tail)) => {
      let (client_keys, _) = @crypto.initial(demo_dcid[:])
      // Header protection masks the first byte and the packet number, so what they say is only
      // known once it is removed; the wire byte is shown beside it.
      let (head, pn_size) = client_keys.unprotect(packet[:], at=tail.at)
      let fields : Array[String] = []
      fields.push(
        field(
          "Header form, type, number length",
          0,
          1,
          hex(head[0:1]),
          "long header, Initial, 4-byte number; 0x" +
          hex(packet[0:1]) +
          " on the wire, masked",
        ),
      )
      fields.push(field("Version", 1, 5, hex(packet[1:5]), "QUIC version 1"))
      let dcid_len = packet[5].to_int()
      fields.push(
        field(
          "Destination connection id",
          6,
          6 + dcid_len,
          hex(packet[6:6 + dcid_len]),
          "the id the server answers by; the Initial keys come from it",
        ),
      )
      let scid_at = 6 + dcid_len + 1
      let scid_len = packet[scid_at - 1].to_int()
      fields.push(
        field(
          "Source connection id",
          scid_at,
          scid_at + scid_len,
          hex(packet[scid_at:scid_at + scid_len]),
          "the client's own id",
        ),
      )
      let token_at = scid_at + scid_len + 1
      fields.push(
        field(
          "Token length",
          scid_at + scid_len,
          token_at,
          "0",
          "no Retry token",
        ),
      )
      let length_at = tail.at - 2
      fields.push(
        field(
          "Length",
          length_at,
          tail.at,
          tail.length.to_string(),
          "packet number, payload and AEAD tag, to the end of the packet",
        ),
      )
      fields.push(
        field(
          "Packet number",
          tail.at,
          tail.at + pn_size,
          "0",
          "protected; the low byte survives the mask here",
        ),
      )
      let end = tail.at + tail.length.to_int()
      fields.push(
        field(
          "Protected payload",
          tail.at + pn_size,
          end - 16,
          "\{end - 16 - tail.at - pn_size} bytes",
          "the frames, sealed",
        ),
      )
      fields.push(
        field(
          "AEAD tag",
          end - 16,
          end,
          hex(packet[end - 16:end]),
          "AES-128-GCM over the payload with the header as data",
        ),
      )
      // The frames, each with the bytes it occupies once the packet is opened.
      let frames : Array[String] = []
      let plain = client_keys.open(packet[:], largest=-1L)
      match plain {
        Some((opened, _)) => {
          let start = tail.at + pn_size
          let mut at = 0
          while at < opened.length() {
            let view = opened[at:]
            let (frame, used) = @frame.decode(view[:]) catch { _ => break }
            frames.push(
              "{\"type\":" +
              q(frame_name(frame)) +
              ",\"from\":" +
              (start + at).to_string() +
              ",\"to\":" +
              (start + at + used).to_string() +
              ",\"note\":" +
              q(frame_detail(frame)) +
              "}",
            )
            at = at + used
          }
        }
        None => ()
      }
      let mut first = true
      for f in fields {
        if !first {
          out.write_char(',')
        }
        first = false
        out.write_string(f)
      }
      out.write_string("],\"frames\":[")
      let mut first_frame = true
      for f in frames {
        if !first_frame {
          out.write_char(',')
        }
        first_frame = false
        out.write_string(f)
      }
      out.write_string("]")
    }
    None => out.write_string("],\"frames\":[]")
  }
  out.write_string("}")
  out.to_string()
}

///|
/// The transport parameters a connection of this library declares, with the bytes of each one, so
/// the page can show the block a handshake carries and not only a packet.
#export_name("params")
pub fn transport_parameters() -> String {
  let block = @conn.encode(declared_block())
  let out = StringBuilder()
  out.write_string("{\"hex\":")
  out.write_string(q(hex(block[:])))
  out.write_string(",\"length\":")
  out.write_string(block.length().to_string())
  out.write_string(",\"params\":[")
  let params = @conn.decode(block[:]) catch { _ => [] }
  let mut at = 0
  let mut first = true
  for param in params {
    let wire = @conn.encode([param])
    let size = wire.length()
    if !first {
      out.write_char(',')
    }
    first = false
    out.write_string("{\"code\":")
    out.write_string(param.kind.code().to_string())
    out.write_string(",\"name\":")
    out.write_string(q(kind_name(param.kind)))
    out.write_string(",\"from\":")
    out.write_string(at.to_string())
    out.write_string(",\"to\":")
    out.write_string((at + size).to_string())
    out.write_string(",\"value\":")
    out.write_string(
      q(
        match param.kind {
          // These carry an id or a token, so their value is bytes rather than a number.
          OriginalDcid | InitialScid | RetryScid | StatelessResetToken =>
            hex(param.value[:])
          PreferredAddress => "\{param.value.length()} bytes"
          _ =>
            match param.as_int() {
              Some(v) => v.to_string()
              None => hex(param.value[:])
            }
        },
      ),
    )
    out.write_string(",\"note\":")
    out.write_string(q(kind_note(param.kind)))
    out.write_string("}")
    at = at + size
  }
  out.write_string("]}")
  out.to_string()
}

///|
/// The parameter block this connection declares: the defaults an HTTP/3 server would use, plus the
/// ids the handshake has to pin down.
fn declared_block() -> Array[@conn.Param] {
  let params = @conn.Limits::new(
    idle_timeout=30_000UL,
    data=1_048_576UL,
    stream_data_bidi_local=1_048_576UL,
    stream_data_bidi_remote=1_048_576UL,
    stream_data_uni=1_048_576UL,
    streams_bidi=100UL,
    streams_uni=100UL,
  ).params()
  params.push({ kind: @conn.InitialScid, value: demo_scid, })
  params.push({ kind: @conn.InitialMaxPathId, value: b"\x01", })
  params
}

///|
/// The name RFC 9000 §18.2 gives a parameter.
fn kind_name(kind : @conn.Kind) -> String {
  match kind {
    OriginalDcid => "original_destination_connection_id"
    MaxIdleTimeout => "max_idle_timeout"
    StatelessResetToken => "stateless_reset_token"
    MaxUdpPayload => "max_udp_payload_size"
    MaxData => "initial_max_data"
    MaxStreamDataBidiLocal => "initial_max_stream_data_bidi_local"
    MaxStreamDataBidiRemote => "initial_max_stream_data_bidi_remote"
    MaxStreamDataUni => "initial_max_stream_data_uni"
    MaxStreamsBidi => "initial_max_streams_bidi"
    MaxStreamsUni => "initial_max_streams_uni"
    AckDelayExponent => "ack_delay_exponent"
    MaxAckDelay => "max_ack_delay"
    DisableActiveMigration => "disable_active_migration"
    PreferredAddress => "preferred_address"
    ActiveConnectionIdLimit => "active_connection_id_limit"
    InitialScid => "initial_source_connection_id"
    RetryScid => "retry_source_connection_id"
    MaxDatagramFrameSize => "max_datagram_frame_size"
    InitialMaxPathId => "initial_max_path_id"
    VersionInformation => "version_information"
    Other(code) => "0x" + code.to_string()
  }
}

///|
/// What a parameter means, in one line.
fn kind_note(kind : @conn.Kind) -> String {
  match kind {
    MaxIdleTimeout => "microseconds the connection may sit idle"
    MaxUdpPayload => "largest datagram this end will receive"
    MaxData => "credit on the connection, in bytes"
    MaxStreamDataBidiLocal => "credit on a stream the peer opened"
    MaxStreamDataBidiRemote => "credit on a stream this end opened"
    MaxStreamDataUni => "credit on a unidirectional stream"
    MaxStreamsBidi => "streams the peer may open, bidirectional"
    MaxStreamsUni => "streams the peer may open, unidirectional"
    AckDelayExponent => "how the peer scales acknowledgement delay"
    MaxAckDelay => "how long the peer may hold an acknowledgement"
    ActiveConnectionIdLimit => "connection ids the peer may hold at once"
    InitialScid => "the id this end calls itself"
    MaxDatagramFrameSize => "largest DATAGRAM frame, zero meaning none"
    InitialMaxPathId =>
      "paths this end will maintain, draft-ietf-quic-multipath"
    _ => ""
  }
}
