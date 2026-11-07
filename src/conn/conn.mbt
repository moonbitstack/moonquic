// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A QUIC connection's numbering and handshake-input core (RFC 9000 §12.3, RFC 9001
// §4.1.3). A connection keeps three independent packet-number spaces — Initial,
// Handshake, and Application (1-RTT) — and a CRYPTO byte stream per encryption level,
// each ordered on its own. This skeleton routes a received packet's number to its space
// (for acknowledgement) and a received CRYPTO frame to its level's reassembler (yielding
// the contiguous TLS handshake bytes to feed the handshake), and hands out send-side
// packet numbers per space. It holds no keys or socket — the key schedule and the async
// UDP transport wrap this pure core.

///|
/// A QUIC encryption level / packet-number space (RFC 9001 §4.1.1). 0-RTT shares the
/// Application space, so the three long-lived spaces are Initial, Handshake, and
/// Application.
#derive(Eq, Debug)
pub(all) enum Level {
  Initial
  Handshake
  Application
}

///|
/// A QUIC connection's per-space numbering/ACK state and per-level CRYPTO streams.
pub struct Conn {
  is_server : Bool
  initial_space : @packet.Space
  handshake_space : @packet.Space
  application_space : @packet.Space
  /// Further paths' packet-number spaces (draft-ietf-quic-multipath §2.3). Each path id after
  /// 0 numbers its packets from zero and acknowledges them separately; path 0 is
  /// `application_space`, so a connection with one path allocates nothing extra.
  path_spaces : Map[UInt64, @packet.Space]
  initial_crypto : @stream.Assembler
  handshake_crypto : @stream.Assembler
  application_crypto : @stream.Assembler
}

///|
/// A fresh connection (client or server) with empty spaces and CRYPTO streams.
pub fn Conn::new(is_server : Bool) -> Conn {
  {
    is_server,
    initial_space: @packet.Space::new(),
    handshake_space: @packet.Space::new(),
    application_space: @packet.Space::new(),
    path_spaces: Map([]),
    initial_crypto: @stream.Assembler::new(),
    handshake_crypto: @stream.Assembler::new(),
    application_crypto: @stream.Assembler::new(),
  }
}

///|
/// Whether this endpoint is the server.
pub fn Conn::is_server(self : Conn) -> Bool {
  self.is_server
}

///|
/// The packet-number space for `level`.
pub fn Conn::space(self : Conn, level : Level) -> @packet.Space {
  match level {
    Initial => self.initial_space
    Handshake => self.handshake_space
    Application => self.application_space
  }
}

///|
/// The packet-number space for `level` on path `path`. Only Application has one per path: the
/// handshake runs on path 0, and the draft gives 0-RTT and 1-RTT a space for each path id
/// (draft-ietf-quic-multipath §2.3). Path 0 is the connection's own space.
pub fn Conn::space_on(
  self : Conn,
  path : UInt64,
  level : Level,
) -> @packet.Space {
  if level != Level::Application || path == 0UL {
    return self.space(level)
  }
  match self.path_spaces.get(path) {
    Some(space) => space
    None => {
      let space = @packet.Space::new()
      self.path_spaces[path] = space
      space
    }
  }
}

///|
/// How many paths the connection numbers packets for, path 0 among them.
pub fn Conn::paths(self : Conn) -> Int32 {
  self.path_spaces.length() + 1
}

///|
/// The CRYPTO reassembler for `level`.
pub fn Conn::crypto_stream(self : Conn, level : Level) -> @stream.Assembler {
  match level {
    Initial => self.initial_crypto
    Handshake => self.handshake_crypto
    Application => self.application_crypto
  }
}

///|
/// Allocate the next packet number to send at `level`.
pub fn Conn::next_packet_number(self : Conn, level : Level) -> Int64 {
  self.space(level).next_packet_number()
}

///|
/// Record that a packet numbered `pn` arrived at `level`; `ack_eliciting` marks one that
/// must be acknowledged.
pub fn Conn::on_packet_received(
  self : Conn,
  level : Level,
  pn : Int64,
  ack_eliciting : Bool,
) -> Unit {
  self.space(level).on_packet_received(pn, ack_eliciting)
}

///|
/// Record the peer's acknowledgement of up to `largest` at `level`.
pub fn Conn::on_ack_received(
  self : Conn,
  level : Level,
  largest : Int64,
) -> Unit {
  self.space(level).on_ack_received(largest)
}

///|
/// Build the ACK frame owed at `level`, or `None` if nothing has been received there.
pub fn Conn::build_ack(
  self : Conn,
  level : Level,
  ack_delay : UInt64,
) -> @frame.Frame? {
  self.space(level).build_ack(ack_delay)
}

///|
/// Feed a CRYPTO frame's `data` at `offset` and `level` into that level's handshake
/// stream, returning the newly contiguous TLS handshake bytes now readable (empty while
/// an earlier gap is still outstanding). CRYPTO streams carry no fin.
pub fn Conn::on_crypto_frame(
  self : Conn,
  level : Level,
  offset : UInt64,
  data : Bytes,
) -> Bytes raise @stream.Refused {
  let stream = self.crypto_stream(level)
  // A fragment past the window would have to be held across the gap it leaves. §7.5 lets an
  // endpoint refuse that, and a handshake with a gap this wide is not going to finish.
  if offset > stream.limit() {
    raise @stream.Exceeded(limit=stream.limit(), got=offset)
  }
  stream.insert(offset, data, fin=false)
  stream.read()
}

///|
pub extend Level with Debug::{to_repr}

///|
pub extend Level with Eq::{not_equal, equal}
