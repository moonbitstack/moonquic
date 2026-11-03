// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What an application sees of a connection: events to read off, and streams to read and write.
// A stream's credit goes back to the peer as the application reads, so a slow reader slows its
// peer down rather than filling this process (RFC 9000 §4.1).

///|
/// Something a connection has to tell its application.
#derive(Eq, Debug)
pub(all) enum Event {
  /// The handshake is complete.
  Connected
  /// A stream has bytes to read, or has ended.
  Readable(UInt64)
  /// The peer abandoned the stream it was sending (RESET_STREAM).
  Reset(UInt64, UInt64)
  /// The peer no longer wants what this end sends on the stream (STOP_SENDING).
  Stopped(UInt64, UInt64)
  /// The connection is over, with the error code that ended it; 0 for an idle timeout.
  Closed(UInt64)
  /// A DATAGRAM frame arrived (RFC 9221); `take_datagrams` reads what is waiting.
  Datagram
}

///|
pub extend Event with Eq::{not_equal, equal}

///|
pub extend Event with Debug::{to_repr}

///|
/// What has happened on this connection since the last call, emptied by it.
pub fn[A] Session::take_events(self : Session[A]) -> Array[Event] {
  let out = self.events.copy()
  self.events.clear()
  out
}

///|
/// The bytes readable on stream `id` in order, emptied by the call. Their flow-control credit
/// goes back to the peer here.
pub fn[A] Session::read(self : Session[A], id : UInt64) -> Bytes {
  let data = self.streams.read(id)
  if data.length() > 0 {
    if self.streams.max_data() is Some(max) {
      self.sender.queue_control(MaxData(max))
    }
    if self.streams.max_stream_data(id) is Some(max) {
      self.sender.queue_control(MaxStreamData(id~, max~))
    }
  }
  data
}

///|
/// Whether stream `id` has ended and every byte of it has been read.
pub fn[A] Session::finished(self : Session[A], id : UInt64) -> Bool {
  self.streams.finished(id)
}

///|
/// Queue `data` on stream `id`, and end the stream after it when `fin`.
pub fn[A] Session::write(
  self : Session[A],
  id : UInt64,
  data : Bytes,
  fin~ : Bool = false,
) -> Unit {
  self.sender.queue_stream(id, data)
  if fin {
    self.sender.queue_fin(id)
  }
}

///|
/// How many bytes written to stream `id` the peer has not acknowledged, which is what an
/// application paces itself by.
pub fn[A] Session::buffered(self : Session[A], id : UInt64) -> UInt64 {
  self.sender.buffered(id)
}

///|
/// A new unidirectional stream from this server (RFC 9000 §2.1).
pub fn[A] Session::open_uni(self : Session[A]) -> UInt64 {
  let id = self.next_uni * 4UL + 3UL
  self.next_uni = self.next_uni + 1UL
  id
}

///|
/// Abandon sending on stream `id` with `code`.
pub fn[A] Session::reset(self : Session[A], id : UInt64, code : UInt64) -> Unit {
  self.sender.abandon(id, code)
}

///|
/// Ask the peer to stop sending on stream `id` with `code`.
pub fn[A] Session::stop(self : Session[A], id : UInt64, code : UInt64) -> Unit {
  self.sender.queue_control(StopSending(id~, error_code=code))
}

///|
/// Queue an unreliable application datagram (RFC 9221), answering whether it was taken. It is
/// refused when the peer did not advertise datagram support or when it would not fit.
pub fn[A] Session::send_datagram(self : Session[A], data : Bytes) -> Bool {
  self.sender.queue_datagram(data)
}

///|
/// The datagrams that arrived since the last call, emptied by it, in arrival order. A datagram
/// is whole; it is not a byte stream and nothing is retransmitted.
pub fn[A] Session::take_datagrams(self : Session[A]) -> Array[Bytes] {
  let out = self.datagrams.copy()
  self.datagrams.clear()
  out
}

///|
/// The application is done with stream `id`: its slot goes back to the peer (RFC 9000 §4.6).
pub fn[A] Session::release(self : Session[A], id : UInt64) -> Unit {
  self.streams.release(id)
  if self.streams.max_streams(bidi=true) is Some(max) {
    self.sender.queue_control(MaxStreams(bidi=true, max~))
  }
  if self.streams.max_streams(bidi=false) is Some(max) {
    self.sender.queue_control(MaxStreams(bidi=false, max~))
  }
}

///|
/// The ALPN protocol the handshake settled on.
pub fn[A] Session::alpn(self : Session[A]) -> String? {
  match self.tls {
    Some(tls) => tls.alpn()
    None => None
  }
}

///|
/// The host name the client asked for by SNI.
pub fn[A] Session::server_name(self : Session[A]) -> String? {
  match self.tls {
    Some(tls) => tls.server_name()
    None => None
  }
}

///|
/// The TLS code of the cipher suite in force, 0 before one is chosen.
pub fn[A] Session::suite_code(self : Session[A]) -> Int32 {
  match self.tls {
    Some(tls) =>
      match tls.suite() {
        Some(suite) => suite.code()
        None => 0
      }
    None => 0
  }
}
