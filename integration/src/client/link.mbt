// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The socket a connection runs on, and the loop that moves datagrams through it. A connection
// here holds no socket: the caller says which path a datagram arrived on and which one it leaves
// by, which is exactly what a peer holding two paths needs.

///|
/// One connection, the socket its path 0 leaves by, and one more per further path.
struct Link {
  socket : @udp.Socket
  to : @socket.Addr
  client : @conn.Client
  /// Datagram bytes sent and received on each path, path 0 included.
  sent : Map[UInt64, Int64]
  received : Map[UInt64, Int64]
  /// A further path's socket, and where that socket sends.
  wires : Map[UInt64, (@udp.Socket, @socket.Addr)]
}

///|
fn Link::new(
  socket : @udp.Socket,
  to : @socket.Addr,
  client : @conn.Client,
) -> Link {
  { socket, to, client, sent: Map([]), received: Map([]), wires: Map([]), }
}

///|
/// Add up what a path has carried.
fn bump(counts : Map[UInt64, Int64], path : UInt64, by : Int32) -> Unit {
  counts[path] = counts.get(path).unwrap_or(0L) + by.to_int64()
}

///|
/// Send everything the connection has queued: path 0 leaves by the connection's own socket, and
/// every further path by the socket the caller gave it.
async fn Link::flush(self : Link) -> Unit {
  let mark = now()
  for datagram in self.client.poll_out(mark) {
    bump(self.sent, 0UL, datagram.length())
    self.socket.send(self.to, datagram) catch {
      _ => ()
    }
  }
  for entry in self.client.poll_paths(mark) {
    let (path, datagram) = entry
    guard self.wires.get(path) is Some(wire) else { continue }
    let (socket, to) = wire
    bump(self.sent, path, datagram.length())
    socket.send(to, datagram) catch {
      _ => ()
    }
  }
}

///|
/// One turn of the loop: send what is due, wait up to `timeout` milliseconds for a datagram on
/// path 0, and give it to the connection. Answers whether one arrived.
async fn Link::turn(self : Link, timeout~ : Int32 = 20) -> Bool {
  self.client.tick(now())
  self.flush()
  guard self.socket.recv(timeout~) is Some((bytes, _)) else { return false }
  bump(self.received, 0UL, bytes.length())
  self.client.recv(bytes, now()) catch {
    e => println("error recv: \{e}")
  }
  true
}

///|
/// A datagram that arrived on a further path, given to that path's packet-number space.
async fn Link::turn_on(
  self : Link,
  path : UInt64,
  timeout~ : Int32 = 20,
) -> Bool {
  self.client.tick(now())
  self.flush()
  guard self.wires.get(path) is Some((socket, _)) else { return false }
  guard socket.recv(timeout~) is Some((bytes, _)) else { return false }
  bump(self.received, path, bytes.length())
  self.client.recv_on(path, bytes, now()) catch {
    e => println("error recv on \{path}: \{e}")
  }
  true
}

///|
/// Run until the handshake is confirmed, or give up after five hundred turns with nothing
/// arriving.
async fn Link::handshake(self : Link) -> Unit {
  let mut idle = 0
  while !self.client.is_connected() {
    if self.turn() {
      idle = 0
    } else {
      idle += 1
    }
    if idle > 500 {
      fail("the handshake did not finish")
    }
  }
  println("alpn \{self.client.alpn().unwrap_or("none")}")
}

///|
/// The wall clock as the platform gives it, in milliseconds.
fn ticks() -> Int64 {
  @env.now().reinterpret_as_int64()
}

///|
/// Where this process's clock starts, in microseconds. A connection's timers count from its own
/// beginning, so the run hands them a clock that starts at zero rather than one that starts in
/// 1970 — an idle timeout of thirty seconds would otherwise have expired before the first packet
/// went out.
let origin : Ref[Int64] = Ref(0L)

///|
/// The clock the transport takes, in microseconds from the start of the run: every duration in
/// this library is measured in microseconds.
fn now() -> Int64 {
  ticks() * 1_000L - origin.val
}

///|
/// Start the transport's clock at zero.
fn start() -> Unit {
  origin.val = ticks() * 1_000L
}

///|
/// Seconds since the epoch, the clock a certificate and a ticket are judged by.
fn wall() -> Int64 {
  ticks() / 1_000L
}

///|
/// The transport parameters this client declares. `paths` is how many paths beyond this one it
/// will maintain, which is what a peer reads before it offers connection ids for them.
fn params(scid : Bytes, paths~ : UInt64 = 0UL) -> Bytes {
  let limits = @conn.Limits::new(
    idle_timeout=60_000_000UL,
    data=16_000_000UL,
    stream_data_bidi_local=8_000_000UL,
    stream_data_bidi_remote=8_000_000UL,
    stream_data_uni=1_000_000UL,
    streams_bidi=128UL,
    streams_uni=16UL,
  )
  let block = limits.params()
  block.push({ kind: @conn.Kind::InitialScid, value: scid, })
  if paths > 0UL {
    block.push({
      kind: @conn.Kind::InitialMaxPathId,
      value: @quic.encode(paths),
    })
  }
  @conn.encode(block[:])
}

///|
fn hex(bytes : BytesView) -> String {
  let digits : Array[Char] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  let out = StringBuilder()
  for byte in bytes {
    out.write_char(digits[(byte.to_int() >> 4) & 0xf])
    out.write_char(digits[byte.to_int() & 0xf])
  }
  out.to_string()
}
