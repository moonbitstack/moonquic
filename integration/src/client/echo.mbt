// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The plain exchange: shake hands, write one stream, and read the same bytes back. This is what
// the interop scripts run first, to tell a peer that cannot be reached from one whose 0-RTT or
// path handling is wrong.

///|
async fn echo(
  socket : @udp.Socket,
  to : @socket.Addr,
  host : String,
  options : Map[String, String],
  payload : String,
) -> Unit {
  let scid = entropy(8)
  let client = @conn.Client::new(
    tls_client(options),
    host,
    params(scid),
    entropy,
    entropy(8),
    scid,
    wall(),
    cfg={ ..@conn.Config::default(), versions: versions_of(options), },
  ) catch {
    e => return fail("the client did not start: \{e}")
  }
  let link = Link::new(socket, to, client)
  link.handshake()
  let request = @utf8.encode(payload)
  client.write(0UL, request, fin=true)
  let answer = Buffer()
  let mut idle = 0
  while idle < 300 && answer.length() < request.length() {
    if link.turn() {
      idle = 0
    } else {
      idle += 1
    }
    let arrived = client.read(0UL)
    if arrived.length() > 0 {
      answer.write_bytes(arrived)
    }
  }
  println("echo \{@utf8.decode(answer.to_bytes())}")
  println("returned \{(answer.length() == request.length()).to_string()}")
  // The version the handshake settled on. A server that converted the first flight answers in
  // another version, and the scripts read this line rather than a server's buffered log.
  println("version \{client.negotiated_version()}")
  socket.close()
}
