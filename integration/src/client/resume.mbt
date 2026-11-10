// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Resumption, twice in one process: a first connection that draws a ticket, and a second that
// resumes from it with neither `Config` credit field set. Everything the early data may spend
// therefore comes out of the ticket's own transport parameters (RFC 9000 §7.4.1), and the bytes
// of the first flight that carry a stream are 0-RTT packets.

///|
async fn resumed(
  socket : @udp.Socket,
  to : @socket.Addr,
  host : String,
  options : Map[String, String],
  payload : String,
) -> Unit {
  let store = @tls.Sessions::new()
  // The first connection: a handshake, an exchange, and a ticket on the way out.
  let first_scid = entropy(8)
  let first = @conn.Client::new(
    tls_client(options, sessions=store, early=false),
    host,
    params(first_scid),
    entropy,
    entropy(8),
    first_scid,
    wall(),
  ) catch {
    e => return fail("the first client did not start: \{e}")
  }
  let opening = Link::new(socket, to, first)
  opening.handshake()
  // The exchange that makes the server issue a ticket. `read` is what says whether the answer
  // has come back; a stream that was only written has no receive side to ask about.
  let warm = @utf8.encode(payload)
  first.write(0UL, warm, fin=true)
  let answer = Buffer()
  let mut idle = 0
  while idle < 300 && answer.length() < warm.length() {
    if opening.turn() {
      idle = 0
    } else {
      idle += 1
    }
    let arrived = first.read(0UL)
    if arrived.length() > 0 {
      answer.write_bytes(arrived)
    }
  }
  // The ticket arrives in a 1-RTT CRYPTO frame after the handshake, sometimes after the answer.
  while idle < 300 && first.remembered() is None {
    if opening.turn() {
      idle = 0
    } else {
      idle += 1
    }
  }
  guard first.remembered() is Some(kept) else {
    return fail("no ticket came back")
  }
  println("warm_echo \{@utf8.decode(answer.to_bytes())}")
  println("ticket yes")
  socket.close()

  // The second connection: the ticket's session, nothing of `Config` saying how much early data
  // may spend.
  let early = @utf8.encode(payload)
  let scid = entropy(8)
  let socket = @udp.bind(host="127.0.0.1", port=0)
  let client = @conn.Client::new(
    tls_client(options, sessions=store, early=true),
    host,
    params(scid),
    entropy,
    entropy(8),
    scid,
    wall(),
    resumption=kept,
  ) catch {
    e => return fail("the resuming client did not start: \{e}")
  }
  let link = Link::new(socket, to, client)
  client.write(0UL, early, fin=true)
  // Nothing has been sent yet, so the handshake cannot have finished: what comes out of this call
  // is the opening flight, and whatever of it is 0-RTT carries the stream.
  println("early_before_handshake \{!client.is_connected()}")
  let flight = client.poll_out(now())
  let mut zero = 0
  let mut zero_bytes = 0
  for datagram in flight {
    // RFC 9000 §17.2.3: the two most significant bits are 11 and the next two are 00 for 0-RTT.
    if datagram.length() > 0 && (datagram[0].to_int() & 0xf0) == 0xd0 {
      zero += 1
      zero_bytes += datagram.length()
    }
    link.socket.send(link.to, datagram) catch {
      _ => ()
    }
  }
  println("early_datagrams \{zero}")
  println("early_bytes \{zero_bytes}")
  // The exchange proper: the handshake finishes, then the server's answer to the early bytes.
  let answer = Buffer()
  let mut idle = 0
  while idle < 300 && answer.length() < early.length() {
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
  println("early_accepted \{client.early_accepted()}")
  println("echo \{@utf8.decode(answer.to_bytes())}")
  println("returned \{(answer.length() == early.length()).to_string()}")
  socket.close()
}
