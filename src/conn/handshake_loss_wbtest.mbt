// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A handshake that loses the one packet it cannot do without: the client's Finished
// (RFC 9000 §17.2.3, RFC 9002 §6.2). The client owes four flights and the server three, and a
// loss in either direction has to be recovered by the probe timeout, or the handshake wedges with
// both ends waiting.

///|
/// The datagrams a client's flight consists of, split by what they carry.
fn split_flight(flight : Array[Bytes]) -> (Array[Bytes], Array[Bytes]) {
  let handshake : Array[Bytes] = []
  let rest : Array[Bytes] = []
  for datagram in flight {
    let first = datagram[0].to_int()
    // A long header's type sits in the two bits above the form and fixed bits: 0x20 is Handshake
    // and 0x00 is Initial in QUIC version 1 (RFC 9000 §17.2).
    if (first & 0x80) != 0 && (first & 0x30) == 0x20 {
      handshake.push(datagram)
    } else {
      rest.push(datagram)
    }
  }
  (handshake, rest)
}

///|
test "a handshake completes when only the client's Finished is lost" {
  let client = make_client()
  let server = new_server()
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L)
  }
  for datagram in drain(server, 1000L) {
    client.recv(datagram, 1000L)
  }
  // The client's last flight: its Finished in a Handshake packet, whatever else it had.
  let (finished, rest) = split_flight(client.poll_out(1000L))
  assert_eq(finished.length(), 1)
  for datagram in rest {
    server.recv(datagram, from, 1000L)
  }
  // Only the Finished was dropped.
  let conn = only_conn(server)
  assert_false(conn.take_events().contains(Connected))
  // The probe timeout puts it back on the wire, numbered on rather than from the start.
  let pto = client.sender.recovery.pto()
  client.tick(1000L + pto)
  let again = client.poll_out(1000L + pto)
  assert_true(again.length() > 0)
  for datagram in again {
    server.recv(datagram, from, 1000L + pto)
  }
  assert_true(conn.take_events().contains(Connected))
  // And the connection works: the stream written here arrives under the 1-RTT keys.
  client.write(0UL, b"after the loss", fin=true)
  for datagram in client.poll_out(1000L + 2L * pto) {
    server.recv(datagram, from, 1000L + 2L * pto)
  }
  assert_eq(conn.read(0UL), b"after the loss")
}

///|
test "a handshake completes when the server's handshake flight is lost once" {
  let client = make_client()
  let server = new_server()
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L)
  }
  // The server's whole handshake flight is lost: nothing reaches the client.
  let lost = drain(server, 1000L)
  assert_true(lost.length() > 0)
  assert_false(client.tls.is_connected())
  // The server's own probe timeout puts the flight back on the wire.
  let pto = only_conn(server).sender.recovery.pto()
  server.tick(1000L + pto)
  let again = drain(server, 1000L + pto)
  assert_eq(again.length(), lost.length())
  for datagram in again {
    client.recv(datagram, 1000L + pto)
  }
  for datagram in client.poll_out(1000L + pto) {
    server.recv(datagram, from, 1000L + pto)
  }
  assert_true(client.is_connected())
  assert_true(only_conn(server).take_events().contains(Connected))
}

///|
test "losing the client's Finished twice still leaves a handshake that finishes" {
  let client = make_client()
  let server = new_server()
  for datagram in client.poll_out(1000L) {
    server.recv(datagram, from, 1000L)
  }
  for datagram in drain(server, 1000L) {
    client.recv(datagram, 1000L)
  }
  let (finished, rest) = split_flight(client.poll_out(1000L))
  assert_eq(finished.length(), 1)
  for datagram in rest {
    server.recv(datagram, from, 1000L)
  }
  let conn = only_conn(server)
  // Each probe timeout doubles, as RFC 9002 §6.2.1 asks.
  let pto = client.sender.recovery.pto()
  client.tick(1000L + pto)
  let (again, leftovers) = split_flight(client.poll_out(1000L + pto))
  for datagram in leftovers {
    server.recv(datagram, from, 1000L + pto)
  }
  assert_eq(again.length(), 1)
  // Dropped again: the timer backs off rather than repeating at the same interval.
  let second = 1000L + pto + 2L * pto
  client.tick(second)
  let (third, other) = split_flight(client.poll_out(second))
  for datagram in other {
    server.recv(datagram, from, second)
  }
  assert_eq(third.length(), 1)
  for datagram in third {
    server.recv(datagram, from, second)
  }
  assert_true(conn.take_events().contains(Connected))
}
