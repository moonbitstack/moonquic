// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Pacing (RFC 9002 §7.7) as the send loop applies it: a window goes out over the round trip
// rather than all at once.

///|
/// A sender with one stream and room to send it, used by the tests below.
fn paced_sender() -> Sender {
  let sender = Sender::new(
    1_000_000UL, 1_000_000UL, 1200L, 25_000L, 1_000L, 1024UL,
  )
  sender.queue_stream(0UL, Bytes::make(20_000, b'x'))
  sender
}

///|
test "an acknowledgement sets a pacing rate from the window and the round trip" {
  let sender = paced_sender()
  assert_eq(sender.pacing_rate(), 0.0)
  let (pn, _) = sender.poll_send(0L).unwrap()
  sender.on_ack(
    Ack(largest=pn.reinterpret_as_uint64(), delay=0UL, first_range=0UL, ranges=[]),
    1000L,
  )
  // The window over one and a quarter round trips, in bytes per microsecond.
  assert_true(sender.pacing_rate() > 0.0)
}

///|
test "a paced sender sends a burst and then holds the rest for the timer" {
  let sender = paced_sender()
  let (pn, _) = sender.poll_send(0L).unwrap()
  sender.on_ack(
    Ack(largest=pn.reinterpret_as_uint64(), delay=0UL, first_range=0UL, ranges=[]),
    1000L,
  )
  let mut sent = 0
  while true {
    match sender.poll_send(1000L) {
      Some(_) => {
        sent = sent + 1
        if sent > 100 {
          break
        }
      }
      None => break
    }
  }
  // Ten datagrams of burst, and no more at one instant: 12000 bytes of credit, about 1024
  // bytes a packet.
  assert_true(sent > 0 && sent <= 12)
  guard sender.paced_at(1000L) is Some(at) else {
    fail("a paced sender with data left has no timer")
  }
  assert_true(at > 1000L)
  assert_true(sender.poll_send(at) is Some(_))
}
