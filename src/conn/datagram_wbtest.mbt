// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// DATAGRAM through the send loop and the transport parameters (RFC 9221): a datagram is
// queued only when the peer advertised support and it fits, it goes out once, and a probe
// does not resend it.

///|
test "a peer that advertised datagram support receives one" {
  let s = Sender::new(1_000_000UL, 1_000_000UL, 1200L, 25000L, 1000L, 1000UL)
  s.on_peer_datagram(1200UL)
  assert_eq(s.queue_datagram(b"ping"), true)
  assert_eq(s.pending_datagrams(), 1)
  match s.poll_send(1000L) {
    Some((_, frames)) => {
      assert_eq(frames.length(), 1)
      match frames[0] {
        @frame.Datagram(data~) => assert_eq(data, b"ping")
        _ => abort("the packet did not carry the datagram")
      }
    }
    None => abort("nothing was sent")
  }
  assert_eq(s.pending_datagrams(), 0)
}

///|
test "a peer that did not advertise datagram support refuses them" {
  let s = Sender::new(1_000_000UL, 1_000_000UL, 1200L, 25000L, 1000L, 1000UL)
  assert_eq(s.queue_datagram(b"ping"), false)
  assert_eq(s.pending_datagrams(), 0)
}

///|
test "a datagram larger than the peer accepts is refused" {
  let s = Sender::new(1_000_000UL, 1_000_000UL, 1200L, 25000L, 1000L, 1000UL)
  s.on_peer_datagram(100UL)
  // 95 bytes plus the type and length is 104, past the 100 the peer accepts.
  assert_eq(s.queue_datagram(Bytes::make(95, 0)), false)
  assert_eq(s.queue_datagram(Bytes::make(40, 0)), true)
}

///|
test "a probe does not resend a datagram" {
  let s = Sender::new(1_000_000UL, 1_000_000UL, 1200L, 25000L, 1000L, 1000UL)
  s.on_peer_datagram(1200UL)
  assert_eq(s.queue_datagram(b"once"), true)
  match s.poll_send(0L) {
    Some(_) => ()
    None => abort("the datagram was not sent")
  }
  // Fire the probe timer long after the first send. The outstanding packet carried only the
  // datagram, which is not re-queued, so the probe falls back to a PING.
  assert_eq(s.on_pto_timeout(10_000_000_000L), true)
  match s.poll_send(10_000_000_001L) {
    Some((_, frames)) => {
      let mut resent = false
      for frame in frames {
        match frame {
          @frame.Datagram(..) => resent = true
          _ => ()
        }
      }
      assert_eq(resent, false)
    }
    None => abort("the probe was not built")
  }
}

///|
test "max_datagram_frame_size survives a parameter block" {
  let limits = Limits::new(datagram_frame=1200UL)
  let back = Limits::read(limits.params()[:])
  assert_eq(back.datagram_frame, 1200UL)
  // The default advertises nothing, which RFC 9221 reads as no support.
  assert_eq(Limits::read([][:]).datagram_frame, 0UL)
}
