// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9000 §2, §3 and §4, one section at a time: the ID bits, both state
// machines, reassembly, flow control, the stream quota and the scheduler.

///|
test "stream id: RFC 9000 Table 1 classifies the four low-bit patterns" {
  assert_eq(initiator(0), Client)
  assert_eq(direction(0), Bidi)
  assert_eq(initiator(1), Server)
  assert_eq(direction(1), Bidi)
  assert_eq(initiator(2), Client)
  assert_eq(direction(2), Uni)
  assert_eq(initiator(3), Server)
  assert_eq(direction(3), Uni)
}

///|
test "stream id: generation places the type bits and sequence" {
  assert_eq(id_of(Client, Bidi, 0), 0)
  assert_eq(id_of(Server, Bidi, 0), 1)
  assert_eq(id_of(Client, Uni, 0), 2)
  assert_eq(id_of(Server, Uni, 0), 3)
  // Streams of one type are four apart.
  assert_eq(id_of(Client, Bidi, 1), 4)
  assert_eq(id_of(Server, Uni, 5), 23)
}

///|
test "stream id: sequence recovers the index within the type" {
  assert_eq(sequence(0), 0)
  assert_eq(sequence(4), 1)
  assert_eq(sequence(23), 5)
  assert_eq(is_bidi(4), true)
  assert_eq(is_bidi(3), false)
  assert_eq(is_client(2), true)
  assert_eq(is_client(1), false)
}

///|
test "stream id: generation and classification round-trip" {
  let inits = [Client, Server]
  let dirs = [Bidi, Uni]
  for who in inits {
    for way in dirs {
      for seq = 0UL; seq < 4; seq = seq + 1 {
        let id = id_of(who, way, seq)
        assert_eq(initiator(id), who)
        assert_eq(direction(id), way)
        assert_eq(sequence(id), seq)
      }
    }
  }
}

///|
test "stream id: locally-initiated depends on role" {
  // Even ids are client-initiated.
  assert_eq(is_local(0, server=false), true) // client, client stream
  assert_eq(is_local(0, server=true), false) // server, client stream
  assert_eq(is_local(1, server=true), true) // server, server stream
  assert_eq(is_local(1, server=false), false)
}

///|
test "stream id: writability follows ownership and directionality" {
  // A client may write its own bidi and uni streams, and peer-opened bidi streams,
  // but not a server-opened unidirectional (receive-only) stream.
  assert_eq(is_writable(0, server=false), true) // client bidi (own)
  assert_eq(is_writable(2, server=false), true) // client uni (own)
  assert_eq(is_writable(1, server=false), true) // server bidi (peer, bidi)
  assert_eq(is_writable(3, server=false), false) // server uni (peer, recv-only)
  // Symmetrically for the server on a client-opened unidirectional stream.
  assert_eq(is_writable(2, server=true), false) // client uni (peer, recv-only)
  assert_eq(is_writable(0, server=true), true) // client bidi (peer, bidi)
}

///|
test "send stream: the data path Ready -> Send -> Data Sent -> Data Recvd" {
  assert_eq(Sending::next(Ready, Write(fin=false)), Send)
  assert_eq(Sending::next(Send, Write(fin=false)), Send)
  assert_eq(Sending::next(Send, Write(fin=true)), DataSent)
  assert_eq(Sending::next(DataSent, AllAcked), DataRecvd)
  // An empty stream closed immediately with fin jumps straight to Data Sent.
  assert_eq(Sending::next(Ready, Write(fin=true)), DataSent)
}

///|
test "send stream: reset from any pre-terminal state" {
  assert_eq(Sending::next(Ready, ResetStream), ResetSent)
  assert_eq(Sending::next(Send, ResetStream), ResetSent)
  assert_eq(Sending::next(DataSent, ResetStream), ResetSent)
  assert_eq(Sending::next(ResetSent, ResetAcked), ResetRecvd)
}

///|
test "send stream: illegal transitions raise" {
  // Writing after all data is acknowledged.
  let after_terminal = try {
    let _ = Sending::next(DataRecvd, Write(fin=false))
    false
  } catch {
    _ => true
  }
  assert_eq(after_terminal, true)
  // Acknowledgement before anything was sent.
  let premature_ack = try {
    let _ = Sending::next(Ready, AllAcked)
    false
  } catch {
    _ => true
  }
  assert_eq(premature_ack, true)
}

///|
test "recv stream: the data path Recv -> Size Known -> Data Recvd -> Data Read" {
  assert_eq(Receiving::next(Recv, Receive(fin=false)), Recv)
  assert_eq(Receiving::next(Recv, Receive(fin=true)), SizeKnown)
  assert_eq(Receiving::next(SizeKnown, AllReceived), DataReceived)
  assert_eq(Receiving::next(DataReceived, AppRead), DataRead)
}

///|
test "recv stream: reset path from any pre-terminal state" {
  assert_eq(Receiving::next(Recv, ReceiveReset), ResetReceived)
  assert_eq(Receiving::next(SizeKnown, ReceiveReset), ResetReceived)
  assert_eq(Receiving::next(DataReceived, ReceiveReset), ResetReceived)
  assert_eq(Receiving::next(ResetReceived, AppReadReset), ResetRead)
}

///|
test "recv stream: illegal transitions raise" {
  // Receiving more data after the application has read the whole stream.
  let after_read = try {
    let _ = Receiving::next(DataRead, Receive(fin=false))
    false
  } catch {
    _ => true
  }
  assert_eq(after_read, true)
  // Declaring all received before the final size is known.
  let premature = try {
    let _ = Receiving::next(Recv, AllReceived)
    false
  } catch {
    _ => true
  }
  assert_eq(premature, true)
}

// QUIC flow-control accounting (RFC 9000 §4): send-window consumption and blocking,
// receive-window enforcement, and the extend-when-half-consumed auto-tuning.

///|
test "send flow: available shrinks with sends and refuses to overshoot" {
  let f = Credit::new(100)
  assert_eq(f.available(), 100)
  assert_eq(f.blocked(), false)
  f.spend(30)
  assert_eq(f.sent(), 30)
  assert_eq(f.available(), 70)
  f.spend(70)
  assert_eq(f.available(), 0)
  assert_eq(f.blocked(), true)
  let overshoot = try {
    f.spend(1)
    false
  } catch {
    _ => true
  }
  assert_eq(overshoot, true)
}

///|
test "send flow: the limit only ever grows" {
  let f = Credit::new(100)
  f.spend(100)
  assert_eq(f.blocked(), true)
  f.grant(200)
  assert_eq(f.available(), 100)
  assert_eq(f.blocked(), false)
  // A stale, smaller MAX_DATA is ignored.
  f.grant(150)
  assert_eq(f.available(), 100)
}

///|
test "recv flow: data past the advertised limit is a violation" {
  let f = Window::new(100)
  assert_eq(f.limit(), 100)
  f.arrived(50) // within the window
  f.arrived(100) // exactly at the limit is allowed
  let violation = try {
    f.arrived(101)
    false
  } catch {
    _ => true
  }
  assert_eq(violation, true)
}

///|
test "recv flow: the window extends once half is consumed" {
  let f = Window::new(100)
  f.arrived(60)
  f.consume(40)
  // Consumed 40 of a 100-byte window: desired 140 is not yet half a window past 100.
  assert_eq(f.should_grant(), false)
  f.consume(20) // consumed 60 -> desired 160 >= 100 + 50
  assert_eq(f.should_grant(), true)
  assert_eq(f.grant(), 160)
  assert_eq(f.limit(), 160)
  // Just extended: no further extension is due yet.
  assert_eq(f.should_grant(), false)
  // The peer may now send further, up to the new limit.
  f.arrived(160)
  let violation = try {
    f.arrived(161)
    false
  } catch {
    _ => true
  }
  assert_eq(violation, true)
}

///|
test "send flow: a stream is bounded by the smaller of its window and the connection window" {
  let f = Budget::new(1000UL, 600UL)
  // Stream 0: min(connection 1000, stream 600) = 600.
  assert_eq(f.available(0UL), 600UL)
  f.spend(0UL, 400UL) // stream 200 left, connection 600 left
  assert_eq(f.available(0UL), 200UL)
  // A fresh stream 4: its own window is 600, but the connection has 600 left → 600.
  assert_eq(f.available(4UL), 600UL)
  f.spend(4UL, 500UL) // connection 100 left, stream 4 100 left
  assert_eq(f.connection(), 100UL)
  assert_eq(f.available(4UL), 100UL)
  // Stream 0 is now bounded by the connection window (100), not its own (200).
  assert_eq(f.available(0UL), 100UL)
}

///|
test "send flow: exceeding either window raises" {
  // Over the stream's own limit.
  let f = Budget::new(1000UL, 300UL)
  let stream_over = try {
    f.spend(0UL, 400UL)
    false
  } catch {
    _ => true
  }
  assert_eq(stream_over, true)
  // Within the stream but over the connection limit.
  let g = Budget::new(100UL, 1000UL)
  let conn_over = try {
    g.spend(0UL, 200UL)
    false
  } catch {
    _ => true
  }
  assert_eq(conn_over, true)
}

///|
test "send flow: MAX_DATA and MAX_STREAM_DATA raise the limits" {
  let f = Budget::new(500UL, 500UL)
  f.spend(0UL, 500UL) // both windows exhausted
  assert_eq(f.available(0UL), 0UL)
  f.on_max_data(1200UL) // connection 500 → 1200
  f.on_max_stream_data(0UL, 900UL) // stream 0 500 → 900
  // stream available 400, connection available 700 → 400.
  assert_eq(f.available(0UL), 400UL)
  f.spend(0UL, 400UL)
  assert_eq(f.available(0UL), 0UL)
}

// QUIC stream reassembly behaviour (RFC 9000 §2.2): fragments arriving in order, out of
// order, with gaps, overlapping (identically or in conflict), duplicated, or straddling
// the read cursor, plus final-size tracking from the fin bit.

///|
test "reassembly: in-order fragments read straight through" {
  let r = Assembler::new()
  r.insert(0, b"abc", fin=false)
  assert_eq(r.read(), b"abc")
  assert_eq(r.consumed(), 3)
  r.insert(3, b"def", fin=false)
  assert_eq(r.read(), b"abcdef"[3:6].to_owned())
  assert_eq(r.consumed(), 6)
}

///|
test "reassembly: out-of-order fragments reorder before reading" {
  let r = Assembler::new()
  r.insert(3, b"def", fin=false)
  // Nothing contiguous yet — the run at offset 0 has not arrived.
  assert_eq(r.read(), b"")
  r.insert(0, b"abc", fin=false)
  assert_eq(r.read(), b"abcdef")
}

///|
test "reassembly: a gap holds back later data until it is filled" {
  let r = Assembler::new()
  r.insert(0, b"ab", fin=false)
  r.insert(5, b"fg", fin=false)
  assert_eq(r.read(), b"ab") // 2..4 still missing
  r.insert(2, b"cde", fin=false)
  assert_eq(r.read(), b"cdefg")
  assert_eq(r.consumed(), 7)
}

///|
test "reassembly: identical overlap is merged, tail appended once" {
  let r = Assembler::new()
  r.insert(0, b"abcd", fin=false)
  r.insert(2, b"cdef", fin=false) // overlaps cd, extends with ef
  assert_eq(r.read(), b"abcdef")
}

///|
test "reassembly: a duplicate fragment is idempotent" {
  let r = Assembler::new()
  r.insert(0, b"abc", fin=false)
  r.insert(0, b"abc", fin=false)
  assert_eq(r.read(), b"abc")
  assert_eq(r.consumed(), 3)
}

///|
test "reassembly: a fragment straddling the read cursor keeps only its new tail" {
  let r = Assembler::new()
  r.insert(0, b"abcdef", fin=false)
  assert_eq(r.read(), b"abcdef")
  // Retransmit overlapping already-consumed bytes plus two new ones.
  r.insert(4, b"efgh", fin=false)
  assert_eq(r.read(), b"gh")
  assert_eq(r.consumed(), 8)
}

///|
test "reassembly: fin sets the final size and completes when drained" {
  let r = Assembler::new()
  assert_eq(r.complete(), false)
  r.insert(0, b"abc", fin=true)
  assert_eq(r.final_size(), Some(3))
  assert_eq(r.complete(), false) // not yet read
  assert_eq(r.read(), b"abc")
  assert_eq(r.complete(), true)
}

///|
test "reassembly: conflicting overlap bytes raise" {
  let r = Assembler::new()
  r.insert(0, b"abcd", fin=false)
  let conflict = try {
    r.insert(2, b"XYef", fin=false) // bytes at 2..4 disagree (cd vs XY)
    false
  } catch {
    _ => true
  }
  assert_eq(conflict, true)
}

///|
test "reassembly: data beyond a known final size raises" {
  let r = Assembler::new()
  r.insert(0, b"abc", fin=true) // final size 3
  let beyond = try {
    r.insert(3, b"d", fin=false)
    false
  } catch {
    _ => true
  }
  assert_eq(beyond, true)
}

///|
test "reassembly: two fins with different sizes raise" {
  let r = Assembler::new()
  r.insert(0, b"abc", fin=true)
  let conflict = try {
    r.insert(0, b"abcd", fin=true) // final size 4 contradicts 3
    false
  } catch {
    _ => true
  }
  assert_eq(conflict, true)
}

// QUIC receive-side stream management (RFC 9000 §2, §4): routing STREAM frames to
// per-stream reassembly, independence across streams, per-stream and connection-level
// flow-control enforcement, and connection MAX_DATA auto-tuning.

///|
test "stream mgr: a stream delivers contiguous data, reordering fragments" {
  let m = Streams::new(100, 100, server=true)
  assert_eq(m.on_stream(0, 3, b"def", fin=false), b"") // gap before it
  assert_eq(m.on_stream(0, 0, b"abc", fin=false), b"abcdef")
  assert_eq(m.count(), 1)
}

///|
test "stream mgr: streams are independent" {
  let m = Streams::new(100, 100, server=true)
  assert_eq(m.on_stream(0, 0, b"hello", fin=false), b"hello")
  assert_eq(m.on_stream(4, 0, b"world", fin=false), b"world")
  assert_eq(m.count(), 2)
  // A later fragment on stream 0 continues its own sequence.
  assert_eq(m.on_stream(0, 5, b"!", fin=false), b"!")
}

///|
test "stream mgr: per-stream flow control rejects data past the window" {
  let m = Streams::new(100, 10, server=true)
  let violation = try {
    // Offset 8 + 4 bytes = 12, past the 10-byte per-stream window.
    let _ = m.on_stream(0, 8, b"abcd", fin=false)
    false
  } catch {
    _ => true
  }
  assert_eq(violation, true)
}

///|
test "stream mgr: connection flow control sums across streams" {
  // 10 bytes of connection credit, generous per-stream windows.
  let m = Streams::new(10, 100, server=true)
  let _ = m.on_stream(0, 0, b"abcdef", fin=false) // 6 bytes, ok
  let violation = try {
    let _ = m.on_stream(4, 0, b"ghijkl", fin=false) // +6 = 12 > 10
    false
  } catch {
    _ => true
  }
  assert_eq(violation, true)
}

///|
test "stream mgr: connection MAX_DATA extends as data is consumed" {
  let m = Streams::new(10, 100, server=true)
  // Receive and deliver 6 bytes; the read consumes them against the connection window.
  assert_eq(m.on_stream(0, 0, b"abcdef", fin=false), b"abcdef")
  // Consumed 6 of a 10-byte window: the advertisable limit (6 + 10) is half a window
  // past the current 10, so an update is due.
  assert_eq(m.max_data(), Some(16))
  // Immediately after, no further update is due.
  assert_eq(m.max_data(), None)
}

///|
test "stream mgr: reading an unknown stream yields nothing" {
  let m = Streams::new(100, 100, server=true)
  assert_eq(m.read(9), b"")
}

// The send-side stream scheduler (RFC 9000 §2, §4): round-robin multiplexing bounded by flow
// control, with FIN handling.

///|
fn next_send(sch : Scheduler) -> Chunk raise {
  match sch.next() {
    Some(d) => d
    None => abort("expected a scheduling decision")
  }
}

///|
test "scheduler: round-robins streams and caps each frame by the max frame size" {
  let sch = Scheduler::new(Budget::new(1000UL, 1000UL), frame=300UL)
  sch.queue(0UL, 500UL)
  sch.queue(4UL, 500UL)
  // Stream 0 first, capped at the 300-byte frame size.
  let d0 = next_send(sch)
  assert_eq(d0.stream, 0UL)
  assert_eq(d0.offset, 0UL)
  assert_eq(d0.length, 300UL)
  assert_eq(d0.fin, false)
  // Round-robin to stream 4.
  let d1 = next_send(sch)
  assert_eq(d1.stream, 4UL)
  assert_eq(d1.offset, 0UL)
  assert_eq(d1.length, 300UL)
  // Back to stream 0 for the remaining 200.
  let d2 = next_send(sch)
  assert_eq(d2.stream, 0UL)
  assert_eq(d2.offset, 300UL)
  assert_eq(d2.length, 200UL)
  // Stream 4's remaining 200 — the connection window (1000) is now exactly spent.
  let d3 = next_send(sch)
  assert_eq(d3.stream, 4UL)
  assert_eq(d3.offset, 300UL)
  assert_eq(d3.length, 200UL)
  // Nothing left to schedule.
  match sch.next() {
    None => ()
    Some(_) => abort("expected no more frames")
  }
}

///|
test "scheduler: a frame is bounded by the connection window, freed by MAX_DATA" {
  // Connection window 400, generous per-stream window, one stream with 1000 bytes.
  let sch = Scheduler::new(Budget::new(400UL, 5000UL), frame=5000UL)
  sch.queue(0UL, 1000UL)
  let d = next_send(sch)
  assert_eq(d.length, 400UL) // capped by the connection window, not the 1000 pending
  // The connection window is now exhausted: nothing more until MAX_DATA.
  match sch.next() {
    None => ()
    Some(_) => abort("connection window should be blocked")
  }
  // A MAX_DATA frame frees the window and the remaining 600 bytes flow.
  sch.on_max_data(1000UL)
  let d2 = next_send(sch)
  assert_eq(d2.offset, 400UL)
  assert_eq(d2.length, 600UL)
}

///|
test "scheduler: FIN rides the draining frame, or a FIN-only frame when empty" {
  let sch = Scheduler::new(Budget::new(1000UL, 1000UL), frame=1000UL)
  sch.queue(0UL, 100UL)
  sch.queue_fin(0UL)
  let d = next_send(sch)
  assert_eq(d.stream, 0UL)
  assert_eq(d.length, 100UL)
  assert_eq(d.fin, true) // rides the last data
  match sch.next() {
    None => ()
    Some(_) => abort("FIN already sent")
  }
  // A stream that closes with no data: a FIN-only frame.
  sch.queue_fin(4UL)
  let f = next_send(sch)
  assert_eq(f.stream, 4UL)
  assert_eq(f.offset, 0UL)
  assert_eq(f.length, 0UL)
  assert_eq(f.fin, true)
}

///|
test "a peer may not open more streams than its quota allows (§4.6)" {
  let q = Quota::new(3)
  assert_eq(q.available(), 3UL)
  // Client-initiated bidirectional streams are 0, 4, 8; the fourth is 12.
  q.open(0)
  q.open(4)
  q.open(8)
  assert_eq(q.available(), 0UL)
  let mut refused = false
  q.open(12) catch {
    Exceeded(limit~, got~) => {
      assert_eq(limit, 3UL)
      assert_eq(got, 4UL)
      refused = true
    }
    _ => ()
  }
  assert_eq(refused, true)
  // A MAX_STREAMS frame raises it, and an old one does not lower it.
  q.grant(5)
  assert_eq(q.available(), 2UL)
  q.grant(1)
  assert_eq(q.available(), 2UL)
  q.open(12)
}

///|
test "a stream already counted may be mentioned again" {
  let q = Quota::new(2)
  q.open(4)
  q.open(4)
  q.open(0)
  // Two streams opened, whichever order their frames arrived in.
  assert_eq(q.available(), 0UL)
}

///|
test "the peer's streams are counted and ours are not" {
  let s = Streams::new(1000, 1000, server=true, bidi=Quota::new(1))
  assert_eq(s.on_stream(0, 0, b"a", fin=false), b"a")
  // Stream 4 is a second client-initiated bidirectional stream, past the quota of one.
  let mut refused = false
  try {
    let _ = s.on_stream(4, 0, b"b", fin=false)
  } catch {
    Exceeded(_) => refused = true
    _ => ()
  }
  assert_eq(refused, true)
  // Our own streams — server-initiated, odd — are ours to open.
  assert_eq(s.on_stream(1, 0, b"c", fin=false), b"c")
  assert_eq(s.on_stream(5, 0, b"d", fin=false), b"d")
}

///|
test "an assembler refuses to buffer past its limit" {
  let a = Assembler::new(limit=8)
  // A gap at the front, so nothing can be read and everything stays buffered.
  a.insert(100, b"abcd", fin=false)
  a.insert(200, b"efgh", fin=false)
  assert_eq(a.buffered(), 8UL)
  let mut refused = false
  a.insert(300, b"i", fin=false) catch {
    Exceeded(limit~, got~) => {
      assert_eq(limit, 8UL)
      assert_eq(got, 9UL)
      refused = true
    }
    _ => ()
  }
  assert_eq(refused, true)
  // Reading frees the room again: what has been handed to the application is no
  // longer held.
  let b = Assembler::new(limit=8)
  b.insert(4, b"efgh", fin=false)
  assert_eq(b.buffered(), 4UL)
  b.insert(0, b"abcd", fin=false)
  assert_eq(b.read(), b"abcdefgh")
  assert_eq(b.buffered(), 0UL)
  b.insert(8, b"ijkl", fin=false)
  assert_eq(b.buffered(), 4UL)
}

///|
test "the window's update ratio decides when a new limit is worth a frame" {
  // Half a window by default: ten of twenty consumed before it is worth saying so.
  let w = Window::new(20)
  w.consume(9)
  assert_eq(w.should_grant(), false)
  w.consume(1)
  assert_eq(w.should_grant(), true)
  assert_eq(w.grant(), 30UL)
  // A tenth instead: two consumed is enough.
  let eager = Window::new(20, ratio=0.1)
  eager.consume(1)
  assert_eq(eager.should_grant(), false)
  eager.consume(1)
  assert_eq(eager.should_grant(), true)
}

///|
test "the frame cap is a knob, and the default leaves room in a datagram" {
  assert_eq(frame, 1024UL)
  let sch = Scheduler::new(Budget::new(10000UL, 10000UL))
  sch.queue(0, 3000UL)
  guard sch.next() is Some(first) else { fail("a queued stream should send") }
  assert_eq(first.length, 1024UL)
  let small = Scheduler::new(Budget::new(10000UL, 10000UL), frame=100UL)
  small.queue(0, 3000UL)
  guard small.next() is Some(chunk) else { fail("a queued stream should send") }
  assert_eq(chunk.length, 100UL)
}

///|
test "a reader's progress earns a MAX_STREAM_DATA as well as a MAX_DATA" {
  let s = Streams::new(20, 20, server=true)
  assert_eq(s.max_data(), None)
  assert_eq(s.max_stream_data(0), None)
  assert_eq(s.on_stream(0, 0, Bytes::make(10, b'x'), fin=false).length(), 10)
  // Ten of a twenty-byte window consumed on both counts.
  assert_eq(s.max_data(), Some(30UL))
  assert_eq(s.max_stream_data(0), Some(30UL))
  // And not twice for the same progress.
  assert_eq(s.max_data(), None)
  assert_eq(s.max_stream_data(0), None)
  assert_eq(s.window(0).limit(), 30UL)
}
