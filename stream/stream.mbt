// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Why a stream operation was refused.
///
/// `Illegal` is a transition §3.1 or §3.2 does not allow — a bug on this side.
/// `Exceeded` is the peer sending past a limit we advertised, or this side being asked
/// to send past one the peer advertised (§4.1, §4.6). `Conflict` is a retransmission
/// that disagrees with what arrived before, or a final size contradicting one already
/// known (§2.2, §4.5) — which RFC 9000 makes a connection error.
pub(all) suberror Refused {
  Illegal(String)
  Exceeded(limit~ : UInt64, got~ : UInt64)
  Conflict(String)
} derive(Eq)

///|
/// A refusal prints as the fault it is.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Illegal(m) => logger.write_string("Illegal(" + m + ")")
    Exceeded(limit~, got~) =>
      logger.write_string("Exceeded(limit=\{limit}, got=\{got})")
    Conflict(m) => logger.write_string("Conflict(" + m + ")")
  }
}

///|
pub extend Refused with Show::{to_string, output}

///|
pub extend Refused with Eq::{not_equal, equal}

// Stream identifiers (RFC 9000 §2.1). The low two bits of a stream ID say who opened it
// and which way it carries data; the rest is a per-kind sequence number.

///|
/// Which endpoint opened a stream.
pub(all) enum Initiator {
  Client
  Server
} derive(Eq, Debug)

///|
/// Whether a stream carries data one way or both.
pub(all) enum Direction {
  Bidi
  Uni
} derive(Eq, Debug)

///|
/// The endpoint that opened stream `id` — bit 0.
pub fn initiator(id : UInt64) -> Initiator {
  if (id & 1) == 0 {
    Client
  } else {
    Server
  }
}

///|
/// Which way stream `id` carries data — bit 1.
pub fn direction(id : UInt64) -> Direction {
  if (id & 2) == 0 {
    Bidi
  } else {
    Uni
  }
}

///|
/// Whether stream `id` carries data both ways.
pub fn is_bidi(id : UInt64) -> Bool {
  (id & 2) == 0
}

///|
/// Whether the client opened stream `id`.
pub fn is_client(id : UInt64) -> Bool {
  (id & 1) == 0
}

///|
/// The stream's sequence number within its kind — the ID with its low two bits dropped.
pub fn sequence(id : UInt64) -> UInt64 {
  id >> 2
}

///|
/// The ID of the `seq`-th stream of that kind, counting from zero.
pub fn id_of(
  initiator : Initiator,
  direction : Direction,
  seq : UInt64,
) -> UInt64 {
  let who = match initiator {
    Client => 0UL
    Server => 1UL
  }
  let way = match direction {
    Bidi => 0UL
    Uni => 2UL
  }
  (seq << 2) | way | who
}

///|
/// Whether this endpoint opened stream `id`.
pub fn is_local(id : UInt64, server~ : Bool) -> Bool {
  match initiator(id) {
    Client => !server
    Server => server
  }
}

///|
/// Whether this endpoint may send on stream `id`: one it opened, or a bidirectional one
/// the peer opened. A peer's unidirectional stream is receive-only (§2.1, §3).
pub fn is_writable(id : UInt64, server~ : Bool) -> Bool {
  is_local(id, server~) || is_bidi(id)
}

// The stream state machines (RFC 9000 §3.1 and §3.2), with the RFC's own state names.

///|
/// The sending part's state (§3.1).
pub(all) enum Sending {
  Ready
  Send
  DataSent
  DataRecvd
  ResetSent
  ResetRecvd
} derive(Eq, Debug)

///|
/// What the sending part did: wrote a STREAM frame, with `fin` on the last one; had all
/// its data acknowledged; sent a RESET_STREAM; had that reset acknowledged.
pub(all) enum SendEvent {
  Write(fin~ : Bool)
  AllAcked
  ResetStream
  ResetAcked
} derive(Eq, Debug)

///|
/// The state after `event` (§3.1). A stream may be reset from any state short of a
/// terminal one; writing after a terminal or reset state is refused.
pub fn Sending::next(
  self : Sending,
  event : SendEvent,
) -> Sending raise Refused {
  match (self, event) {
    (Ready, Write(fin~)) | (Send, Write(fin~)) =>
      if fin {
        DataSent
      } else {
        Send
      }
    (DataSent, AllAcked) => DataRecvd
    (Ready, ResetStream) | (Send, ResetStream) | (DataSent, ResetStream) =>
      ResetSent
    (ResetSent, ResetAcked) => ResetRecvd
    _ => raise Illegal("a sending stream cannot take that step")
  }
}

///|
/// The receiving part's state (§3.2).
pub(all) enum Receiving {
  Recv
  SizeKnown
  DataReceived
  DataRead
  ResetReceived
  ResetRead
} derive(Eq, Debug)

///|
/// What reached the receiving part: a STREAM frame, with `fin` fixing the final size;
/// all the data up to that size; the application reading it all; a RESET_STREAM; the
/// application being told of that reset.
pub(all) enum RecvEvent {
  Receive(fin~ : Bool)
  AllReceived
  AppRead
  ReceiveReset
  AppReadReset
} derive(Eq, Debug)

///|
/// The state after `event` (§3.2). A stream may be reset from any state short of a
/// terminal one; the read events apply only once the data or the reset has arrived.
pub fn Receiving::next(
  self : Receiving,
  event : RecvEvent,
) -> Receiving raise Refused {
  match (self, event) {
    (Recv, Receive(fin~)) => if fin { SizeKnown } else { Recv }
    (SizeKnown, AllReceived) => DataReceived
    (DataReceived, AppRead) => DataRead
    (Recv, ReceiveReset)
    | (SizeKnown, ReceiveReset)
    | (DataReceived, ReceiveReset) => ResetReceived
    (ResetReceived, AppReadReset) => ResetRead
    _ => raise Illegal("a receiving stream cannot take that step")
  }
}

// Data flow control (RFC 9000 §4.1). Each direction of each stream, and the connection
// as a whole, has a limit the receiver advertises and the sender spends against.

///|
/// The send side of one window: how much has gone out against the limit the peer gave.
pub struct Credit {
  mut spent : UInt64
  mut limit : UInt64
}

///|
/// A send window at the peer's initial maximum.
pub fn Credit::new(limit : UInt64) -> Credit {
  { spent: 0, limit, }
}

///|
/// How much more may go out right now — zero when blocked.
pub fn Credit::available(self : Credit) -> UInt64 {
  if self.spent >= self.limit {
    0
  } else {
    self.limit - self.spent
  }
}

///|
/// Whether the window is spent, which is the STREAM_DATA_BLOCKED and DATA_BLOCKED
/// condition.
pub fn Credit::blocked(self : Credit) -> Bool {
  self.spent >= self.limit
}

///|
/// How much has gone out in total.
pub fn Credit::sent(self : Credit) -> UInt64 {
  self.spent
}

///|
/// Account for `n` bytes going out. Refused when that would pass the peer's limit, and
/// nothing is charged when it is.
pub fn Credit::spend(self : Credit, n : UInt64) -> Unit raise Refused {
  if self.spent + n > self.limit {
    raise Exceeded(limit=self.limit, got=self.spent + n)
  }
  self.spent = self.spent + n
}

///|
/// Adopt a limit from a MAX_DATA or MAX_STREAM_DATA frame. A limit only ever rises, so
/// an old frame arriving late is ignored rather than shrinking the window (§4.1).
pub fn Credit::grant(self : Credit, limit : UInt64) -> Unit {
  if limit > self.limit {
    self.limit = limit
  }
}

///|
/// How much of a window must become reclaimable before advertising a new limit is worth
/// a frame. Half a window is what quiche uses; RFC 9000 §4.1 leaves it open, saying only
/// that an endpoint should avoid a frame per byte.
pub let ratio : Double = 0.5

///|
/// The receive side of one window: the peer may send up to the limit we advertised, and
/// the limit moves up as the application consumes what arrived.
pub struct Window {
  mut received : UInt64
  mut consumed : UInt64
  mut limit : UInt64
  size : UInt64
  ratio : Double
}

///|
/// A receive window of `size` bytes, which is also the initial advertised limit.
pub fn Window::new(size : UInt64, ratio? : Double = ratio) -> Window {
  { received: 0, consumed: 0, limit: size, size, ratio, }
}

///|
/// The limit currently advertised.
pub fn Window::limit(self : Window) -> UInt64 {
  self.limit
}

///|
/// How much the application has taken.
pub fn Window::consumed(self : Window) -> UInt64 {
  self.consumed
}

///|
/// Record that data up to absolute offset `offset` has arrived. Refused when the peer
/// passed the limit we advertised, which §4.1 makes a connection error.
pub fn Window::arrived(self : Window, offset : UInt64) -> Unit raise Refused {
  if offset > self.limit {
    raise Exceeded(limit=self.limit, got=offset)
  }
  if offset > self.received {
    self.received = offset
  }
}

///|
/// Account for the application taking `n` more bytes, which frees window space.
pub fn Window::consume(self : Window, n : UInt64) -> Unit {
  self.consumed = self.consumed + n
}

///|
/// Whether a new limit is worth advertising: what we could offer is at least `ratio` of
/// a window beyond what we have.
pub fn Window::should_grant(self : Window) -> Bool {
  let want = self.consumed + self.size
  want >= self.limit + (self.size.to_double() * self.ratio).to_uint64()
}

///|
/// Issue a new limit — what has been consumed plus a window — and answer with it: the
/// MAX_DATA or MAX_STREAM_DATA value to send. The mirror of `Credit::grant`, which is
/// how the other end takes it.
pub fn Window::grant(self : Window) -> UInt64 {
  self.limit = self.consumed + self.size
  self.limit
}

///|
/// How many streams of one kind the peer may still open (RFC 9000 §4.6), and how many it
/// has. A peer that opens past the limit is a connection error, and without this an
/// endpoint would let one hold open as many as it liked.
pub struct Quota {
  mut limit : UInt64
  mut opened : UInt64
}

///|
/// A quota of `limit` streams, none opened.
pub fn Quota::new(limit : UInt64) -> Quota {
  { limit, opened: 0, }
}

///|
/// How many more may be opened.
pub fn Quota::available(self : Quota) -> UInt64 {
  if self.opened >= self.limit {
    0
  } else {
    self.limit - self.opened
  }
}

///|
/// Record stream `id` as opened, by its sequence number. Refused when it is past the
/// limit; opening one already counted changes nothing, because a stream is opened by
/// whichever frame mentions it first and several may.
pub fn Quota::open(self : Quota, id : UInt64) -> Unit raise Refused {
  let seq = sequence(id) + 1
  if seq > self.limit {
    raise Exceeded(limit=self.limit, got=seq)
  }
  if seq > self.opened {
    self.opened = seq
  }
}

///|
/// Adopt a limit from a MAX_STREAMS frame; as with data, a limit only rises.
pub fn Quota::grant(self : Quota, limit : UInt64) -> Unit {
  if limit > self.limit {
    self.limit = limit
  }
}

///|
/// A connection's send windows: the connection-wide one and one per stream, each opened
/// at the peer's initial per-stream maximum when the stream is first written to.
pub struct Budget {
  connection : Credit
  streams : Map[UInt64, Credit]
  initial : UInt64
}

///|
/// A budget at the peer's initial connection-wide and per-stream maxima, which come from
/// its transport parameters (RFC 9000 §18.2).
pub fn Budget::new(data : UInt64, stream_data : UInt64) -> Budget {
  { connection: Credit::new(data), streams: Map([]), initial: stream_data, }
}

///|
/// Stream `id`'s window, opened at the initial maximum on first use.
pub fn Budget::stream(self : Budget, id : UInt64) -> Credit {
  match self.streams.get(id) {
    Some(c) => c
    None => {
      let c = Credit::new(self.initial)
      self.streams[id] = c
      c
    }
  }
}

///|
/// How much may go out on stream `id` right now: the smaller of the connection's window
/// and the stream's (§4.1).
pub fn Budget::available(self : Budget, id : UInt64) -> UInt64 {
  let c = self.connection.available()
  let s = self.stream(id).available()
  if c < s {
    c
  } else {
    s
  }
}

///|
/// Account for `n` bytes on stream `id`, against both windows. Both are checked before
/// either is charged, so a refusal leaves neither half spent.
pub fn Budget::spend(
  self : Budget,
  id : UInt64,
  n : UInt64,
) -> Unit raise Refused {
  let s = self.stream(id)
  if s.available() < n {
    raise Exceeded(limit=s.limit, got=s.spent + n)
  }
  if self.connection.available() < n {
    raise Exceeded(limit=self.connection.limit, got=self.connection.spent + n)
  }
  s.spend(n)
  self.connection.spend(n)
}

///|
/// Raise the connection-wide limit from a MAX_DATA frame.
pub fn Budget::on_max_data(self : Budget, limit : UInt64) -> Unit {
  self.connection.grant(limit)
}

///|
/// Raise stream `id`'s limit from a MAX_STREAM_DATA frame.
pub fn Budget::on_max_stream_data(
  self : Budget,
  id : UInt64,
  limit : UInt64,
) -> Unit {
  self.stream(id).grant(limit)
}

///|
/// What may still go out across all streams together.
pub fn Budget::connection(self : Budget) -> UInt64 {
  self.connection.available()
}

// Reassembly (RFC 9000 §2.2). STREAM frames may arrive out of order, overlapping, or
// twice; what the application reads is the contiguous run from where it left off.

///|
/// How many bytes an assembler will hold ahead of the read cursor before refusing more.
///
/// A connection's receive window already bounds this, and a megabyte is what quiche
/// advertises per stream by default; the limit is here so an assembler used on its own
/// is bounded too.
pub let limit : UInt64 = 1 << 20

///|
/// A stream's reassembly buffer. `consumed` is the next offset the reader has not taken;
/// the runs beyond it are sorted, non-overlapping, and each starts at or after it.
pub struct Assembler {
  mut consumed : UInt64
  mut runs : Array[(UInt64, Bytes)]
  mut final_size : UInt64?
  limit : UInt64
}

///|
/// A fresh assembler at the start of a stream.
pub fn Assembler::new(limit? : UInt64 = limit) -> Assembler {
  { consumed: 0, runs: [], final_size: None, limit, }
}

///|
/// The next contiguous offset the reader has taken.
pub fn Assembler::consumed(self : Assembler) -> UInt64 {
  self.consumed
}

///|
/// The stream's final size, once a fin has fixed it.
pub fn Assembler::final_size(self : Assembler) -> UInt64? {
  self.final_size
}

///|
/// How many bytes are buffered ahead of the cursor.
pub fn Assembler::buffered(self : Assembler) -> UInt64 {
  let mut n = 0UL
  for run in self.runs {
    n = n + run.1.length().to_uint64()
  }
  n
}

///|
/// Whether the whole stream has arrived and been read.
pub fn Assembler::complete(self : Assembler) -> Bool {
  match self.final_size {
    Some(size) => self.consumed == size && self.runs.length() == 0
    None => false
  }
}

///|
/// Take a fragment at `offset`, with `fin` marking it the last.
///
/// A fragment wholly behind the cursor is dropped; one that overlaps buffered bytes with
/// different values, or contradicts a known final size, is refused — §2.2 requires a
/// retransmission to carry the same bytes, so disagreement is the peer misbehaving.
pub fn Assembler::insert(
  self : Assembler,
  offset : UInt64,
  data : Bytes,
  fin~ : Bool,
) -> Unit raise Refused {
  let end = offset + data.length().to_uint64()
  if fin {
    match self.final_size {
      Some(size) =>
        if size != end {
          raise Conflict("a second fin fixes a different final size")
        }
      None => self.final_size = Some(end)
    }
  }
  match self.final_size {
    Some(size) => if end > size { raise Conflict("data past the final size") }
    None => ()
  }
  let mut start = offset
  let mut payload = data
  if start < self.consumed {
    let skip = self.consumed - start
    if skip >= payload.length().to_uint64() {
      return
    }
    payload = payload[skip.to_int():payload.length()].to_owned()
    start = self.consumed
  }
  if payload.length() == 0 {
    return
  }
  let buffered = self.buffered() + payload.length().to_uint64()
  if buffered > self.limit {
    raise Exceeded(limit=self.limit, got=buffered)
  }
  self.runs.push((start, payload))
  self.runs = coalesce(self.runs)
}

///|
/// Take the contiguous run from the cursor, moving it past what comes back. Empty when
/// the next expected offset has not arrived.
pub fn Assembler::read(self : Assembler) -> Bytes {
  let buf = Buffer()
  let mut i = 0
  while i < self.runs.length() {
    let (start, data) = self.runs[i]
    if start != self.consumed {
      break
    }
    buf.write_bytes(data)
    self.consumed = self.consumed + data.length().to_uint64()
    i = i + 1
  }
  if i > 0 {
    self.runs = self.runs[i:self.runs.length()].to_owned()
  }
  buf.to_bytes()
}

///|
/// Sort the runs and merge those that overlap or touch, keeping the earlier one's bytes
/// where they overlap and requiring the overlap to agree.
fn coalesce(
  runs : Array[(UInt64, Bytes)],
) -> Array[(UInt64, Bytes)] raise Refused {
  let sorted = runs.copy()
  sorted.sort_by((a, b) => a.0.compare(b.0))
  let out : Array[(UInt64, Bytes)] = []
  for run in sorted {
    let (start, data) = run
    let end = start + data.length().to_uint64()
    if out.length() == 0 {
      out.push((start, data))
      continue
    }
    let (last_start, last_data) = out[out.length() - 1]
    let last_end = last_start + last_data.length().to_uint64()
    if start > last_end {
      out.push((start, data))
    } else if end > last_end {
      agree(last_start, last_data, start, data)
      let from = (last_end - start).to_int()
      let tail = data[from:data.length()].to_owned()
      let joined = Buffer()
      joined.write_bytes(last_data)
      joined.write_bytes(tail)
      out[out.length() - 1] = (last_start, joined.to_bytes())
    } else {
      agree(last_start, last_data, start, data)
    }
  }
  out
}

///|
/// Check that two runs carry the same bytes where they overlap.
fn agree(
  a_start : UInt64,
  a : Bytes,
  b_start : UInt64,
  b : Bytes,
) -> Unit raise Refused {
  let a_end = a_start + a.length().to_uint64()
  let b_end = b_start + b.length().to_uint64()
  let stop = if a_end < b_end { a_end } else { b_end }
  let mut at = b_start
  while at < stop {
    if a[(at - a_start).to_int()] != b[(at - b_start).to_int()] {
      raise Conflict("a retransmission carries different bytes")
    }
    at = at + 1
  }
}

// The receive side of a connection's streams, and the send side's scheduler.

///|
/// One receiving stream: its assembler, its own window, and the highest offset seen,
/// which is what the connection-wide window is charged against.
struct Incoming {
  assembler : Assembler
  window : Window
  mut highest : UInt64
}

///|
/// A connection's receiving streams and its connection-wide window.
pub struct Streams {
  streams : Map[UInt64, Incoming]
  connection : Window
  mut charged : UInt64
  size : UInt64
  bidi : Quota
  uni : Quota
  server : Bool
}

///|
/// Streams advertising `data` of connection-wide credit and `stream_data` per stream,
/// admitting `bidi` and `uni` peer-opened streams of each kind (RFC 9000 §4.6).
///
/// `server` says which side this is, so a peer's stream is told from our own. The stream
/// quotas default to a hundred each, which is what quic-go and quiche both start at;
/// leave them out and they apply, or pass a `Quota` to set them from the transport
/// parameters that were actually negotiated.
pub fn Streams::new(
  data : UInt64,
  stream_data : UInt64,
  server~ : Bool,
  bidi? : Quota,
  uni? : Quota,
) -> Streams {
  {
    streams: Map([]),
    connection: Window::new(data),
    charged: 0,
    size: stream_data,
    bidi: match bidi {
      Some(q) => q
      None => Quota::new(100)
    },
    uni: match uni {
      Some(q) => q
      None => Quota::new(100)
    },
    server,
  }
}

///|
/// Take a STREAM frame for `id` carrying `data` at `offset`, `fin` on the last fragment.
///
/// Enforces the stream quota, then both flow-control windows, then reassembles, and
/// answers with the bytes now readable — charged against both windows as they go out,
/// because from the connection's point of view delivered is consumed.
pub fn Streams::on_stream(
  self : Streams,
  id : UInt64,
  offset : UInt64,
  data : Bytes,
  fin~ : Bool,
) -> Bytes raise Refused {
  if !is_local(id, server=self.server) {
    if is_bidi(id) {
      self.bidi.open(id)
    } else {
      self.uni.open(id)
    }
  }
  let s = self.open(id)
  let high = offset + data.length().to_uint64()
  s.window.arrived(high)
  // The connection's window is charged only with this stream's growth, so a
  // retransmission does not count twice.
  if high > s.highest {
    self.charged = self.charged + (high - s.highest)
    s.highest = high
  }
  self.connection.arrived(self.charged)
  s.assembler.insert(offset, data, fin~)
  let out = s.assembler.read()
  self.take(s, out.length().to_uint64())
  out
}

///|
/// Any further contiguous bytes readable on `id`, empty when the stream is unknown or
/// nothing new is contiguous.
pub fn Streams::read(self : Streams, id : UInt64) -> Bytes {
  match self.streams.get(id) {
    Some(s) => {
      let out = s.assembler.read()
      self.take(s, out.length().to_uint64())
      out
    }
    None => b""
  }
}

///|
/// The stream for `id`, opened on first reference.
fn Streams::open(self : Streams, id : UInt64) -> Incoming {
  match self.streams.get(id) {
    Some(s) => s
    None => {
      let s = {
        assembler: Assembler::new(),
        window: Window::new(self.size),
        highest: 0,
      }
      self.streams[id] = s
      s
    }
  }
}

///|
fn Streams::take(self : Streams, s : Incoming, n : UInt64) -> Unit {
  if n > 0 {
    s.window.consume(n)
    self.connection.consume(n)
  }
}

///|
/// How many streams are being tracked.
pub fn Streams::count(self : Streams) -> Int {
  self.streams.length()
}

///|
/// Stream `id`'s receive window, for the MAX_STREAM_DATA a reader's progress earns.
pub fn Streams::window(self : Streams, id : UInt64) -> Window {
  self.open(id).window
}

///|
/// The new MAX_DATA to advertise, or `None` when the gain would not be worth the frame
/// (RFC 9000 §4.1).
pub fn Streams::max_data(self : Streams) -> UInt64? {
  if self.connection.should_grant() {
    Some(self.connection.grant())
  } else {
    None
  }
}

///|
/// The new MAX_STREAM_DATA to advertise on `id`, or `None`.
pub fn Streams::max_stream_data(self : Streams, id : UInt64) -> UInt64? {
  let w = self.open(id).window
  if w.should_grant() {
    Some(w.grant())
  } else {
    None
  }
}

///|
/// What one stream still has to send: how much is queued, where its next frame starts,
/// and whether a FIN is queued and whether it has gone out.
pub(all) struct Out {
  mut pending : UInt64
  mut offset : UInt64
  mut fin_queued : Bool
  mut fin_sent : Bool
} derive(Eq, Debug)

///|
/// A scheduling decision: send `length` bytes of `stream` at `offset`, ending it when
/// `fin`.
pub(all) struct Chunk {
  stream : UInt64
  offset : UInt64
  length : UInt64
  fin : Bool
} derive(Eq, Debug)

///|
/// How many bytes of stream data one frame carries at most.
///
/// A QUIC packet must fit the path, and 1200 is the datagram every path is required to
/// carry (RFC 9000 §14); the rest of that goes to the header and the AEAD tag, so a
/// kilobyte of payload leaves room without needing to know the header's exact shape.
pub let frame : UInt64 = 1024

///|
/// A round-robin scheduler over a connection's sending streams, bounded by the send
/// budget and by how much one frame carries.
pub struct Scheduler {
  budget : Budget
  streams : Map[UInt64, Out]
  order : Array[UInt64]
  mut cursor : Int
  frame : UInt64
}

///|
/// A scheduler over `budget`, with frames capped at `frame` bytes.
pub fn Scheduler::new(budget : Budget, frame? : UInt64 = frame) -> Scheduler {
  { budget, streams: Map([]), order: [], cursor: 0, frame, }
}

///|
/// Queue `n` more bytes to send on stream `id`.
pub fn Scheduler::queue(self : Scheduler, id : UInt64, n : UInt64) -> Unit {
  self.ensure(id).pending += n
}

///|
/// Mark stream `id` finished: the FIN rides the frame that drains it, or goes alone.
pub fn Scheduler::queue_fin(self : Scheduler, id : UInt64) -> Unit {
  self.ensure(id).fin_queued = true
}

///|
/// Raise the connection-wide send limit from a MAX_DATA frame.
pub fn Scheduler::on_max_data(self : Scheduler, limit : UInt64) -> Unit {
  self.budget.on_max_data(limit)
}

///|
/// Raise stream `id`'s send limit from a MAX_STREAM_DATA frame.
pub fn Scheduler::on_max_stream_data(
  self : Scheduler,
  id : UInt64,
  limit : UInt64,
) -> Unit {
  self.budget.on_max_stream_data(id, limit)
}

///|
fn Scheduler::ensure(self : Scheduler, id : UInt64) -> Out {
  match self.streams.get(id) {
    Some(o) => o
    None => {
      let o = { pending: 0, offset: 0, fin_queued: false, fin_sent: false, }
      self.streams[id] = o
      self.order.push(id)
      o
    }
  }
}

///|
/// The next decision, or `None` when no stream can send — all drained, or every one of
/// them blocked by flow control.
///
/// Streams take turns: whichever sent last goes to the back, so one stream with a great
/// deal queued cannot starve the rest.
pub fn Scheduler::next(self : Scheduler) -> Chunk? raise Refused {
  let n = self.order.length()
  if n == 0 {
    return None
  }
  for k = 0; k < n; k = k + 1 {
    let at = (self.cursor + k) % n
    let id = self.order[at]
    guard self.streams.get(id) is Some(out) else {
      abort("moonquic: the scheduler's order and streams disagree")
    }
    let window = self.budget.available(id)
    let take = min(min(out.pending, window), self.frame)
    if take > 0UL {
      let last = take == out.pending && out.fin_queued && !out.fin_sent
      self.budget.spend(id, take)
      let chunk = { stream: id, offset: out.offset, length: take, fin: last, }
      out.offset += take
      out.pending -= take
      if last {
        out.fin_sent = true
      }
      self.cursor = (at + 1) % n
      return Some(chunk)
    }
    if out.pending == 0UL && out.fin_queued && !out.fin_sent {
      out.fin_sent = true
      self.cursor = (at + 1) % n
      return Some({ stream: id, offset: out.offset, length: 0UL, fin: true, })
    }
  }
  None
}

///|
fn min(a : UInt64, b : UInt64) -> UInt64 {
  if a < b {
    a
  } else {
    b
  }
}

///|
pub extend Initiator with Debug::{to_repr}

///|
pub extend Initiator with Eq::{not_equal, equal}

///|
pub extend Direction with Debug::{to_repr}

///|
pub extend Direction with Eq::{not_equal, equal}

///|
pub extend Sending with Debug::{to_repr}

///|
pub extend Sending with Eq::{not_equal, equal}

///|
pub extend SendEvent with Debug::{to_repr}

///|
pub extend SendEvent with Eq::{not_equal, equal}

///|
pub extend Receiving with Debug::{to_repr}

///|
pub extend Receiving with Eq::{not_equal, equal}

///|
pub extend RecvEvent with Debug::{to_repr}

///|
pub extend RecvEvent with Eq::{not_equal, equal}

///|
pub extend Out with Debug::{to_repr}

///|
pub extend Out with Eq::{not_equal, equal}

///|
pub extend Chunk with Debug::{to_repr}

///|
pub extend Chunk with Eq::{not_equal, equal}
