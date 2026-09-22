///|
/// The assembled QUIC data path: a receive-side `StreamManager` routes STREAM
/// frames to per-stream reassembly; a send-side `QuicStreamScheduler`
/// round-robins streams capped by the frame size; the `QuicSender` packetizes
/// queued data and an ACK clears it; and a `QuicConnection` numbers its three
/// packet-number spaces and reassembles CRYPTO per level.
///
///     moon run examples/26-quic-sender --target native
#coverage.skip
fn main {
  run() catch {
    e => println("sender error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let m = @stream.Streams::new(100UL, 100UL, server=true)
  let _ = m.on_stream(0UL, 3UL, b"def", fin=false)
  let delivered = m.on_stream(0UL, 0UL, b"abc", fin=false)
  println("stream mgr delivered = \"\{ascii(delivered)}\" streams=\{m.count()}")
  let sch = @stream.Scheduler::new(
    @stream.Budget::new(1000UL, 1000UL),
    frame=300UL,
  )
  sch.queue(0UL, 500UL)
  sch.queue(4UL, 500UL)
  let d0 = next(sch)
  let d1 = next(sch)
  println(
    "scheduler: d0 stream=\{d0.stream.to_string()} len=\{d0.length.to_string()}, d1 stream=\{d1.stream.to_string()} len=\{d1.length.to_string()}",
  )
  let s = @conn.Sender::new(100000UL, 100000UL, 1200L, 25000L, 1000L, 8UL)
  s.queue_stream(0UL, b"abcdefghij")
  s.queue_fin(0UL)
  let (pn0, f0) = poll(s, 0L)
  let (pn1, _) = poll(s, 1L)
  println(
    "sender pn0=\{pn0.to_string()} pn1=\{pn1.to_string()} first packet carries \{f0.length()} frame(s)",
  )
  let ack : @frame.Frame = Ack(largest=1UL, delay=0UL, first_range=1UL, ranges=[])
  s.on_ack(ack, 10L)
  println("outstanding after ack = \{s.outstanding().length()}")
  let c = @conn.Conn::new(false)
  let _ = c.next_packet_number(@conn.Level::Initial)
  println(
    "next initial pn=\{c.next_packet_number(@conn.Level::Initial).to_string()} next handshake pn=\{c.next_packet_number(@conn.Level::Handshake).to_string()}",
  )
  let _ = c.on_crypto_frame(@conn.Level::Initial, 3UL, b"def")
  println(
    "crypto reassembled = \"\{ascii(c.on_crypto_frame(@conn.Level::Initial, 0UL, b"abc"))}\"",
  )
}

///|
fn next(sch : @stream.Scheduler) -> @stream.Chunk raise {
  match sch.next() {
    Some(d) => d
    None => abort("expected a scheduling decision")
  }
}

///|
fn poll(s : @conn.Sender, now : Int64) -> (Int64, Array[@frame.Frame]) raise {
  match s.poll_send(now) {
    Some(p) => p
    None => abort("expected a packet")
  }
}

///|
fn ascii(b : Bytes) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}
