///|
/// QUIC loss recovery and congestion control (RFC 9002): NewReno slow-start and
/// the halving on a congestion signal (§7); the RTT estimator's smoothed_rtt /
/// rttvar / PTO (§5.3, §6.2.1); and the composed `QuicRecovery` loop sampling an
/// RTT and freeing bytes on an ACK.
///
///     moon run examples/24-quic-recovery --target native
#coverage.skip
fn main {
  run() catch {
    e => println("recovery error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let cc = @recovery.NewReno::new(policy=@recovery.Policy::new(datagram=1200L))
  println("initial cwnd = \{cc.window().to_string()}")
  cc.on_ack(1200L)
  println("after ack cwnd = \{cc.window().to_string()} (slow start)")
  cc.on_congestion(at=0L, now=0L)
  println(
    "after loss cwnd = \{cc.window().to_string()} ssthresh=\{cc.ssthresh().to_string()}",
  )
  let rtt = @recovery.Rtt::new()
  rtt.sample(100000L, ack_delay=0L)
  rtt.sample(80000L, ack_delay=5000L)
  println(
    "rtt: smoothed=\{rtt.smoothed().to_string()} var=\{rtt.variation().to_string()} min=\{rtt.min().to_string()} pto=\{rtt.pto().to_string()}",
  )
  let rec = @recovery.State::new(
    policy=@recovery.Policy::new(
      datagram=1200L,
      ack_delay=25000L,
      granularity=1000L,
    ),
  )
  rec.on_sent(0L, at=0L, size=1200L)
  let ack : @frame.Frame = Ack(largest=0UL, delay=0UL, first_range=0UL, ranges=[])
  let lost = rec.on_ack(ack, 100L, ack_delay=0L)
  println(
    "after ack: in_flight=\{rec.in_flight().to_string()} smoothed_rtt=\{rec.rtt().smoothed().to_string()} window=\{rec.window().to_string()} lost=\{lost.length()}",
  )
  // The sent-packet tracker underneath: record two sends, acknowledge one.
  let tr = @recovery.Flight::new()
  tr.on_sent(0L, at=0L, size=1200L)
  tr.on_sent(1L, at=100L, size=1200L)
  let acked_bytes = tr.on_ack([(1L, 1L)])
  println(
    "tracker: acked_bytes=\{acked_bytes.to_string()} largest_acked=\{tr.largest_acked().to_string()} outstanding=\{tr.outstanding().length()}",
  )
}
