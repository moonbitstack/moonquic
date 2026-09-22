///|
/// QUIC ACK generation (RFC 9000 §13.2, §19.3): an `AckRangeSet` records
/// received packet numbers with gaps, produces the Largest / First Range /
/// (Gap, Length) fields, and reconstructs the ranges. A `PacketNumberSpace`
/// then owes an ACK after ack-eliciting packets and clears it once built.
///
///     moon run examples/22-quic-ack --target native
#coverage.skip
fn main {
  run() catch {
    e => println("ack error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let set = @frame.Seen::new()
  for pn in [0UL, 1UL, 2UL, 4UL, 5UL, 7UL] {
    set.add(pn)
  }
  println(
    "largest=\{opt_u(set.largest())} contains(3)=\{set.contains(3UL)} contains(5)=\{set.contains(5UL)}",
  )
  match set.fields() {
    Some((largest, first_range, pairs)) => {
      println(
        "ack fields: largest=\{largest.to_string()} first_range=\{first_range.to_string()} gap/len pairs=\{pairs.length()}",
      )
      let ranges = @frame.Seen::read(largest, first_range, pairs)
      println(
        "reconstructed ranges = \{ranges.ranges().length()} (expect 3: 0-2, 4-5, 7-7)",
      )
    }
    None => println("empty set")
  }
  let s = @packet.Space::new()
  s.on_packet_received(0L, true)
  s.on_packet_received(1L, true)
  s.on_packet_received(3L, true)
  println("ack pending = \{s.ack_pending()}")
  match s.build_ack(0UL) {
    Some(frame) => {
      println("built ACK, ack_pending now = \{s.ack_pending()}")
      println("acked ranges from frame = \{frame.acked().length()}")
    }
    None => println("no ack owed")
  }
}

///|
fn opt_u(o : UInt64?) -> String {
  match o {
    Some(n) => n.to_string()
    None => "(none)"
  }
}
