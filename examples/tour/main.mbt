///|
/// A QUIC packet built from the connection ID up, then taken back apart.
///
///     moon run examples/tour
#coverage.skip
fn main {
  // A varint says how long it is in its own first two bits (RFC 9000 §16).
  for v in [0UL, 63UL, 16383UL, 1073741823UL] {
    println("varint \{v} -> \{hex(@varint.encode(v))}")
  }

  // Frames are the payload's contents (§19). A CRYPTO frame carries the handshake.
  let frames : Array[@frame.Frame] = [
    Crypto(offset=0UL, data=b"the ClientHello would go here"),
    Ping,
    Padding(3),
  ]
  let payload = @packet.payload(frames)
  println(
    "payload            \{payload.length()} bytes, \{frames.length()} frames",
  )
  println("elicits an ACK     \{@packet.payload_elicits_ack(frames)}")

  // Both endpoints can compute the Initial keys from the client's connection ID
  // alone — no TLS exchange needed, which is what makes an Initial packet readable
  // by anyone on the path and protected against everyone off it (RFC 9001 §5.2).
  let dcid = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
  let (client, server) = @crypto.initial(dcid[:])
  println("client key         \{hex(client.key)}")
  println("server key         \{hex(server.key)}")

  // The header a packet is sealed under: the invariant part, the Initial token, the
  // Length covering the packet number and the sealed payload (§17.2).
  let long : @packet.Long = {
    packet_type: Initial,
    type_specific: 0,
    version: 1,
    dcid,
    scid: b"\xc0\xff\xee",
  }
  let number = @packet.number(2L, None)
  let header = long.header(number[:], payload=payload.length() + 16)
  println("header             \{hex(header)}")

  // Seal the payload under that header, then hide the packet number (§5.3–§5.4).
  let wire = client.seal(header[:], payload[:], number=2L)
  println(
    "packet             \{wire.length()} bytes, first byte \{hex(wire[0:1].to_owned())}",
  )

  // The receiver reads the Length field — which protection leaves alone — to find
  // the packet number, recovers it against what it has already seen, and opens.
  guard client.open(wire[:], largest=1L) is Some((plain, pn)) else {
    println("the packet did not open")
    return
  }
  println("opened             packet number \{pn}, \{plain.length()} bytes")
  let back = @packet.read_payload(plain) catch {
    e => {
      println("the payload did not parse: \{e}")
      return
    }
  }
  println(
    "frames back        \{back.length()}, same as sent: \{back == frames}",
  )

  // An ACK reports the packet numbers seen as a largest and a run of gaps (§19.3.1).
  let seen = @frame.Seen::new()
  for pn in [0UL, 1UL, 2UL, 5UL, 6UL, 9UL] {
    seen.add(pn)
  }
  guard seen.fields() is Some((largest, first, pairs)) else { return }
  let ack : @frame.Frame = Ack(
    largest~,
    delay=0UL,
    first_range=first,
    ranges=pairs,
  )
  println("ack                \{hex(@frame.encode(ack))}")
  let acked = ack.acked() catch {
    e => {
      println("the ACK did not read back: \{e}")
      return
    }
  }
  for run in acked {
    println("  acknowledges     \{run.0}..\{run.1}")
  }
  // An endpoint declares its limits in a block the TLS handshake carries (§18).
  let mine = @conn.Limits::new(
    idle_timeout=30_000,
    data=1048576,
    stream_data_bidi_remote=65536,
    streams_bidi=100,
  )
  let block = @conn.encode(mine.params()[:])
  println(
    "params             \{block.length()} bytes, \{mine.params().length()} of them",
  )
  guard @conn.decode(block[:]) is Some(back) else { return }
  println("read back          \{@conn.Limits::read(back[:]) == mine}")
  // Everything the block leaves out keeps RFC 9000 §18.2's default.
  println(
    "ack delay exponent \{@conn.Limits::read(back[:]).ack_delay_exponent}",
  )

  // A server holds one connection per connection id, and answers a datagram by it.
  let server : @conn.Endpoint[String] = @conn.Endpoint::new(
    @conn.Config::default(),
  )
  println("connections        \{server.count()}")
}

///|
fn hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}
