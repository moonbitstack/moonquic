///|
/// QUIC packet protection (RFC 9001): the Initial key/iv/hp derive from the
/// client's Destination Connection ID (Appendix A.1), a client Initial packet is
/// protected and then recovered — AEAD authentication plus header protection —
/// and a key update advances the secret deterministically (§6.1).
///
///     moon run examples/04-crypto
#coverage.skip
fn main {
  run() catch {
    e => println("quic crypto error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let dcid = hexb("8394c8f03e515708")
  let keys = @crypto.initial(dcid[:]).0
  println("initial key = \{hex(keys.key)}")
  println("initial iv  = \{hex(keys.iv)}")
  println("initial hp  = \{hex(keys.hp)}")
  let frames : Array[@frame.Frame] = [
    Crypto(offset=0UL, data=b"\x01\x02\x03"),
    Ping,
  ]
  let packet = @conn.send_long(Initial, 1U, dcid, b"", 2L, 4, frames, keys)
  println("protected packet = \{packet.length()} bytes")
  match @conn.recv_long(packet, keys) {
    Some((got, pn)) =>
      println(
        "recovered pn=\{pn.to_string()} frames=\{got.length()} crypto+ping intact=\{got.length() >= 2 && got[0] == frames[0] && got[1] == frames[1]}",
      )
    None => println("authentication failed")
  }
  // Header-protection mask over the RFC 9001 A.2 sample, under the same client
  // Initial keys the appendix derives.
  let sample = hexb("d1b1c98dd7689fb8ec11d242b123dc9b")
  println("hp mask (A.2) = \{hex(keys.mask(sample[:]))}  (expect 437b9aec36)")
  // Key update (§6.1): the next secret is deterministic and distinct.
  let secret = @crypto.secret(dcid[:])
  let updated = @crypto.update(secret[:])
  println(
    "key update deterministic and advances = \{@crypto.update(secret[:]) == updated && updated != secret}",
  )
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

///|
fn hexb(h : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < h.length(); i = i + 2 {
    buf.write_byte(
      ((nib(h[i].to_int()) << 4) | nib(h[i + 1].to_int())).to_byte(),
    )
  }
  buf.to_bytes()
}

///|
fn nib(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else {
    0
  }
}
