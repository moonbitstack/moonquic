///|
/// QUIC variable-length integers (RFC 9000 §16) and truncated packet numbers
/// (§17.1, Appendix A). Each varint encodes to its shortest form and decodes
/// back; a packet number is truncated against the largest-acked and recovered
/// to its full value.
///
///     moon run examples/18-quic-varint --target native
#coverage.skip
fn main {
  for v in [37UL, 15293UL, 494878333UL, 151288809941952652UL] {
    let enc = @varint.encode(v)
    let ok = match @varint.decode(enc[:]) {
      Some((d, n)) => d == v && n == enc.length()
      None => false
    }
    println("varint \{v.to_string()} = \{hex(enc)}  round-trip=\{ok}")
  }
  let full = 0xac5c02L
  let lacked = 0xabe8bcL
  println(
    "pn 0x\{"ac5c02"}: len=\{@packet.number_size(full, Some(lacked))} encoded=\{hex(@packet.number(full, Some(lacked)))}",
  )
  let decoded = @packet.read_number(0xa82f30eaL, 0x9b32L, 16)
  println(
    "pn_decode(trunc 0x9b32, 16 bits) -> \{decoded.to_string()} (= 0xa82f9b32)",
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
