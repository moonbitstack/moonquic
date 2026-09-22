///|
/// QUIC transport parameters (RFC 9000 §18) — the (id, length, value) block a
/// peer carries in its TLS handshake. Named integer parameters encode, decode
/// back, and their varint values read out; the identifier constants are the RFC
/// 9000 §18.2 assignments.
///
///     moon run examples/20-quic-transport-params --target native
#coverage.skip
fn main {
  let params = [
    @conn.Param::int(@conn.MaxData, 1048576UL),
    @conn.Param::int(@conn.MaxStreamsBidi, 100UL),
    @conn.Param::int(@conn.MaxIdleTimeout, 30000UL),
    @conn.Param::int(@conn.MaxUdpPayload, 1472UL),
  ]
  let enc = @conn.encode(params)
  println("encoded = \{hex(enc)}")
  match @conn.decode(enc[:]) {
    Some(got) => {
      println("decoded \{got.length()} parameters:")
      for p in got {
        println(
          "  id=\{p.kind.code().to_string()} value=\{opt_u(@conn.Param::as_int(p))}",
        )
      }
    }
    None => println("decode failed")
  }
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
fn opt_u(o : UInt64?) -> String {
  match o {
    Some(n) => n.to_string()
    None => "(none)"
  }
}
