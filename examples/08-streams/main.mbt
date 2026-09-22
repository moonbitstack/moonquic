///|
/// QUIC streams: id classification and generation (RFC 9000 §2.1, Table 1), the
/// send and receive stream state machines (§3.1, §3.2), and stream reassembly
/// (§2.2) reordering out-of-order fragments and tracking the final size from the
/// fin bit.
///
///     moon run examples/25-quic-streams --target native
#coverage.skip
fn main {
  run() catch {
    e => println("stream error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  println(
    "id_of(Client,Bidi,1)=\{@stream.id_of(Client, Bidi, 1UL).to_string()} (expect 4)",
  )
  println(
    "initiator(3)=\{sinit(@stream.initiator(3UL))} direction(3)=\{sdir(@stream.direction(3UL))}",
  )
  println(
    "is_bidi(4)=\{@stream.is_bidi(4UL)} client_initiated(2)=\{@stream.is_client(2UL)} sequence(23)=\{@stream.sequence(23UL).to_string()}",
  )
  println(
    "server writable on client-uni(2)=\{@stream.is_writable(2UL, server=true)} locally_initiated(1,server)=\{@stream.is_local(1UL, server=true)}",
  )
  let s1 = @stream.Sending::next(Ready, Write(fin=false))
  let s2 = @stream.Sending::next(s1, Write(fin=true))
  let s3 = @stream.Sending::next(s2, AllAcked)
  println("send path: \{sendst(s1)} -> \{sendst(s2)} -> \{sendst(s3)}")
  let r1 = @stream.Receiving::next(Recv, Receive(fin=true))
  let r2 = @stream.Receiving::next(r1, AllReceived)
  let r3 = @stream.Receiving::next(r2, AppRead)
  println("recv path: \{recvst(r1)} -> \{recvst(r2)} -> \{recvst(r3)}")
  let re = @stream.Assembler::new()
  re.insert(3UL, b"def", fin=false)
  println("read before gap filled = \"\{ascii(re.read())}\"")
  re.insert(0UL, b"abc", fin=true)
  println(
    "read after gap filled = \"\{ascii(re.read())}\" final_size=\{opt_u(re.final_size())} complete=\{re.complete()}",
  )
}

///|
fn sinit(s : @stream.Initiator) -> String {
  match s {
    Client => "Client"
    Server => "Server"
  }
}

///|
fn sdir(d : @stream.Direction) -> String {
  match d {
    Bidi => "Bidi"
    Uni => "Uni"
  }
}

///|
fn sendst(s : @stream.Sending) -> String {
  match s {
    Ready => "Ready"
    Send => "Send"
    DataSent => "DataSent"
    DataRecvd => "DataRecvd"
    ResetSent => "ResetSent"
    ResetRecvd => "ResetRecvd"
  }
}

///|
fn recvst(s : @stream.Receiving) -> String {
  match s {
    Recv => "Recv"
    SizeKnown => "SizeKnown"
    DataReceived => "DataReceived"
    DataRead => "DataRead"
    ResetReceived => "ResetReceived"
    ResetRead => "ResetRead"
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

///|
fn opt_u(o : UInt64?) -> String {
  match o {
    Some(n) => n.to_string()
    None => "(none)"
  }
}
