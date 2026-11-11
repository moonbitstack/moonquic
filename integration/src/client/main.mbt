// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A QUIC client over UDP, for the interop scripts to drive against another implementation.
//
//     quic-client echo <host> <port> ca=<pem> [insecure] [payload=<text>]
//     quic-client resume <host> <port> ca=<pem> [insecure] [payload=<text>]
//     quic-client multipath <host> <port> ca=<pem> [insecure] [payload=<text>]
//
// Each mode prints one fact per line — `alpn h3`, `early_datagrams 1`, `path1_validated true` —
// so that a script can assert on them without reading prose.

///|
/// The arguments after the mode, as `key=value` pairs and bare words.
fn options(args : ArrayView[String]) -> Map[String, String] {
  let out = Map([])
  for arg in args {
    match arg.find("=") {
      Some(i) => out[arg[:i].to_owned()] = arg[i + 1:].to_owned()
      None => out[arg] = ""
    }
  }
  out
}

///|
fn entropy(n : Int32) -> Bytes {
  guard @env.rand(n) is Some(bytes) else { abort("no system entropy") }
  bytes
}

///|
/// Report a failure the way a script reads it: one line, then a non-zero exit.
fn fail(message : String) -> Unit raise {
  println("error \{message}")
  raise Failure(message)
}

///|
/// A TLS client for the peer named on the command line: `ca=` names the root to trust, and
/// `insecure` judges no certificate at all, which is what a peer with a throwaway one needs.
async fn tls_client(
  options : Map[String, String],
  sessions? : @tls.Sessions,
  early~ : Bool = false,
) -> @tls.Client {
  let alpn = transport_of(options)
  let roots = match options.get("ca") {
    Some(path) => @x509.Roots::pem(@fs.read_file(path).text())
    None => @x509.Roots::new()
  }
  let verify = if options.contains("insecure") {
    @tls.Verify::Custom((_, _) => ())
  } else {
    @tls.Verify::Chain
  }
  let groups = match options.get("groups") {
    Some(list) => names_of(list)
    None => @tls.groups
  }
  @tls.Client::new(roots, alpn~, verify~, sessions?, early~, groups~)
}

///|
/// The key-exchange groups a comma-separated list names, or the defaults.
fn names_of(list : String) -> Array[Int32] {
  let out : Array[Int32] = []
  for name in list.split(",") {
    out.push(
      match name {
        "x25519" => @ext.x25519
        "secp256r1" => @ext.secp256r1
        "secp384r1" => @ext.secp384r1
        "x448" => @ext.x448
        "x25519mlkem768" => @ext.x25519mlkem768
        _ => @ext.x25519
      },
    )
  }
  out
}

///|
/// The versions the call names to offer, in its order: `versions=1,2` offers version 1 and takes
/// version 2 if the peer has nothing else.
fn versions_of(options : Map[String, String]) -> Array[UInt32] {
  match options.get("versions") {
    Some(list) => {
      let out : Array[UInt32] = []
      for name in list.split(",") {
        match name {
          "2" => out.push(@packet.version2)
          _ => out.push(@packet.version1)
        }
      }
      out
    }
    None => @conn.Config::default().versions
  }
}

///|
/// The ALPN the call names, or HTTP/3's. A peer that only speaks HTTP/0.9 over QUIC answers a raw
/// request line, and says so with the protocol's own name.
fn transport_of(options : Map[String, String]) -> Array[String] {
  match options.get("alpn") {
    Some(name) => [name]
    None => ["h3"]
  }
}

///|
/// The payload with `\r` and `\n` written out, so that a request line can be named on a command
/// line without the shell or the script having to carry a carriage return.
fn unescape(text : String) -> String {
  let out = StringBuilder()
  let mut at = 0
  while at < text.length() {
    let c = text[at].to_int()
    if c == 0x5c && at + 1 < text.length() {
      match text[at + 1].to_int() {
        0x72 => out.write_char('\r')
        0x6e => out.write_char('\n')
        0x74 => out.write_char('\t')
        0x5c => out.write_char('\\')
        other => {
          out.write_char('\\')
          out.write_char(other.unsafe_to_char())
        }
      }
      at += 2
    } else {
      out.write_char(c.unsafe_to_char())
      at += 1
    }
  }
  out.to_string()
}

///|
async fn main {
  start()
  let args = @env.args()
  guard args.length() >= 4 else {
    fail(
      "usage: quic-client <echo|resume|multipath> <host> <port> [ca=<pem>] [insecure] [payload=<text>]",
    )
  }
  let mode = args[1]
  let host = args[2]
  let port = @string.parse_int(args[3]) catch {
    _ => abort("the port is not a number")
  }
  let options = options(args[4:])
  let payload = unescape(options.get("payload").unwrap_or("moonquic interop"))
  // The name the certificate is judged by, when it is not the address dialled: a test peer's
  // certificate names its own host, not 127.0.0.1.
  let name = options.get("name").unwrap_or(host)
  let to = @socket.Addr::resolve(host, port~)
  let socket = @udp.bind(host="127.0.0.1", port=0)
  match mode {
    "echo" => echo(socket, to, name, options, payload)
    "resume" => resumed(socket, to, name, options, payload)
    "multipath" => multipath(socket, to, name, options, payload)
    _ => fail("no such mode: \{mode}")
  }
}
