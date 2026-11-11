// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A QUIC server over UDP, for the interop scripts to point another implementation at.
//
//     quic-server echo <port> cert=<pem> key=<pem> [alpn=h3] [version=1|2|both]
//
// It prints `port <n>` once it is listening, then `version <number>` for each connection, so a
// script asserts on facts rather than reading prose.

///|
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
fn fail(message : String) -> Unit raise {
  println("error \{message}")
  raise Failure(message)
}

///|
/// The versions the call names, in the order it names them: one, or both with version 1 first.
fn versions_of(options : Map[String, String]) -> Array[UInt32] {
  let out : Array[UInt32] = []
  match options.get("version") {
    Some("2") => out.push(@packet.version2)
    Some("both") => {
      out.push(@packet.version1)
      out.push(@packet.version2)
    }
    _ => out.push(@packet.version1)
  }
  out
}

///|
/// The clock the transport takes, in microseconds from the start of the run.
let origin : Ref[Int64] = Ref(0L)

///|
fn now() -> Int64 {
  @env.now().reinterpret_as_int64() - origin.val
}

///|
async fn main {
  origin.val = @env.now().reinterpret_as_int64()
  let args = @env.args()
  guard args.length() >= 4 else {
    fail(
      "usage: quic-server <echo> <port> cert=<pem> key=<pem> [alpn=h3] [version=1|2|both]",
    )
  }
  let mode = args[1]
  guard mode == "echo" else { fail("no such mode: \{mode}") }
  let port = @string.parse_int(args[2]) catch {
    _ => abort("the port is not a number")
  }
  let options = options(args[3:])
  let cert = match options.get("cert") {
    Some(path) => path
    None => return fail("cert= is required")
  }
  let key = match options.get("key") {
    Some(path) => path
    None => return fail("key= is required")
  }
  let alpn = match options.get("alpn") {
    Some(name) => [name]
    None => ["h3"]
  }
  let tls = @tls.Server::new(
    [@x509.pem(@fs.read_file(cert).text())],
    @x509.PrivateKey::pem(@fs.read_file(key).text()) catch {
      _ => abort("the key is not a private key")
    },
    alpn~,
  )
  let cfg = { ..@conn.Config::default(), versions: versions_of(options), }
  let endpoint : @conn.Endpoint[@socket.Addr] = @conn.Endpoint::server(
    cfg,
    tls,
    rand=entropy,
  )
  let socket = @udp.bind(host="127.0.0.1", port~)
  println("port \{socket.addr().port()}")
  let mut running = true
  while running {
    endpoint.tick(now())
    for session in endpoint.take_busy() {
      for event in session.take_events() {
        match event {
          Readable(id) => {
            let data = session.read(id)
            // Only a bidirectional stream the peer opened can be written to: a unidirectional
            // one is the peer's to send on, and a stream this end opened is not a request
            // (RFC 9000 §2.1).
            if data.length() > 0 && id % 4UL == 0UL {
              session.write(id, data, fin=session.finished(id))
            }
          }
          Closed(_) => ()
          _ => ()
        }
      }
    }
    while endpoint.poll_out(now()) is Some((datagram, to)) {
      socket.send(to, datagram) catch {
        _ => ()
      }
    }
    match socket.recv(timeout=10) {
      Some((bytes, from)) => endpoint.recv(bytes, from, now()) catch { _ => () }
      None => ()
    }
    // A connection that has closed is the peer's to forget; this server keeps serving.
    let _ = running
    running = true
  }
  socket.close()
}
