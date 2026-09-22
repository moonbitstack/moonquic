///|
/// QUIC flow control (RFC 9000 §4): a `SendFlow` window shrinks with sends and
/// grows only via MAX_DATA; a `RecvFlow` enforces the advertised limit and
/// auto-extends once half a window is consumed; and a connection-wide
/// `QuicSendFlow` bounds each stream by the smaller of its own and the
/// connection window.
///
///     moon run examples/23-quic-flow --target native
#coverage.skip
fn main {
  run() catch {
    e => println("flow error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let f = @stream.Credit::new(100UL)
  f.spend(30UL)
  println(
    "send: available=\{f.available().to_string()} sent=\{f.sent().to_string()} blocked=\{f.blocked()}",
  )
  f.spend(70UL)
  println("send: available=\{f.available().to_string()} blocked=\{f.blocked()}")
  f.grant(200UL)
  println("after MAX_DATA 200: available=\{f.available().to_string()}")
  let r = @stream.Window::new(100UL)
  r.arrived(60UL)
  r.consume(60UL)
  println(
    "recv: should_extend=\{r.should_grant()} new_limit=\{r.grant().to_string()}",
  )
  let q = @stream.Budget::new(1000UL, 600UL)
  println(
    "stream 0 window = \{q.available(0UL).to_string()} (min of conn 1000, stream 600)",
  )
  q.spend(0UL, 400UL)
  q.spend(4UL, 500UL)
  println(
    "conn available = \{q.connection().to_string()}, stream 0 now bounded to \{q.available(0UL).to_string()}",
  )
}
