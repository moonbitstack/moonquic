name = "moonbitstack/moonquic"

version = "0.3.1"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonquic"

license = "Apache-2.0"

keywords = [ "quic", "rfc9000", "rfc9001", "transport", "moonbit" ]

description = "moonquic — the QUIC transport for MoonBit (RFC 9000/9001/9002): packets, frames, loss recovery, congestion control, streams and flow control, bytes in and events out. No sockets; the handshake is moontls' and HTTP/3 is moonhttp's."

preferred_target = "wasm-gc"

import {
  "moonbitstack/moontls@0.6.0",
  "moonbitstack/mooncrypt@0.3.0",
  "moonbitstack/moonvar@0.2.0",
}
