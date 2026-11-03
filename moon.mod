name = "moonbitstack/moonquic"

version = "0.3.10"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonquic"

license = "Apache-2.0"

keywords = [
  "quic",
  "quic-transport",
  "transport",
  "udp",
  "http3",
  "rfc9000",
  "rfc9001",
  "rfc9002",
  "rfc9221",
  "rfc9438",
  "congestion-control",
  "newreno",
  "cubic",
  "bbr",
  "loss-recovery",
  "datagram",
  "connection-migration",
  "path-validation",
  "stateless-reset",
  "client",
  "tls13",
  "retry",
  "version-negotiation",
  "moonbit",
]

description = "QUIC transport for MoonBit."

import {
  "moonbitstack/moontls@0.9.7",
  "moonbitstack/mooncred@0.6.7",
  "moonbitstack/mooncrypt@0.4.6",
  "moonbitstack/moonvar@0.2.0",
}

source = "src"
