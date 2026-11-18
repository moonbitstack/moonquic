name = "moonbitstack/moonquic"

version = "0.4.1"

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
  "0-rtt",
  "early-data",
  "connection-migration",
  "path-validation",
  "stateless-reset",
  "client",
  "tls13",
  "retry",
  "multipath",
  "pacing",
  "address-validation",
  "version-negotiation",
  "packet-recovery",
  "probe-timeout",
  "stream-multiplexing",
  "rfc9369",
  "rfc9368",
  "quic-v2",
  "version-2",
  "moonbit",
]

description = "QUIC transport for MoonBit."

import {
  "moonbitstack/moontls@0.10.2",
  "moonbitstack/mooncred@0.8.1",
  "moonbitstack/mooncrypt@0.5.2",
  "moonbitstack/moonvar@0.3.1",
}

source = "src"
