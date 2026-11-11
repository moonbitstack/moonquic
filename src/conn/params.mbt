// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A transport parameter's identifier (RFC 9000 §18.2, and RFC 9221's datagram
/// extension). `Other` carries anything else: the block is read and written generically,
/// so a parameter this build has no name for survives a round trip intact.
#derive(Eq, Debug)
pub(all) enum Kind {
  OriginalDcid
  MaxIdleTimeout
  StatelessResetToken
  MaxUdpPayload
  MaxData
  MaxStreamDataBidiLocal
  MaxStreamDataBidiRemote
  MaxStreamDataUni
  MaxStreamsBidi
  MaxStreamsUni
  AckDelayExponent
  MaxAckDelay
  DisableActiveMigration
  PreferredAddress
  ActiveConnectionIdLimit
  InitialScid
  RetryScid
  MaxDatagramFrameSize
  /// draft-ietf-quic-multipath §2.1: the largest path id this endpoint will maintain.
  InitialMaxPathId
  /// RFC 9368 §3: the version this endpoint chose and the ones it would accept.
  VersionInformation
  Other(UInt64)
}

///|
/// The identifier on the wire.
pub fn Kind::code(self : Kind) -> UInt64 {
  match self {
    OriginalDcid => 0x00
    MaxIdleTimeout => 0x01
    StatelessResetToken => 0x02
    MaxUdpPayload => 0x03
    MaxData => 0x04
    MaxStreamDataBidiLocal => 0x05
    MaxStreamDataBidiRemote => 0x06
    MaxStreamDataUni => 0x07
    MaxStreamsBidi => 0x08
    MaxStreamsUni => 0x09
    AckDelayExponent => 0x0a
    MaxAckDelay => 0x0b
    DisableActiveMigration => 0x0c
    PreferredAddress => 0x0d
    ActiveConnectionIdLimit => 0x0e
    InitialScid => 0x0f
    RetryScid => 0x10
    MaxDatagramFrameSize => 0x20
    InitialMaxPathId => 0x3e
    VersionInformation => 0x11
    Other(code) => code
  }
}

///|
/// The parameter a wire identifier names.
pub fn Kind::of(code : UInt64) -> Kind {
  match code {
    0x00 => OriginalDcid
    0x01 => MaxIdleTimeout
    0x02 => StatelessResetToken
    0x03 => MaxUdpPayload
    0x04 => MaxData
    0x05 => MaxStreamDataBidiLocal
    0x06 => MaxStreamDataBidiRemote
    0x07 => MaxStreamDataUni
    0x08 => MaxStreamsBidi
    0x09 => MaxStreamsUni
    0x0a => AckDelayExponent
    0x0b => MaxAckDelay
    0x0c => DisableActiveMigration
    0x0d => PreferredAddress
    0x0e => ActiveConnectionIdLimit
    0x0f => InitialScid
    0x10 => RetryScid
    0x20 => MaxDatagramFrameSize
    0x3e => InitialMaxPathId
    0x11 => VersionInformation
    _ => Other(code)
  }
}

///|
/// A `version_information` parameter (RFC 9368 §3): the version `chosen`, then the versions the
/// sender would accept, four bytes each. Both sides send one, which is what makes a version
/// negotiation the peer cannot forge: the list arrives under the handshake's own authentication.
pub fn version_information(
  chosen : UInt32,
  available : ArrayView[UInt32],
) -> Param {
  let buf = Buffer()
  @fixed.write_u32(buf, chosen)
  for version in available {
    @fixed.write_u32(buf, version)
  }
  { kind: VersionInformation, value: buf.to_bytes(), }
}

///|
/// The versions a `version_information` value carries: the chosen one and the list. `None` when
/// the value is shorter than one version or not a whole number of them, which is what RFC 9368
/// §4 makes a connection error.
pub fn read_version_information(value : BytesView) -> (UInt32, Array[UInt32])? {
  if value.length() < 4 || value.length() % 4 != 0 {
    return None
  }
  let versions : Array[UInt32] = []
  for at = 0; at < value.length(); at = at + 4 {
    guard @fixed.read_u32(value, at~) is Some(version) else { break }
    versions.push(version)
  }
  let chosen = versions.remove(0)
  Some((chosen, versions))
}

///|
/// Whether only a server may send this parameter (RFC 9000 §18.2's closing paragraph).
/// A client that sends one is a TRANSPORT_PARAMETER_ERROR.
pub fn Kind::server_only(self : Kind) -> Bool {
  match self {
    OriginalDcid | PreferredAddress | RetryScid | StatelessResetToken => true
    _ => false
  }
}

///|
/// One transport parameter: what it is, and its value bytes. An integer parameter's
/// value is a single varint — `Param::int` writes one and `Param::as_int` reads one.
#derive(Eq, Debug)
pub(all) struct Param {
  kind : Kind
  value : Bytes
}

///|
/// A parameter whose value is one varint (RFC 9000 §18.2).
pub fn Param::int(kind : Kind, value : UInt64) -> Param {
  { kind, value: @quic.encode(value), }
}

///|
/// A parameter with no value, which is how the flag parameters are carried.
pub fn Param::flag(kind : Kind) -> Param {
  { kind, value: b"", }
}

///|
/// The integer a varint-valued parameter carries, or `None` when its value is not
/// exactly one well-formed varint.
pub fn Param::as_int(self : Param) -> UInt64? {
  guard @quic.decode(self.value[:]) is Some((v, n)) else { return None }
  if n == self.value.length() {
    Some(v)
  } else {
    None
  }
}

///|
/// Encode a block: each parameter as its identifier varint, a length varint, then its
/// value (RFC 9000 §18).
pub fn encode(params : ArrayView[Param]) -> Bytes {
  let buf = Buffer()
  for p in params {
    buf.write_bytes(@quic.encode(p.kind.code())[:])
    buf.write_bytes(@quic.encode(p.value.length().to_uint64())[:])
    buf.write_bytes(p.value[:])
  }
  buf.to_bytes()
}

///|
/// A malformed transport-parameter block: a truncated parameter, or a length running past the
/// block. `decode` raises it rather than answering with an empty list, so a caller cannot
/// mistake a broken block for a peer that declared nothing.
#derive(Eq)
pub(all) suberror Refused {
  Malformed(String)
}

///|
/// A refused block prints as the fault it is.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Malformed(m) => logger.write_string("Malformed(" + m + ")")
  }
}

///|
pub extend Refused with Show::{to_string, output}

///|
pub extend Refused with Eq::{not_equal, equal}

///|
/// Decode a block, keeping the order and any duplicates so the caller can apply
/// RFC 9000 §7.4's rules itself. `None` on a truncated parameter; `decode` is the strict face.
fn decode_opt(b : BytesView) -> Array[Param]? {
  let out : Array[Param] = []
  let mut at = 0
  while at < b.length() {
    guard @quic.decode(b[at:]) is Some((code, used)) else { return None }
    at = at + used
    guard @quic.decode(b[at:]) is Some((length, used)) else { return None }
    at = at + used
    let n = length.to_int()
    if n < 0 || b.length() < at + n {
      return None
    }
    out.push({ kind: Kind::of(code), value: b[at:at + n].to_owned(), })
    at = at + n
  }
  Some(out)
}

///|
/// Decode a block, or raise `Refused` when a parameter is truncated. The strict face of
/// `decode_opt`, and what the connection reads a peer's block through.
pub fn decode(b : BytesView) -> Array[Param] raise Refused {
  match decode_opt(b) {
    Some(params) => params
    None => raise Malformed("truncated transport parameter")
  }
}

///|
/// The parameter in a block, or `None`. A repeated parameter is a connection error, so
/// the first one is what counts.
pub fn find(params : ArrayView[Param], kind : Kind) -> Param? {
  for p in params {
    if p.kind == kind {
      return Some(p)
    }
  }
  None
}

///|
/// What a block says, with RFC 9000 §18.2's default for everything it leaves out.
///
/// The integer parameters only; the connection IDs, the preferred address and the
/// stateless reset token stay in the block, because they are identifiers and addresses
/// rather than limits and the connection reads them where it needs them.
#derive(Eq, Debug)
pub(all) struct Limits {
  idle_timeout : UInt64
  udp_payload : UInt64
  data : UInt64
  stream_data_bidi_local : UInt64
  stream_data_bidi_remote : UInt64
  stream_data_uni : UInt64
  streams_bidi : UInt64
  streams_uni : UInt64
  ack_delay_exponent : UInt64
  max_ack_delay : UInt64
  active_connection_ids : UInt64
  migration : Bool
  datagram_frame : UInt64
}

///|
/// RFC 9000 §18.2's defaults: no idle timeout, the largest UDP payload the protocol
/// permits, no flow-control credit and no streams until the peer says otherwise, an
/// acknowledgement delay exponent of three, twenty-five milliseconds of acknowledgement
/// delay, two connection IDs, migration allowed, and no datagram frames.
pub let limits : Limits = {
  idle_timeout: 0,
  udp_payload: 65527,
  data: 0,
  stream_data_bidi_local: 0,
  stream_data_bidi_remote: 0,
  stream_data_uni: 0,
  streams_bidi: 0,
  streams_uni: 0,
  ack_delay_exponent: 3,
  max_ack_delay: 25,
  active_connection_ids: 2,
  migration: true,
  datagram_frame: 0,
}

///|
/// Limits by name, each defaulting to RFC 9000 §18.2's.
pub fn Limits::new(
  idle_timeout~ : UInt64 = 0,
  udp_payload~ : UInt64 = 65527,
  data~ : UInt64 = 0,
  stream_data_bidi_local~ : UInt64 = 0,
  stream_data_bidi_remote~ : UInt64 = 0,
  stream_data_uni~ : UInt64 = 0,
  streams_bidi~ : UInt64 = 0,
  streams_uni~ : UInt64 = 0,
  ack_delay_exponent~ : UInt64 = 3,
  max_ack_delay~ : UInt64 = 25,
  active_connection_ids~ : UInt64 = 2,
  migration~ : Bool = true,
  datagram_frame~ : UInt64 = 0,
) -> Limits {
  {
    idle_timeout,
    udp_payload,
    data,
    stream_data_bidi_local,
    stream_data_bidi_remote,
    stream_data_uni,
    streams_bidi,
    streams_uni,
    ack_delay_exponent,
    max_ack_delay,
    active_connection_ids,
    migration,
    datagram_frame,
  }
}

///|
/// The limits a block conveys, starting from `base` and applying what the block sets.
///
/// A parameter whose value is not a well-formed varint is left at its default rather
/// than refused: §18.1 makes that a connection error, and deciding to close is the
/// connection's call, not this reader's.
pub fn Limits::read(
  params : ArrayView[Param],
  base~ : Limits = limits,
) -> Limits {
  let mut out = base
  for p in params {
    let n = p.as_int()
    match (p.kind, n) {
      (MaxIdleTimeout, Some(v)) => out = { ..out, idle_timeout: v, }
      (MaxUdpPayload, Some(v)) => out = { ..out, udp_payload: v, }
      (MaxData, Some(v)) => out = { ..out, data: v, }
      (MaxStreamDataBidiLocal, Some(v)) =>
        out = { ..out, stream_data_bidi_local: v, }
      (MaxStreamDataBidiRemote, Some(v)) =>
        out = { ..out, stream_data_bidi_remote: v, }
      (MaxStreamDataUni, Some(v)) => out = { ..out, stream_data_uni: v, }
      (MaxStreamsBidi, Some(v)) => out = { ..out, streams_bidi: v, }
      (MaxStreamsUni, Some(v)) => out = { ..out, streams_uni: v, }
      (AckDelayExponent, Some(v)) => out = { ..out, ack_delay_exponent: v, }
      (MaxAckDelay, Some(v)) => out = { ..out, max_ack_delay: v, }
      (ActiveConnectionIdLimit, Some(v)) =>
        out = { ..out, active_connection_ids: v, }
      (MaxDatagramFrameSize, Some(v)) => out = { ..out, datagram_frame: v, }
      (DisableActiveMigration, _) => out = { ..out, migration: false, }
      _ => ()
    }
  }
  out
}

///|
/// The block these limits amount to, leaving out everything still at its default so a
/// handshake carries only what it changes.
pub fn Limits::params(self : Limits) -> Array[Param] {
  let out : Array[Param] = []
  let put = (kind : Kind, v : UInt64, base : UInt64) => {
    if v != base {
      out.push(Param::int(kind, v))
    }
  }
  put(MaxIdleTimeout, self.idle_timeout, limits.idle_timeout)
  put(MaxUdpPayload, self.udp_payload, limits.udp_payload)
  put(MaxData, self.data, limits.data)
  put(
    MaxStreamDataBidiLocal,
    self.stream_data_bidi_local,
    limits.stream_data_bidi_local,
  )
  put(
    MaxStreamDataBidiRemote,
    self.stream_data_bidi_remote,
    limits.stream_data_bidi_remote,
  )
  put(MaxStreamDataUni, self.stream_data_uni, limits.stream_data_uni)
  put(MaxStreamsBidi, self.streams_bidi, limits.streams_bidi)
  put(MaxStreamsUni, self.streams_uni, limits.streams_uni)
  put(AckDelayExponent, self.ack_delay_exponent, limits.ack_delay_exponent)
  put(MaxAckDelay, self.max_ack_delay, limits.max_ack_delay)
  put(
    ActiveConnectionIdLimit,
    self.active_connection_ids,
    limits.active_connection_ids,
  )
  put(MaxDatagramFrameSize, self.datagram_frame, limits.datagram_frame)
  if !self.migration {
    out.push(Param::flag(DisableActiveMigration))
  }
  out
}

///|
pub extend Kind with Debug::{to_repr}

///|
pub extend Kind with Eq::{not_equal, equal}

///|
pub extend Param with Debug::{to_repr}

///|
pub extend Param with Eq::{not_equal, equal}

///|
pub extend Limits with Debug::{to_repr}

///|
pub extend Limits with Eq::{not_equal, equal}

///|
/// The block a TLS extension list carries (RFC 9001 §8.2), empty when the extension is
/// absent or its block is truncated: an endpoint with no block falls back to RFC 9000
/// §18.2's defaults, which is what an empty list reads as.
pub fn of_extensions(extensions : ArrayView[@ext.Ext]) -> Array[Param] {
  match @ext.find(extensions, QuicTransportParameters) {
    Some(e) =>
      match decode_opt(e.data[:]) {
        Some(params) => params
        None => []
      }
    None => []
  }
}

///|
/// The extension a block rides in. RFC 9001 §8.2 makes it mandatory for both endpoints,
/// and `moontls` carries it without reading it, because the contents are QUIC's.
pub fn extension(params : ArrayView[Param]) -> @ext.Ext {
  { kind: QuicTransportParameters, data: encode(params), }
}
