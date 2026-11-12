// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9368's compatible version negotiation on a server. The client's first flight names the
// version it was sent in and the versions that flight can be converted into; a server reads
// that from the ClientHello before it starts the handshake, picks the version it prefers, and
// answers in it. This is the part of §2.3 that cannot be done after the TLS connection exists:
// the server's own transport parameters are written into EncryptedExtensions by the handshake,
// so the choice has to be made first.

///|
/// What a first flight's contiguous CRYPTO bytes say about versions. `Incomplete` means the
/// ClientHello is still arriving; the other three are the outcomes RFC 9368 §4 names.
priv enum FirstFlight {
  Incomplete
  /// No `version_information` parameter: a server MAY complete the handshake anyway (§4).
  Absent
  /// A parameter that is not four-byte versions, or one that names version zero.
  Malformed
  Present(UInt32, Array[UInt32])
}

///|
/// Read the client's `version_information` out of the first flight without running a TLS
/// handshake. The bytes are the contiguous CRYPTO stream at the Initial level: a TLS handshake
/// message's type and 24-bit length first, then the ClientHello, then its extensions. The
/// parameters themselves are QUIC's own encoding, decoded by this package's `decode_opt`.
fn client_version_information(crypto : BytesView) -> FirstFlight {
  guard @msg.unframe(crypto) is Some((@msg.Kind::ClientHello, body)) else {
    return Incomplete
  }
  guard @msg.read_hello(body) is Some(hello) else { return Absent }
  guard @ext.find(hello.extensions[:], @ext.QuicTransportParameters) is Some(e) else {
    return Absent
  }
  guard decode_opt(e.data[:]) is Some(params) else { return Absent }
  match find(params[:], VersionInformation) {
    Some(p) =>
      match read_version_information(p.value[:]) {
        Some((chosen, available)) => Present(chosen, available)
        None => Malformed
      }
    None => Absent
  }
}

///|
/// Whether a first flight sent in `chosen` can be converted into one in `candidate`. RFC 9368
/// §2.2 leaves compatibility to the document that defines the two versions; this library
/// defines it for the two it speaks. Version 1 and version 2 long headers differ in the salt,
/// the four labels, the Retry key and the two-bit type codes, and in nothing else a first
/// flight carries — the frames, the TLS messages and the transport parameters are the same —
/// so re-deriving the Initial keys and re-reading the type bits is a lossless conversion.
/// No other pair is assumed compatible (§2.2).
fn compatible(chosen : UInt32, candidate : UInt32) -> Bool {
  let known = (v : UInt32) => v == @packet.version1 || v == @packet.version2
  known(chosen) && known(candidate)
}

///|
/// The Negotiated Version (RFC 9368 §2.3): the first of this server's own preferences that the
/// client says its first flight is compatible with and that this server knows how to convert.
/// The client's Chosen Version is always such a version — the identity transformation — so the
/// search always answers, and a client that offers only its Chosen Version disables the
/// mechanism (§2.3).
fn choose_version(
  cfg : Config,
  chosen : UInt32,
  available : Array[UInt32],
) -> UInt32 {
  for version in cfg.versions {
    if available.contains(version) && compatible(chosen, version) {
      return version
    }
  }
  chosen
}

///|
/// What a connection needs to open its handshake once the first flight has been read: the TLS
/// configuration, its randomness and clock, and the transport parameters other than
/// `version_information`, whose Chosen Version is the decision this file makes.
priv struct Pending {
  config : @tls.Server
  rand : (Int32) -> Bytes
  wall : Int64?
  base : Bytes
}

///|
/// Transport parameters whose `version_information` names `chosen`.
fn declared_for(
  base : Bytes,
  chosen : UInt32,
  versions : ArrayView[UInt32],
) -> Bytes {
  let buf = Buffer()
  buf.write_bytes(base)
  buf.write_bytes(encode([version_information(chosen, versions)]))
  buf.to_bytes()
}
