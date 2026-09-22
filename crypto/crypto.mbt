// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The cipher a packet is protected with (RFC 9001 §5.1, §5.3, §5.4.3): how many bytes
/// of key, IV, header-protection key and authentication tag a traffic secret expands
/// to, which hash the expansion runs under, the AEAD that seals a payload, and the
/// cipher that turns a ciphertext sample into a header-protection mask.
///
/// The preset is AEAD_AES_128_GCM with SHA-256, which §5.2 fixes for Initial packets
/// and every space uses until TLS negotiates otherwise. AES-256-GCM is `{ ..suite,
/// key: 32 }`; a suite this library has no cipher for — ChaCha20-Poly1305, say — is a
/// `@spec.Aead` implementation away and needs no change here.
pub(all) struct Suite {
  digest : @keys.Digest
  key : Int
  iv : Int
  hp : Int
  tag : Int
  aead : (Bytes) -> &@spec.Aead
  mask : (Bytes, BytesView) -> Bytes
}

///|
/// AEAD_AES_128_GCM with SHA-256 (RFC 9001 §5.2).
pub let suite : Suite = {
  digest: Sha256,
  key: 16,
  iv: 12,
  hp: 16,
  tag: 16,
  aead: aes_gcm,
  mask: aes_mask,
}

///|
/// A suite by name, each part defaulting to the AES-128-GCM preset.
pub fn Suite::new(
  digest? : @keys.Digest = Sha256,
  key? : Int = 16,
  iv? : Int = 12,
  hp? : Int = 16,
  tag? : Int = 16,
  aead? : (Bytes) -> &@spec.Aead = aes_gcm,
  mask? : (Bytes, BytesView) -> Bytes = aes_mask,
) -> Suite {
  { digest, key, iv, hp, tag, aead, mask, }
}

///|
/// How many bytes of ciphertext a header-protection mask is sampled from (RFC 9001
/// §5.4.2). Every AEAD QUIC defines samples sixteen, so this is the protocol's number
/// rather than a suite's.
pub let sample : Int = 16

///|
/// AES-GCM over a key of the length the caller passes: AES-128 for sixteen bytes,
/// AES-256 for thirty-two.
///
/// A key of another length aborts rather than raising. Key lengths come from a suite,
/// which is a constant of the program, so a wrong one is a mistake in the code and not
/// something a peer can provoke.
pub fn aes_gcm(key : Bytes) -> &@spec.Aead {
  let cipher = @aes.Cipher::new(key[:]) catch {
    _ => abort("moonquic: \{key.length()} bytes is not an AES key")
  }
  @gcm.Gcm::new(cipher) catch {
    _ => abort("moonquic: GCM refused the AES cipher")
  }
}

///|
/// The AES header-protection mask: the first five bytes of one ECB block over the
/// sample (RFC 9001 §5.4.3).
pub fn aes_mask(hp : Bytes, sample : BytesView) -> Bytes {
  let cipher = @aes.Cipher::new(hp[:]) catch {
    _ => abort("moonquic: \{hp.length()} bytes is not an AES key")
  }
  cipher.encrypt(sample)[0:5].to_owned()
}

///|
/// The constants a QUIC version fixes (RFC 9001 §5.2, §5.8): the Initial salt, the four
/// HKDF labels, and the key and nonce a Retry's integrity tag is computed under.
///
/// The preset is version 1. RFC 9369 changes every one of them for version 2, which is
/// a record away; this library ships no version-2 constants because it has not checked
/// them against that RFC.
pub(all) struct Version {
  salt : Bytes
  key : Bytes
  iv : Bytes
  hp : Bytes
  ku : Bytes
  retry : Bytes
  nonce : Bytes
} derive(Eq, Debug)

///|
/// QUIC version 1 (RFC 9001 §5.2 and §5.8).
pub let version : Version = {
  salt: b"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a",
  key: b"quic key",
  iv: b"quic iv",
  hp: b"quic hp",
  ku: b"quic ku",
  retry: b"\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e",
  nonce: b"\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb",
}

///|
/// A version's constants by name, each defaulting to version 1's.
pub fn Version::new(
  salt? : Bytes = version.salt,
  key? : Bytes = version.key,
  iv? : Bytes = version.iv,
  hp? : Bytes = version.hp,
  ku? : Bytes = version.ku,
  retry? : Bytes = version.retry,
  nonce? : Bytes = version.nonce,
) -> Version {
  { salt, key, iv, hp, ku, retry, nonce, }
}

///|
/// One direction's packet-protection keys (RFC 9001 §5.1): the AEAD key, the IV each
/// packet's nonce is built from, and the header-protection key.
pub(all) struct Keys {
  key : Bytes
  iv : Bytes
  hp : Bytes
} derive(Eq, Debug)

///|
/// The keys a traffic secret expands to (RFC 9001 §5.1), under the three labels the
/// version fixes and at the lengths the suite fixes.
pub fn Keys::of(
  secret : BytesView,
  suite? : Suite = suite,
  version? : Version = version,
) -> Keys {
  let expand = (label : Bytes, len : Int) => {
    @keys.expand_label(secret, label[:], b""[:], len~, digest=suite.digest)
  }
  {
    key: expand(version.key, suite.key),
    iv: expand(version.iv, suite.iv),
    hp: expand(version.hp, suite.hp),
  }
}

///|
/// The Initial secret both endpoints share: `HKDF-Extract(salt, dcid)` over the
/// Destination Connection ID from the client's first packet (RFC 9001 §5.2).
pub fn secret(
  dcid : BytesView,
  suite? : Suite = suite,
  version? : Version = version,
) -> Bytes {
  @keys.extract(version.salt[:], dcid, digest=suite.digest)
}

///|
/// The client's and server's Initial keys, in that order (RFC 9001 §5.2).
///
/// These are the one part of the handshake that needs no TLS exchange: both sides can
/// compute them from the connection ID alone, which is also why Initial packets are
/// protected against off-path observers rather than against anybody at all.
pub fn initial(
  dcid : BytesView,
  suite? : Suite = suite,
  version? : Version = version,
) -> (Keys, Keys) {
  let shared = secret(dcid, suite~, version~)
  let side = (label : Bytes) => {
    @keys.expand_label(
      shared[:],
      label[:],
      b""[:],
      len=suite.digest.size(),
      digest=suite.digest,
    )
  }
  (
    Keys::of(side(b"client in")[:], suite~, version~),
    Keys::of(side(b"server in")[:], suite~, version~),
  )
}

///|
/// This endpoint's Handshake-space keys, from the handshake traffic secret over the
/// ClientHello..ServerHello transcript (RFC 9001 §5.2).
pub fn handshake(
  handshake_secret : BytesView,
  transcript : BytesView,
  client~ : Bool,
  suite? : Suite = suite,
  version? : Version = version,
) -> Keys {
  let secret = if client {
    @keys.client_handshake(handshake_secret, transcript, digest=suite.digest)
  } else {
    @keys.server_handshake(handshake_secret, transcript, digest=suite.digest)
  }
  Keys::of(secret[:], suite~, version~)
}

///|
/// This endpoint's Application (1-RTT) keys, from the master secret over the
/// ClientHello..server Finished transcript (RFC 9001 §5.2).
pub fn application(
  master : BytesView,
  transcript : BytesView,
  client~ : Bool,
  suite? : Suite = suite,
  version? : Version = version,
) -> Keys {
  let secret = if client {
    @keys.client_application(master, transcript, digest=suite.digest)
  } else {
    @keys.server_application(master, transcript, digest=suite.digest)
  }
  Keys::of(secret[:], suite~, version~)
}

///|
/// The next generation's 1-RTT traffic secret (RFC 9001 §6.1). Applying it again
/// advances another generation; the Key Phase bit in the short header says which
/// generation protects a packet.
pub fn update(
  secret : BytesView,
  suite? : Suite = suite,
  version? : Version = version,
) -> Bytes {
  @keys.expand_label(
    secret,
    version.ku[:],
    b""[:],
    len=suite.digest.size(),
    digest=suite.digest,
  )
}

///|
/// Roll to the next key generation: the updated traffic secret and the keys it expands
/// to, which is what an endpoint installs when it flips the Key Phase bit.
pub fn next(
  secret : BytesView,
  suite? : Suite = suite,
  version? : Version = version,
) -> (Bytes, Keys) {
  let rolled = update(secret, suite~, version~)
  (rolled, Keys::of(rolled[:], suite~, version~))
}

///|
/// The AEAD nonce for a packet number: the number, left-padded to the IV's length,
/// XORed with the IV (RFC 9001 §5.3). The number occupies the low eight bytes and any
/// higher IV bytes pass through.
pub fn Keys::nonce(self : Keys, number : Int64) -> Bytes {
  let buf = Buffer()
  let n = self.iv.length()
  for i = 0; i < n; i = i + 1 {
    let at = n - 1 - i
    let byte = if at >= 8 { 0 } else { ((number >> (at * 8)) & 0xffL).to_int() }
    buf.write_byte((self.iv[i].to_int() ^ byte).to_byte())
  }
  buf.to_bytes()
}

///|
/// The header-protection mask for a ciphertext sample (RFC 9001 §5.4.2).
pub fn Keys::mask(
  self : Keys,
  sample : BytesView,
  suite? : Suite = suite,
) -> Bytes {
  (suite.mask)(self.hp, sample)
}

///|
/// Which of the first byte's bits are protected: the low four of a long header, the low
/// five of a short one (RFC 9001 §5.4.1). The header form is bit 0x80 and is never
/// itself protected, which is what lets a receiver tell the two apart before it has any
/// keys at all.
fn masked(first : Int) -> Int {
  if (first & 0x80) != 0 {
    0x0f
  } else {
    0x1f
  }
}

///|
/// Apply header protection: XOR the first byte's protected bits and the `size`
/// packet-number bytes at `at` with the mask (RFC 9001 §5.4.1).
///
/// The sample starts at `at + 4`, the fixed position that assumes the longest
/// packet-number field whatever this packet's is, so a receiver can take the sample
/// before it knows how long the field is.
pub fn Keys::protect(
  self : Keys,
  packet : BytesView,
  at~ : Int,
  size~ : Int,
  suite? : Suite = suite,
) -> Bytes {
  let mask = self.mask(packet[at + 4:at + 4 + sample], suite~)
  let out = bytes(packet)
  out[0] = out[0] ^ (mask[0].to_int() & masked(out[0]))
  for i = 0; i < size; i = i + 1 {
    out[at + i] = out[at + i] ^ mask[1 + i].to_int()
  }
  pack(out)
}

///|
/// Remove header protection: recover the first byte, read the packet-number length from
/// its low two bits, and unmask that many bytes. Returns the unprotected packet and the
/// recovered length (RFC 9001 §5.4.1).
pub fn Keys::unprotect(
  self : Keys,
  packet : BytesView,
  at~ : Int,
  suite? : Suite = suite,
) -> (Bytes, Int) {
  let mask = self.mask(packet[at + 4:at + 4 + sample], suite~)
  let first = packet[0].to_int() ^
    (mask[0].to_int() & masked(packet[0].to_int()))
  let size = (first & 0x03) + 1
  let out = bytes(packet)
  out[0] = first
  for i = 0; i < size; i = i + 1 {
    out[at + i] = out[at + i] ^ mask[1 + i].to_int()
  }
  (pack(out), size)
}

///|
/// A protected packet: seal `payload` with `header` as associated data, then protect
/// the header (RFC 9001 §5.3–§5.4).
///
/// `header` ends in the packet number, and its first byte's low two bits say how many
/// bytes that is, so both header forms are handled without being told which is which —
/// build it with `@packet.Long::header` or `@packet.Short::header`.
pub fn Keys::seal(
  self : Keys,
  header : BytesView,
  payload : BytesView,
  number~ : Int64,
  suite? : Suite = suite,
) -> Bytes {
  let size = (header[0].to_int() & 0x03) + 1
  let body = (suite.aead)(self.key).seal(
    nonce=self.nonce(number)[:],
    plain=payload,
    aad=header,
  )
  let buf = Buffer()
  buf.write_bytes(header)
  buf.write_bytes(body)
  self.protect(buf.to_bytes()[:], at=header.length() - size, size~, suite~)
}

///|
/// A received packet opened: header protection removed, the packet number recovered
/// against `largest`, and the payload AEAD-opened with the recovered header as
/// associated data (RFC 9001 §5.3–§5.4).
///
/// `largest` is the largest packet number already received in this space, or `-1` when
/// none has been: the number on the wire is truncated, and RFC 9000 §A.3 recovers the
/// full one from what the receiver has seen.
///
/// `at` is where the packet number starts. Leave it out for a long header, whose own
/// Length field says where; a short header needs it, because how long the connection ID
/// is is something only the receiver knows.
///
/// `None` when the packet is too short to sample, when a long header does not parse, or
/// when the tag does not match — one answer for every way of being unreadable, because
/// a receiver's response to all of them is to drop the packet.
pub fn Keys::open(
  self : Keys,
  packet : BytesView,
  largest~ : Int64,
  at? : Int,
  suite? : Suite = suite,
) -> (Bytes, Int64)? {
  let long = packet.length() > 0 && (packet[0].to_int() & 0x80) != 0
  let tail = if long { @packet.read_header(packet) } else { None }
  let at = match at {
    Some(at) => at
    None =>
      match tail {
        Some((_, t)) => t.at
        None => return None
      }
  }
  if at < 0 || packet.length() < at + 4 + sample {
    return None
  }
  let (recovered, size) = self.unprotect(packet, at~, suite~)
  // `unprotect` has just read these bytes, so the read cannot come up short.
  let truncated = @fixed.read_uint(recovered[:], at~, size~)
    .unwrap()
    .reinterpret_as_int64()
  let number = @packet.read_number(largest, truncated, size * 8)
  let from = at + size
  // A long header's Length bounds the packet, so a datagram carrying more than one is
  // read correctly; a short header's payload runs to the end of the datagram.
  let stop = match tail {
    Some((_, t)) => t.at + t.length.to_int()
    None => recovered.length()
  }
  if from > stop || stop > recovered.length() {
    return None
  }
  let plain = (suite.aead)(self.key).open(
    nonce=self.nonce(number)[:],
    cipher=recovered[from:stop],
    aad=recovered[0:from],
  ) catch {
    _ => return None
  }
  Some((plain, number))
}

///|
/// A Retry packet's integrity tag (RFC 9001 §5.8), over everything up to but not
/// including the tag, bound to the original Destination Connection ID.
///
/// The associated data is the Retry Pseudo-Packet: the ODCID's length byte, the ODCID,
/// then the Retry packet. The plaintext is empty, so the AEAD's output is the tag alone.
pub fn retry_tag(
  body : BytesView,
  odcid : BytesView,
  suite? : Suite = suite,
  version? : Version = version,
) -> Bytes {
  let pseudo = Buffer()
  pseudo.write_byte(odcid.length().to_byte())
  pseudo.write_bytes(odcid)
  pseudo.write_bytes(body)
  (suite.aead)(version.retry).seal(
    nonce=version.nonce[:],
    plain=b""[:],
    aad=pseudo.to_bytes()[:],
  )
}

///|
/// Whether a Retry packet's trailing integrity tag is the right one for `odcid`.
///
/// The comparison accumulates the difference rather than stopping at the first byte
/// that differs, so how long it takes says nothing about how much of the tag was right.
pub fn retry_ok(
  packet : BytesView,
  odcid : BytesView,
  suite? : Suite = suite,
  version? : Version = version,
) -> Bool {
  if packet.length() < suite.tag {
    return false
  }
  let cut = packet.length() - suite.tag
  let want = retry_tag(packet[0:cut], odcid, suite~, version~)
  if want.length() != suite.tag {
    return false
  }
  let mut diff = 0
  for i = 0; i < suite.tag; i = i + 1 {
    diff = diff | (want[i].to_int() ^ packet[cut + i].to_int())
  }
  diff == 0
}

///|
/// A view as mutable bytes, since protection XORs a few of them in place.
fn bytes(b : BytesView) -> Array[Int] {
  let out = Array::make(b.length(), 0)
  for i = 0; i < b.length(); i = i + 1 {
    out[i] = b[i].to_int()
  }
  out
}

///|
fn pack(out : Array[Int]) -> Bytes {
  let buf = Buffer()
  for v in out {
    buf.write_byte(v.to_byte())
  }
  buf.to_bytes()
}

///|
pub extend Keys with Debug::{to_repr}

///|
pub extend Keys with Eq::{not_equal, equal}

///|
pub extend Version with Debug::{to_repr}

///|
pub extend Version with Eq::{not_equal, equal}
