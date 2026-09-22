// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Every vector below is RFC 9001 Appendix A, lifted from the RFC's own text rather than
// typed out: what this package computes is checked against what the working group
// published, not against itself.
// https://www.rfc-editor.org/rfc/rfc9001#appendix-A

///|
/// A hex string as bytes, and back — the shape RFC 9001's appendix prints its
/// vectors in. Eight lines beat a dependency the package does not have.
fn qc_hexb(h : String) -> Bytes {
  let buf = Buffer()
  for i = 0; i < h.length(); i = i + 2 {
    buf.write_byte(
      ((qc_nibble(h[i].to_int()) << 4) | qc_nibble(h[i + 1].to_int())).to_byte(),
    )
  }
  buf.to_bytes()
}

///|
fn qc_nibble(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    0
  }
}

///|
fn qc_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    sb.write_char(digits[x >> 4].unsafe_to_char())
    sb.write_char(digits[x & 0xf].unsafe_to_char())
  }
  sb.to_string()
}

///|
/// The client's Destination Connection ID that A.1 derives everything from.
let odcid : String = "8394c8f03e515708"

///|
test "the Initial secrets are RFC 9001 A.1's" {
  let dcid = qc_hexb(odcid)
  assert_eq(
    qc_hex(secret(dcid[:])),
    "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
  )
  let (client, server) = initial(dcid[:])
  assert_eq(qc_hex(client.key), "1f369613dd76d5467730efcbe3b1a22d")
  assert_eq(qc_hex(client.iv), "fa044b2f42a3fd3b46fb255c")
  assert_eq(qc_hex(client.hp), "9f50449e04a0e810283a1e9933adedd2")
  assert_eq(qc_hex(server.key), "cf3a5331653c364c88f0f379b6067e37")
  assert_eq(qc_hex(server.iv), "0ac1493ca1905853b0bba03e")
  assert_eq(qc_hex(server.hp), "c206b8d9b9f0f37644430b490eeaa314")
}

///|
test "the per-direction secrets themselves are A.1's" {
  // The keys above are expanded from these, so checking them separately says which of
  // the two steps is wrong when one day something is.
  let shared = secret(qc_hexb(odcid)[:])
  let side = (label : Bytes) => {
    @keys.expand_label(shared[:], label[:], b""[:], len=32)
  }
  assert_eq(
    qc_hex(side(b"client in")),
    "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
  )
  assert_eq(
    qc_hex(side(b"server in")),
    "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
  )
}

///|
test "the header-protection mask and protected header are A.2's" {
  let (client, _) = initial(qc_hexb(odcid)[:])
  assert_eq(
    qc_hex(client.mask(qc_hexb("d1b1c98dd7689fb8ec11d242b123dc9b")[:])),
    "437b9aec36",
  )

  // The unprotected header, then the sixteen ciphertext bytes the sample is taken from.
  let packet = qc_hexb(
    "c300000001088394c8f03e5157080000449e00000002" +
    "d1b1c98dd7689fb8ec11d242b123dc9b",
  )
  let masked = client.protect(packet[:], at=18, size=4)
  assert_eq(
    qc_hex(masked[0:22].to_owned()),
    "c000000001088394c8f03e5157080000449e7b9aec34",
  )

  // And back: the recovered header is the one we started from, four bytes of number.
  let (plain, size) = client.unprotect(masked[:], at=18)
  assert_eq(qc_hex(plain), qc_hex(packet))
  assert_eq(size, 4)
}

///|
test "the A.3 server Initial seals to the published packet, byte for byte" {
  let (_, server) = initial(qc_hexb(odcid)[:])
  let payload = qc_hexb(
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304",
  )
  let h : @packet.Long = {
    packet_type: Initial,
    type_specific: 0,
    version: 1,
    dcid: b"",
    scid: qc_hexb("f067a5502a4262b5"),
  }
  // Two bytes of packet number, then the payload and the sixteen-byte tag.
  let header = h.header(qc_hexb("0001")[:], payload=payload.length() + 16)
  assert_eq(qc_hex(header), "c1000000010008f067a5502a4262b50040750001")
  let packet = server.seal(header[:], payload[:], number=1)
  assert_eq(
    qc_hex(packet),
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee",
  )
  assert_eq(
    qc_hex(packet[0:20].to_owned()),
    "cf000000010008f067a5502a4262b5004075c0d9",
  )
}

///|
test "the A.3 packet opens back to its payload and packet number" {
  let (_, server) = initial(qc_hexb(odcid)[:])
  let packet = qc_hexb(
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee",
  )
  guard server.open(packet[:], largest=-1L) is Some((plain, number)) else {
    fail("the published packet should open")
  }
  assert_eq(
    qc_hex(plain),
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304",
  )
  assert_eq(number, 1L)
}

///|
test "a tampered packet does not open, however it was tampered with" {
  let (_, server) = initial(qc_hexb(odcid)[:])
  let good = qc_hexb(
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee",
  )
  // One bit anywhere — in the header, the ciphertext or the tag — and the tag fails.
  for at in [0, 3, 19, 40, good.length() - 1] {
    let bad = Bytes::from_array(good.to_array())
    let flipped = Array::make(good.length(), b'\x00')
    for i = 0; i < good.length(); i = i + 1 {
      flipped[i] = bad[i]
    }
    flipped[at] = (flipped[at].to_int() ^ 0x01).to_byte()
    let buf = Buffer()
    for b in flipped {
      buf.write_byte(b)
    }
    assert_eq(server.open(buf.to_bytes()[:], largest=-1L) is None, true)
  }
  // And the untampered one still opens, so the loop above proves something.
  assert_eq(server.open(good[:], largest=-1L) is None, false)
}

///|
test "a packet too short to sample does not open" {
  let (_, server) = initial(qc_hexb(odcid)[:])
  let packet = qc_hexb(
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee",
  )
  // The sample runs from the packet number's offset plus four for twenty bytes.
  assert_eq(server.open(packet[0:30], largest=-1L) is None, true)
  assert_eq(server.open(b""[:], largest=-1L) is None, true)
}

///|
test "the Retry integrity tag is RFC 9001 A.4's" {
  let packet = qc_hexb(
    "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
  )
  let dcid = qc_hexb(odcid)
  let cut = packet.length() - 16
  assert_eq(
    qc_hex(retry_tag(packet[0:cut], dcid[:])),
    qc_hex(packet[cut:].to_owned()),
  )
  assert_eq(retry_ok(packet[:], dcid[:]), true)

  // The tag binds the packet to that connection ID and to nothing else.
  assert_eq(retry_ok(packet[:], qc_hexb("8394c8f03e515709")[:]), false)
  assert_eq(retry_ok(packet[0:cut], dcid[:]), false)
}

///|
test "a packet number of zero leaves the IV alone, and others XOR into its tail" {
  let keys : Keys = {
    key: b"",
    iv: qc_hexb("000102030405060708090a0b"),
    hp: b"",
  }
  assert_eq(qc_hex(keys.nonce(0L)), "000102030405060708090a0b")
  // The number occupies the low eight bytes, so the first four pass through.
  assert_eq(qc_hex(keys.nonce(1L)), "000102030405060708090a0a")
  assert_eq(qc_hex(keys.nonce(0xffL)), "000102030405060708090af4")
}

///|
test "a key update changes the secret and the keys, and keeps changing them" {
  let secret = qc_hexb(
    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
  )
  let (first, keys) = next(secret[:])
  assert_eq(first == secret, false)
  assert_eq(keys, Keys::of(first[:]))
  let (second, _) = next(first[:])
  assert_eq(second == first, false)
  assert_eq(second == secret, false)
  // Deriving it twice gives the same answer: it is a function, not a counter.
  assert_eq(update(secret[:]), first)
}

///|
test "the handshake and application keys are the traffic secrets' own keys" {
  // Which secret keys which space is the whole of what RFC 9001 §5.2 adds on top of
  // TLS's schedule, so the composition is what there is to check: `handshake` must be
  // `Keys::of` over the handshake traffic secret, and nothing else.
  let handshake_secret = qc_hexb(
    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
  )
  let transcript = qc_hexb(
    "0101010101010101010101010101010101010101010101010101010101010101",
  )
  assert_eq(
    handshake(handshake_secret[:], transcript[:], client=true),
    Keys::of(@keys.client_handshake(handshake_secret[:], transcript[:])[:]),
  )
  assert_eq(
    handshake(handshake_secret[:], transcript[:], client=false),
    Keys::of(@keys.server_handshake(handshake_secret[:], transcript[:])[:]),
  )
  assert_eq(
    application(handshake_secret[:], transcript[:], client=true),
    Keys::of(@keys.client_application(handshake_secret[:], transcript[:])[:]),
  )
  assert_eq(
    application(handshake_secret[:], transcript[:], client=false),
    Keys::of(@keys.server_application(handshake_secret[:], transcript[:])[:]),
  )
}

///|
test "the two directions get different keys from the same secrets" {
  let handshake_secret = qc_hexb(
    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
  )
  let transcript = qc_hexb(
    "0101010101010101010101010101010101010101010101010101010101010101",
  )
  let c = handshake(handshake_secret[:], transcript[:], client=true)
  let s = handshake(handshake_secret[:], transcript[:], client=false)
  assert_eq(c == s, false)
  let ca = application(handshake_secret[:], transcript[:], client=true)
  let sa = application(handshake_secret[:], transcript[:], client=false)
  assert_eq(ca == sa, false)
  // Handshake and application keys differ too, which is what keeps a retired key from
  // opening a packet from the next space.
  assert_eq(c == ca, false)
}

///|
test "the suite is a knob on both sides: AES-256 seals and opens" {
  let big : Suite = { ..suite, key: 32, }
  let keys = Keys::of(
    qc_hexb("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")[:],
    suite=big,
  )
  assert_eq(keys.key.length(), 32)
  let h : @packet.Short = {
    spin: false,
    key_phase: false,
    pn_length: 2,
    dcid: qc_hexb("c0ffee"),
  }
  let payload = qc_hexb("0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e")
  let header = h.header(qc_hexb("0007")[:])
  let packet = keys.seal(header[:], payload[:], number=7L, suite=big)
  // A short header's connection-id length is the receiver's to know.
  guard keys.open(packet[:], largest=6L, at=4, suite=big)
    is Some((plain, number)) else {
    fail("an AES-256 packet should open")
  }
  assert_eq(qc_hex(plain), qc_hex(payload))
  assert_eq(number, 7L)
}

///|
test "the named constructor and the record update agree" {
  assert_eq(Suite::new().key, suite.key)
  assert_eq(Suite::new(key=32).key, { ..suite, key: 32, }.key)
  assert_eq(Version::new(), version)
  assert_eq(Version::new(ku=b"quic ku"), version)
  assert_eq(Version::new(salt=b"\x00").salt, b"\x00")
}

///|
test "the version's salt and labels are knobs, and changing one changes the keys" {
  let dcid = qc_hexb(odcid)
  let v2 : Version = { ..version, salt: b"\x00\x01\x02\x03", }
  assert_eq(secret(dcid[:]) == secret(dcid[:], version=v2), false)
  let relabelled : Version = { ..version, key: b"quicv2 key", }
  let (a, _) = initial(dcid[:])
  let (b, _) = initial(dcid[:], version=relabelled)
  assert_eq(a.key == b.key, false)
  // Only the key label moved, so the IV and header-protection key did not.
  assert_eq(a.iv, b.iv)
  assert_eq(a.hp, b.hp)
}

///|
test "a short-header packet round-trips under the preset suite" {
  let keys = Keys::of(
    qc_hexb("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")[:],
  )
  let h : @packet.Short = {
    spin: true,
    key_phase: true,
    pn_length: 1,
    dcid: qc_hexb("0102030405060708"),
  }
  let payload = qc_hexb("48656c6c6f2c20515549432e")
  for number in [0L, 1L, 255L, 65535L, 16777216L] {
    let pn = @packet.number(number, None)
    let packet = keys.seal(h.header(pn[:])[:], payload[:], number~)
    guard keys.open(packet[:], largest=number - 1L, at=9) is Some((plain, got)) else {
      fail("a short-header packet should open")
    }
    assert_eq(qc_hex(plain), qc_hex(payload))
    assert_eq(got, number)
  }
}
