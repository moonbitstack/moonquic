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
fn qc_nibble(c : Int32) -> Int32 {
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
    suite,
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
  let packet = keys.seal(header[:], payload[:], number=7L)
  // A short header's connection-id length is the receiver's to know.
  guard keys.open(packet[:], largest=6L, at=4) is Some((plain, number)) else {
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

///|
test "ChaCha20-Poly1305 protects a short packet as RFC 9001 A.5 shows" {
  let secret = qc_hexb(
    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
  )
  let keys = Keys::of(secret[:], suite=chacha20)
  assert_eq(
    keys.key,
    qc_hexb("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
  )
  assert_eq(keys.iv, qc_hexb("e0459b3474bdd0e44a41c144"))
  assert_eq(
    keys.hp,
    qc_hexb("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
  )
  let packet = keys.seal(qc_hexb("4200bff4")[:], b"\x01"[:], number=654360564L)
  assert_eq(packet, qc_hexb("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"))
  let (plain, number) = keys.open(packet[:], largest=654360563L, at=1).unwrap()
  assert_eq(plain, b"\x01")
  assert_eq(number, 654360564L)
}

///|
test "AES-256-GCM expands to the sizes its cipher needs" {
  let keys = Keys::of(Bytes::make(48, b'\x11')[:], suite=aes256)
  assert_eq(keys.key.length(), 32)
  assert_eq(keys.hp.length(), 32)
  assert_eq(keys.iv.length(), 12)
  let packet = keys.seal(b"\x43\x00\x00\x00\x07"[:], b"payload"[:], number=7L)
  assert_eq(keys.open(packet[:], largest=6L, at=1).unwrap().0, b"payload")
}

// RFC 9369 Appendix A, lifted from the RFC's own text: the version-2 vectors that say whether
// the new salt, the four new labels, the Retry key and the type codes are the ones the working
// group published. https://www.rfc-editor.org/rfc/rfc9369#appendix-A

///|
/// A hex dump as bytes, with the spaces and line breaks the RFC prints it with left out.
fn qv_bytes(text : String) -> Bytes {
  let sb = StringBuilder()
  for c in text {
    let x = c.to_int()
    if x != 0x20 && x != 0x0a && x != 0x0d && x != 0x09 {
      sb.write_char(c)
    }
  }
  qc_hexb(sb.to_string())
}

///|
let a2_payload : String =
  #|060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c0000
  #|0413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017
  #|001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559f
  #|edba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408
  #|050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff080110
  #|0104800075300901100f088394c8f03e51570806048000ffff

///|
let a2_packet : String =
  #|d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485dd04de806071bf03dceebfa1
  #|62e75d6c96058bdbfb127cdfcbf903388e99ad049f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f1
  #|7ac2053d21f57c5d250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a12834e3f
  #|249a78d395e0d18f4d766004f1a2674802a747eaa901c3f10cda5500cb9122faa9f1df66c392079a1b40f0de
  #|1c6054196a11cbea40afb6ef5253cd6818f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da5
  #|8976ff3312ae50b187c1433c0f028edcc4c2838b6a9bfc226ca4b4530e7a4ccee1bfa2a3d396ae5a3fb51238
  #|4b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc3
  #|75eb198c63301c21801f6520bcfb7966fc49b393f0061d974a2706df8c4a9449f11d7f3d2dcbb90c6b877045
  #|636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1fac7cf4ed77f322e8fa894b6a
  #|83810a34b361901751a6f5eb65a0326e07de7c1216ccce2d0193f958bb3850a833f7ae432b65bc5a53975c15
  #|5aa4bcb4f7b2c4e54df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4fdf85290
  #|fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b8017c25ca9052ca1079d8b78aebd4787
  #|6d330a30f6a8c6d61dd1ab5589329de714d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2
  #|bb522ff99c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91abfe43960977c874
  #|71cf9ad4074d30e10d6a7f03c63bd5d4317f68ff325ba3bd80bf4dc8b52a0ba031758022eb025cdd770b44d6
  #|d6cf0670f4e990b22347a7db848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18
  #|d703dd84045a274ae8bfa73379661388d6991fe39b0d93debb41700b41f90a15c4d526250235ddcd6776fc77
  #|bc97e7a417ebcb31600d01e57f32162a8560cacc7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d77
  #|40f81193e8238e61f6b5b984d4d3dfa033c1bb7e4f0037febf406d91c0dccf32acf423cfa1e7071010d3f270
  #|121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b3d6758158197107c14ebb193230cd115
  #|7380aa79cae1374a7c1e5bbcb80ee23e06ebfde206bfb0fcbc0edc4ebec309661bdd908d532eb0c6adc38b7c
  #|a7331dce8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d134b90c9058f8632c
  #|798d4490da4987307cba922d61c39805d072b589bd52fdf1e86215c2d54e6670e07383a27bbffb5addf47d66
  #|aa85a0c6f9f32e59d85a44dd5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e3
  #|8d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89d5974ee12e5cf7d5da4d6a31
  #|123041f33e61407e76cffcdcfd7e19ba58cf4b536f4c4938ae79324dc402894b44faf8afbab35282ab659d13
  #|c93f70412e85cb199a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96ba18b2faa
  #|745b6fe189cf772a9f84cbfc

///|
let a3_payload : String =
  #|02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a
  #|045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bc
  #|f32bb9da1a002b00020304

///|
let a3_packet : String =
  #|dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698baeea26b91eb761d9b89237b
  #|bf87263017915358230035f7fd3945d88965cf17f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e
  #|42757507698075b2c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca84bed8521
  #|e2e140

///|
let a4_retry : String =
  #|cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6

///|
test "the version 2 Initial secrets and keys are RFC 9369 A.1's" {
  let dcid = qc_hexb(odcid)
  let v2 = version2
  assert_eq(
    qc_hex(secret(dcid[:], version=v2)),
    "2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba",
  )
  let (client, server) = initial(dcid[:], version=v2)
  assert_eq(qc_hex(client.key), "8b1a0bc121284290a29e0971b5cd045d")
  assert_eq(qc_hex(client.iv), "91f73e2351d8fa91660e909f")
  assert_eq(qc_hex(client.hp), "45b95e15235d6f45a6b19cbcb0294ba9")
  assert_eq(qc_hex(server.key), "82db637861d55e1d011f19ea71d5d2a7")
  assert_eq(qc_hex(server.iv), "dd13c276499c0249d3310652")
  assert_eq(qc_hex(server.hp), "edf6d05c83121201b436e16877593c3a")
}

///|
test "the client Initial of RFC 9369 A.2 protects to the packet the RFC prints" {
  let (client, _) = initial(qc_hexb(odcid)[:], version=version2)
  // The frame plus PADDING frames, which are zero octets, to the 1162 bytes the RFC names.
  let payload = @packet.pad(qv_bytes(a2_payload), 1162)
  let header = qc_hexb("d36b3343cf088394c8f03e5157080000449e00000002")
  let packet = client.seal(header[:], payload[:], number=2L)
  assert_eq(qc_hex(packet), qc_hex(qv_bytes(a2_packet)))
  // And the mask the RFC prints for the sample it takes from that ciphertext.
  assert_eq(
    qc_hex(client.mask(qc_hexb("ffe67b6abcdb4298b485dd04de806071")[:])),
    "94a0c95e80",
  )
}

///|
test "the server Initial of RFC 9369 A.3 protects to the packet the RFC prints" {
  let (_, server) = initial(qc_hexb(odcid)[:], version=version2)
  let payload = qv_bytes(a3_payload)
  let header = qc_hexb("d16b3343cf0008f067a5502a4262b50040750001")
  let packet = server.seal(header[:], payload[:], number=1L)
  assert_eq(qc_hex(packet), qc_hex(qv_bytes(a3_packet)))
  // What a receiver gets back, and the packet number it recovers.
  let (plain, number) = server.open(packet[:], largest=0L).unwrap()
  assert_eq(qc_hex(plain), qc_hex(payload))
  assert_eq(number, 1L)
}

///|
test "the Retry of RFC 9369 A.4 carries the tag the RFC prints" {
  let packet = qv_bytes(a4_retry)
  assert_eq(
    qc_hex(retry_tag(packet[0:20], qc_hexb(odcid)[:], version=version2)),
    "c8646ce8bfe33952d955543665dcc7b6",
  )
  assert_eq(retry_ok(packet[:], qc_hexb(odcid)[:], version=version2), true)
  // The same packet under version 1's key is not this tag, which is what makes the version a
  // parameter rather than a constant.
  assert_eq(retry_ok(packet[:], qc_hexb(odcid)[:]), false)
}

///|
test "a version 2 short packet with ChaCha20-Poly1305 protects as RFC 9369 A.5 shows" {
  let secret = qc_hexb(
    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
  )
  let keys = Keys::of(secret[:], suite=chacha20, version=version2)
  assert_eq(
    keys.key,
    qc_hexb("3bfcddd72bcf02541d7fa0dd1f5f9eeea817e09a6963a0e6c7df0f9a1bab90f2"),
  )
  assert_eq(keys.iv, qc_hexb("a6b5bc6ab7dafce30ffff5dd"))
  assert_eq(
    keys.hp,
    qc_hexb("d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2"),
  )
  assert_eq(
    qc_hex(update(secret[:], suite=chacha20, version=version2)),
    "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88",
  )
  let packet = keys.seal(qc_hexb("4200bff4")[:], b"\x01"[:], number=654360564L)
  assert_eq(packet, qc_hexb("5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"))
}

///|
test "a version's constants are found by the number its headers carry" {
  assert_eq(Version::of(@packet.version1), Some(version))
  assert_eq(Version::of(@packet.version2), Some(version2))
  // The draft codepoint RFC 9369 reserves for testing is not a version this library speaks.
  assert_eq(Version::of(0x709a50c4U), None)
  assert_eq(Version::of(0U), None)
}
