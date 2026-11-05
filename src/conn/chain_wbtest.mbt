// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A server certificate chain that does not fit in one datagram: six certificates, 3755 bytes of
// PEM, so the Handshake flight takes more than one packet and the client has to acknowledge what
// it has before the rest can come (RFC 9000 §14.1, RFC 9001 §4.1.3). Test material, in the open
// on purpose.

///|
let chain_leaf : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBvDCCAWKgAwIBAgIURBgmqXFJ55feTMdLix+ZRUo+EnIwCgYIKoZIzj0EAwIw
  #|GTEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlIDUwHhcNMjYxMTA1MTIwNzQwWhcNMzYx
  #|MTAyMTIwNzQwWjAUMRIwEAYDVQQDDAlhLmV4YW1wbGUwWTATBgcqhkjOPQIBBggq
  #|hkjOPQMBBwNCAAT2wHp5nRL4fE1Z0Dg1fEOu2M+QfsYhr1Iif/xtcLHtIeE9W1LY
  #|RLjILHmryy7fGeAur8bKmnNkz41QSPM7T9Hto4GMMIGJMAwGA1UdEwEB/wQCMAAw
  #|DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBQGA1UdEQQNMAuC
  #|CWEuZXhhbXBsZTAfBgNVHSMEGDAWgBRCYr+5GLCiL1Oo6Ti7DdMv1jYCfDAdBgNV
  #|HQ4EFgQULGO+KQMXJmlclL4Gw+VPJIQO1bwwCgYIKoZIzj0EAwIDSAAwRQIhAPVX
  #|AWOBbEoJ5xFC7xgFZrYsffVkDLPaVfrtuBlQJi4oAiAVmajBb5XDgrEjDqgcss6r
  #|vVTh0nvHU5wNpV/9z9KOYg==
  #|-----END CERTIFICATE-----

///|
let chain_i1 : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBnzCCAUSgAwIBAgIUN8V+mTjlTcEiKWnQAC6DRxbmWX4wCgYIKoZIzj0EAwIw
  #|HTEbMBkGA1UEAwwSbW9vbnF1aWMgdGVzdCByb290MB4XDTI2MTEwNTEyMDc0MFoX
  #|DTM2MTEwMjEyMDc0MFowGTEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlIDEwWTATBgcq
  #|hkjOPQIBBggqhkjOPQMBBwNCAARXJoR2BA+0NGvN3LIEqd12s0JuY20Q5X0L7/9j
  #|H2hJscgtA1DpG3pPpGwmdE6NvM5MmkBWJiX11IFgIBd00zKho2YwZDASBgNVHRMB
  #|Af8ECDAGAQH/AgEFMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU3rcaz5kajUvr
  #|jeS64av2+UMo05QwHwYDVR0jBBgwFoAUtjjzyWgyrUxHWnypY/xXkv8Vtd8wCgYI
  #|KoZIzj0EAwIDSQAwRgIhAKc84EhOaB0S6bjEyJCdVxC1epoIQx2AoITPiquKw3YO
  #|AiEAjxwt42x+BHM34Y8hlMPRPF5VwerCoV+GQXr4Z3MRbEY=
  #|-----END CERTIFICATE-----

///|
let chain_i2 : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBmjCCAUCgAwIBAgIUGqXWuIOattHMV/bl+0DLPmfPwQ4wCgYIKoZIzj0EAwIw
  #|GTEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlIDEwHhcNMjYxMTA1MTIwNzQwWhcNMzYx
  #|MTAyMTIwNzQwWjAZMRcwFQYDVQQDDA5pbnRlcm1lZGlhdGUgMjBZMBMGByqGSM49
  #|AgEGCCqGSM49AwEHA0IABKcmAo2bZd9Q89gN0n/U1zMvFDE+MfVeWH+mA730q8cF
  #|Hc4AT1cgA1775oBkwbiOqW+0WuQ1918j+MEwGWjRCBqjZjBkMBIGA1UdEwEB/wQI
  #|MAYBAf8CAQQwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQye0Ci3kfmafVnOMJM
  #|a2vYfDZAmDAfBgNVHSMEGDAWgBTetxrPmRqNS+uN5Lrhq/b5QyjTlDAKBggqhkjO
  #|PQQDAgNIADBFAiBnAIsy4FJdmmEELdZXhqR8rXN9Z+13my+Xr/hb9CTNewIhAO40
  #|BnOJgxkDYTIclJomeMjYxprN9o7osPSoaBmYsLXE
  #|-----END CERTIFICATE-----

///|
let chain_i3 : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBmzCCAUCgAwIBAgIUXpmqU+2FYAJJigfLYwhaGimRmjMwCgYIKoZIzj0EAwIw
  #|GTEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlIDIwHhcNMjYxMTA1MTIwNzQwWhcNMzYx
  #|MTAyMTIwNzQwWjAZMRcwFQYDVQQDDA5pbnRlcm1lZGlhdGUgMzBZMBMGByqGSM49
  #|AgEGCCqGSM49AwEHA0IABL8y41EXYuEbE/u1cEI9eAjGeRUTYdskcwLJlfCMGois
  #|kvznnaxsEsO2FME+uyujEKDP32YhFAAA9m5Zsx+IFBKjZjBkMBIGA1UdEwEB/wQI
  #|MAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQRUDgvj6/evzjtlF2y
  #|i/pEr9a7ZTAfBgNVHSMEGDAWgBQye0Ci3kfmafVnOMJMa2vYfDZAmDAKBggqhkjO
  #|PQQDAgNJADBGAiEA4PzKdvSQsAmbGlGRvrqMuKLphAejaQp+TxfP4mf4SUYCIQDg
  #|e02NRp4ty/mAkoB3/80rB0Dz6/W2ube0/Ijdf9ClmQ==
  #|-----END CERTIFICATE-----

///|
let chain_i4 : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBmzCCAUCgAwIBAgIUSnk8ViEODucjFfLaGTTU9nQY9KQwCgYIKoZIzj0EAwIw
  #|GTEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlIDMwHhcNMjYxMTA1MTIwNzQwWhcNMzYx
  #|MTAyMTIwNzQwWjAZMRcwFQYDVQQDDA5pbnRlcm1lZGlhdGUgNDBZMBMGByqGSM49
  #|AgEGCCqGSM49AwEHA0IABIl6Nogz5zY4KKbWVkMwrHlFlAOroFtotp/Va+5jsmOB
  #|p++LldyG78FovvKRUDr5+MfgqEqbC4QWcmIzWK+ZOC2jZjBkMBIGA1UdEwEB/wQI
  #|MAYBAf8CAQIwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRnzBeC2jJlbR1ceYeb
  #|btqt9VqLDDAfBgNVHSMEGDAWgBQRUDgvj6/evzjtlF2yi/pEr9a7ZTAKBggqhkjO
  #|PQQDAgNJADBGAiEAgaWO8AuKMEKjVFMbYf7NlIpfUF/+z/h07pej9cM2XPICIQCZ
  #|eedBNgAf4LP6eji1BNk8KS419TnOu7z5fOkfmT8DeQ==
  #|-----END CERTIFICATE-----

///|
let chain_i5 : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBmjCCAUCgAwIBAgIUOQUdTE92aq4WyHfbRC/1O6TEA2cwCgYIKoZIzj0EAwIw
  #|GTEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlIDQwHhcNMjYxMTA1MTIwNzQwWhcNMzYx
  #|MTAyMTIwNzQwWjAZMRcwFQYDVQQDDA5pbnRlcm1lZGlhdGUgNTBZMBMGByqGSM49
  #|AgEGCCqGSM49AwEHA0IABDcEJhXn/+qfOX/Ry3oR6dxFmOLMpHWlVMu16Y9oJd9I
  #|iv1XY5XouKJjMyCZ1ONG1T5zxwqdCPvQF4pDj3UOFMWjZjBkMBIGA1UdEwEB/wQI
  #|MAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRCYr+5GLCiL1Oo6Ti7
  #|DdMv1jYCfDAfBgNVHSMEGDAWgBRnzBeC2jJlbR1ceYebbtqt9VqLDDAKBggqhkjO
  #|PQQDAgNIADBFAiEA+cMKF7TqljgjD0he0Fay79AGwEPLYIZvIwFDaLs2aoACIDDS
  #|LkEX0Itnv64CHQwpszPaqskMZvnltM3NUwD3fiRu
  #|-----END CERTIFICATE-----

///|
let chain_root : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBkTCCATigAwIBAgIUXtAXFTiKH6pYwBIPA/z+rwqrDIowCgYIKoZIzj0EAwIw
  #|HTEbMBkGA1UEAwwSbW9vbnF1aWMgdGVzdCByb290MB4XDTI2MTEwNTEyMDc0MFoX
  #|DTM2MTEwMjEyMDc0MFowHTEbMBkGA1UEAwwSbW9vbnF1aWMgdGVzdCByb290MFkw
  #|EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPkP4Yh9sIkGqJ5NFdaF/oxiaaEMItEqD
  #|BwXAjUuAxOdecHKHHgxxE0uDEHywjj21ucSe/37TaJG9Sg4Ht33elKNWMFQwHQYD
  #|VR0OBBYEFLY488loMq1MR1p8qWP8V5L/FbXfMB8GA1UdIwQYMBaAFLY488loMq1M
  #|R1p8qWP8V5L/FbXfMBIGA1UdEwEB/wQIMAYBAf8CAQYwCgYIKoZIzj0EAwIDRwAw
  #|RAIgE/lhOblJEjcEPWaGj+XYbHW6K2ebU9qpAzTg5zJXx4sCIBIC/w8lCcVssZYO
  #|VvpaJM0unJe4MFUPsOcwgxYn1s0N
  #|-----END CERTIFICATE-----

///|
let chain_key_pem : String =
  #|-----BEGIN EC PRIVATE KEY-----
  #|MHcCAQEEIMlIfjRiYnmCVZ7Oyuh46hn7E8yiPiFzyPf5V1GA8dgUoAoGCCqGSM49
  #|AwEHoUQDQgAE9sB6eZ0S+HxNWdA4NXxDrtjPkH7GIa9SIn/8bXCx7SHhPVtS2ES4
  #|yCx5q8su3xngLq/GyppzZM+NUEjzO0/R7Q==
  #|-----END EC PRIVATE KEY-----

///|
fn chain_key() -> @x509.PrivateKey raise {
  @x509.PrivateKey::pem(chain_key_pem)
}

///|
/// A wall clock after the chain was issued: these certificates start on 2026-11-05, and a
/// handshake judged at an earlier time would be told they are not valid yet.
const CHAIN_WALL : Int64 = 1_800_000_000L

///|
test "a certificate chain past three kilobytes still completes the handshake" {
  let chain : Array[String] = [
    chain_leaf, chain_i5, chain_i4, chain_i3, chain_i2, chain_i1,
  ]
  let mut bytes = 0
  for pem in chain {
    bytes = bytes + pem.length()
  }
  assert_true(bytes > 3600)
  let server : Endpoint[String] = Endpoint::server(
    Config::default(),
    @tls.Server::new(chain.map(@x509.pem), chain_key(), alpn=["h3"]),
    rand=fake_rand(99),
  )
  // The parameters have to name the id this client calls itself (§7.3).
  let params = Limits::new(
    idle_timeout=30000UL,
    data=10_000_000UL,
    stream_data_bidi_local=2_000_000UL,
    stream_data_bidi_remote=1_000_000UL,
    stream_data_uni=1_000_000UL,
    streams_bidi=100UL,
    streams_uni=100UL,
  ).params()
  params.push({ kind: InitialScid, value: b"\xaa\xbb\xcc\xdd", })
  let client = Client::new(
    @tls.Client::new(
      @x509.Roots::new(certs=[@x509.pem(chain_root)][:]),
      alpn=["h3"],
      suites=@tls.suites,
    ),
    "a.example",
    encode(params[:]),
    fake_rand(5),
    b"\x83\x94\xc8\xf0\x3e\x51\x57\x08",
    b"\xaa\xbb\xcc\xdd",
    CHAIN_WALL,
  )
  exchange(client, server, CHAIN_WALL, 1000L)
  assert_true(client.is_connected())
  assert_eq(client.alpn(), Some("h3"))
  assert_true(only_conn(server).phase() is Active)
}
