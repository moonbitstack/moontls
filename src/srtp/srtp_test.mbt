// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 5764 publishes no test vectors, so the keying material below was produced
// by RFC 8446 §7.5, RFC 9147 §5.9 and RFC 5764 §4.2 written out over Python's
// own HMAC, which shares no code with this package. That reference had the same
// author as this package and once carried the same mistake — a TLS label prefix
// where DTLS wants `dtls13` — which is why the key schedule under it is now
// checked against pion/dtls as well (`dtls/pion_wbtest.mbt`).

///|
/// The exporter master secret of the handshake `keys` tests against: a fixed
/// ECDHE secret of the octets 0..31, and a stand-in transcript.
fn secret() -> Bytes {
  let ecdhe = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
  let master = @keys.master(@keys.handshake(@keys.early()[:], ecdhe[:])[:])
  @keys.exporter_master(
    master[:],
    @keys.digest.hash(b"client hello .. server finished")[:],
  )
}

///|
test "every profile's code round-trips, and an unknown one is refused" {
  let all = [
    @srtp.Aes128CmSha1Tag80,
    @srtp.Aes128CmSha1Tag32,
    @srtp.NullSha1Tag80,
    @srtp.NullSha1Tag32,
    @srtp.Aead128Gcm,
    @srtp.Aead256Gcm,
  ]
  for p in all {
    assert_eq(@srtp.Profile::of(p.code()), Some(p))
  }
  // 0x0003 and 0x0004 are not assigned; 0x0009 is past the last profile.
  assert_eq(@srtp.Profile::of(0x0003), None)
  assert_eq(@srtp.Profile::of(0x0004), None)
  assert_eq(@srtp.Profile::of(0x0009), None)
  assert_eq(@srtp.Profile::of(0x0000), None)
}

///|
/// The lengths RFC 5764 §4.1.2 and RFC 7714 §14.2 fix. They are what the
/// negotiation is for, so they are worth stating twice.
test "each profile fixes its key and salt lengths" {
  assert_eq(@srtp.Aes128CmSha1Tag80.key_size(), 16)
  assert_eq(@srtp.Aes128CmSha1Tag80.salt_size(), 14)
  assert_eq(@srtp.Aes128CmSha1Tag32.key_size(), 16)
  assert_eq(@srtp.Aes128CmSha1Tag32.salt_size(), 14)
  assert_eq(@srtp.NullSha1Tag80.key_size(), 16)
  assert_eq(@srtp.NullSha1Tag80.salt_size(), 14)
  assert_eq(@srtp.Aead128Gcm.key_size(), 16)
  assert_eq(@srtp.Aead128Gcm.salt_size(), 12)
  assert_eq(@srtp.Aead256Gcm.key_size(), 32)
  assert_eq(@srtp.Aead256Gcm.salt_size(), 12)
}

///|
/// RFC 5764 §4.1.1: the answerer picks, so its order decides and the offerer's
/// does not.
test "the answerer's preference decides, not the offerer's" {
  // The offer lists the counter-mode profile first; the default preference
  // puts the AEAD ones ahead of it, so the AEAD one wins.
  assert_eq(@srtp.select([0x0001, 0x0007][:]), Some(@srtp.Aead128Gcm))
  assert_eq(@srtp.select([0x0007, 0x0001][:]), Some(@srtp.Aead128Gcm))
  // With a preference of its own, the same offer answers differently.
  assert_eq(
    @srtp.select([0x0001, 0x0007][:], supported=[@srtp.Aes128CmSha1Tag80][:]),
    Some(@srtp.Aes128CmSha1Tag80),
  )
  // Nothing in common is a failure, not a connection without SRTP.
  assert_eq(@srtp.select([0x0002, 0x0005][:]), None)
  assert_eq(@srtp.select([][:]), None)
  // A profile the default preference leaves out stays out even when offered.
  assert_eq(@srtp.select([0x0005][:]), None)
}

///|
test "the AEAD-128 profile's keying material matches an independent implementation" {
  let keys = @srtp.keys(secret()[:], Aead128Gcm)
  assert_eq(@base16.encode(keys.client_key), "095bf21b0d03749f049191a302d9cd47")
  assert_eq(@base16.encode(keys.server_key), "1c529ad550e6817c3d33119c52561b58")
  assert_eq(@base16.encode(keys.client_salt), "35e6263322ac6046fff73ba1")
  assert_eq(@base16.encode(keys.server_salt), "96ab6e637e2cea576d7f00fe")
}

///|
test "the counter-mode profile's keying material matches an independent implementation" {
  let keys = @srtp.keys(secret()[:], Aes128CmSha1Tag80)
  assert_eq(@base16.encode(keys.client_key), "e91ed49f2b93eaf68094e96131846a37")
  assert_eq(@base16.encode(keys.server_key), "7812fef9f93e673c13ea1a6fd5619b1f")
  assert_eq(@base16.encode(keys.client_salt), "289b4b6d28452e9d2b29ba2b9dbd")
  assert_eq(@base16.encode(keys.server_salt), "e5bbe75239ef79c658ec133e1b35")
}

///|
test "the AEAD-256 profile's keying material matches an independent implementation" {
  let keys = @srtp.keys(secret()[:], Aead256Gcm)
  assert_eq(
    @base16.encode(keys.client_key),
    "6362267d2b20d10e5cab7d338845b7d3dfa260dad5553a3f3b56fed4a8fc45ef",
  )
  assert_eq(
    @base16.encode(keys.server_key),
    "cbf5eaea25479772e6686496243ea8adbc8e61fd62f27afcc22cddfe0dc53d87",
  )
  assert_eq(@base16.encode(keys.client_salt), "b88c4c5d56f89645929c5975")
  assert_eq(@base16.encode(keys.server_salt), "88500872f08a6d006a6e0e38")
}

///|
/// The cut is key, key, salt, salt — not key, salt, key, salt. Getting it wrong
/// gives a connection where each end can decrypt only its own traffic, which no
/// single-ended test catches.
test "the four pieces are the right lengths and do not overlap" {
  for p in [@srtp.Aes128CmSha1Tag80, @srtp.Aead128Gcm, @srtp.Aead256Gcm] {
    let keys = @srtp.keys(secret()[:], p)
    assert_eq(keys.client_key.length(), p.key_size())
    assert_eq(keys.server_key.length(), p.key_size())
    assert_eq(keys.client_salt.length(), p.salt_size())
    assert_eq(keys.server_salt.length(), p.salt_size())
    assert_not_eq(keys.client_key, keys.server_key)
    assert_not_eq(keys.client_salt, keys.server_salt)
  }
}

///|
/// The digest is a knob here as everywhere in the schedule: a SHA-384 suite
/// exports different material from the same secret.
test "the digest reaches the exported keys" {
  let sha256 = @srtp.keys(secret()[:], Aead128Gcm)
  let sha384 = @srtp.keys(secret()[:], Aead128Gcm, digest=Sha384)
  assert_not_eq(sha256.client_key, sha384.client_key)
  assert_eq(sha384.client_key.length(), 16)
}
