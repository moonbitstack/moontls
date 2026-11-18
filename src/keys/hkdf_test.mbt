// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 5869 Appendix A, the published HKDF test cases.
//
// TLS 1.3's whole key schedule is HKDF over a handshake transcript (RFC 8446 §7.1), so a KDF that
// is only self-consistent would make every secret in the library wrong in the same direction and
// invisible: two ends of this library would still agree. These are the answers someone else
// computed, and they are the only thing here that can disagree with a mistake made twice.
//
// https://www.rfc-editor.org/rfc/rfc5869#appendix-A

///|
fn hkdf_hex(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One of the RFC's cases: extract, then expand, then check both answers.
fn hkdf_case(
  ikm : String,
  salt : String,
  info : String,
  len : Int32,
  prk : String,
  okm : String,
) -> Unit raise {
  let extracted = @keys.extract(hkdf_hex(salt), hkdf_hex(ikm))
  assert_eq(@base16.encode(extracted), prk)
  let expanded = @keys.expand(extracted, hkdf_hex(info), len~)
  assert_eq(@base16.encode(expanded), okm)
}

///|
/// A.1: a short input, a short output, and the smallest case there is.
test "hkdf: RFC 5869 test case 1, SHA-256" {
  hkdf_case(
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c",
    "f0f1f2f3f4f5f6f7f8f9", 42, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
  )
}

///|
/// A.2: inputs longer than one hash block, and an output longer than one block — the case that
/// exercises the counter and the chaining of `T(n)`.
test "hkdf: RFC 5869 test case 2, SHA-256, long inputs and output" {
  hkdf_case(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
    "404142434445464748494a4b4c4d4e4f",
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    82,
    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
    "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
    "cc30c58179ec3e87c14c01d5c1f3434f1d87",
  )
}

///|
/// A.3: no salt and no info. An absent salt is `HashLen` zero octets (RFC 5869 §2.2), which is the
/// case a handshake with no PSK runs — every TLS 1.3 handshake without resumption starts here.
test "hkdf: RFC 5869 test case 3, SHA-256, an absent salt and info" {
  hkdf_case(
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 42, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
  )
}

///|
/// The extraction is HMAC with the salt as the key, and RFC 5869 §2.2 says so in one line. Written
/// out that way here, since the RFC's own cases would still pass a schedule that swapped the two.
test "hkdf: an extraction is the HMAC its salt keys" {
  let ikm = hkdf_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt = hkdf_hex("000102030405060708090a0b0c")
  assert_eq(
    @base16.encode(@keys.extract(salt, ikm)),
    @base16.encode(@hmac.mac(salt, ikm, fn() { @sha2.Hasher::new() })),
  )
  // Swapping salt and IKM gives a different key, which is what makes the order worth pinning.
  assert_true(@keys.extract(salt, ikm) != @keys.extract(ikm, salt))
}
