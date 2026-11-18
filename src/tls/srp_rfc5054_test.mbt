// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 5054 Appendix B: the one published SRP-6 vector, run end to end.
//
// The vector fixes every value in the exchange — the salt, x, the verifier, a, A, b, B, u and the
// premaster secret — so a mistake anywhere in the SHA-1 framing (§2.4's `s | SHA1(I | ":" | P)`,
// §2.6's `PAD()` and the multiplier) shows up as a premaster that is not the published one. Two
// ends of this library agreeing with each other would not.
//
// https://www.rfc-editor.org/rfc/rfc5054#appendix-B

///|
fn srp_hex(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
test "srp: RFC 5054 appendix B, the verifier and both public values" {
  let salt = srp_hex("beb25379d1a8581eb5a727673a2441ee")
  let verifier = @srp.verifier(
    @srp.Group::G1024,
    b"alice",
    b"password123",
    salt,
  )
  assert_eq(
    @base16.encode(verifier),
    "7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d812" +
    "9bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5" +
    "c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5" +
    "ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78" +
    "e955a5e29e7ab245db2be315e2099afb",
  )

  // The client's public value is g^a, and the RFC's A is what a correct `a` produces.
  let client = @srp.Client::new(
    @srp.Group::G1024,
    srp_hex("60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393"),
  )
  assert_eq(
    @base16.encode(client.public()),
    "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec4" +
    "4352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec" +
    "8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44" +
    "be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efea" +
    "b349ef5d76988a3672fac47b0769447b",
  )

  // B = k*v + g^b: the multiplier and the padding are what make this B and not another.
  let server = @srp.Server::new(
    @srp.Group::G1024,
    verifier,
    srp_hex("e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20"),
  )
  assert_eq(
    @base16.encode(server.public()),
    "bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011" +
    "baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec99" +
    "6c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa" +
    "37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeae" +
    "eb4012b7d7665238a8e3fb004b117b58",
  )
}

///|
/// The same exchange's premaster, computed on both sides. `u` is a hash of both public values, so
/// the two answers agreeing here is the check that each side hashed what the other sent.
test "srp: RFC 5054 appendix B, the premaster secret from both ends" {
  let salt = srp_hex("beb25379d1a8581eb5a727673a2441ee")
  let verifier = @srp.verifier(
    @srp.Group::G1024,
    b"alice",
    b"password123",
    salt,
  )
  let client = @srp.Client::new(
    @srp.Group::G1024,
    srp_hex("60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393"),
  )
  let server = @srp.Server::new(
    @srp.Group::G1024,
    verifier,
    srp_hex("e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20"),
  )
  // The RFC prints the premaster over five lines; all 128 octets of it are checked here.
  let want = "b0dc82babcf30674ae450c0287745e7990a3381f63b387aaf271a10d" +
    "233861e359b48220f7c4693c9ae12b0a6f67809f0876e2d013800d6c" +
    "41bb59b6d5979b5c00a172b4a2a5903a0bdcaf8a709585eb2afafa8f" +
    "3499b200210dcc1f10eb33943cd67fc88a2f39a4be5bec4ec0a3212d" +
    "c346d7e474b29ede8a469ffeca686e5a"
  let from_client = client.premaster(
    server.public(),
    salt~,
    identity=b"alice",
    password=b"password123",
  )
  assert_eq(@base16.encode(from_client), want)
  assert_eq(@base16.encode(server.premaster(client.public())), want)
}

///|
/// §2.4's three framings, which are the ones a reader is most likely to get subtly wrong: the
/// inner hash is over `I ":" P` with no length prefixes, and the outer one over `s | inner`.
/// Changing the salt changes the verifier; changing only the password does too; and an identity
/// that differs only in case is a different user, because nothing here folds case.
test "srp: the verifier moves with every one of its inputs" {
  let salt = b"0123456789abcdef"
  let base_v = @srp.verifier(@srp.Group::G1024, b"alice", b"password123", salt)
  assert_true(
    base_v != @srp.verifier(@srp.Group::G1024, b"alice", b"password124", salt),
  )
  assert_true(
    base_v != @srp.verifier(@srp.Group::G1024, b"Alice", b"password123", salt),
  )
  assert_true(
    base_v !=
    @srp.verifier(
      @srp.Group::G1024,
      b"alice",
      b"password123",
      b"fedcba9876543210",
    ),
  )
}
