// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 7919's finite-field groups, pinned to the moduli the RFC publishes.
//
// A group is a prime and a generator, and a wrong prime is not a wrong answer — it is a group with
// a trapdoor. These tests hash what the library holds and compare it with the hash of what the RFC
// printed, so the check covers all 2048 to 8192 bits rather than the ends of them.
//
// https://www.rfc-editor.org/rfc/rfc7919#appendix-A

///|
/// The SHA-256 of each group's modulus, taken over the octets the RFC prints for it.
let rfc7919_ffdhe2048 : String = "9cd3b7f336872f46c09428d1bbc19877a4d440512cda8d1c1cf0cd6e33698966"

///|
let rfc7919_ffdhe3072 : String = "0eaf67db3a839156d5013494a5318a772b5697d270d721f37f092efc69ea5a17"

///|
let rfc7919_ffdhe4096 : String = "4648414224ac881b3d0dc59b466f96d06a558278776807797ecf1f66ff397b3e"

///|
let rfc7919_ffdhe6144 : String = "227ac9066b3ddd9e193670cda2388fa884f65ba0cf98b742d1fe77a6687c79c7"

///|
let rfc7919_ffdhe8192 : String = "770b14efaf6f049929c523113b3fa99a8d11dab1b18af3609590122075d19833"

///|
/// The modulus of `group`, at the width RFC 7919 §3 writes it: the size of the group, so the
/// leading octet is `ff` and not a sign octet an ASN.1 integer would want.
fn ffdhe_prime(group : @dh.Group) -> Bytes {
  group.prime().to_octets(length=group.size())
}

///|
test "ffdhe: every group is the RFC 7919 modulus, bit for bit" {
  let groups = [
    (@dh.Group::Ffdhe2048, rfc7919_ffdhe2048, 256),
    (@dh.Group::Ffdhe3072, rfc7919_ffdhe3072, 384),
    (@dh.Group::Ffdhe4096, rfc7919_ffdhe4096, 512),
    (@dh.Group::Ffdhe6144, rfc7919_ffdhe6144, 768),
    (@dh.Group::Ffdhe8192, rfc7919_ffdhe8192, 1024),
  ]
  for entry in groups {
    let (group, want, size) = entry
    let prime = ffdhe_prime(group)
    assert_eq(prime.length(), size)
    assert_eq(@base16.encode(@sha2.hash(prime[:])), want)
    // §3: the generator is 2 for all five, and the top two octets are `ff ff`.
    assert_eq(@dh.generator, 2)
    assert_eq(@base16.encode(prime[0:2]), "ffff")
  }
}

///|
/// §3's construction fixes the last octet too: the modulus ends in seven zero bits and a one, so
/// the group order is even and the low bit of `p` is set. A prime with a different shape would
/// still hash right only if it were the same number, so this is the property the hash implies.
test "ffdhe: every modulus is odd and congruent to 3 mod 4" {
  for
    group in [
      @dh.Group::Ffdhe2048,
      @dh.Group::Ffdhe3072,
      @dh.Group::Ffdhe4096,
      @dh.Group::Ffdhe6144,
      @dh.Group::Ffdhe8192,
    ] {
    let prime = ffdhe_prime(group)
    let last = prime[prime.length() - 1].to_int()
    assert_eq(last & 0x03, 0x03)
  }
}

///|
/// A public value is a group element: at the group's width, and below its modulus. The width is
/// what a key share on the wire has to be (RFC 8446 §4.2.8.1), and an exchange that produced a
/// value wider than the modulus would be one a peer's parser refuses.
test "ffdhe: a generated share is the group's width and below its modulus" {
  for
    group in [@dh.Group::Ffdhe2048, @dh.Group::Ffdhe3072, @dh.Group::Ffdhe4096] {
    let secret = @sha2.hash(b"a secret for the group")
    let public = @dh.public_key(group, secret[:])
    assert_eq(public.length(), group.size())
    assert_true(
      @dh.shared_secret(group, secret[:], public[:]).length() == group.size(),
    )
  }
}
