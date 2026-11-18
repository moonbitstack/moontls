// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2's pre-shared key suites (RFC 4279, RFC 5489): what goes out, what is refused, and that a
// suite taking a key is only ever offered or picked with one.

///|
fn psk_suite(code : Int32) -> @record.Suite12 {
  @record.Suite12::of(code).unwrap()
}

///|
/// TLS_PSK_WITH_AES_128_GCM_SHA256, TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 and
/// TLS_RSA_PSK_WITH_AES_128_GCM_SHA256.
let plain : Int32 = 0x00a8

///|
let curve : Int32 = 0xc037

///|
let wrapped : Int32 = 0x00ac

///|
test "psk 1.2: a suite without a certificate shows none" {
  for code in [plain, curve] {
    let s = server12(p256_leaf, p256(), suites12=[psk_suite(code)], psk=[
      shared_psk(),
    ])
    let c = client12(suites12=[psk_suite(code)], psk=[shared_psk()])
    shuttle(c, s)
    assert_true(c.is_connected() && s.is_connected())
    assert_eq(c.peer().length(), 0)
  }
  // RSA_PSK has the server's certificate as well as the key.
  let s = server12(rsa_leaf, key(rsa_key), suites12=[psk_suite(wrapped)], psk=[
    shared_psk(),
  ])
  let c = client12(suites12=[psk_suite(wrapped)], psk=[shared_psk()])
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_eq(c.peer().length(), 1)
}

///|
test "psk 1.2: a suite that takes a key is offered and picked only with one" {
  let gcm = @record.Suite12::of(0xc02b).unwrap()
  let hello = hello_of(client12(suites12=[psk_suite(plain), gcm]).take())
  assert_false(hello.suites.contains(plain))
  assert_true(hello.suites.contains(0xc02b))
  // A server with no key passes over the PSK suite the client prefers.
  let s = server12(p256_leaf, p256(), suites12=[psk_suite(plain), gcm])
  let c = client12(suites12=[psk_suite(plain), gcm], psk=[shared_psk()])
  shuttle(c, s)
  assert_eq(s.suite12(), Some(gcm))
}

///|
test "psk 1.2: an identity the server does not hold is unknown_psk_identity" {
  let s = server12(p256_leaf, p256(), suites12=[psk_suite(plain)], psk=[
    shared_psk(),
  ])
  let stranger = @tls.Psk::new(b"client 2"[:], Bytes::make(32, b'\x5a')[:])
  let c = client12(suites12=[psk_suite(plain)], psk=[stranger])
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("an unknown identity was taken")
  }
  assert_true(e is @alert.Alert(kind=UnknownPskIdentity, ..))
}

///|
test "psk 1.2: the wrong key for a known identity ends at Finished" {
  for code in [plain, curve, wrapped] {
    let (leaf, pem) = if code == wrapped {
      (rsa_leaf, rsa_key)
    } else {
      (p256_leaf, p256_key)
    }
    let s = server12(leaf, key(pem), suites12=[psk_suite(code)], psk=[
      shared_psk(),
    ])
    let wrong = @tls.Psk::new(b"client 1"[:], Bytes::make(32, b'\x5b')[:])
    let c = client12(suites12=[psk_suite(code)], psk=[wrong])
    let e = try shuttle(c, s) catch {
      e => e
    } noraise {
      _ => fail("a wrong key agreed")
    }
    assert_true(e is @alert.Alert(kind=BadRecordMac | DecryptError, ..))
    assert_false(c.is_connected())
  }
}
