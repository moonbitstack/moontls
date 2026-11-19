// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn fixed(n : Int32) -> Bytes {
  Bytes::makei(n, i => (i * 7 + 3).to_byte())
}

///|
test "kx: X25519MLKEM768 sends the ML-KEM key first and puts its secret first" {
  let group = @ext.x25519mlkem768
  let (secret, public) = share(group, fixed)
  assert_eq(public.length(), 1184 + 32)
  let kem = @mlkem.PrivateKey::from_seed(kind=K768, secret[:64])
  assert_eq(public[:1184].to_owned(), kem.encapsulation_key().bytes())
  assert_eq(public[1184:].to_owned(), @x25519.public(secret[64:]))
  let (answer, server_shared) = respond(group, public, fixed)
  assert_eq(answer.length(), 1088 + 32)
  let shared = agree(group, secret, answer)
  assert_eq(shared, server_shared)
  assert_eq(shared[:32].to_owned(), kem.decapsulate(answer[:1088]))
  assert_eq(shared[32:].to_owned(), @x25519.shared(secret[64:], answer[1088:]))
}

///|
test "kx: SecP256r1MLKEM768 sends the curve point first and puts its secret first" {
  let group = @ext.secp256r1mlkem768
  let (secret, public) = share(group, fixed)
  assert_eq(public.length(), 65 + 1184)
  assert_eq(public[0], b'\x04')
  let kem = @mlkem.PrivateKey::from_seed(kind=K768, secret[:64])
  assert_eq(public[65:].to_owned(), kem.encapsulation_key().bytes())
  let (answer, server_shared) = respond(group, public, fixed)
  let shared = agree(group, secret, answer)
  assert_eq(shared, server_shared)
  assert_eq(shared[32:].to_owned(), kem.decapsulate(answer[65:]))
  assert_eq(
    shared[:32].to_owned(),
    @ecdh.shared(secret[64:], answer[:65], curve=P256),
  )
}

///|
test "kx: a hybrid share one byte short, or a ciphertext one byte long, is an illegal_parameter" {
  let group = @ext.x25519mlkem768
  let (secret, public) = share(group, fixed)
  let short = try
    respond(group, public[:public.length() - 1].to_owned(), fixed)
  catch {
    e => e
  } noraise {
    _ => fail("a short share was answered")
  }
  assert_true(short is @alert.Alert(kind=IllegalParameter, ..))
  let (answer, _) = respond(@ext.mlkem768, public[:1184].to_owned(), fixed)
  let long = try
    agree(@ext.mlkem768, secret[:64].to_owned(), answer + b"\x00")
  catch {
    e => e
  } noraise {
    _ => fail("a long ciphertext was taken")
  }
  assert_true(long is @alert.Alert(kind=IllegalParameter, ..))
}

///|
test "kx: a group this build does not run is named but carries no share" {
  let e = try share(0x01ff, fixed) catch {
    e => e
  } noraise {
    _ => fail("shared")
  }
  assert_true(e is @alert.Alert(kind=IllegalParameter, ..))
}

///|
test "kx: the RFC 7027 brainpool groups agree on the same secret" {
  for group in [@ext.brainpool_p256, @ext.brainpool_p384, @ext.brainpool_p512] {
    let (secret, public) = share(group, fixed)
    assert_eq(public[0], b'\x04')
    let (answer, server_shared) = respond(group, public, fixed)
    let shared = agree(group, secret, answer)
    assert_eq(shared, server_shared)
  }
}

///|
/// RFC 8734 §2: TLS 1.3 names the same three curves by its own code points, and each runs the same
/// exchange — a share that starts with the SEC 1 point marker, and a secret both ends agree on.
test "kx: RFC 8734's brainpool groups agree on the same secret" {
  for
    group in [
      @ext.brainpool_p256_tls13, @ext.brainpool_p384_tls13, @ext.brainpool_p512_tls13,
    ] {
    let (secret, public) = share(group, fixed)
    assert_eq(public[0], b'\x04')
    let (answer, server_shared) = respond(group, public, fixed)
    assert_eq(agree(group, secret, answer), server_shared)
  }
}

///|
test "sig: the RFC 8734 schemes name a hash" {
  assert_true(ecdsa_hash(@ext.ecdsa_brainpool_p256) is Some(_))
  assert_true(ecdsa_hash(@ext.ecdsa_brainpool_p384) is Some(_))
  assert_true(ecdsa_hash(@ext.ecdsa_brainpool_p512) is Some(_))
}

///|
test "kx: a brainpool scalar above the order is drawn again until one fits" {
  let mut calls = 0
  let rand = fn(size : Int32) -> Bytes {
    calls = calls + 1
    Bytes::make(size, if calls <= 20 { b'\xff' } else { b'\x01' })
  }
  let (secret, public) = share(@ext.brainpool_p384_tls13, rand)
  assert_eq(calls, 21)
  assert_eq(secret, Bytes::make(48, b'\x01'))
  assert_eq(public.length(), 97)
}

///|
test "kx: a source that never draws a scalar is refused" {
  let rand = fn(size : Int32) -> Bytes { Bytes::make(size, b'\xff') }
  let refused = try share(@ext.brainpool_p384_tls13, rand) catch {
    @alert.Alert(kind~, ..) => Some(kind)
  } noraise {
    _ => None
  }
  assert_eq(refused, Some(InternalError))
}
