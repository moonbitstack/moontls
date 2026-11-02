// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The post-quantum groups: ML-KEM alone (draft-ietf-tls-mlkem) and the three hybrids of
// draft-ietf-tls-ecdhe-mlkem.

///|
test "tls: every post-quantum group runs a handshake both ends agree on" {
  for
    group in [
      @ext.x25519mlkem768, @ext.secp256r1mlkem768, @ext.secp384r1mlkem1024, @ext.mlkem512,
      @ext.mlkem768, @ext.mlkem1024,
    ] {
    let s = server_with(p256_leaf, p256(), groups=[group])
    let c = client_with(groups=[group])
    shuttle(c, s)
    assert_eq(c.group(), Some(group))
    assert_eq(s.group(), Some(group))
    c.write(b"after the quantum computer"[:])
    shuttle(c, s)
    assert_eq(s.read(), b"after the quantum computer")
  }
}

///|
test "tls: two defaults settle on X25519MLKEM768" {
  let s = server_with(p256_leaf, p256())
  let c = client_with()
  shuttle(c, s)
  assert_eq(c.group(), Some(@ext.x25519mlkem768))
  assert_eq(s.group(), Some(@ext.x25519mlkem768))
}

///|
test "tls: a server without the hybrid takes the X25519 share the default client also sent" {
  let s = server_with(p256_leaf, p256(), groups=[@ext.x25519])
  let c = client_with()
  s.receive(c.take()[:])
  // A HelloRetryRequest would leave the group unsettled; a ServerHello has settled it.
  assert_eq(s.group(), Some(@ext.x25519))
  shuttle(c, s)
  assert_eq(c.group(), Some(@ext.x25519))
}

///|
test "tls: one share asked for, and a server without the hybrid asks for another" {
  let s = server_with(p256_leaf, p256(), groups=[@ext.x25519])
  let c = client_with(shares=1)
  s.receive(c.take()[:])
  assert_eq(s.group(), None)
  shuttle(c, s)
  assert_eq(c.group(), Some(@ext.x25519))
}
