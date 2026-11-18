// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// DSA certificates (RFC 5246 §7.4.1.4.1): TLS 1.2 signs a DHE_DSS exchange under the DSA scheme
// the client offers, and TLS 1.3, which has none, has nothing to sign with such a key.

///|
/// TLS_DHE_DSS_WITH_AES_128_GCM_SHA256.
fn dhe_dss() -> @record.Suite12 {
  @record.Suite12::of(0x00a2).unwrap()
}

///|
fn refusal12(steps : () -> Unit raise) -> @alert.Kind raise {
  try steps() catch {
    @alert.Alert(kind~, ..) => kind
    e => raise e
  } noraise {
    _ => fail("the handshake went through")
  }
}

///|
test "dss 1.2: a DHE_DSS exchange is signed under the DSA scheme the client offers" {
  for scheme in [@ext.dsa_sha256, @ext.dsa_sha384, @ext.dsa_sha512] {
    let s = server12(
      dsa_leaf,
      key(dsa_key),
      suites12=[dhe_dss()],
      schemes12=@tls.all_schemes12,
    )
    let c = client12(suites12=[dhe_dss()], schemes12=[scheme])
    shuttle(c, s)
    assert_true(c.is_connected())
    assert_eq(c.suite12(), Some(dhe_dss()))
  }
  // A client that offers no DSA scheme leaves the key nothing to sign under.
  let s = server12(
    dsa_leaf,
    key(dsa_key),
    suites12=[dhe_dss()],
    schemes12=@tls.all_schemes12,
  )
  let c = client12(suites12=[dhe_dss()], schemes12=[@ext.rsa_pkcs1_sha256])
  assert_eq(refusal12(() => shuttle(c, s)), HandshakeFailure)
}

///|
test "dss 1.2: DSA is off until asked for" {
  for scheme in [@ext.dsa_sha256, @ext.dsa_sha384, @ext.dsa_sha512] {
    assert_false(@tls.schemes12.contains(scheme))
    assert_true(@tls.all_schemes12.contains(scheme))
  }
  // Either end left at its default refuses DSA.
  let s = server12(
    dsa_leaf,
    key(dsa_key),
    suites12=[dhe_dss()],
    schemes12=@tls.all_schemes12,
  )
  let c = client12(suites12=[dhe_dss()])
  assert_eq(refusal12(() => shuttle(c, s)), HandshakeFailure)
  let s = server12(dsa_leaf, key(dsa_key), suites12=[dhe_dss()])
  let c = client12(suites12=[dhe_dss()], schemes12=@tls.all_schemes12)
  assert_eq(refusal12(() => shuttle(c, s)), HandshakeFailure)
}

///|
test "dss 1.2: a DSA key has no TLS 1.3 scheme" {
  let s = server12(dsa_leaf, key(dsa_key), versions=[Tls13])
  let c = client12(versions=[Tls13])
  assert_eq(refusal12(() => shuttle(c, s)), HandshakeFailure)
}
