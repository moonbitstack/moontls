// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2's SRP suites (RFC 5054): the user name in the hello, the refusals of §2.5 and §2.9, and
// a password that is wrong failing where a key would.

///|
/// TLS_SRP_SHA_WITH_AES_128_CBC_SHA and TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA.
let srp_plain : Int32 = 0xc01d

///|
let srp_signed : Int32 = 0xc01e

///|
fn srp_pair(
  code : Int32,
  login : @tls.SrpLogin,
  user~ : @tls.SrpUser = alice(),
  dh_bits~ : Int32 = @tls.dh_bits,
) -> (@tls.Conn, @tls.Conn) raise {
  let suite = @record.Suite12::of(code).unwrap()
  let s = server12(rsa_leaf, key(rsa_key), suites12=[suite], srp=[user])
  let c = client12(suites12=[suite], srp=login, dh_bits~)
  (c, s)
}

///|
fn ends_with(steps : () -> Unit raise) -> @alert.Kind raise {
  try steps() catch {
    @alert.Alert(kind~, ..) => kind
    e => raise e
  } noraise {
    _ => fail("the handshake went through")
  }
}

///|
test "srp 1.2: a user logs in with the password, and the signed suite shows the certificate" {
  for code in [srp_plain, srp_signed] {
    let (c, s) = srp_pair(code, alice_login())
    shuttle(c, s)
    assert_true(c.is_connected() && s.is_connected())
    assert_eq(c.peer().length(), if code == srp_signed { 1 } else { 0 })
  }
}

///|
test "srp 1.2: the wrong password ends at Finished" {
  for code in [srp_plain, srp_signed] {
    let (c, s) = srp_pair(code, {
      identity: b"alice",
      password: b"password124",
    })
    let kind = ends_with(() => shuttle(c, s))
    assert_true(kind is (BadRecordMac | DecryptError))
  }
}

///|
test "srp 1.2: a user the server holds no verifier for is unknown_psk_identity" {
  let (c, s) = srp_pair(srp_plain, {
    identity: b"bob",
    password: b"password123",
  })
  assert_eq(ends_with(() => shuttle(c, s)), UnknownPskIdentity)
}

///|
/// §2.5.1.2: SRP suites offered without the srp extension get `unknown_psk_identity`, before the
/// server says anything else.
test "srp 1.2: a hello without the user name is unknown_psk_identity" {
  let (c, s) = srp_pair(srp_plain, alice_login())
  let hello = hello_of(c.take())
  let bare = @msg.hello({
    ..hello,
    extensions: hello.extensions.filter(e => !(e.kind is Srp)),
  })
  let kind = ends_with(() => s.receive(@record.encode(Handshake, bare[:])[:]))
  assert_eq(kind, UnknownPskIdentity)
}

///|
/// §2.5.3: a group outside what the client will take is `insufficient_security`. The 1024-bit
/// group is RFC 5054's mandatory one and smaller than `dh_bits`.
test "srp 1.2: a group under dh_bits is insufficient_security, and taken when allowed" {
  let small = @tls.SrpUser::new(
    b"alice"[:],
    b"password123"[:],
    b"salt"[:],
    group=G1024,
  )
  let (c, s) = srp_pair(srp_plain, alice_login(), user=small)
  assert_eq(ends_with(() => shuttle(c, s)), InsufficientSecurity)
  let (c, s) = srp_pair(srp_plain, alice_login(), user=small, dh_bits=1024)
  shuttle(c, s)
  assert_true(c.is_connected())
}

///|
test "srp 1.2: the user name rides the hello only when an SRP suite is offered" {
  let named = (exts : Array[@ext.Ext]) => @ext.find(exts[:], Srp) is Some(_)
  let (c, _) = srp_pair(srp_plain, alice_login())
  let hello = hello_of(c.take())
  assert_true(named(hello.extensions))
  assert_eq(
    @ext.read_srp(@ext.find(hello.extensions[:], Srp).unwrap().data[:]),
    Some(b"alice"),
  )
  let plain = client12(srp=alice_login())
  assert_false(named(hello_of(plain.take()).extensions))
}
