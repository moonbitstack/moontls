// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.0 and 1.1 (RFC 2246, RFC 4346): the PRF over MD5 and SHA-1, a CBC IV that is implicit in
// 1.0 and written out in 1.1, and no scheme in a CertificateVerify.

///|
/// The CBC suite these versions are exercised with: ECDHE with an ECDSA certificate and AES-128-CBC
/// under SHA-1's MAC, which is what a 1.0 peer has.
fn cbc12() -> @record.Suite12 raise {
  guard @record.Suite12::of(0xc009) is Some(suite) else {
    fail("the suite is not in the table")
  }
  suite
}

///|
/// A pair that speaks one of the two old versions, and nothing newer.
fn legacy_pair(version~ : @tls.Version) -> (@tls.Conn, @tls.Conn) raise {
  let suite = cbc12()
  let sconfig = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    versions=[version],
    suites12=[suite],
    schemes12=@tls.all_schemes12,
  )
  let cconfig = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    versions=[version],
    suites12=[suite],
    schemes12=@tls.all_schemes12,
  )
  (
    @tls.Conn::client(cconfig, "a.example", rand=rng(7), now~),
    @tls.Conn::server(sconfig, rand=rng(8), now~),
  )
}

///|
test "tls 1.0: the handshake runs over the MD5-SHA1 PRF and an implicit IV" {
  let (c, s) = legacy_pair(version=Tls10)
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_true(s.is_connected())
  assert_eq(c.version(), Some(Tls10))
  assert_eq(s.version(), Some(Tls10))
  c.write(b"legacy"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"legacy")
  s.write(b"answer"[:])
  shuttle(c, s)
  assert_eq(c.read(), b"answer")
}

///|
test "tls 1.1: the same handshake with the IV written out with each record" {
  let (c, s) = legacy_pair(version=Tls11)
  shuttle(c, s)
  assert_eq(c.version(), Some(Tls11))
  c.write(b"eleven"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"eleven")
  s.write(b"back"[:])
  shuttle(c, s)
  assert_eq(c.read(), b"back")
}

///|
test "tls: several records under a chained IV still read back in order" {
  let (c, s) = legacy_pair(version=Tls10)
  shuttle(c, s)
  for i in 0..<4 {
    c.write(Bytes::make(100 + i, b'a'))
  }
  shuttle(c, s)
  assert_eq(s.read().length(), 406)
  s.write(Bytes::make(5000, b'b'))
  shuttle(c, s)
  assert_eq(c.read().length(), 5000)
}

///|
test "tls: a client certificate in TLS 1.0 carries no scheme on the wire" {
  let suite = cbc12()
  let anchors = @x509.Roots::new(certs=[der(client_root)][:])
  let sconfig = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    versions=[Tls10],
    suites12=[suite],
    schemes12=@tls.all_schemes12,
    client_auth=@tls.ClientAuth::new(mode=Required, roots=anchors),
  )
  let cconfig = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    versions=[Tls10],
    suites12=[suite],
    schemes12=@tls.all_schemes12,
    cert=[der(client_leaf)],
    cert_key=key(client_key),
  )
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(7), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(8), now~)
  shuttle(c, s)
  assert_true(s.is_connected())
  assert_eq(s.peer().length(), 1)
}

///|
test "tls: 1.0 and 1.1 are off unless both ends name them" {
  let suite = cbc12()
  let sconfig = @tls.Server::new([der(p256_leaf)], p256(), suites12=[suite])
  let cconfig = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    versions=[Tls10],
    suites12=[suite],
    schemes12=@tls.all_schemes12,
  )
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(7), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(8), now~)
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("expected an alert")
  }
  assert_true(e is @alert.Alert(kind=ProtocolVersion, ..))
}
