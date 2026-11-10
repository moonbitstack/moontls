// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.0 and 1.1 with RSA key exchange: the suite a 1.0-only peer is most likely to have, and the
// one place where the versions differ from 1.2 in something other than the record's framing. The
// premaster secret repeats the ClientHello's version, and a server compares it with what it read.

///|
fn rsa12() -> @record.Suite12 raise {
  guard @record.Suite12::of(0x002f) is Some(suite) else {
    fail("the suite is not in the table")
  }
  suite
}

///|
/// A pair that speaks one old version with RSA key exchange and nothing else.
fn rsa_legacy_pair(version~ : @tls.Version) -> (@tls.Conn, @tls.Conn) raise {
  let suite = rsa12()
  let sconfig = @tls.Server::new(
    [der(rsa_leaf)],
    key(rsa_key),
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
test "tls 1.0: an RSA exchange between two instances finishes" {
  let (c, s) = rsa_legacy_pair(version=Tls10)
  shuttle(c, s)
  assert_eq(c.version(), Some(Tls10))
  assert_eq(c.suite12(), Some(rsa12()))
  c.write(b"ten"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"ten")
}

///|
test "tls 1.1: an RSA exchange between two instances finishes" {
  let (c, s) = rsa_legacy_pair(version=Tls11)
  shuttle(c, s)
  assert_eq(c.version(), Some(Tls11))
  assert_eq(c.suite12(), Some(rsa12()))
  s.write(b"eleven"[:])
  shuttle(c, s)
  assert_eq(c.read(), b"eleven")
}
