// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Static Diffie-Hellman (RFC 5246 §7.4.2): the server's certificate carries its DH key, no
// ServerKeyExchange is sent, and the client's ephemeral value travels in its ClientKeyExchange.

///|
/// An instant `dh_leaf` is valid at.
let dh_now : Int64 = 1830000000

///|
fn dh_pair(
  suite : @record.Suite12,
  dh_bits~ : Int32 = @tls.dh_bits,
) -> (@tls.Conn, @tls.Conn) raise {
  let s = @tls.Conn::server(
    @tls.Server::new([der(dh_leaf)], key(dh_key), versions=[Tls12], suites12=[
      suite,
    ]),
    rand=rng(31),
    now=dh_now,
  )
  let c = @tls.Conn::client(
    @tls.Client::new(
      @x509.Roots::new(certs=[der(named_root)][:]),
      versions=[Tls12],
      suites12=[suite],
      dh_bits~,
    ),
    "a.example",
    rand=rng(32),
    now=dh_now,
  )
  (c, s)
}

///|
test "dh 1.2: every static DH suite carries data both ways" {
  let suites = @record.all12.filter(s => s.exchange is Dh)
  assert_true(suites.length() > 0)
  for suite in suites {
    let (c, s) = dh_pair(suite)
    shuttle(c, s)
    assert_true(c.is_connected() && s.is_connected())
    c.write(b"static"[:])
    shuttle(c, s)
    assert_eq(s.read(), b"static")
  }
}

///|
test "dh 1.2: a group smaller than dh_bits is insufficient_security" {
  let suite = @record.all12.filter(s => s.exchange is Dh)[0]
  let (c, s) = dh_pair(suite, dh_bits=3072)
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("a group under dh_bits was taken")
  }
  assert_true(e is @alert.Alert(kind=InsufficientSecurity, ..))
}

///|
test "dh 1.2: a server without a DH key never picks a static DH suite" {
  let dh = @record.all12.filter(s => s.exchange is Dh && s.auth is Rsa)[0]
  let gcm = @record.Suite12::of(0xc02f).unwrap()
  let s = server12(rsa_leaf, key(rsa_key), suites12=[dh, gcm])
  let c = client12(suites12=[dh, gcm])
  shuttle(c, s)
  assert_eq(s.suite12(), Some(gcm))
}
