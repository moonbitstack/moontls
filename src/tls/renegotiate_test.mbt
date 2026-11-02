// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A TLS 1.2 pair, each end saying whether it will renegotiate.
fn renewing_pair(
  client~ : Bool,
  server~ : Bool,
) -> (@tls.Conn, @tls.Conn) raise {
  let sconfig = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    versions=[Tls12],
    renegotiation=server,
  )
  let cconfig = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    versions=[Tls12],
    renegotiation=client,
  )
  (
    @tls.Conn::client(cconfig, "a.example", rand=rng(5), now~),
    @tls.Conn::server(sconfig, rand=rng(6), now~),
  )
}

///|
test "tls: a renegotiation on both sides runs a second handshake and the connection goes on" {
  let (c, s) = renewing_pair(client=true, server=true)
  shuttle(c, s)
  assert_true(c.is_connected())
  c.write(b"before"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"before")
  s.renegotiate()
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_true(s.is_connected())
  // The same connection, with new keys and a new transcript, still carries data both ways.
  c.write(b"after"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"after")
  s.write(b"back"[:])
  shuttle(c, s)
  assert_eq(c.read(), b"back")
}

///|
test "tls: a second renegotiation names the handshake before it" {
  let (c, s) = renewing_pair(client=true, server=true)
  shuttle(c, s)
  s.renegotiate()
  shuttle(c, s)
  assert_true(c.is_connected())
  s.renegotiate()
  shuttle(c, s)
  assert_true(c.is_connected())
  c.write(b"third"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"third")
}

///|
test "tls: a server that did not ask to renegotiate cannot start one" {
  let (c, s) = renewing_pair(client=true, server=false)
  shuttle(c, s)
  let e = try s.renegotiate() catch {
    e => e
  } noraise {
    _ => fail("expected a refusal")
  }
  assert_true(e is @alert.Alert(kind=InternalError, ..))
  // The connection is untouched.
  c.write(b"still"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"still")
}

///|
test "tls: a HelloRequest from a server the client did not agree with is declined" {
  // The server is told to renegotiate but the client is not: the client answers with the warning
  // that says so, and the connection stays open.
  let (c, s) = renewing_pair(client=false, server=true)
  shuttle(c, s)
  s.renegotiate()
  shuttle(c, s)
  assert_true(c.is_connected())
  s.write(b"one"[:])
  shuttle(c, s)
  assert_eq(c.read(), b"one")
}

///|
test "tls: a renegotiation is only for TLS 1.2" {
  let sconfig = @tls.Server::new([der(p256_leaf)], p256(), renegotiation=true)
  let cconfig = @tls.Client::new(@x509.Roots::new(certs=[der(root)][:]))
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(5), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(6), now~)
  shuttle(c, s)
  assert_true(c.is_connected())
  let e = try s.renegotiate() catch {
    e => e
  } noraise {
    _ => fail("expected a refusal")
  }
  assert_true(e is @alert.Alert(kind=InternalError, ..))
}
