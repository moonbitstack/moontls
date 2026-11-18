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
/// The body length of the first record of `kind` in `flight`, or -1.
fn record_length(flight : Bytes, kind : Int32) -> Int32 {
  let mut at = 0
  while at + 5 <= flight.length() {
    let size = (flight[at + 3].to_int() << 8) | flight[at + 4].to_int()
    if flight[at].to_int() == kind {
      return size
    }
    at = at + 5 + size
  }
  -1
}

///|
test "tls: a renegotiation seals its change_cipher_spec" {
  // RFC 5246 §7.1 protects the message under the current state, which on a renegotiation is the
  // cipher the connection has been using: one octet of plaintext and, under an AEAD suite, a
  // sixteen-octet tag. The two ends of this library would agree on a bare octet too, so the length
  // is asserted rather than the handshake's success.
  let (c, s) = renewing_pair(client=true, server=true)
  shuttle(c, s)
  s.renegotiate()
  c.receive(s.take()[:])
  s.receive(c.take()[:])
  c.receive(s.take()[:])
  // The client's half of the second handshake: the exchange, then its change_cipher_spec and its
  // Finished, the last two under the new keys.
  let flight = c.take()
  assert_eq(record_length(flight, 20), 17)
  s.receive(flight[:])
  // The server's answer is the other half, and its change_cipher_spec is sealed the same way.
  let server_flight = s.take()
  assert_eq(record_length(server_flight, 20), 17)
  c.receive(server_flight[:])
  assert_true(c.is_connected())
}

///|
test "tls: a renegotiation while both ends are writing keeps the connection" {
  // What a live connection does: the server asks for a second handshake while the client's data is
  // already on its way, so both ends read a record of the other's that belongs to the other phase.
  let (c, s) = renewing_pair(client=true, server=true)
  shuttle(c, s)
  s.renegotiate()
  c.write(b"during"[:])
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_true(s.is_connected())
  assert_eq(s.read(), b"during")
  c.write(b"after"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"after")
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
