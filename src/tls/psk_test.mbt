// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// External pre-shared keys (RFC 8446 §4.2.11): a secret two ends already share, named by an
// identity, that authenticates a handshake in place of a certificate.

///|
/// The key the cases here share: 32 octets, the length SHA-256 binds.
fn psk_key() -> Bytes {
  @sha2.hash(@utf8.encode("a shared secret nobody else has")[:])
}

///|
/// A server that accepts `key` under the identity `name`, and optionally lets it key the handshake
/// without a key exchange.
fn psk_server(
  name~ : String = "test",
  key~ : Bytes,
  modes~ : Array[Int32] = @tls.psk_modes,
) -> @tls.Conn raise {
  let config = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    psk=[@tls.Psk::new(@utf8.encode(name), key)],
    psk_modes=modes,
  )
  @tls.Conn::server(config, rand=rng(1000), now~)
}

///|
fn psk_client(
  name~ : String = "test",
  key~ : Bytes,
  modes~ : Array[Int32] = @tls.psk_modes,
) -> @tls.Conn raise {
  let config = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    psk=[@tls.Psk::new(@utf8.encode(name), key)],
    psk_modes=modes,
  )
  @tls.Conn::client(config, "a.example", rand=rng(1), now~)
}

///|
test "tls: a configured pre-shared key finishes a handshake with no certificate" {
  let key = psk_key()
  let client = psk_client(key~)
  let server = psk_server(key~)
  shuttle(client, server)
  assert_true(client.is_connected())
  assert_true(server.is_connected())
  assert_true(client.is_resumed())
  assert_true(server.is_resumed())
  // §4.4.2: a PSK handshake authenticates with the secret, so no chain travels either way.
  assert_eq(client.peer().length(), 0)
  assert_eq(server.peer().length(), 0)
  assert_true(client.group() is Some(_))
  client.write(b"ping"[:])
  shuttle(client, server)
  assert_eq(server.read(), b"ping")
}

///|
test "tls: a pre-shared key under another identity is not taken" {
  let key = psk_key()
  let client = psk_client(key~)
  let server = psk_server(name="other", key~)
  shuttle(client, server)
  // §4.2.11: a server that does not accept an identity continues without it, so the certificate
  // the server does hold is what authenticates the handshake.
  assert_true(server.is_connected())
  assert_false(server.is_resumed())
  assert_eq(client.peer().length(), 1)
}

///|
test "tls: a pre-shared key with the wrong secret is not taken" {
  let client = psk_client(key=psk_key())
  let other = @sha2.hash(@utf8.encode("not the shared secret")[:])
  let server = psk_server(key=other)
  // The binder does not verify, which is the identity being declined rather than the handshake
  // ending: the certificate the server holds is what authenticates it instead.
  shuttle(client, server)
  assert_true(server.is_connected())
  assert_false(server.is_resumed())
  assert_eq(client.peer().length(), 1)
}

///|
test "tls: psk_ke keys the handshake with no key exchange at all" {
  let key = psk_key()
  // §4.2.9: with this mode alone the ClientHello carries no key_share, and §7.1's shared secret is
  // a string of zeros.
  let client = psk_client(key~, modes=[@ext.psk_ke])
  let server = psk_server(key~, modes=[@ext.psk_ke])
  shuttle(client, server)
  assert_true(client.is_connected())
  assert_true(server.is_connected())
  assert_true(client.is_resumed())
  assert_true(server.is_resumed())
  assert_true(client.group() is None)
  assert_true(server.group() is None)
  client.write(b"sole"[:])
  shuttle(client, server)
  assert_eq(server.read(), b"sole")
}

///|
test "tls: a server that does not accept psk_ke refuses a hello without a key share" {
  let key = psk_key()
  let client = psk_client(key~, modes=[@ext.psk_ke])
  let server = psk_server(key~)
  let refused = try {
    shuttle(client, server)
    false
  } catch {
    _ => true
  }
  assert_true(refused)
  assert_false(server.is_connected())
}

///|
test "tls: a ticket resumes under psk_ke alone" {
  let store = @tls.Sessions::new()
  let key = ticket_key(31)
  let modes = [@ext.psk_dhe_ke, @ext.psk_ke]
  let server_config = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    tickets=@tls.Tickets::new([key][:], count=2),
    psk_modes=modes,
  )
  let client_config = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    sessions=store,
    psk_modes=[@ext.psk_ke],
  )
  let first = @tls.Conn::server(server_config, rand=rng(3000), now~)
  let client = @tls.Conn::client(client_config, "a.example", rand=rng(3), now~)
  shuttle(client, first)
  assert_true(client.is_connected())
  assert_true(store.length() > 0)
  let resumed = @tls.Conn::server(server_config, rand=rng(3001), now~)
  let again = @tls.Conn::client(client_config, "a.example", rand=rng(4), now~)
  shuttle(again, resumed)
  assert_true(again.is_resumed())
  assert_true(resumed.is_resumed())
  assert_true(again.group() is None)
}
