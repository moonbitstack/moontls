// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn quic_server(
  alpn~ : Array[String] = ["h3"],
  groups? : Array[Int32],
) -> @tls.Conn raise {
  let config = @tls.Server::new(
    [der(p256_leaf)],
    key(p256_key),
    alpn~,
    groups=groups.unwrap_or(@tls.groups),
  )
  @tls.Conn::quic_server(config, params=b"server", rand=rng(1000))
}

///|
fn quic_client(
  alpn~ : Array[String] = ["h3"],
  groups? : Array[Int32],
) -> @tls.Conn raise {
  let config = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    alpn~,
    groups=groups.unwrap_or(@tls.groups),
  )
  @tls.Conn::quic_client(
    config,
    "a.example",
    params=b"client",
    rand=rng(1),
    now~,
  )
}

///|
/// Run both ends until neither has anything to say, and write down the secrets each was given.
fn converse(
  client : @tls.Conn,
  server : @tls.Conn,
) -> (Array[@tls.Step], Array[@tls.Step]) raise {
  let (seen_client, seen_server) : (Array[@tls.Step], Array[@tls.Step]) = (
    [],
    [],
  )
  for ;; {
    let (from_client, from_server) = (client.steps(), server.steps())
    if from_client.length() == 0 && from_server.length() == 0 {
      break
    }
    for step in from_client {
      match step {
        Send(level, data) => server.crypto(level, data[:])
        Keys(_, ..) | Early(..) => seen_client.push(step)
      }
    }
    for step in from_server {
      match step {
        Send(level, data) => client.crypto(level, data[:])
        Keys(_, ..) | Early(..) => seen_server.push(step)
      }
    }
  }
  (seen_client, seen_server)
}

///|
test "a QUIC handshake runs over CRYPTO bytes, and both ends reach the same secrets" {
  let (client, server) = (quic_client(), quic_server())
  let (a, b) = converse(client, server)
  assert_eq(a.length(), 2)
  assert_eq(a, b)
  assert_true(client.is_connected() && server.is_connected())
  assert_eq(server.alpn(), Some("h3"))
  assert_eq(client.alpn(), Some("h3"))
  assert_eq(server.peer_params(), Some(b"client"))
  assert_eq(client.peer_params(), Some(b"server"))
  assert_eq(client.take(), b"")
  assert_eq(server.take(), b"")
}

///|
test "a QUIC handshake survives a HelloRetryRequest" {
  let client = quic_client(groups=[@ext.secp256r1, @ext.x25519])
  let server = quic_server(groups=[@ext.x25519])
  let (a, b) = converse(client, server)
  assert_eq(a, b)
  assert_true(client.is_connected() && server.is_connected())
}

///|
test "the keys for a level come before anything sent at it" {
  let (client, server) = (quic_client(), quic_server())
  let hello = client.steps()
  match hello {
    [Send(Initial, data)] => server.crypto(Initial, data[:])
    _ => fail("the client starts with a ClientHello at the Initial level")
  }
  match server.steps() {
    [
      Send(Initial, _),
      Keys(Handshake, ..),
      Send(Handshake, _),
      Keys(Application, ..),
    ] => ()
    other => fail("server steps: \{other.length()}")
  }
}

///|
test "bytes at the wrong level are an unexpected_message" {
  let (client, server) = (quic_client(), quic_server())
  guard client.steps() is [Send(_, hello)] else { fail("no hello") }
  let refused = try server.crypto(Handshake, hello[:]) catch {
    @alert.Alert(kind=UnexpectedMessage, ..) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(refused)
}

///|
test "a ClientHello without ALPN or transport parameters is refused" {
  let server = quic_server()
  let plain = client_with(alpn=["h3"])
  let hello = plain.take()
  let refused = try server.crypto(Initial, hello[5:]) catch {
    @alert.Alert(kind=IllegalParameter, ..) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(refused)
  let agreed = try {
    let server = quic_server(alpn=["h3"])
    let client = quic_client(alpn=["other"])
    let _ = converse(client, server)
    false
  } catch {
    @alert.Alert(kind=NoApplicationProtocol, ..) => true
    _ => false
  }
  assert_true(agreed)
}

///|
test "a KeyUpdate has no place in QUIC" {
  let (client, server) = (quic_client(), quic_server())
  let _ = converse(client, server)
  let update = @msg.frame(KeyUpdate, b"\x00"[:])
  let refused = try server.crypto(Application, update[:]) catch {
    @alert.Alert(kind=UnexpectedMessage, ..) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(refused)
}

///|
test "CRYPTO bytes may arrive one at a time" {
  let (client, server) = (quic_client(), quic_server())
  guard client.steps() is [Send(level, hello)] else { fail("no hello") }
  for i in 0..<hello.length() {
    server.crypto(level, hello[i:i + 1])
  }
  assert_true(server.steps().length() > 0)
}

///|
/// A resumable pair: the client keeps tickets in `store`, the server seals them under one key and
/// allows 0-RTT, as a QUIC server does by saying so in the ticket.
fn early_pair(
  store : @tls.Sessions,
  ticket_key : Bytes,
  now~ : Int64,
  early~ : Bool = true,
) -> (@tls.Conn, @tls.Conn) raise {
  let server = @tls.Conn::quic_server(
    @tls.Server::new(
      [der(p256_leaf)],
      key(p256_key),
      alpn=["h3"],
      tickets=@tls.Tickets::new([ticket_key][:], early=1024),
    ),
    params=b"server",
    rand=rng(1000),
    now~,
  )
  let client = @tls.Conn::quic_client(
    @tls.Client::new(
      @x509.Roots::new(certs=[der(root)][:]),
      alpn=["h3"],
      sessions=store,
      early~,
    ),
    "a.example",
    params=b"client",
    rand=rng(1),
    now~,
  )
  (client, server)
}

///|
/// The secret of the `Early` step in `steps`, if there is one.
fn early_secret(steps : Array[@tls.Step]) -> Bytes? {
  for step in steps {
    if step is Early(secret~, ..) {
      return Some(secret)
    }
  }
  None
}

///|
test "both ends of a resumed QUIC handshake reach the same early secret" {
  let store = @tls.Sessions::new()
  let ticket_key = Bytes::make(32, b'\x07')
  let (first_client, first_server) = early_pair(store, ticket_key, now~)
  let (a, b) = converse(first_client, first_server)
  // A first handshake has no ticket yet, so neither end has an early secret.
  assert_eq(early_secret(a), None)
  assert_eq(early_secret(b), None)
  assert_true(first_client.is_connected() && first_server.is_connected())
  let (client, server) = early_pair(store, ticket_key, now~)
  let (c, d) = converse(client, server)
  guard early_secret(c) is Some(secret) else {
    fail("the client offered 0-RTT and must hold its secret")
  }
  assert_eq(early_secret(d), Some(secret))
  assert_true(client.is_connected() && server.is_connected())
  assert_true(client.is_resumed())
  assert_true(client.early_accepted())
  // The client must have the secret before its hello goes out, or nothing can follow it.
  assert_true(c[0] is Early(..))
}

///|
test "a QUIC client that does not ask for 0-RTT gets no early secret" {
  let store = @tls.Sessions::new()
  let ticket_key = Bytes::make(32, b'\x07')
  let (first_client, first_server) = early_pair(store, ticket_key, now~)
  ignore(converse(first_client, first_server))
  let (client, server) = early_pair(store, ticket_key, now~, early=false)
  let (c, d) = converse(client, server)
  assert_eq(early_secret(c), None)
  assert_eq(early_secret(d), None)
  assert_true(client.is_resumed())
  assert_false(client.early_accepted())
}

///|
test "EndOfEarlyData never crosses QUIC" {
  let store = @tls.Sessions::new()
  let ticket_key = Bytes::make(32, b'\x07')
  let (first_client, first_server) = early_pair(store, ticket_key, now~)
  ignore(converse(first_client, first_server))
  let (client, server) = early_pair(store, ticket_key, now~)
  // Run by hand, so each CRYPTO chunk the client sends at the handshake level can be read.
  for ;; {
    let (from_client, from_server) = (client.steps(), server.steps())
    if from_client.length() == 0 && from_server.length() == 0 {
      break
    }
    for step in from_client {
      if step is Send(level, data) {
        if level is Handshake {
          // A handshake message opens with its type, and 5 is EndOfEarlyData.
          assert_true(data[0] != b'\x05')
        }
        server.crypto(level, data[:])
      }
    }
    for step in from_server {
      if step is Send(level, data) {
        client.crypto(level, data[:])
      }
    }
  }
  assert_true(client.early_accepted())
  assert_true(server.is_connected())
}

///|
test "a ticket over QUIC says 0xffffffff, and anything else is refused" {
  // RFC 9001 §4.6.1. A real server's ticket has to pass, since resuming with it is the test above;
  // this is the other side: a server that names an amount does not know it is speaking QUIC.
  let store = @tls.Sessions::new()
  let ticket_key = Bytes::make(32, b'\x07')
  let (client, server) = early_pair(store, ticket_key, now~)
  ignore(converse(client, server))
  let ticket = @msg.new_session_ticket({
    lifetime: 7200,
    age_add: 0,
    nonce: b"\x00",
    ticket: b"forged",
    extensions: [{ kind: EarlyData, data: @ext.max_early_data(1024), }],
  })
  let refused = try {
    client.crypto(Application, ticket[:])
    false
  } catch {
    @alert.Alert(kind=IllegalParameter, ..) => true
    _ => false
  }
  assert_true(refused)
}
