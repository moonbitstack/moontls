// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A server that hands out tickets sealed under `keys`, allowing `early` octets of 0-RTT data.
fn ticket_server(
  keys~ : Array[Bytes],
  early~ : Int32 = 0,
  count~ : Int32 = 2,
  lifetime~ : Int64 = @tls.ticket_lifetime,
  now_~ : Int64 = now,
) -> @tls.Conn raise {
  let config = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    tickets=@tls.Tickets::new(keys[:], count~, lifetime~, early~),
  )
  @tls.Conn::server(config, rand=rng(3000), now=now_)
}

///|
/// A client that will remember what it is given, and may ask to send 0-RTT data.
fn ticket_client(
  store : @tls.Sessions,
  early~ : Bool = false,
  now_~ : Int64 = now,
) -> @tls.Conn raise {
  let config = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    sessions=store,
    early~,
  )
  @tls.Conn::client(config, "a.example", rand=rng(3), now=now_)
}

///|
/// The key every ticket in these tests is sealed under.
fn ticket_key(seed : Int32) -> Bytes {
  let out = Buffer()
  while out.length() < 32 {
    out.write_bytes(@sha2.hash(@utf8.encode(seed.to_string())[:]))
  }
  out.to_bytes()[0:32].to_owned()
}

///|
test "tls: a second connection resumes the first one's ticket" {
  let store = @tls.Sessions::new()
  let key = ticket_key(1)
  let first = ticket_client(store)
  let server = ticket_server(keys=[key])
  shuttle(first, server)
  assert_true(first.is_connected())
  assert_false(first.is_resumed())
  assert_true(store.length() > 0)
  let second = ticket_client(store)
  let resumed = ticket_server(keys=[key])
  shuttle(second, resumed)
  assert_true(second.is_connected())
  assert_true(second.is_resumed())
  assert_true(resumed.is_resumed())
  assert_eq(second.peer().length(), 0)
  second.write(b"resumed"[:])
  shuttle(second, resumed)
  assert_eq(resumed.read(), b"resumed")
}

///|
test "tls: a server that rotates its keys still opens the last one's tickets" {
  let store = @tls.Sessions::new()
  let old = ticket_key(7)
  shuttle(ticket_client(store), ticket_server(keys=[old]))
  assert_true(store.length() > 0)
  let rotated = @tls.Tickets::new([old][:]).rotate(ticket_key(8))
  let config = @tls.Server::new([der(p256_leaf)], p256(), tickets=rotated)
  let server = @tls.Conn::server(config, rand=rng(3000), now~)
  let client = ticket_client(store)
  shuttle(client, server)
  assert_true(server.is_resumed())
}

///|
test "tls: a ticket sealed under a key the server no longer has is no resumption" {
  let store = @tls.Sessions::new()
  shuttle(ticket_client(store), ticket_server(keys=[ticket_key(9)]))
  let server = ticket_server(keys=[ticket_key(10)])
  let client = ticket_client(store)
  shuttle(client, server)
  assert_true(server.is_connected())
  assert_false(server.is_resumed())
  assert_false(client.is_resumed())
  // A full handshake proves the chain again.
  assert_eq(client.peer().length(), 1)
}

///|
test "tls: a ticket past its lifetime is offered and refused" {
  let store = @tls.Sessions::new()
  let key = ticket_key(11)
  shuttle(ticket_client(store), ticket_server(keys=[key], lifetime=60))
  assert_true(store.length() > 0)
  let server = ticket_server(keys=[key])
  let client = ticket_client(store, now_=now + 120)
  shuttle(client, server)
  assert_true(server.is_connected())
  assert_false(server.is_resumed())
}

///|
test "tls: a client with no store resumes nothing" {
  let config = @tls.Client::new(@x509.Roots::new(certs=[der(root)][:]))
  let client = @tls.Conn::client(config, "a.example", rand=rng(3), now~)
  let server = ticket_server(keys=[ticket_key(12)])
  shuttle(client, server)
  assert_true(server.is_connected())
  assert_false(server.is_resumed())
}

///|
test "tls: a ticket with one octet changed opens nothing" {
  let store = @tls.Sessions::new()
  let key = ticket_key(13)
  shuttle(ticket_client(store), ticket_server(keys=[key]))
  guard store.get(host="a.example", version=Tls13, now~) is Some(session) else {
    fail("no session was stored")
  }
  let forged = session.ticket.to_array()
  forged[forged.length() - 1] = forged[forged.length() - 1] ^ b'\x01'
  store.put({ ..session, ticket: Bytes::from_array(forged), })
  let server = ticket_server(keys=[key])
  let client = ticket_client(store)
  shuttle(client, server)
  assert_true(server.is_connected())
  assert_false(server.is_resumed())
}

///|
test "tls: 0-RTT data the server took arrives before the handshake is over" {
  let store = @tls.Sessions::new()
  let key = ticket_key(14)
  let warmup = ticket_client(store, early=true)
  let first = ticket_server(keys=[key], early=1024)
  shuttle(warmup, first)
  assert_true(warmup.is_connected())
  let client = ticket_client(store, early=true)
  let server = ticket_server(keys=[key], early=1024)
  // The ClientHello first, as it would go on a real socket.
  server.receive(client.take()[:])
  client.write_early(b"early bytes"[:])
  server.receive(client.take()[:])
  assert_eq(server.read(), b"early bytes")
  shuttle(client, server)
  assert_true(client.is_connected())
  assert_true(client.is_resumed())
  assert_true(client.early_accepted())
}

///|
test "tls: 0-RTT data the server declined is sent again as ordinary data" {
  let store = @tls.Sessions::new()
  let key = ticket_key(15)
  // The ticket allows early data; the server it comes back to does not.
  shuttle(
    ticket_client(store, early=true),
    ticket_server(keys=[key], early=1024),
  )
  let client = ticket_client(store, early=true)
  let server = ticket_server(keys=[key], early=0)
  server.receive(client.take()[:])
  client.write_early(b"late"[:])
  server.receive(client.take()[:])
  shuttle(client, server)
  assert_true(client.is_connected())
  assert_false(client.early_accepted())
  assert_eq(server.read(), b"late")
}

///|
test "tls: a client cannot write more 0-RTT data than its ticket allows" {
  let store = @tls.Sessions::new()
  let key = ticket_key(16)
  shuttle(ticket_client(store, early=true), ticket_server(keys=[key], early=4))
  let client = ticket_client(store, early=true)
  let e = try client.write_early(b"more than four"[0:8]) catch {
    e => e
  } noraise {
    _ => fail("expected a refusal")
  }
  assert_true(e is @alert.Alert(kind=InternalError, ..))
}

///|
test "tls: a resumed handshake carries a client certificate if one is asked for again" {
  let store = @tls.Sessions::new()
  let anchor = @x509.Roots::new(certs=[der(client_root)][:])
  let sealing = ticket_key(17)
  let server_of = () => {
    let config = @tls.Server::new(
      [der(p256_leaf)],
      p256(),
      tickets=@tls.Tickets::new([sealing][:]),
      client_auth=@tls.ClientAuth::new(mode=Required, roots=anchor),
    )
    @tls.Conn::server(config, rand=rng(3000), now~)
  }
  let client_of = () => {
    let config = @tls.Client::new(
      @x509.Roots::new(certs=[der(root)][:]),
      sessions=store,
      cert=[der(client_leaf)],
      cert_key=key(client_key),
    )
    @tls.Conn::client(config, "a.example", rand=rng(3), now~)
  }
  shuttle(client_of(), server_of())
  let client = client_of()
  let server = server_of()
  shuttle(client, server)
  assert_true(server.is_resumed())
  assert_eq(server.peer().length(), 1)
}

///|
test "tls: the store keeps a bounded number of sessions and forgets the oldest" {
  let store = @tls.Sessions::new(limit=2)
  let born = now
  for i in 0..<4 {
    store.put({
      host: "a.example",
      version: Tls13,
      suite: 0x1301,
      ticket: Bytes::from_array([i.to_byte()]),
      secret: Bytes::make(32, b'\x01'),
      lifetime: 100L,
      born,
      early: 0,
      age_add: 0,
    })
  }
  assert_eq(store.length(), 2)
  // The same ticket put again replaces the first copy rather than piling up.
  store.put({
    host: "a.example",
    version: Tls13,
    suite: 0x1301,
    ticket: Bytes::from_array([3]),
    secret: Bytes::make(32, b'\x02'),
    lifetime: 100L,
    born,
    early: 0,
    age_add: 0,
  })
  assert_eq(store.length(), 2)
  assert_true(store.get(host="a.example", version=Tls13, now~) is Some(_))
  assert_true(store.get(host="b.example", version=Tls13, now~) is None)
  assert_true(
    store.get(host="a.example", version=Tls13, now=born + 200) is None,
  )
}
