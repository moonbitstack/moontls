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
      kind: Psk,
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
    kind: Psk,
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

// ---------------------------------------------------------------- TLS 1.2

///|
/// A TLS 1.2 server that caches session ids, or hands out tickets, or both.
fn server12_of(
  cache? : @tls.Sessions,
  keys? : Array[Bytes],
  now_~ : Int64 = now,
  seed~ : Int32 = 4000,
) -> @tls.Conn raise {
  let tickets = @tls.Tickets::new(
    keys.unwrap_or([])[:],
    count=1,
    lifetime=@tls.ticket_lifetime,
  )
  let config = match cache {
    Some(c) =>
      @tls.Server::new(
        [der(p256_leaf)],
        p256(),
        versions=[Tls12],
        sessions=c,
        tickets~,
      )
    None =>
      @tls.Server::new([der(p256_leaf)], p256(), versions=[Tls12], tickets~)
  }
  @tls.Conn::server(config, rand=rng(seed), now=now_)
}

///|
/// A TLS 1.2 client with a store to remember a session in.
fn client12_of(store : @tls.Sessions, now_~ : Int64 = now) -> @tls.Conn raise {
  let config = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    versions=[Tls12],
    sessions=store,
  )
  @tls.Conn::client(config, "a.example", rand=rng(4), now=now_)
}

///|
test "tls: a TLS 1.2 session id resumes the next connection" {
  let cache = @tls.Sessions::new()
  let store = @tls.Sessions::new()
  let first = client12_of(store)
  let server = server12_of(cache~)
  shuttle(first, server)
  assert_true(first.is_connected())
  assert_eq(first.peer().length(), 1)
  assert_true(store.length() > 0)
  assert_true(cache.length() > 0)
  let second = client12_of(store)
  let resumed = server12_of(cache~)
  shuttle(second, resumed)
  assert_true(second.is_connected())
  assert_true(second.is_resumed())
  assert_true(resumed.is_resumed())
  // An abbreviated handshake shows no certificate, so nothing was verified this time.
  assert_eq(second.peer().length(), 0)
  second.write(b"again"[:])
  shuttle(second, resumed)
  assert_eq(resumed.read(), b"again")
}

///|
test "tls: a TLS 1.2 ticket resumes without the server keeping anything" {
  let store = @tls.Sessions::new()
  let key = ticket_key(21)
  shuttle(client12_of(store), server12_of(keys=[key]))
  assert_true(store.length() > 0)
  let second = client12_of(store)
  let resumed = server12_of(keys=[key])
  shuttle(second, resumed)
  assert_true(second.is_resumed())
  assert_true(resumed.is_resumed())
  second.write(b"ticket"[:])
  shuttle(second, resumed)
  assert_eq(resumed.read(), b"ticket")
}

///|
test "tls: a TLS 1.2 session id the server never issued is a full handshake" {
  let cache = @tls.Sessions::new()
  let store = @tls.Sessions::new()
  shuttle(client12_of(store), server12_of(cache~))
  // A different cache is a different server: the id means nothing to it.
  let second = client12_of(store)
  let fresh = server12_of(cache=@tls.Sessions::new(), seed=5000)
  shuttle(second, fresh)
  assert_true(second.is_connected())
  assert_false(fresh.is_resumed())
  assert_eq(second.peer().length(), 1)
}

///|
test "tls: a TLS 1.2 session that has run out is not resumed" {
  let cache = @tls.Sessions::new()
  let store = @tls.Sessions::new()
  shuttle(client12_of(store), server12_of(cache~))
  let later = now + 100000
  let second = client12_of(store, now_=later)
  let server = server12_of(cache~, now_=later)
  shuttle(second, server)
  assert_true(second.is_connected())
  assert_false(server.is_resumed())
}

///|
test "tls: a client whose clock is a minute off still resumes, without its 0-RTT" {
  // §8.3: a clock difference says the hello may be a replay. That costs the early data and
  // nothing else, or a server would fall back to a full handshake for every client it cannot
  // agree the time with.
  let store = @tls.Sessions::new()
  let k = ticket_key(7)
  shuttle(ticket_client(store, early=true), ticket_server(keys=[k], early=4096))
  let client = @tls.Conn::client(
    @tls.Client::new(
      @x509.Roots::new(certs=[der(root)][:]),
      sessions=store,
      early=true,
    ),
    "a.example",
    rand=rng(2000),
    now=now + 60L,
  )
  let server = ticket_server(keys=[k], early=4096)
  shuttle(client, server)
  assert_true(client.is_resumed())
  assert_true(server.is_resumed())
  assert_false(client.early_accepted())
}

///|
test "tls: a ticket held for half a minute is the same age on both clocks, in milliseconds" {
  // A client counting seconds where the wire means milliseconds would report 30 for 30000, and
  // be declined as a replay at any age past the allowance.
  let store = @tls.Sessions::new()
  let k = ticket_key(7)
  shuttle(ticket_client(store, early=true), ticket_server(keys=[k], early=4096))
  let later = now + 30L
  let client = @tls.Conn::client(
    @tls.Client::new(
      @x509.Roots::new(certs=[der(root)][:]),
      sessions=store,
      early=true,
    ),
    "a.example",
    rand=rng(2000),
    now=later,
  )
  let server = @tls.Conn::server(
    @tls.Server::new(
      [der(p256_leaf)],
      p256(),
      tickets=@tls.Tickets::new([k][:], early=4096),
    ),
    rand=rng(3000),
    now=later,
  )
  shuttle(client, server)
  assert_true(server.is_resumed())
  assert_true(client.early_accepted())
}

///|
test "tls: the allowance is the server's to set" {
  let store = @tls.Sessions::new()
  let k = ticket_key(7)
  shuttle(ticket_client(store, early=true), ticket_server(keys=[k], early=4096))
  let client = @tls.Conn::client(
    @tls.Client::new(
      @x509.Roots::new(certs=[der(root)][:]),
      sessions=store,
      early=true,
    ),
    "a.example",
    rand=rng(2000),
    now=now + 60L,
  )
  let server = @tls.Conn::server(
    @tls.Server::new(
      [der(p256_leaf)],
      p256(),
      tickets=@tls.Tickets::new([k][:], early=4096, drift=120000L),
    ),
    rand=rng(3000),
    now~,
  )
  shuttle(client, server)
  assert_true(client.early_accepted())
}

///|
test "tls: a server with no clock neither issues nor takes a ticket" {
  let store = @tls.Sessions::new()
  let k = ticket_key(7)
  let config = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    tickets=@tls.Tickets::new([k][:]),
  )
  shuttle(ticket_client(store), @tls.Conn::server(config, rand=rng(3000)))
  assert_eq(store.length(), 0)
}

///|
test "tls: a client that keeps tickets says so in its first hello, before it holds one" {
  // A server sends no ticket to a client that did not (RFC 8446 §4.2.9), so without this no
  // conforming server ever gives it the first one.
  let hello_of = (config : @tls.Client) => {
    let client = @tls.Conn::client(config, "a.example", rand=rng(2000), now~)
    let framed = client.take()[5:].to_owned()
    guard @msg.read_hello(framed[4:]) is Some(hello) else {
      abort("no ClientHello")
    }
    hello
  }
  let roots = @x509.Roots::new(certs=[der(root)][:])
  let keeping = hello_of(@tls.Client::new(roots, sessions=@tls.Sessions::new()))
  guard @ext.find(keeping.extensions[:], PskKeyExchangeModes) is Some(_) else {
    fail("no psk_key_exchange_modes")
  }
  assert_true(@ext.find(keeping.extensions[:], PreSharedKey) is None)
  let plain = hello_of(@tls.Client::new(roots))
  assert_true(@ext.find(plain.extensions[:], PskKeyExchangeModes) is None)
}

///|
/// Drive a handshake to its end, one flight at a time, and hand back what the server had left to
/// say once it saw the client's Finished.
fn finish_and_take(client : @tls.Conn, server : @tls.Conn) -> Bytes raise {
  let mut rounds = 0
  // The round that completes the handshake on the server is the one whose output is asked about,
  // so it is left in the outbox rather than delivered.
  while rounds < 10 && !server.is_connected() {
    let up = client.take()
    if up.length() > 0 {
      server.receive(up[:])
    }
    if server.is_connected() {
      break
    }
    let down = server.take()
    if down.length() > 0 {
      client.receive(down[:])
    }
    rounds = rounds + 1
  }
  assert_true(client.is_connected())
  assert_true(server.is_connected())
  server.take()
}

///|
/// RFC 8446 §4.2.9: a ticket is only good for a mode the client advertised, and the only mode this
/// library resumes in is `psk_dhe_ke`. A client that never says so is spared tickets it could not
/// use — here a client with no ticket store, whose ClientHello carries no `psk_key_exchange_modes`.
test "tls: a client that did not advertise psk_dhe_ke is sent no ticket" {
  let config = @tls.Client::new(@x509.Roots::new(certs=[der(root)][:]))
  let client = @tls.Conn::client(config, "a.example", rand=rng(4), now~)
  let server = ticket_server(keys=[ticket_key(11)])
  assert_eq(finish_and_take(client, server).length(), 0)
}

///|
/// The other side of the same rule: a client that keeps tickets says it can resume with (EC)DHE,
/// and the tickets arrive.
test "tls: a client that advertised psk_dhe_ke is sent its tickets" {
  let store = @tls.Sessions::new()
  let client = ticket_client(store)
  let server = ticket_server(keys=[ticket_key(12)], count=2)
  let tickets = finish_and_take(client, server)
  assert_true(tickets.length() > 0)
  client.receive(tickets[:])
  assert_eq(store.length(), 2)
}
