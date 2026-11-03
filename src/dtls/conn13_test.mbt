// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn server13() -> @dtls.Conn13 raise {
  let config = @tls.Server::new([der(p256_leaf)], key(p256_key), alpn=["h3"])
  @dtls.Conn13::server(config, rand=rng(2000), now=0L, wall=now)
}

///|
fn client13() -> @dtls.Conn13 raise {
  let config = @tls.Client::new(@x509.Roots::new(certs=[der(root)][:]), alpn=[
    "h3",
  ])
  @dtls.Conn13::client(config, "a.example", rand=rng(2), now=0L, wall=now)
}

///|
fn collect(conn : @dtls.Conn13) -> Array[Bytes] {
  let out : Array[Bytes] = []
  for ;; {
    let datagram = conn.take()
    if datagram.length() == 0 {
      break
    }
    out.push(datagram)
  }
  out
}

///|
/// Carry datagrams both ways until neither end has anything to say.
fn pump(client : @dtls.Conn13, server : @dtls.Conn13) -> Unit raise {
  let mut clock = 0L
  for _ in 0..<200 {
    let mut moved = false
    for datagram in collect(client) {
      server.receive(datagram, now=clock)
      moved = true
    }
    for datagram in collect(server) {
      client.receive(datagram, now=clock)
      moved = true
    }
    clock = clock + 100L
    if !moved {
      break
    }
  }
}

///|
test "dtls 1.3: a full handshake carries data both ways" {
  let server = server13()
  let client = client13()
  pump(client, server)
  assert_true(client.is_connected())
  assert_true(server.is_connected())
  assert_eq(client.alpn(), Some("h3"))
  assert_eq(server.alpn(), Some("h3"))
  assert_eq(server.server_name(), Some("a.example"))
  assert_true(client.version() is Some(@tls.Tls13))
  assert_true(server.suite() is Some(@record.Aes128Gcm | @record.Aes256Gcm))
  client.write(b"hello over datagrams"[:], now=1000L)
  for datagram in collect(client) {
    server.receive(datagram, now=1100L)
  }
  assert_eq(server.read(), b"hello over datagrams")
  server.write(b"and back"[:], now=1200L)
  for datagram in collect(server) {
    client.receive(datagram, now=1300L)
  }
  assert_eq(client.read(), b"and back")
}

///|
test "dtls 1.3: the encrypted flight survives arriving out of order" {
  let server = server13()
  let client = client13()
  for datagram in collect(client) {
    server.receive(datagram, now=0L)
  }
  let flight = collect(server)
  assert_true(flight.length() >= 2)
  // The clear records — the ACKs and the ServerHello that opens the epoch —
  // go first and in order; the ciphertexts ones then arrive backwards.
  let ciphertexts : Array[Bytes] = []
  for datagram in flight {
    if (datagram[0].to_int() & 0xe0) == 0x20 {
      ciphertexts.push(datagram)
    } else {
      client.receive(datagram, now=100L)
    }
  }
  assert_true(ciphertexts.length() >= 2)
  let mut i = ciphertexts.length()
  while i > 0 {
    i = i - 1
    client.receive(ciphertexts[i], now=100L)
  }
  pump(client, server)
  assert_true(client.is_connected())
  assert_true(server.is_connected())
}

///|
test "dtls 1.3: a duplicated datagram does not repeat a message" {
  let server = server13()
  let client = client13()
  let mut clock = 0L
  for _ in 0..<200 {
    let mut moved = false
    for datagram in collect(client) {
      server.receive(datagram, now=clock)
      server.receive(datagram, now=clock)
      moved = true
    }
    for datagram in collect(server) {
      client.receive(datagram, now=clock)
      client.receive(datagram, now=clock)
      moved = true
    }
    clock = clock + 100L
    if !moved {
      break
    }
  }
  assert_true(client.is_connected())
  assert_true(server.is_connected())
}

///|
test "dtls 1.3: a flight with no answer is retransmitted at the deadline" {
  let server = server13()
  let client = client13()
  let lost = collect(client)
  assert_true(lost.length() > 0)
  guard client.deadline() is Some(due) else { fail("the flight is armed") }
  client.tick(now=due)
  let again = collect(client)
  assert_true(again.length() > 0)
  for datagram in again {
    server.receive(datagram, now=due)
  }
  pump(client, server)
  assert_true(client.is_connected())
  assert_true(server.is_connected())
}

///|
test "dtls 1.3: a datagram that is not DTLS is dropped, not fatal" {
  let server = server13()
  server.receive(b"\x00\x01\x02\x03"[:], now=0L)
  server.receive(@record.encode(@record.ApplicationData, b"junk"[:])[:], now=0L)
  assert_false(server.is_closed())
}
