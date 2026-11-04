// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn server12() -> @dtls.Conn12 raise {
  let config = @tls.Server::new([der(p256_leaf)], key(p256_key), alpn=["h3"])
  @dtls.Conn12::server(config, rand=rng(2000), now=0L, wall=now)
}

///|
fn client12() -> @dtls.Conn12 raise {
  let config = @tls.Client::new(@x509.Roots::new(certs=[der(root)][:]), alpn=[
    "h3",
  ])
  @dtls.Conn12::client(config, "a.example", rand=rng(2), now=0L, wall=now)
}

///|
fn collect12(conn : @dtls.Conn12) -> Array[Bytes] {
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
fn pump12(client : @dtls.Conn12, server : @dtls.Conn12) -> Unit raise {
  let mut clock = 0L
  for _ in 0..<200 {
    let mut moved = false
    for datagram in collect12(client) {
      server.receive(datagram, now=clock)
      moved = true
    }
    for datagram in collect12(server) {
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
test "dtls 1.2: a full handshake carries data both ways" {
  let server = server12()
  let client = client12()
  pump12(client, server)
  assert_true(client.is_connected())
  assert_true(server.is_connected())
  assert_eq(client.alpn(), Some("h3"))
  assert_eq(server.alpn(), Some("h3"))
  assert_true(client.version() is Some(@tls.Tls12))
  assert_true(server.suite() is Some(_))
  client.write(b"hello dtls 1.2"[:], now=1000L)
  for datagram in collect12(client) {
    server.receive(datagram, now=1100L)
  }
  assert_eq(server.read(), b"hello dtls 1.2")
  server.write(b"and back again"[:], now=1200L)
  for datagram in collect12(server) {
    client.receive(datagram, now=1300L)
  }
  assert_eq(client.read(), b"and back again")
}

///|
test "dtls 1.2: a flight with no answer is retransmitted at the deadline" {
  let server = server12()
  let client = client12()
  let lost = collect12(client)
  assert_true(lost.length() > 0)
  guard client.deadline() is Some(due) else { fail("the flight is armed") }
  client.tick(now=due)
  let again = collect12(client)
  assert_true(again.length() > 0)
  for datagram in again {
    server.receive(datagram, now=due)
  }
  pump12(client, server)
  assert_true(client.is_connected())
  assert_true(server.is_connected())
}

///|
test "dtls 1.2: use_srtp exports the same keying material on both ends" {
  let server_config = @tls.Server::new(
    [der(p256_leaf)],
    key(p256_key),
    alpn=["h3"],
    srtp=@srtp.supported,
  )
  let client_config = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    alpn=["h3"],
    srtp=@srtp.supported,
  )
  let server = @dtls.Conn12::server(
    server_config,
    rand=rng(2000),
    now=0L,
    wall=now,
  )
  let client = @dtls.Conn12::client(
    client_config,
    "a.example",
    rand=rng(2),
    now=0L,
    wall=now,
  )
  pump12(client, server)
  guard client.srtp() is Some(mine) && server.srtp() is Some(theirs) else {
    fail("use_srtp was not negotiated")
  }
  assert_eq(mine, theirs)
  assert_eq(mine.client_key.length(), 32)
}

///|
test "dtls 1.2: a duplicated datagram does not repeat a message" {
  let server = server12()
  let client = client12()
  let mut clock = 0L
  for _ in 0..<200 {
    let mut moved = false
    for datagram in collect12(client) {
      server.receive(datagram, now=clock)
      server.receive(datagram, now=clock)
      moved = true
    }
    for datagram in collect12(server) {
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
test "dtls 1.2: a duplicated application record is delivered once" {
  let server = server12()
  let client = client12()
  pump12(client, server)
  client.write(b"once"[:], now=1000L)
  let datagram = client.take()
  assert_true(datagram.length() > 0)
  server.receive(datagram, now=1100L)
  server.receive(datagram, now=1100L)
  assert_eq(server.read(), b"once")
}

///|
test "dtls 1.2: the timer starts at a second and doubles with each retransmission" {
  // RFC 6347 §4.2.4.1: an initial timer of one second, doubled at each
  // retransmission up to at least sixty seconds.
  let client = client12()
  ignore(collect12(client))
  guard client.deadline() is Some(first) else { fail("the flight is armed") }
  assert_eq(first, 1000L)
  client.tick(now=first)
  ignore(collect12(client))
  guard client.deadline() is Some(second) else { fail("still armed") }
  assert_eq(second - first, 2000L)
  client.tick(now=second)
  ignore(collect12(client))
  guard client.deadline() is Some(third) else { fail("still armed") }
  assert_eq(third - second, 4000L)
  let mut due = third
  for _ in 0..<8 {
    client.tick(now=due)
    ignore(collect12(client))
    guard client.deadline() is Some(next) else { fail("still armed") }
    assert_true(next - due <= 60000L)
    due = next
  }
}
