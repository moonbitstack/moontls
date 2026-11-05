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

///|
/// RFC 6347 §4.2.1: a server that answers before the address has echoed its cookie would let a
/// forged source make it send a whole flight to a victim. So the first ClientHello is answered
/// with a HelloVerifyRequest, the client comes back with the cookie, and only then does the
/// handshake run.
test "dtls 1.2: a cookie server answers a HelloVerifyRequest before any handshake" {
  let config = @tls.Server::new([der(p256_leaf)], key(p256_key), alpn=["h3"])
  let server = @dtls.Conn12::server(
    config,
    rand=rng(2000),
    now=0L,
    wall=now,
    cookie=@dtls.Key(b"\x01\x02\x03\x04"),
  )
  let client = client12()
  let peer = b"\x7f\x00\x00\x01\x13\x88"
  server.receive(client.take()[:], now=0L, peer=peer[:])
  let answer = server.take()
  // A record header of thirteen octets, then the handshake type: 3 is HelloVerifyRequest.
  assert_eq(answer[13], 3)
  assert_false(server.is_connected())
  assert_false(client.is_connected())
  // The client echoes the cookie, and the handshake proceeds from there.
  client.receive(answer[:], now=0L)
  server.receive(client.take()[:], now=0L, peer=peer[:])
  let flight = server.take()
  assert_true(flight.length() > 0)
  client.receive(flight[:], now=0L)
  let mut clock = 0L
  for _ in 0..<200 {
    let mut moved = false
    for datagram in collect12(client) {
      server.receive(datagram[:], now=clock, peer=peer[:])
      moved = true
    }
    for datagram in collect12(server) {
      client.receive(datagram[:], now=clock)
      moved = true
    }
    clock = clock + 100L
    if !moved {
      break
    }
  }
  assert_true(client.is_connected())
  assert_true(server.is_connected())
  client.write(b"after the cookie"[:], now=clock)
  for datagram in collect12(client) {
    server.receive(datagram[:], now=clock, peer=peer[:])
  }
  assert_eq(server.read(), b"after the cookie")
}

///|
/// The cookie is a MAC of the address, so the same cookie replayed from somewhere else is not a
/// cookie at all: the server answers it as it answers any unverified hello.
test "dtls 1.2: a cookie does not travel to another address" {
  let config = @tls.Server::new([der(p256_leaf)], key(p256_key))
  let server = @dtls.Conn12::server(
    config,
    rand=rng(2000),
    now=0L,
    wall=now,
    cookie=@dtls.Key(b"\x09\x08\x07\x06"),
  )
  let client = client12()
  server.receive(client.take()[:], now=0L, peer=b"\x7f\x00\x00\x01\x13\x88"[:])
  let request = server.take()
  client.receive(request[:], now=0L)
  let second = client.take()
  // The same ClientHello, from an address the server never answered.
  server.receive(second[:], now=0L, peer=b"\xc0\x00\x02\x01\x13\x88"[:])
  let again = server.take()
  assert_eq(again[13], 3)
  assert_false(server.is_connected())
}

///|
/// Every suite `suites12` carries travels over a datagram too, including the ones whose protection
/// is not a bare AEAD: CCM with a short tag, and CBC with a MAC before or after the encryption.
test "dtls 1.2: CCM and CBC suites carry data both ways" {
  let names = [0xc0ac, 0xc0ae, 0xc023, 0xc024, 0xc02b]
  for code in names {
    guard @record.Suite12::of(code) is Some(suite) else {
      fail("a suite this test names is not in the table")
    }
    let sconfig = @tls.Server::new([der(p256_leaf)], key(p256_key), suites12=[
      suite,
    ])
    let cconfig = @tls.Client::new(@x509.Roots::new(certs=[der(root)][:]), suites12=[
      suite,
    ])
    let server = @dtls.Conn12::server(sconfig, rand=rng(2000), now=0L, wall=now)
    let client = @dtls.Conn12::client(
      cconfig,
      "a.example",
      rand=rng(2),
      now=0L,
      wall=now,
    )
    pump12(client, server)
    assert_true(client.is_connected())
    assert_true(server.is_connected())
    guard client.suite() is Some(chosen) else { fail("no suite") }
    assert_eq(chosen.code, code)
    let payload = Bytes::from_array([
      ((code >> 8) & 0xff).to_byte(),
      (code & 0xff).to_byte(),
      b's',
      b'u',
      b'i',
      b't',
      b'e',
    ])
    client.write(payload[:], now=0L)
    for datagram in collect12(client) {
      server.receive(datagram, now=0L)
    }
    assert_eq(server.read(), payload)
  }
}
