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

///|
test "dtls 1.3: use_srtp exports the same keying material on both ends" {
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
  let server = @dtls.Conn13::server(
    server_config,
    rand=rng(2000),
    now=0L,
    wall=now,
  )
  let client = @dtls.Conn13::client(
    client_config,
    "a.example",
    rand=rng(2),
    now=0L,
    wall=now,
  )
  pump(client, server)
  guard client.srtp() is Some(mine) && server.srtp() is Some(theirs) else {
    fail("use_srtp was not negotiated")
  }
  assert_eq(mine, theirs)
  assert_eq(mine.client_key.length(), 32)
  assert_eq(mine.client_salt.length(), 12)
}

///|
test "dtls 1.3: a duplicated application record is delivered once" {
  let server = server13()
  let client = client13()
  pump(client, server)
  client.write(b"once"[:], now=1000L)
  let datagram = client.take()
  assert_true(datagram.length() > 0)
  server.receive(datagram, now=1100L)
  server.receive(datagram, now=1100L)
  assert_eq(server.read(), b"once")
}

// ------------------------------------------------------------- the cookie

///|
/// A cookie server: the key is the caller's, so a test can tell two servers apart by whether they
/// accept each other's cookies.
fn cookie_server(secret : Bytes) -> @dtls.Conn13 raise {
  let config = @tls.Server::new([der(p256_leaf)], key(p256_key), alpn=["h3"])
  @dtls.Conn13::server(
    config,
    rand=rng(2000),
    now=0L,
    wall=now,
    cookie=@dtls.Cookie::Key(secret),
  )
}

///|
/// The one whole handshake message a flight carries in the clear, reassembled from whatever
/// fragments it was cut into, as `(type, message)` where the message is the TLS-shaped one the
/// transcript is taken over. `None` when the flight holds no whole plaintext handshake message.
fn message_of(flight : Array[Bytes]) -> (Int32, Bytes)? raise {
  let mut inbound : @dtls.Flight? = None
  for datagram in flight {
    guard @dtls.shape(datagram[0]) is Plain(@record.Handshake) else { continue }
    guard @dtls.decode(datagram[:]) is Some((_, _, fragment, _)) else {
      continue
    }
    guard @dtls.read_piece(fragment[:]) is Some((piece, _)) else { continue }
    // A flight starts where its first message is numbered, which is not zero for everything a
    // server sends after a HelloRetryRequest.
    let flight = match inbound {
      Some(f) => f
      None => {
        let f = @dtls.Flight::new(from=piece.seq)
        inbound = Some(f)
        f
      }
    }
    for message in flight.take(piece) {
      guard @msg.unframe(message[:]) is Some((kind, _)) else { continue }
      return Some((kind.code(), message))
    }
  }
  None
}

///|
/// The cookie a ClientHello message carries, or `None`.
fn hello_cookie(message : Bytes) -> Bytes? {
  guard @msg.unframe(message[:]) is Some((_, body)) else { return None }
  guard @msg.read_hello(body[:], cookie=true) is Some(hello) else {
    return None
  }
  match @ext.find(hello.extensions[:], Cookie) {
    Some(e) => @ext.read_cookie(e.data[:])
    None => None
  }
}

///|
/// The key shares a ClientHello offers, as `(group, public key)`.
fn hello_shares(message : Bytes) -> Array[(Int32, Bytes)] {
  guard @msg.unframe(message[:]) is Some((_, body)) else { return [] }
  // A DTLS hello has the cookie field in front of the suites (RFC 9147 §5.3), even the empty one.
  guard @msg.read_hello(body[:], cookie=true) is Some(hello) else { return [] }
  match @ext.find(hello.extensions[:], KeyShare) {
    Some(e) =>
      match @ext.read_shares(e.data[:]) {
        Some(shares) => shares
        None => []
      }
    None => []
  }
}

///|
/// Feed `flight` to a fresh cookie server and answer with the datagrams it sends back, which for a
/// hello it has not seen before is the HelloRetryRequest alone.
fn retry_answer(
  flight : Array[Bytes],
  peer : BytesView,
  secret : Bytes,
) -> Array[Bytes] raise {
  let server = cookie_server(secret)
  for datagram in flight {
    server.receive(datagram, now=0L, peer~)
  }
  // Nothing is kept and no key is derived: what the server owes is one retry.
  assert_false(server.is_connected())
  let answer = collect(server)
  guard message_of(answer) is Some((2, hrr)) else {
    fail("a HelloRetryRequest is owed")
  }
  guard @msg.unframe(hrr[:]) is Some((_, body)) else { fail("a whole message") }
  guard @msg.read_server_hello(body[:]) is Some(sh) else {
    fail("a whole message")
  }
  assert_true(@hs.is_retry(sh))
  answer
}

///|
/// What a fresh cookie server makes of `flight` from `peer`: the alert it gives up with, in the
/// name `@alert.Kind` knows it by, or `"none"` when it went on with the handshake.
fn refusal(
  flight : Array[Bytes],
  peer : BytesView,
  secret : Bytes,
) -> String raise {
  let server = cookie_server(secret)
  let caught = try {
    for datagram in flight {
      server.receive(datagram, now=0L, peer~)
    }
    None
  } catch {
    e => Some(e)
  }
  match caught {
    Some(@alert.Alert(kind=@alert.IllegalParameter, ..)) => "illegal_parameter"
    Some(_) => "another alert"
    None => "none"
  }
}

///|
/// The datagrams a fresh cookie server answers `flight` with, from `peer`.
fn collected(
  flight : Array[Bytes],
  peer : BytesView,
  secret : Bytes,
) -> Array[Bytes] raise {
  let server = cookie_server(secret)
  for datagram in flight {
    server.receive(datagram, now=0L, peer~)
  }
  collect(server)
}

///|
/// The HelloRetryRequest message itself, out of the datagrams `retry_answer` returned.
fn retry_message(answer : Array[Bytes]) -> Bytes raise {
  guard message_of(answer) is Some((2, hrr)) else {
    fail("a HelloRetryRequest is owed")
  }
  hrr
}

///|
/// The cookie a HelloRetryRequest message asks to have echoed.
fn retry_cookie(hrr : Bytes) -> Bytes raise {
  guard @msg.unframe(hrr[:]) is Some((_, body)) else { fail("a whole message") }
  guard @msg.read_server_hello(body[:]) is Some(sh) else {
    fail("a whole message")
  }
  guard @hs.read_retry_cookie(sh) is Some(cookie) else {
    fail("a retry that asks for nothing says nothing")
  }
  cookie
}

///|
test "dtls 1.3: a cookie server answers a HelloRetryRequest before any handshake" {
  let client = client13()
  let flight = collect(client)
  guard message_of(flight) is Some((1, hello)) else { fail("a ClientHello") }
  assert_true(hello_cookie(hello) is None)
  let hrr = retry_message(
    retry_answer(flight, b"192.0.2.1:4433"[:], b"a cookie key"),
  )
  guard @msg.unframe(hrr[:]) is Some((_, body)) else { fail("a whole message") }
  guard @msg.read_server_hello(body[:]) is Some(sh) else {
    fail("a whole message")
  }
  // A retry that asks for a cookie alone asks for no key share: the client already sent what it
  // means to use, and a second hello that changed them would have thrown them away.
  assert_eq(@hs.retry_group(sh), None)
  assert_true(retry_cookie(hrr).length() > 32)
}

///|
test "dtls 1.3: the second ClientHello repeats the shares and carries the cookie" {
  let client = client13()
  let flight = collect(client)
  guard message_of(flight) is Some((1, hello1)) else { fail("a ClientHello") }
  let answer = retry_answer(flight, b"192.0.2.1:4433"[:], b"a cookie key")
  let cookie = retry_cookie(retry_message(answer))
  for datagram in answer {
    client.receive(datagram, now=100L)
  }
  guard message_of(collect(client)) is Some((1, hello2)) else {
    fail("the second ClientHello")
  }
  // RFC 8446 §4.1.2: the shares are the ones already sent, unchanged — a retry that asks for no
  // group asks for no new key. Both lists are checked non-empty first: two reads that both failed
  // would compare equal and say nothing.
  assert_true(hello_shares(hello1).length() > 0)
  assert_eq(hello_shares(hello2), hello_shares(hello1))
  assert_eq(hello_cookie(hello2), Some(cookie))
}

///|
test "dtls 1.3: a cookie is an answer about one address" {
  let client = client13()
  let flight = collect(client)
  let answer = retry_answer(flight, b"192.0.2.1:4433"[:], b"a cookie key")
  assert_true(retry_cookie(retry_message(answer)).length() > 32)
  for datagram in answer {
    client.receive(datagram, now=100L)
  }
  let second = collect(client)
  // RFC 9147 §5.1: a ClientHello whose cookie this server did not give ends the handshake with
  // illegal_parameter. It is not owed a second retry — a spoofer that never received the first one
  // would be handed the second as well.
  assert_eq(
    refusal(second, b"192.0.2.2:4433"[:], b"a cookie key"),
    "illegal_parameter",
  )
  assert_eq(
    refusal(second, b"192.0.2.1:4433"[:], b"another key"),
    "illegal_parameter",
  )
  // The address the cookie was given to walks on: a ServerHello, not another retry.
  guard message_of(collected(second, b"192.0.2.1:4433"[:], b"a cookie key"))
    is Some((2, sh)) else {
    fail("a ServerHello is owed")
  }
  guard @msg.unframe(sh[:]) is Some((_, body)) else { fail("a whole message") }
  guard @msg.read_server_hello(body[:]) is Some(hello) else {
    fail("a whole message")
  }
  assert_false(@hs.is_retry(hello))
}

///|
test "dtls 1.3: the handshake completes through the cookie exchange" {
  let client = client13()
  let server = cookie_server(b"a cookie key")
  let peer = b"192.0.2.1:4433"[:]
  for datagram in collect(client) {
    server.receive(datagram, now=0L, peer~)
  }
  for datagram in collect(server) {
    client.receive(datagram, now=100L)
  }
  for datagram in collect(client) {
    server.receive(datagram, now=200L, peer~)
  }
  for datagram in collect(server) {
    client.receive(datagram, now=300L)
  }
  for datagram in collect(client) {
    server.receive(datagram, now=400L, peer~)
  }
  assert_true(client.is_connected())
  assert_true(server.is_connected())
  assert_eq(server.alpn(), Some("h3"))
  // The retry is what the transcript is taken over: the first hello enters as its hash, and the
  // second one is message zero of the flight the server reads.
  assert_eq(client.read(), b"")
}

///|
test "dtls 1.3: a cookie and a key share are asked for in one retry" {
  // A server that runs one group only, against a client that offered a share for another: the
  // retry has to carry both requests, because §4.1.4 allows exactly one retry.
  let config = @tls.Server::new([der(p256_leaf)], key(p256_key), alpn=["h3"], groups=[
    @ext.secp256r1,
  ])
  let server = @dtls.Conn13::server(
    config,
    rand=rng(2000),
    now=0L,
    wall=now,
    cookie=@dtls.Cookie::Key(b"a cookie key"),
  )
  let client = client13()
  let peer = b"192.0.2.1:4433"[:]
  for datagram in collect(client) {
    server.receive(datagram, now=0L, peer~)
  }
  guard message_of(collect(server)) is Some((2, hrr)) else {
    fail("a HelloRetryRequest is owed")
  }
  guard @msg.unframe(hrr[:]) is Some((_, body)) else { fail("a whole message") }
  guard @msg.read_server_hello(body[:]) is Some(sh) else {
    fail("a whole message")
  }
  assert_eq(@hs.retry_group(sh), Some(@ext.secp256r1))
  assert_true(@hs.read_retry_cookie(sh) is Some(_))
}

///|
test "dtls 1.3: a hello that puts a cookie in the DTLS field is refused" {
  // RFC 9147 §5.3: the field stays for compatibility and must be empty; the cookie travels in an
  // extension. A hello that fills it is a DTLS 1.2 client this server cannot answer.
  let client = client13()
  guard message_of(collect(client)) is Some((1, hello)) else {
    fail("a ClientHello")
  }
  guard @msg.unframe(hello[:]) is Some((_, body)) else {
    fail("a whole message")
  }
  guard @msg.read_hello(body[:], cookie=true) is Some(base) else {
    fail("a whole message")
  }
  let filled = @msg.hello({ ..base, cookie: b"old style", }, cookie=true)
  let flight : Array[Bytes] = []
  for one in @dtls.pieces(filled, seq=0, room=1171) {
    flight.push(
      @dtls.encode(Handshake, { epoch: 0UL, seq: 0UL, }, @dtls.piece(one)),
    )
  }
  assert_eq(
    refusal(flight, b"192.0.2.1:4433"[:], b"a cookie key"),
    "illegal_parameter",
  )
}

///|
test "dtls 1.3: a server that kept nothing finishes the handshake a new instance began" {
  // The point of the cookie: the instance that answered the first hello keeps nothing, so the
  // second hello may reach a different one. The numbers a flight starts at have to come from the
  // hello, because the HelloRetryRequest that took message zero went out from the other instance.
  let client = client13()
  let peer = b"192.0.2.1:4433"[:]
  let opener = cookie_server(b"a cookie key")
  for datagram in collect(client) {
    opener.receive(datagram, now=0L, peer~)
  }
  for datagram in collect(opener) {
    client.receive(datagram, now=100L)
  }
  let closer = cookie_server(b"a cookie key")
  for datagram in collect(client) {
    closer.receive(datagram, now=200L, peer~)
  }
  for datagram in collect(closer) {
    client.receive(datagram, now=300L)
  }
  for datagram in collect(client) {
    closer.receive(datagram, now=400L, peer~)
  }
  assert_true(client.is_connected())
  assert_true(closer.is_connected())
  assert_eq(client.alpn(), Some("h3"))
}
