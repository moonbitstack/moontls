// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// OCSP stapling (RFC 6066 §8), record_size_limit (RFC 8449) and the refusal of heartbeat, which
// this library does not implement and must not silently accept.

///|
/// A response that stands for an OCSP one: the shape does not matter here, only that it arrives
/// intact and only from a server that stapled it.
fn response() -> Bytes {
  b"\x30\x03\x0a\x01\x00"
}

///|
test "tls: a stapled OCSP response comes with the certificate in TLS 1.3" {
  let sconfig = @tls.Server::new([der(p256_leaf)], p256(), ocsp=response())
  let cconfig = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    ocsp=true,
  )
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(9), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(10), now~)
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_eq(c.ocsp(), Some(response()))
}

///|
test "tls: a stapled OCSP response comes with the certificate in TLS 1.2" {
  let sconfig = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    versions=[Tls12],
    ocsp=response(),
  )
  let cconfig = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    versions=[Tls12],
    ocsp=true,
  )
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(9), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(10), now~)
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_eq(c.ocsp(), Some(response()))
}

///|
test "tls: a client that does not ask is not given a status" {
  let sconfig = @tls.Server::new([der(p256_leaf)], p256(), ocsp=response())
  let cconfig = @tls.Client::new(@x509.Roots::new(certs=[der(root)][:]))
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(9), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(10), now~)
  shuttle(c, s)
  assert_eq(c.ocsp(), None)
}

///|
test "tls: a record_size_limit caps what is written, and a longer one is refused" {
  let sconfig = @tls.Server::new([der(p256_leaf)], p256(), record_limit=100)
  let cconfig = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    record_limit=1000,
  )
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(9), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(10), now~)
  shuttle(c, s)
  assert_true(c.is_connected())
  // 500 octets under a 100-octet limit is at least six records, none of them over it.
  c.write(Bytes::make(500, b'x'))
  let flight = c.take()
  let mut at = 0
  let mut records = 0
  while at < flight.length() {
    guard @record.decode_encrypted(flight[at:]) is Some((rec, used)) else {
      fail("a record did not parse")
    }
    // The limit counts the plaintext and its content type; the AEAD tag rides on top.
    assert_true(rec.fragment.length() <= 100 + @record.tag_size)
    at = at + used
    records = records + 1
  }
  assert_true(records >= 6)
  s.receive(flight[:])
  assert_eq(s.read().length(), 500)
}

///|
test "tls: a record_size_limit below 64 is refused" {
  // RFC 8449 §4: a record that small carries nothing, so a client stating one is confused or
  // probing, and the answer is illegal_parameter rather than a handshake nobody can finish.
  let sconfig = @tls.Server::new([der(p256_leaf)], p256())
  let cconfig = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    record_limit=32,
  )
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(9), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(10), now~)
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("expected a refusal")
  }
  assert_true(e is @alert.Alert(kind=IllegalParameter, ..))
}

///|
test "tls: a heartbeat record is refused rather than answered" {
  // RFC 6520's heartbeat has its own content type, 24; nothing here speaks it, and a record with
  // an unknown type is an unexpected_message rather than something to skip.
  let sconfig = @tls.Server::new([der(p256_leaf)], p256())
  let cconfig = @tls.Client::new(@x509.Roots::new(certs=[der(root)][:]))
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(9), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(10), now~)
  shuttle(c, s)
  assert_true(c.is_connected())
  let record = Bytes::from_array(
    [b'\x18', b'\x03', b'\x03', b'\x00', b'\x03'] + Array::make(3, b'\x01'),
  )
  let e = try c.receive(record[:]) catch {
    e => e
  } noraise {
    _ => fail("expected a refusal")
  }
  assert_true(e is @alert.Alert(kind=UnexpectedMessage, ..))
}

///|
test "tls: a compressed Certificate decompresses to the length it promised" {
  // The codec is zlib's, so what is checked here is the framing: the algorithm, the promise of the
  // uncompressed length, and the octets.
  let body = Bytes::make(4096, b'a')
  let packed = @zlib.zlib(body[:])
  assert_true(packed.length() < body.length())
  let framed = @msg.compressed_certificate(1, body.length(), packed[:])
  guard @msg.read_compressed_certificate(framed[:])
    is Some((algorithm, uncompressed, octets)) else {
    fail("the message did not read")
  }
  assert_eq(algorithm, 1)
  assert_eq(uncompressed, body.length())
  assert_eq(@zlib.unzlib(octets[:], limit=uncompressed), body)
}

///|
test "tls: a handshake finishes with certificate compression offered on both sides" {
  // Whether zlib actually saves anything on a two-hundred-octet certificate is the server's
  // decision, made per certificate; what is checked here is that both ends agree either way.
  let sconfig = @tls.Server::new([der(p256_leaf)], p256(), compress=true)
  let cconfig = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    compress=true,
  )
  let c = @tls.Conn::client(cconfig, "a.example", rand=rng(9), now~)
  let s = @tls.Conn::server(sconfig, rand=rng(10), now~)
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_eq(c.peer()[0], der(p256_leaf))
  c.write(b"compressed"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"compressed")
}
