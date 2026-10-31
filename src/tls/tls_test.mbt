///|
let now : Int64 = 1767225600

///|
/// Deterministic randomness: SHA-256 of a counter, so a failure reproduces.
fn rng(seed : Int32) -> (Int32) -> Bytes {
  let counter = Ref(seed)
  n => {
    let out = Buffer()
    while out.length() < n {
      counter.val = counter.val + 1
      out.write_bytes(@sha2.hash(@utf8.encode(counter.val.to_string())[:]))
    }
    out.to_bytes()[0:n].to_owned()
  }
}

///|
fn der(text : String) -> Bytes raise {
  @x509.pem(text)
}

///|
fn key(text : String) -> @x509.PrivateKey raise {
  @x509.PrivateKey::pem(text)
}

///|
fn server_with(
  leaf : String,
  key : @x509.PrivateKey,
  alpn? : Array[String],
  suites? : Array[@record.Suite],
  groups? : Array[Int32],
) -> @tls.Conn raise {
  let config = @tls.Server::new(
    [der(leaf)],
    key,
    alpn?,
    suites=suites.unwrap_or(@tls.suites),
    groups=groups.unwrap_or(@tls.groups),
  )
  @tls.Conn::server(config, rand=rng(1000))
}

///|
fn client_with(
  host~ : String = "a.example",
  roots~ : Array[String] = [root],
  alpn? : Array[String],
  suites? : Array[@record.Suite],
  groups? : Array[Int32],
) -> @tls.Conn raise {
  let config = @tls.Client::new(
    @x509.Roots::new(certs=roots.map(der)[:]),
    alpn?,
    suites=suites.unwrap_or(@tls.suites),
    groups=groups.unwrap_or(@tls.groups),
  )
  @tls.Conn::client(config, host, rand=rng(1), now~)
}

///|
/// Shuttle bytes both ways until neither side has anything left to say.
fn shuttle(client : @tls.Conn, server : @tls.Conn) -> Unit raise {
  for _ in 0..<16 {
    let a = client.take()
    let b = server.take()
    if a.length() == 0 && b.length() == 0 {
      break
    }
    server.receive(a[:])
    client.receive(b[:])
  }
}

///|
fn p256() -> @x509.PrivateKey raise {
  key(p256_key)
}

///|
test "tls: a P-256 server and a client finish the handshake and talk" {
  let s = server_with(p256_leaf, p256())
  let c = client_with()
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_true(s.is_connected())
  assert_eq(s.server_name(), Some("a.example"))
  assert_eq(c.peer().length(), 1)
  c.write(b"ping"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"ping")
  s.write(b"pong"[:])
  shuttle(c, s)
  assert_eq(c.read(), b"pong")
}

///|
test "tls: every key type signs a CertificateVerify the client accepts" {
  let keys = [(p384_leaf, p384_key), (rsa_leaf, rsa_key), (ed_leaf, ed_key)]
  for pair in keys {
    let (leaf, pem) = pair
    let s = server_with(leaf, key(pem))
    let c = client_with()
    shuttle(c, s)
    assert_true(c.is_connected())
  }
}

///|
test "tls: each suite and each group" {
  for suite in @tls.suites {
    let s = server_with(p256_leaf, p256())
    let c = client_with(suites=[suite])
    shuttle(c, s)
    assert_eq(c.suite(), Some(suite))
    assert_eq(s.suite(), Some(suite))
  }
  for group in @tls.groups {
    let s = server_with(p256_leaf, p256(), groups=[group])
    let c = client_with(groups=[group])
    shuttle(c, s)
    assert_true(c.is_connected())
  }
}

///|
test "tls: a share for the wrong group gets a HelloRetryRequest, then a handshake" {
  let s = server_with(p256_leaf, p256(), groups=[@ext.x25519])
  let c = client_with(groups=[@ext.secp256r1, @ext.x25519])
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_true(s.is_connected())
  c.write(b"after retry"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"after retry")
}

///|
test "tls: ALPN takes the server's preference among what the client offers" {
  let s = server_with(p256_leaf, p256(), alpn=["http/1.1", "h2"])
  let c = client_with(alpn=["h2", "http/1.1"])
  shuttle(c, s)
  assert_eq(c.alpn(), Some("http/1.1"))
  assert_eq(s.alpn(), Some("http/1.1"))
  let s2 = server_with(p256_leaf, p256(), alpn=["h3"])
  let c2 = client_with(alpn=["h2"])
  let e = try shuttle(c2, s2) catch {
    e => e
  } noraise {
    _ => fail("expected an alert")
  }
  assert_true(e is @alert.Alert(kind=NoApplicationProtocol, ..))
}

///|
test "tls: the client refuses a chain it cannot trust, and says why" {
  let s = server_with(p256_leaf, p256())
  let c = client_with(host="b.example")
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("expected an alert")
  }
  assert_true(e is @alert.Alert(kind=BadCertificate, ..))
  assert_eq(c.refused(), Some(Host("b.example")))
  assert_true(c.is_closed())
  let s2 = server_with(p256_leaf, p256())
  let c2 = client_with(roots=[other_root])
  let e2 = try shuttle(c2, s2) catch {
    e => e
  } noraise {
    _ => fail("expected an alert")
  }
  assert_true(e2 is @alert.Alert(kind=UnknownCa, ..))
}

///|
test "tls: key update in both directions, then close_notify" {
  let s = server_with(p256_leaf, p256())
  let c = client_with()
  shuttle(c, s)
  c.update()
  c.write(b"one"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"one")
  s.write(b"two"[:])
  shuttle(c, s)
  assert_eq(c.read(), b"two")
  c.close()
  shuttle(c, s)
  assert_true(s.is_closed())
}

///|
test "tls: a tampered record is a bad_record_mac" {
  let s = server_with(p256_leaf, p256())
  let c = client_with()
  shuttle(c, s)
  c.write(b"secret"[:])
  let bytes = c.take().to_array()
  bytes[bytes.length() - 1] = bytes[bytes.length() - 1] ^ b'\x01'
  let e = try s.receive(Bytes::from_array(bytes)[:]) catch {
    e => e
  } noraise {
    _ => fail("expected an alert")
  }
  assert_true(e is @alert.Alert(kind=BadRecordMac, ..))
}

///|
test "tls: application data arrives across record boundaries fed a byte at a time" {
  let s = server_with(p256_leaf, p256())
  let c = client_with()
  for _ in 0..<16 {
    let a = c.take()
    for b in a {
      s.receive(Bytes::from_array([b])[:])
    }
    let b = s.take()
    for x in b {
      c.receive(Bytes::from_array([x])[:])
    }
    if a.length() == 0 && b.length() == 0 {
      break
    }
  }
  assert_true(c.is_connected())
  let big = Bytes::make(40000, b'x')
  c.write(big[:])
  shuttle(c, s)
  assert_eq(s.read().length(), 40000)
}

///|
test "tls: a server refuses a key that is not its leaf's, and an empty chain" {
  for chain in [[der(p256_leaf)], []] {
    let e = try @tls.Server::new(chain, key(p384_key)) catch {
      e => e
    } noraise {
      _ => fail("expected a refusal")
    }
    assert_true(e is @asn1.Malformed(_))
  }
}

///|
test "tls: the ClientHello offers the PKCS#1 schemes certificate chains are signed with" {
  let c = client_with()
  let record = c.take()
  // A record header, then a handshake header, then the ClientHello body.
  guard @msg.read_hello(record[9:]) is Some(hello) else {
    fail("no ClientHello")
  }
  guard @ext.find(hello.extensions[:], SignatureAlgorithms) is Some(e) else {
    fail("no signature_algorithms")
  }
  guard @ext.read_schemes(e.data[:]) is Some(schemes) else {
    fail("signature_algorithms did not read")
  }
  for s in [@ext.rsa_pkcs1_sha256, @ext.rsa_pkcs1_sha384, @ext.rsa_pkcs1_sha512] {
    assert_true(schemes.contains(s))
  }
  assert_true(schemes.contains(@ext.rsa_pss_rsae_sha256))
}

///|
/// The client's ClientHello again, as a record, with an early_data offer added.
fn hello_with_early(c : @tls.Conn) -> Bytes raise {
  guard @msg.read_hello(c.take()[9:]) is Some(ch) else {
    fail("no ClientHello")
  }
  let early = @ext.Ext::{ kind: EarlyData, data: b"", }
  let raw = @msg.hello({ ..ch, extensions: ch.extensions + [early], })
  @record.encode(Handshake, raw[:])
}

///|
test "tls: a server reads past 0-RTT data it declines, up to its early_limit" {
  let s = server_with(p256_leaf, p256())
  let garbage = @record.encode(ApplicationData, Bytes::make(1000, b'\x5a')[:])
  s.receive((hello_with_early(client_with()) + garbage + garbage)[:])
  assert_true(s.take().length() > 0)
  assert_false(s.is_closed())
  let flood = @record.encode(ApplicationData, Bytes::make(16000, b'\x5a')[:])
  let s2 = server_with(p256_leaf, p256())
  let e = try
    s2.receive((hello_with_early(client_with()) + flood + flood)[:])
  catch {
    e => e
  } noraise {
    _ => fail("expected an alert past the limit")
  }
  assert_true(e is @alert.Alert(kind=BadRecordMac, ..))
  let s3 = server_with(p256_leaf, p256())
  let c3 = client_with()
  let e3 = try s3.receive((c3.take() + garbage)[:]) catch {
    e => e
  } noraise {
    _ => fail("expected an alert without an early_data offer")
  }
  assert_true(e3 is @alert.Alert(kind=BadRecordMac, ..))
}

///|
test "tls: the finite-field groups, when both sides opt in" {
  for group in [@ext.ffdhe2048, @ext.ffdhe3072] {
    let s = server_with(p256_leaf, p256(), groups=[group])
    let c = client_with(groups=[group])
    shuttle(c, s)
    assert_true(c.is_connected())
    c.write(b"ff"[:])
    shuttle(c, s)
    assert_eq(s.read(), b"ff")
  }
  // A default server does not accept them.
  let s = server_with(p256_leaf, p256())
  let c = client_with(groups=[@ext.ffdhe2048])
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("expected an alert")
  }
  assert_true(e is @alert.Alert(kind=HandshakeFailure, ..))
}

///|
/// A client that will be asked to retry, and the server that asks, with the client's second
/// flight (its compatibility-mode change_cipher_spec, then the second ClientHello) taken off it.
fn retried() -> (@tls.Conn, Bytes, @msg.Hello) raise {
  let s = server_with(p256_leaf, p256(), groups=[@ext.x25519])
  let c = client_with(groups=[@ext.secp256r1, @ext.x25519])
  s.receive(c.take()[:])
  c.receive(s.take()[:])
  let flight = c.take()
  let ccs = flight[0:6].to_owned()
  assert_eq(ccs, @record.encode(ChangeCipherSpec, b"\x01"[:]))
  guard @msg.read_hello(flight[6 + 9:]) is Some(second) else {
    fail("no second ClientHello")
  }
  (s, ccs, second)
}

///|
/// RFC 8446 §4.1.2: the ClientHello after a HelloRetryRequest is the first one again but for the
/// fields a retry changes, so anything else that differs is an illegal_parameter.
test "tls: a second ClientHello that is not the first one again is refused" {
  let changes = [
    (h : @msg.Hello) => { ..h, extensions: h.extensions.rev(), },
    (h : @msg.Hello) => { ..h, random: Bytes::make(32, b'\x07'), },
    (h : @msg.Hello) => { ..h, suites: h.suites.rev(), },
  ]
  for change in changes {
    let (s, ccs, second) = retried()
    let record = @record.encode(Handshake, @msg.hello(change(second))[:])
    let e = try s.receive((ccs + record)[:]) catch {
      e => e
    } noraise {
      _ => fail("expected illegal_parameter")
    }
    assert_true(e is @alert.Alert(kind=IllegalParameter, ..))
  }
  let (s, ccs, second) = retried()
  s.receive((ccs + @record.encode(Handshake, @msg.hello(second)[:]))[:])
  assert_false(s.is_closed())
}

///|
test "tls: a client that gives up mid-handshake with a plaintext alert is heard" {
  let s = server_with(p256_leaf, p256())
  let c = client_with()
  s.receive(c.take()[:])
  s.take() |> ignore
  let alert = @record.encode(Alert, @alert.encode(@alert.fatal(UnknownCa))[:])
  let e = try s.receive(alert[:]) catch {
    e => e
  } noraise {
    _ => fail("expected the peer's alert")
  }
  assert_true(e is @alert.Alert(kind=UnknownCa, ..))
  assert_true(s.is_closed())
  assert_eq(s.take().length(), 0)
}

///|
/// RFC 8446 §5.1: a plaintext record carries at most 2^14 octets; only a sealed one, under
/// application_data, may be longer.
test "tls: a plaintext record past 2^14 is a record_overflow" {
  let s = server_with(p256_leaf, p256())
  let big = Bytes::make(@record.max_fragment + 1, b'\x16')
  let header = b"\x16\x03\x03" + Bytes::from_array([b'\x40', b'\x01'])
  let e = try s.receive((header + big)[:]) catch {
    e => e
  } noraise {
    _ => fail("expected record_overflow")
  }
  assert_true(e is @alert.Alert(kind=RecordOverflow, ..))
}
