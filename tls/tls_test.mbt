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
fn hex(s : String) -> Bytes raise {
  @base16.decode(s)
}

///|
fn server_with(
  leaf : String,
  key : @tls.Key,
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
fn p256() -> @tls.Key raise {
  Ecdsa(@ecdsa.PrivateKey::new(hex(p256_key)[:], curve=P256))
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
  let keys : Array[(String, @tls.Key)] = [
    (p384_leaf, Ecdsa(@ecdsa.PrivateKey::new(hex(p384_key)[:], curve=P384))),
    (
      rsa_leaf,
      Rsa(@rsa.PrivateKey::new(hex(rsa_n)[:], hex(rsa_e)[:], hex(rsa_d)[:])),
    ),
    (ed_leaf, Ed25519(@ed25519.PrivateKey::of_secret(hex(ed_key)[:]))),
  ]
  for pair in keys {
    let (leaf, key) = pair
    let s = server_with(leaf, key)
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
