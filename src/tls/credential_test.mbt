// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A server holding more than one certificate: which goes out (RFC 8446 §4.4.2.2, RFC 5246
// §7.4.2), and the empty server_name that says the client's name chose it (RFC 6066 §3).

///|
fn b_credential() -> @tls.Credential raise {
  @tls.Credential::new([der(b_leaf)], key(b_key))
}

///|
/// A server for a.example that also holds b.example's certificate.
fn two_hosts(
  versions~ : Array[@tls.Version] = @tls.versions,
  groups~ : Array[Int32] = @tls.groups,
) -> @tls.Server raise {
  @tls.Server::new([der(p256_leaf)], p256(), versions~, groups~, alternatives=[
    b_credential(),
  ])
}

///|
fn visitor(
  host : String,
  versions~ : Array[@tls.Version] = @tls.versions,
  suites12~ : Array[@record.Suite12] = @tls.suites12,
  groups~ : Array[Int32] = @tls.groups,
  shares~ : Int32 = @tls.shares,
) -> @tls.Conn raise {
  let roots = @x509.Roots::new(certs=[der(root), der(named_root)][:])
  @tls.Conn::client(
    @tls.Client::new(roots, versions~, suites12~, groups~, shares~),
    host,
    rand=rng(3),
    now~,
  )
}

///|
/// The extensions of the ServerHello a server answers a TLS 1.2 client for `host` with.
fn answer12(config : @tls.Server, host : String) -> Array[@ext.Ext] raise {
  let c = visitor(host, versions=[Tls12])
  let s = @tls.Conn::server(config, rand=rng(4), now~)
  s.receive(c.take()[:])
  server_hello_of(s.take()).extensions
}

///|
test "credential: the host a client names picks the certificate" {
  let each : Array[Array[@tls.Version]] = [[Tls13], [Tls12]]
  for versions in each {
    for pair in [("b.example", b_leaf), ("a.example", p256_leaf)] {
      let (host, leaf) = pair
      let c = visitor(host, versions~)
      let s = @tls.Conn::server(two_hosts(versions~), rand=rng(4), now~)
      shuttle(c, s)
      assert_true(c.is_connected())
      assert_true(s.is_connected())
      assert_eq(c.peer()[0], der(leaf))
      assert_eq(s.server_name(), Some(host))
    }
  }
}

///|
test "credential: server_name is answered only when the name chose the certificate" {
  let named = (exts : Array[@ext.Ext]) => {
    @ext.find(exts[:], ServerName) is Some(_)
  }
  assert_true(named(answer12(two_hosts(versions=[Tls12]), "b.example")))
  assert_true(named(answer12(two_hosts(versions=[Tls12]), "a.example")))
  // No certificate is for c.example, so the first goes out whatever the name.
  assert_false(named(answer12(two_hosts(versions=[Tls12]), "c.example")))
  // One certificate: there was nothing for the name to choose.
  let single = @tls.Server::new([der(p256_leaf)], p256(), versions=[Tls12])
  assert_false(named(answer12(single, "a.example")))
}

///|
test "credential: a host no certificate is for gets the first" {
  let c = visitor("c.example")
  let s = @tls.Conn::server(two_hosts(), rand=rng(4), now~)
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("a certificate for another host was taken")
  }
  assert_true(e is @alert.Alert(kind=BadCertificate, ..))
  assert_eq(c.peer()[0], der(p256_leaf))
}

///|
test "credential: the TLS 1.2 suites a client offers pick the key type" {
  let config = @tls.Server::new(
    [der(rsa_leaf)],
    key(rsa_key),
    versions=[Tls12],
    alternatives=[@tls.Credential::new([der(p256_leaf)], p256())],
  )
  let ecdsa = @tls.suites12.filter(s => s.auth is Ecdsa)
  let rsa = @tls.suites12.filter(s => s.auth is Rsa)
  for pair in [(ecdsa, p256_leaf), (rsa, rsa_leaf)] {
    let (suites12, leaf) = pair
    let c = visitor("a.example", versions=[Tls12], suites12~)
    let s = @tls.Conn::server(config, rand=rng(6), now~)
    shuttle(c, s)
    assert_true(c.is_connected())
    assert_eq(c.peer()[0], der(leaf))
  }
}

///|
/// A TLS 1.3 ClientHello for a.example offering only `schemes` for the CertificateVerify.
fn hello_signed_by(schemes : Array[Int32]) -> Bytes raise {
  let (record, _) = @record.decode(client_with().take()[:]).unwrap()
  let (_, body) = @msg.unframe(record.fragment[:]).unwrap()
  let hello = @msg.read_hello(body[:]).unwrap()
  let extensions = hello.extensions.map(e => {
    if e.kind is SignatureAlgorithms {
      @ext.Ext::{ kind: SignatureAlgorithms, data: @ext.schemes(schemes[:]), }
    } else {
      e
    }
  })
  @record.encode(Handshake, @msg.hello({ ..hello, extensions, })[:])
}

///|
test "credential: the signature algorithms of a TLS 1.3 client pick the key" {
  let hello = hello_signed_by([@ext.ecdsa_secp384r1_sha384])
  let alone = @tls.Conn::server(
    @tls.Server::new([der(p256_leaf)], p256()),
    rand=rng(7),
    now~,
  )
  assert_eq(alert_of(() => alone.receive(hello[:])), HandshakeFailure)
  let both = @tls.Conn::server(
    @tls.Server::new([der(p256_leaf)], p256(), alternatives=[
      @tls.Credential::new([der(p384_leaf)], key(p384_key)),
    ]),
    rand=rng(7),
    now~,
  )
  both.receive(hello[:])
  assert_true(server_hello_of(both.take()).suite is (0x1301..<=0x1305))
}

///|
test "credential: the choice made on the first hello holds after a HelloRetryRequest" {
  let c = visitor("b.example", groups=[@ext.secp256r1, @ext.x25519], shares=1)
  let s = @tls.Conn::server(two_hosts(groups=[@ext.x25519]), rand=rng(4), now~)
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_eq(c.peer()[0], der(b_leaf))
}

///|
test "credential: an alternative with an empty chain or another key is refused" {
  let wrong = [
    () => @tls.Credential::new([], p256()),
    () => @tls.Credential::new([der(b_leaf)], p256()),
    () => {
      let config = @tls.Server::new([der(p256_leaf)], p256(), alternatives=[
        { chain: [der(b_leaf)], key: p256(), ocsp: None, },
      ])
      @tls.Credential::new(config.chain, config.key)
    },
  ]
  for make in wrong {
    let e = try make() catch {
      e => e
    } noraise {
      _ => fail("expected a refusal")
    }
    assert_true(e is @asn1.Malformed(_))
  }
}

///|
/// The EncryptedExtensions a QUIC server holding a.example's and b.example's certificates answers a
/// client for `host` with: QUIC carries the handshake messages in the clear, as TLS over TCP does
/// not.
fn encrypted_extensions_for(host : String) -> Array[@ext.Ext] raise {
  let config = @tls.Server::new([der(p256_leaf)], p256(), alpn=["h3"], alternatives=[
    b_credential(),
  ])
  let server = @tls.Conn::quic_server(config, params=b"server", rand=rng(4))
  let client = @tls.Conn::quic_client(
    @tls.Client::new(@x509.Roots::new(certs=[der(root), der(named_root)][:]), alpn=[
      "h3",
    ]),
    host,
    params=b"client",
    rand=rng(3),
    now~,
  )
  for step in client.steps() {
    if step is Send(level, data) {
      server.crypto(level, data[:])
    }
  }
  for step in server.steps() {
    if step is Send(Handshake, data) {
      let (kind, body) = @msg.unframe(data[:]).unwrap()
      assert_true(kind is EncryptedExtensions)
      return @msg.read_encrypted_extensions(body[:]).unwrap()
    }
  }
  fail("no EncryptedExtensions")
}

///|
test "credential: TLS 1.3 answers server_name in EncryptedExtensions when the name chose" {
  let named = (exts : Array[@ext.Ext]) => {
    @ext.find(exts[:], ServerName) is Some(_)
  }
  assert_true(named(encrypted_extensions_for("b.example")))
  assert_true(named(encrypted_extensions_for("a.example")))
  assert_false(named(encrypted_extensions_for("c.example")))
}
