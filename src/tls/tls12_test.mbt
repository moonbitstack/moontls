// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn server12(
  leaf : String,
  private_key : @x509.PrivateKey,
  alpn? : Array[String],
  suites12? : Array[@record.Suite12],
  groups? : Array[Int32],
  versions~ : Array[@tls.Version] = [Tls12],
) -> @tls.Conn raise {
  let config = @tls.Server::new(
    [der(leaf)],
    private_key,
    alpn?,
    suites12=suites12.unwrap_or(@tls.suites12),
    groups=groups.unwrap_or(@tls.groups),
    versions~,
  )
  @tls.Conn::server(config, rand=rng(1000))
}

///|
fn client12(
  alpn? : Array[String],
  suites? : Array[@record.Suite],
  suites12? : Array[@record.Suite12],
  groups? : Array[Int32],
  versions~ : Array[@tls.Version] = [Tls12],
  dh_bits~ : Int32 = @tls.dh_bits,
) -> @tls.Conn raise {
  let config = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    alpn?,
    suites=suites.unwrap_or(@tls.suites),
    suites12=suites12.unwrap_or(@tls.suites12),
    groups=groups.unwrap_or(@tls.groups),
    versions~,
    dh_bits~,
  )
  @tls.Conn::client(config, "a.example", rand=rng(1), now~)
}

///|
test "tls 1.2: a client and a server finish the handshake and talk" {
  let s = server12(p256_leaf, p256())
  let c = client12()
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_true(s.is_connected())
  assert_eq(c.version(), Some(Tls12))
  assert_eq(s.version(), Some(Tls12))
  assert_eq(s.server_name(), Some("a.example"))
  c.write(b"ping"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"ping")
  s.write(b"pong"[:])
  shuttle(c, s)
  assert_eq(c.read(), b"pong")
}

///|
test "tls 1.2: every key type, suite and curve" {
  for
    pair in [
      (p256_leaf, p256_key),
      (p384_leaf, p384_key),
      (rsa_leaf, rsa_key),
      (ed_leaf, ed_key),
    ] {
    let (leaf, pem) = pair
    let auth : @record.Auth = if pem == rsa_key { Rsa } else { Ecdsa }
    for suite in @tls.suites12.filter(s => s.auth == auth) {
      let s = server12(leaf, key(pem))
      let c = client12(suites12=[suite])
      shuttle(c, s)
      assert_true(c.is_connected())
      assert_eq(s.suite12(), Some(suite))
      assert_eq(c.suite12(), Some(suite))
      c.write(Bytes::make(40000, b'x')[:])
      shuttle(c, s)
      assert_eq(s.read().length(), 40000)
    }
  }
  for
    group in [
      @ext.x25519, @ext.x448, @ext.secp256r1, @ext.secp384r1, @ext.secp521r1,
    ] {
    let s = server12(p256_leaf, p256(), groups=[group])
    let c = client12(groups=[group, @ext.secp256r1])
    shuttle(c, s)
    assert_true(c.is_connected())
  }
}

///|
test "tls 1.2: ALPN is agreed in the hellos" {
  let s = server12(p256_leaf, p256(), alpn=["h2", "http/1.1"])
  let c = client12(alpn=["http/1.1", "h2"])
  shuttle(c, s)
  assert_eq(c.alpn(), Some("h2"))
  assert_eq(s.alpn(), Some("h2"))
}

///|
test "tls 1.2: both versions enabled still means TLS 1.3 when both ends have it" {
  let s = server12(p256_leaf, p256(), versions=@tls.versions)
  let c = client12(versions=@tls.versions)
  shuttle(c, s)
  assert_eq(c.version(), Some(Tls13))
  assert_eq(s.version(), Some(Tls13))
}

///|
test "tls 1.2: a client or a server that only has 1.2 gets 1.2 from one with both" {
  let s = server12(p256_leaf, p256(), versions=@tls.versions)
  let c = client12()
  shuttle(c, s)
  assert_eq(c.version(), Some(Tls12))
  assert_true(c.is_connected())
  let s = server12(p256_leaf, p256())
  let c = client12(versions=@tls.versions)
  shuttle(c, s)
  assert_eq(c.version(), Some(Tls12))
  assert_true(c.is_connected())
}

///|
test "tls 1.2: an end with only 1.3 refuses one with only 1.2" {
  let s = server12(p256_leaf, p256(), versions=[Tls13])
  let c = client12()
  assert_eq(alert_of(() => shuttle(c, s)), ProtocolVersion)
}

///|
test "tls 1.2: a suite with no certificate to match is a handshake_failure" {
  let s = server12(rsa_leaf, key(rsa_key), suites12=[
    @record.Suite12::of(0xc030).unwrap(),
  ])
  let c = client12(suites12=[@record.Suite12::of(0xc02b).unwrap()])
  assert_eq(alert_of(() => shuttle(c, s)), HandshakeFailure)
}

///|
test "tls 1.2: the downgrade sentinel stops a 1.3 client" {
  // A server with both versions is talked down by a hello that says only 1.2, and marks its random.
  let lower = client12()
  let s = server12(p256_leaf, p256(), versions=@tls.versions)
  s.receive(lower.take()[:])
  let flight = s.take()
  // That flight, shown to a client that offered 1.3 too, is a downgrade.
  let c = client12(versions=@tls.versions)
  c.take() |> ignore
  assert_eq(alert_of(() => c.receive(flight[:])), IllegalParameter)
}

///|
test "tls 1.2: TLS_FALLBACK_SCSV is refused by a server with something better" {
  let c = client12()
  let wire = c.take()
  let (hello, _) = @record.decode(wire[:]).unwrap()
  let (_, body) = @msg.unframe(hello.fragment[:]).unwrap()
  let parsed = @msg.read_hello(body[:]).unwrap()
  let marked = @msg.hello({ ..parsed, suites: [..parsed.suites, 0x5600], })
  let record = @record.encode(Handshake, marked[:])
  let s = server12(p256_leaf, p256(), versions=@tls.versions)
  assert_eq(alert_of(() => s.receive(record[:])), InappropriateFallback)
}

///|
test "tls 1.2: a Finished that was tampered with fails the handshake" {
  let s = server12(p256_leaf, p256())
  let c = client12()
  s.receive(c.take()[:])
  c.receive(s.take()[:])
  let flight = c.take().to_array()
  flight[flight.length() - 1] = flight[flight.length() - 1] ^ b'\x01'
  assert_eq(
    alert_of(() => s.receive(Bytes::from_array(flight)[:])),
    BadRecordMac,
  )
}

///|
test "tls 1.2: application data before the handshake ends is refused" {
  let s = server12(p256_leaf, p256())
  let c = client12()
  s.receive(c.take()[:])
  let early = @record.encode(ApplicationData, b"too soon"[:])
  assert_eq(alert_of(() => s.receive(early[:])), UnexpectedMessage)
}

///|
test "tls 1.2: a change_cipher_spec out of place is refused" {
  let s = server12(p256_leaf, p256())
  let c = client12()
  s.receive(c.take()[:])
  let ccs = @record.encode(ChangeCipherSpec, b"\x01"[:])
  assert_eq(alert_of(() => s.receive(ccs[:])), UnexpectedMessage)
}

///|
test "tls 1.2: a ServerHelloDone before the Certificate is refused" {
  let s = server12(p256_leaf, p256())
  let c = client12()
  s.receive(c.take()[:])
  // The server sends its flight as one record, so the hello is cut out of it by its own length.
  let wire = s.take()
  let (flight, _) = @record.decode(wire[:]).unwrap()
  let head = flight.fragment
  let size = 4 +
    ((head[1].to_int() << 16) | (head[2].to_int() << 8) | head[3].to_int())
  let hello = @record.encode(Handshake, flight.fragment[0:size])
  c.receive(hello[:])
  assert_eq(
    alert_of(() => {
      c.receive(
        @record.encode(Handshake, @msg.frame(ServerHelloDone, b""[:])[:])[:],
      )
    }),
    UnexpectedMessage,
  )
}

///|
test "tls 1.2: a KeyUpdate is not a TLS 1.2 message" {
  let s = server12(p256_leaf, p256())
  let c = client12()
  shuttle(c, s)
  assert_eq(alert_of(() => c.update()), InternalError)
  assert_true(c.is_connected())
}

///|
/// A ServerHello choosing TLS 1.2 with `extensions`, shown to a client that has said its hello.
fn hello_to(
  c : @tls.Conn,
  extensions : Array[@ext.Ext],
  suite~ : Int32 = 0xc02b,
) -> Unit raise {
  c.take() |> ignore
  let sh = @msg.server_hello({
    version: 0x0303,
    random: Bytes::make(32, b'\x07'),
    session_id: b"",
    suite,
    compression: 0,
    extensions,
  })
  c.receive(@record.encode(Handshake, sh[:])[:])
}

///|
let indication : @ext.Ext = {
  kind: RenegotiationInfo,
  data: @ext.no_renegotiation(),
}

///|
test "tls 1.2: a server that does not indicate RFC 5746 is refused" {
  let c = client12()
  assert_eq(alert_of(() => hello_to(c, [])), HandshakeFailure)
  let c = client12()
  let spliced : @ext.Ext = { kind: RenegotiationInfo, data: b"\x01\x02", }
  assert_eq(alert_of(() => hello_to(c, [spliced])), HandshakeFailure)
}

///|
test "tls 1.2: a ServerHello is held to what the client offered" {
  let c = client12()
  let unknown : @ext.Ext = { kind: Other(0x1234), data: b"", }
  assert_eq(
    alert_of(() => hello_to(c, [indication, unknown])),
    UnsupportedExtension,
  )
  let c = client12()
  assert_eq(alert_of(() => hello_to(c, [indication, indication])), DecodeError)
  let c = client12()
  assert_eq(
    alert_of(() => hello_to(c, [indication], suite=0xc013)),
    IllegalParameter,
  )
  let c = client12()
  let empty : @ext.Ext = { kind: EcPointFormats, data: b"\x01\x01", }
  assert_eq(alert_of(() => hello_to(c, [indication, empty])), IllegalParameter)
}

///|
test "tls 1.2: a ServerKeyExchange before the Certificate is refused" {
  let c = client12()
  hello_to(c, [indication])
  let message = @msg.frame(ServerKeyExchange, b"\x03\x00\x1d"[:])
  assert_eq(
    alert_of(() => c.receive(@record.encode(Handshake, message[:])[:])),
    UnexpectedMessage,
  )
}

///|
test "tls 1.2: a HelloRequest in the handshake is ignored" {
  let c = client12()
  hello_to(c, [indication])
  c.receive(@record.encode(Handshake, @msg.frame(Other(0), b""[:])[:])[:])
  assert_false(c.is_closed())
}

///|
test "tls 1.2: a signature that does not verify is a decrypt_error" {
  let s = server12(p256_leaf, p256())
  let c = client12()
  s.receive(c.take()[:])
  let flight = s.take().to_array()
  // The flight ends in a ServerHelloDone of four octets, and the signature runs up to it.
  let at = flight.length() - 8
  flight[at] = flight[at] ^ b'\x01'
  assert_eq(
    alert_of(() => c.receive(Bytes::from_array(flight)[:])),
    DecryptError,
  )
}

///|
test "tls 1.2: an ECDSA key on a curve the client left out is refused" {
  let s = server12(p256_leaf, p256())
  let c = client12(groups=[@ext.x25519])
  assert_eq(alert_of(() => shuttle(c, s)), HandshakeFailure)
  let s = server12(p256_leaf, p256())
  let c = client12(groups=[@ext.x25519, @ext.secp256r1])
  shuttle(c, s)
  assert_true(c.is_connected())
}

///|
test "tls 1.2: a client with no signature_algorithms is refused rather than signed for with SHA-1" {
  let c = client12()
  let (record, _) = @record.decode(c.take()[:]).unwrap()
  let (_, body) = @msg.unframe(record.fragment[:]).unwrap()
  let hello = @msg.read_hello(body[:]).unwrap()
  let bare = @msg.hello({
    ..hello,
    extensions: hello.extensions.filter(e => e.kind != SignatureAlgorithms),
  })
  let s = server12(p256_leaf, p256())
  assert_eq(
    alert_of(() => s.receive(@record.encode(Handshake, bare[:])[:])),
    HandshakeFailure,
  )
}

///|
test "tls 1.2: the six default suite codes are the IANA ones, and read back" {
  assert_eq(@tls.suites12.map(s => s.code), [
    0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030,
  ])
  for suite in @record.all12 {
    assert_eq(@record.Suite12::of(suite.code), Some(suite))
  }
  assert_eq(@record.Suite12::of(0x1301), None)
}

///|
test "tls 1.2: a hello offers what the versions enabled say, and nothing else" {
  let only13 = client12(versions=[Tls13], suites=[Aes128Gcm])
  let (r13, _) = @record.decode(only13.take()[:]).unwrap()
  let (_, b13) = @msg.unframe(r13.fragment[:]).unwrap()
  let h13 = @msg.read_hello(b13[:]).unwrap()
  assert_eq(h13.suites, [0x1301])
  assert_true(@ext.find(h13.extensions[:], ExtendedMasterSecret) is None)
  let both = client12(
    versions=@tls.versions,
    suites=[Aes128Gcm],
    suites12=@tls.suites12.filter(s => s.bulk == Aead(Aes128Gcm)),
  )
  let (r, _) = @record.decode(both.take()[:]).unwrap()
  let (_, b) = @msg.unframe(r.fragment[:]).unwrap()
  let h = @msg.read_hello(b[:]).unwrap()
  assert_eq(h.suites, [0x1301, 0xc02b, 0xc02f])
  assert_true(@ext.find(h.extensions[:], ExtendedMasterSecret) is Some(_))
  assert_true(@ext.find(h.extensions[:], RenegotiationInfo) is Some(_))
}

///|
/// A TLS 1.2 ClientHello with `change` applied, as it goes on the wire.
fn hello12(change : (@msg.Hello) -> @msg.Hello) -> Bytes raise {
  let c = client12()
  let (record, _) = @record.decode(c.take()[:]).unwrap()
  let (_, body) = @msg.unframe(record.fragment[:]).unwrap()
  @record.encode(
    Handshake,
    @msg.hello(change(@msg.read_hello(body[:]).unwrap()))[:],
  )
}

///|
test "tls 1.2: renegotiation_info is answered only when it was asked for" {
  let answer = (hello : Bytes) => {
    let s = server12(p256_leaf, p256())
    s.receive(hello[:])
    let (record, _) = @record.decode(s.take()[:]).unwrap()
    let (_, body) = @msg.unframe(record.fragment[:]).unwrap()
    @msg.read_server_hello(body[:]).unwrap().extensions
  }
  let asked = answer(hello12(h => h))
  assert_true(@ext.find(asked[:], RenegotiationInfo) is Some(_))
  let without = (h : @msg.Hello) => {
    ..h,
    extensions: h.extensions.filter(e => e.kind != RenegotiationInfo),
  }
  let silent = answer(hello12(without))
  assert_true(@ext.find(silent[:], RenegotiationInfo) is None)
  let scsv = answer(
    hello12(h => {
      let bare = without(h)
      { ..bare, suites: [..bare.suites, 0x00ff], }
    }),
  )
  assert_true(@ext.find(scsv[:], RenegotiationInfo) is Some(_))
}

///|
test "tls 1.2: TLS_FALLBACK_SCSV goes by the hello's version and the server's best" {
  let at = (version : Int32) => {
    hello12(h => { ..h, version, suites: [..h.suites, 0x5600], })
  }
  let s = server12(p256_leaf, p256())
  assert_eq(alert_of(() => s.receive(at(0x0302)[:])), InappropriateFallback)
  let s = server12(p256_leaf, p256())
  s.receive(at(0x0303)[:])
  assert_true(s.take().length() > 0)
}

///|
test "tls 1.2: a host name with anything but printable ASCII is an illegal_parameter" {
  for
    name in [
      "a\u{7}b.example", "a b.example", "a\tb.example", "caf\u{e9}.example",
    ] {
    let hello = hello12(h => {
      ..h,
      extensions: h.extensions.map(e => {
        if e.kind == ServerName {
          { kind: ServerName, data: @ext.server_name(name), }
        } else {
          e
        }
      }),
    })
    let s = server12(p256_leaf, p256())
    assert_eq(alert_of(() => s.receive(hello[:])), IllegalParameter)
  }
}

///|
test "tls 1.2: a malformed extension is reported before any mismatch" {
  let hello = hello12(h => {
    ..h,
    suites: [0x002f],
    extensions: h.extensions.map(e => {
      if e.kind == ServerName {
        { kind: ServerName, data: b"\xff\xff\xff\xff", }
      } else {
        e
      }
    }),
  })
  let s = server12(p256_leaf, p256())
  assert_eq(alert_of(() => s.receive(hello[:])), DecodeError)
}
