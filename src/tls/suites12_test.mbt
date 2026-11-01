// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn leaves12(suite : @record.Suite12) -> Array[(String, String)] {
  match suite.auth {
    Rsa => [(rsa_leaf, rsa_key)]
    Ecdsa => [(p256_leaf, p256_key), (ed_leaf, ed_key)]
  }
}

///|
fn hello_of(flight : Bytes) -> @msg.Hello raise {
  let (rec, _) = @record.decode(flight[:]).unwrap()
  let (_, body) = @msg.unframe(rec.fragment[:]).unwrap()
  @msg.read_hello(body[:]).unwrap()
}

///|
fn server_hello_of(flight : Bytes) -> @msg.Server raise {
  let (rec, _) = @record.decode(flight[:]).unwrap()
  let (_, body) = @msg.unframe(rec.fragment[:]).unwrap()
  @msg.read_server_hello(body[:]).unwrap()
}

///|
test "tls 1.2: every suite in the table carries data both ways" {
  for suite in @record.all12 {
    for pair in leaves12(suite) {
      let (leaf, pem) = pair
      let s = server12(leaf, key(pem), suites12=[suite])
      let c = client12(suites12=[suite])
      shuttle(c, s)
      assert_true(c.is_connected())
      assert_eq(s.suite12(), Some(suite))
      assert_eq(c.suite12(), Some(suite))
      c.write(Bytes::make(40000, b'x')[:])
      shuttle(c, s)
      assert_eq(s.read().length(), 40000)
      s.write(b"back"[:])
      shuttle(c, s)
      assert_eq(c.read(), b"back")
    }
  }
}

///|
test "tls 1.2: the server's order decides, and only what the key can back counts" {
  let cbc = @record.Suite12::of(0xc027).unwrap()
  let gcm = @record.Suite12::of(0xc02f).unwrap()
  let s = server12(rsa_leaf, key(rsa_key), suites12=[cbc, gcm])
  let c = client12(suites12=[gcm, cbc])
  shuttle(c, s)
  assert_eq(s.suite12(), Some(cbc))
  let mine = @record.Suite12::of(0xc02b).unwrap()
  let s = server12(rsa_leaf, key(rsa_key), suites12=[mine, gcm])
  let c = client12(suites12=[mine, gcm])
  shuttle(c, s)
  assert_eq(s.suite12(), Some(gcm))
}

///|
test "tls 1.2: defaults leave out RSA exchange, DHE, CCM and CBC" {
  for suite in @tls.suites12 {
    assert_true(suite.exchange is Ecdhe)
    assert_true(suite.bulk is Aead(_))
  }
  let rsa = @record.Suite12::of(0x009c).unwrap()
  let s = server12(rsa_leaf, key(rsa_key))
  let c = client12(suites12=[rsa])
  assert_eq(alert_of(() => shuttle(c, s)), HandshakeFailure)
}

///|
test "tls 1.2: encrypt_then_mac is offered with CBC, and answered only for it" {
  let cbc = @record.Suite12::of(0xc027).unwrap()
  let gcm = @record.Suite12::of(0xc02f).unwrap()
  let offered = hello_of(client12(suites12=[cbc]).take())
  assert_true(@ext.find(offered.extensions[:], EncryptThenMac) is Some(_))
  let plain = hello_of(client12(suites12=[gcm]).take())
  assert_true(@ext.find(plain.extensions[:], EncryptThenMac) is None)
  let c = client12(suites12=[cbc])
  let s = server12(rsa_leaf, key(rsa_key), suites12=[cbc])
  s.receive(c.take()[:])
  let answer = server_hello_of(s.take())
  assert_true(@ext.find(answer.extensions[:], EncryptThenMac) is Some(_))
  let c = client12(suites12=[cbc, gcm])
  let s = server12(rsa_leaf, key(rsa_key), suites12=[gcm])
  s.receive(c.take()[:])
  let answer = server_hello_of(s.take())
  assert_true(@ext.find(answer.extensions[:], EncryptThenMac) is None)
}

///|
test "tls 1.2: a client turns down a DHE prime below its floor" {
  let dhe = @record.Suite12::of(0x009e).unwrap()
  let s = server12(rsa_leaf, key(rsa_key), suites12=[dhe])
  let c = client12(suites12=[dhe], dh_bits=3072)
  assert_eq(alert_of(() => shuttle(c, s)), InsufficientSecurity)
}

///|
test "tls 1.2: a client that names finite-field groups is held to them" {
  let dhe = @record.Suite12::of(0x009e).unwrap()
  let s = server12(rsa_leaf, key(rsa_key), suites12=[dhe])
  let c = client12(suites12=[dhe], groups=[@ext.x25519, 0x0101])
  shuttle(c, s)
  assert_true(c.is_connected())
  let s = server12(rsa_leaf, key(rsa_key), suites12=[dhe])
  let c = client12(suites12=[dhe], groups=[@ext.x25519, 0x01ff])
  assert_eq(alert_of(() => shuttle(c, s)), HandshakeFailure)
}

///|
test "tls 1.2: a certificate of the wrong kind for the suite is refused" {
  // A server that picks an ECDSA suite with an RSA certificate, by way of a client told that is fine.
  let suite = @record.Suite12::of(0xc02b).unwrap()
  let c = client12(suites12=[suite])
  let s = server12(rsa_leaf, key(rsa_key), suites12=[
    @record.Suite12::of(0xc02f).unwrap(),
  ])
  assert_eq(alert_of(() => shuttle(c, s)), HandshakeFailure)
}

///|
test "tls 1.2: a wrapped premaster that was tampered with fails at Finished" {
  let rsa = @record.Suite12::of(0x009c).unwrap()
  let c = client12(suites12=[rsa])
  let s = server12(rsa_leaf, key(rsa_key), suites12=[rsa])
  s.receive(c.take()[:])
  c.receive(s.take()[:])
  let flight = c.take().to_array()
  // Past the record header, the handshake header and the two-octet length.
  flight[5 + 4 + 2 + 40] = flight[5 + 4 + 2 + 40] ^ b'\x01'
  let kind = alert_of(() => s.receive(Bytes::from_array(flight)[:]))
  assert_eq(kind, BadRecordMac)
}

///|
test "premaster: what is wrapped unwraps" {
  let private_key = rsa_private()
  let secret = Bytes::make(48, b'\x03')
  let wrapped = @keys.wrap_premaster(
    private_key.public(),
    secret[:],
    rand=rng(5),
  )
  assert_eq(wrapped.length(), private_key.size())
  assert_eq(
    @keys.unwrap_premaster(private_key, wrapped[:], version=0x0303, rand=n => {
      Bytes::make(n, b'\xaa')
    }),
    secret,
  )
}

///|
fn rsa_private() -> @rsa.PrivateKey raise {
  guard key(rsa_key) is Rsa(k) else { fail("the fixture is an RSA key") }
  k
}

///|
/// A block put together by hand: the padding is whatever `break` makes of a good one.
fn block_of(k : Int32, spoil : (Array[Byte]) -> Unit) -> Bytes {
  let start = k - 48
  let block = Array::make(k, b'\x55')
  block[0] = b'\x00'
  block[1] = b'\x02'
  block[start - 1] = b'\x00'
  block[start] = b'\x03'
  block[start + 1] = b'\x03'
  spoil(block)
  Bytes::from_array(block)
}

///|
test "premaster: every way a block can be wrong gives the stand-in, and only then" {
  let private_key = rsa_private()
  let public_key = private_key.public()
  let k = private_key.size()
  let start = k - 48
  let unwrap = (spoil : (Array[Byte]) -> Unit) => {
    let wrapped = public_key.rsaep(block_of(k, spoil)[:])
    @keys.unwrap_premaster(private_key, wrapped[:], version=0x0303, rand=n => {
      Bytes::make(n, b'\xaa')
    })
  }
  let stand_in = Bytes::make(48, b'\xaa')
  assert_true(unwrap(_ => ()) != stand_in)
  let spoilers : Array[(Array[Byte]) -> Unit] = [
    block => block[1] = b'\x01',
    block => block[1] = b'\x00',
    block => block[10] = b'\x00',
    block => block[2] = b'\x00',
    block => block[start - 2] = b'\x00',
    block => block[start - 1] = b'\x01',
    block => block[start] = b'\x02',
    block => block[start + 1] = b'\x02',
  ]
  for spoil in spoilers {
    assert_eq(unwrap(spoil), stand_in)
  }
}

///|
test "premaster: a block of the wrong length gives the stand-in" {
  let private_key = rsa_private()
  let k = private_key.size()
  for size in [0, 1, k - 1, k + 1] {
    assert_eq(
      @keys.unwrap_premaster(
        private_key,
        Bytes::make(size, b'\x01')[:],
        version=0x0303,
        rand=n => Bytes::make(n, b'\xaa'),
      ),
      Bytes::make(48, b'\xaa'),
    )
  }
}
