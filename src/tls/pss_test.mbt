// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RSASSA-PSS certificates (RFC 4055): their keys sign under the rsa_pss_pss schemes and no others
// (RFC 8446 §4.2.3), under the one digest their parameters name when they name one, and are never
// encrypted to.

///|
fn pss_server(
  leaf : String,
  pem : String,
  versions~ : Array[@tls.Version] = @tls.versions,
  suites12~ : Array[@record.Suite12] = @tls.suites12,
) -> @tls.Conn raise {
  @tls.Conn::server(
    @tls.Server::new([der(leaf)], key(pem), versions~, suites12~),
    rand=rng(11),
    now~,
  )
}

///|
fn pss_client(
  versions~ : Array[@tls.Version] = @tls.versions,
  suites12~ : Array[@record.Suite12] = @tls.suites12,
  schemes12~ : Array[Int32] = @tls.schemes12,
) -> @tls.Conn raise {
  @tls.Conn::client(
    @tls.Client::new(
      @x509.Roots::new(certs=[der(named_root)][:]),
      versions~,
      suites12~,
      schemes12~,
    ),
    "pss.example",
    rand=rng(12),
    now~,
  )
}

///|
test "pss: an RSASSA-PSS certificate serves a handshake in TLS 1.3 and TLS 1.2" {
  let each : Array[Array[@tls.Version]] = [[Tls13], [Tls12]]
  for versions in each {
    for pair in [(pss_leaf, pss_key), (pss384_leaf, pss384_key)] {
      let (leaf, pem) = pair
      let c = pss_client(versions~)
      let s = pss_server(leaf, pem, versions~)
      shuttle(c, s)
      assert_true(c.is_connected())
      assert_true(s.is_connected())
      c.write(b"signed"[:])
      shuttle(c, s)
      assert_eq(s.read(), b"signed")
    }
  }
}

///|
/// What a TLS 1.3 server holding `leaf` answers a hello offering only `scheme`: `None` for a
/// ServerHello, or the alert.
fn answer_to(leaf : String, pem : String, scheme : Int32) -> @alert.Kind? raise {
  let s = @tls.Conn::server(
    @tls.Server::new([der(leaf)], key(pem)),
    rand=rng(13),
    now~,
  )
  s.receive(hello_signed_by([scheme])[:]) catch {
    @alert.Alert(kind~, ..) => return Some(kind)
    e => raise e
  }
  None
}

///|
test "pss: each kind of RSA key signs under its own schemes alone" {
  let rsae = [
    @ext.rsa_pss_rsae_sha256, @ext.rsa_pss_rsae_sha384, @ext.rsa_pss_rsae_sha512,
  ]
  let pss = [
    @ext.rsa_pss_pss_sha256, @ext.rsa_pss_pss_sha384, @ext.rsa_pss_pss_sha512,
  ]
  for scheme in rsae {
    assert_eq(answer_to(rsa_leaf, rsa_key, scheme), None)
    assert_eq(answer_to(pss_leaf, pss_key, scheme), Some(HandshakeFailure))
  }
  for scheme in pss {
    assert_eq(answer_to(rsa_leaf, rsa_key, scheme), Some(HandshakeFailure))
    assert_eq(answer_to(pss_leaf, pss_key, scheme), None)
  }
  // A key its parameters hold to SHA-384 signs under rsa_pss_pss_sha384 and nothing else.
  for scheme in [..rsae, ..pss] {
    let expected : @alert.Kind? = if scheme == @ext.rsa_pss_pss_sha384 {
      None
    } else {
      Some(HandshakeFailure)
    }
    assert_eq(answer_to(pss384_leaf, pss384_key, scheme), expected)
  }
}

///|
test "pss: TLS 1.2 never encrypts to an RSASSA-PSS key" {
  let transport = @record.all12.filter(s => s.exchange is Rsa)
  let c = pss_client(versions=[Tls12], suites12=transport)
  let s = pss_server(pss_leaf, pss_key, versions=[Tls12], suites12=transport)
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("an RSA key exchange went to an RSASSA-PSS key")
  }
  assert_true(e is @alert.Alert(kind=HandshakeFailure, ..))
  // The client holds to the same rule: an rsaEncryption server's flight with its certificate
  // swapped for the PSS one is refused at the certificate.
  let c = pss_client(versions=[Tls12], suites12=transport)
  let s = pss_server(rsa_leaf, rsa_key, versions=[Tls12], suites12=transport)
  s.receive(c.take()[:])
  let swapped = rewrite12(s.take(), (kind, body) => {
    if kind is Certificate {
      @msg.certificate12([der(pss_leaf)][:])
    } else {
      body
    }
  })
  let e = try c.receive(swapped[:]) catch {
    e => e
  } noraise {
    _ => fail("the client encrypted to an RSASSA-PSS key")
  }
  assert_true(e is @alert.Alert(kind=UnsupportedCertificate, ..))
}

///|
test "pss: an RSASSA-PSS key does not sign PKCS#1 in TLS 1.2" {
  let c = pss_client(versions=[Tls12], schemes12=[@ext.rsa_pkcs1_sha256])
  let s = pss_server(pss_leaf, pss_key, versions=[Tls12])
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("an RSASSA-PSS key signed PKCS#1")
  }
  assert_true(e is @alert.Alert(kind=HandshakeFailure, ..))
}

///|
test "pss: a TLS 1.2 client refuses a PKCS#1 signature from an RSASSA-PSS key" {
  let c = pss_client(versions=[Tls12])
  let s = pss_server(pss_leaf, pss_key, versions=[Tls12])
  let hello = c.take()
  s.receive(hello[:])
  let client_random = hello_of(hello).random
  let server_random = Ref(b"")
  guard key(pss_key) is Rsa(k) else { fail("not an RSA key") }
  let forged = rewrite12(s.take(), (kind, body) => {
    match kind {
      ServerHello => {
        server_random.val = @msg.read_server_hello(body[:]).unwrap().random
        body
      }
      ServerKeyExchange => {
        let (group, public, _, _) = @msg.read_server_key_exchange(body[:]).unwrap()
        let params = @msg.key_params(group, public[:])
        let signed = Buffer()
        signed.write_bytes(client_random)
        signed.write_bytes(server_random.val)
        signed.write_bytes(params)
        let sig = k
          .with_scheme(digest=Sha256, scheme=Pkcs1)
          .sign(signed.to_bytes()[:])
        @msg.server_key_exchange(params[:], @ext.rsa_pkcs1_sha256, sig[:])
      }
      _ => body
    }
  })
  let e = try c.receive(forged[:]) catch {
    e => e
  } noraise {
    _ => fail("a PKCS#1 signature from an RSASSA-PSS key was taken")
  }
  assert_true(e is @alert.Alert(kind=DecryptError, ..))
}
