// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A server that asks the client for a certificate, over `versions`, judging client chains to
/// `anchors`.
fn asking_server(
  mode~ : @tls.Ask,
  anchors~ : Array[String] = [client_root],
  versions~ : Array[@tls.Version] = @tls.versions,
) -> @tls.Conn raise {
  let config = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    versions~,
    client_auth=@tls.ClientAuth::new(
      mode~,
      roots=@x509.Roots::new(certs=anchors.map(der)[:]),
    ),
  )
  @tls.Conn::server(config, rand=rng(2000), now~)
}

///|
/// A client with a certificate to show, or without one.
fn showing_client(
  cert~ : Array[String] = [],
  key_? : @x509.PrivateKey,
  versions~ : Array[@tls.Version] = @tls.versions,
) -> @tls.Conn raise {
  let roots = @x509.Roots::new(certs=[der(root)][:])
  let config = match key_ {
    Some(k) =>
      @tls.Client::new(roots, versions~, cert=cert.map(der), cert_key=k)
    None => @tls.Client::new(roots, versions~, cert=cert.map(der))
  }
  @tls.Conn::client(config, "a.example", rand=rng(2), now~)
}

///|
/// The alert a handshake ends with, or a failure when it ends without one.

///|
/// Shuttle until one end gives up, and require the alert it gave up with.
fn expect_alert(
  client : @tls.Conn,
  server : @tls.Conn,
  want : @alert.Kind,
) -> Unit raise {
  let e = try shuttle(client, server) catch {
    e => e
  } noraise {
    _ => fail("expected an alert, got a finished handshake")
  }
  match e {
    @alert.Alert(kind~, ..) => if kind != want { fail("the wrong alert") }
    _ => fail("something other than an alert")
  }
}

///|
test "tls: a server that requires a client certificate gets one, and the handshake opens" {
  let s = asking_server(mode=Required)
  let c = showing_client(cert=[client_leaf], key_=key(client_key))
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_true(s.is_connected())
  assert_eq(s.peer().length(), 1)
  assert_eq(s.peer()[0], der(client_leaf))
  c.write(b"signed"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"signed")
}

///|
test "tls: a required certificate that the client does not have is certificate_required" {
  let s = asking_server(mode=Required)
  let c = showing_client()
  expect_alert(c, s, CertificateRequired)
  assert_false(s.is_connected())
}

///|
test "tls: a requested certificate the client does not have is an empty Certificate" {
  let s = asking_server(mode=Requested)
  let c = showing_client()
  shuttle(c, s)
  assert_true(s.is_connected())
  assert_eq(s.peer().length(), 0)
  c.write(b"anonymous"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"anonymous")
}

///|
test "tls: a client certificate from another anchor is unknown_ca" {
  let s = asking_server(mode=Required)
  let c = showing_client(cert=[stranger_leaf], key_=key(stranger_key))
  expect_alert(c, s, UnknownCa)
  // The same chain is accepted where that anchor is the one the server takes: what decides is the
  // anchor, not the chain's belief about itself.
  let s2 = asking_server(mode=Required, anchors=[stranger_root])
  let c2 = showing_client(cert=[stranger_leaf], key_=key(stranger_key))
  shuttle(c2, s2)
  assert_true(s2.is_connected())
  assert_eq(s2.peer()[0], der(stranger_leaf))
}

///|
test "tls: a certificate issued for a server does not authenticate a client" {
  let s = asking_server(mode=Required)
  let c = showing_client(cert=[client_server_leaf], key_=key(client_server_key))
  expect_alert(c, s, BadCertificate)
  assert_false(s.is_connected())
}

///|
test "tls: every client key type proves itself under a scheme the server takes" {
  let s = asking_server(mode=Required)
  let c = showing_client(cert=[client_rsa_leaf], key_=key(client_rsa_key))
  shuttle(c, s)
  assert_true(s.is_connected())
  c.write(b"rsa"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"rsa")
}

///|
test "tls: a certificate asked for after the handshake is verified then" {
  let s = asking_server(mode=Deferred)
  let c = showing_client(cert=[client_leaf], key_=key(client_key))
  shuttle(c, s)
  assert_true(s.is_connected())
  assert_eq(s.peer().length(), 0)
  s.request_certificate()
  shuttle(c, s)
  assert_eq(s.peer().length(), 1)
  assert_eq(s.peer()[0], der(client_leaf))
  c.write(b"after"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"after")
}

///|
test "tls: a client that never offered post_handshake_auth refuses the later request" {
  let s = asking_server(mode=Requested)
  let c = showing_client()
  shuttle(c, s)
  assert_true(c.is_connected())
  s.request_certificate()
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("expected an alert")
  }
  assert_true(e is @alert.Alert(kind=UnexpectedMessage, ..))
}

///|
test "tls: a client certificate in TLS 1.2 is signed over the handshake messages" {
  let s = asking_server(mode=Required, versions=[Tls12])
  let c = showing_client(cert=[client_leaf], key_=key(client_key), versions=[
    Tls12,
  ])
  shuttle(c, s)
  assert_true(c.is_connected())
  assert_true(s.is_connected())
  assert_eq(s.version(), Some(Tls12))
  assert_eq(s.peer().length(), 1)
  c.write(b"one two"[:])
  shuttle(c, s)
  assert_eq(s.read(), b"one two")
}

///|
test "tls: a TLS 1.2 server that requires a certificate and gets none" {
  let s = asking_server(mode=Required, versions=[Tls12])
  let c = showing_client(versions=[Tls12])
  expect_alert(c, s, CertificateRequired)
}

///|
test "tls: a TLS 1.2 server that asks and is refused a certificate still connects" {
  let s = asking_server(mode=Requested, versions=[Tls12])
  let c = showing_client(versions=[Tls12])
  shuttle(c, s)
  assert_true(s.is_connected())
  assert_eq(s.peer().length(), 0)
}

///|
test "tls: a server that asks for a certificate needs a clock and anchors" {
  let empty = try
    @tls.Server::new(
      [der(p256_leaf)],
      p256(),
      client_auth=@tls.ClientAuth::new(mode=Required),
    )
  catch {
    e => e
  } noraise {
    _ => fail("expected a refusal")
  }
  assert_true(empty is @asn1.Malformed(_))
  // The clock is the other half: a server with no time cannot judge validity.
  let config = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    client_auth=@tls.ClientAuth::new(
      mode=Required,
      roots=@x509.Roots::new(certs=[der(client_root)][:]),
    ),
  )
  let s = @tls.Conn::server(config, rand=rng(2000))
  let c = showing_client(cert=[client_leaf], key_=key(client_key))
  let e = try shuttle(c, s) catch {
    e => e
  } noraise {
    _ => fail("expected an alert")
  }
  assert_true(e is @alert.Alert(kind=InternalError, ..))
}

///|
test "tls: a client with a certificate and no key is refused where it is made" {
  let config = @tls.Client::new(@x509.Roots::new(certs=[der(root)][:]), cert=[
    der(client_leaf),
  ])
  let e = try @tls.Conn::client(config, "a.example", rand=rng(2), now~) catch {
    e => e
  } noraise {
    _ => fail("expected a refusal")
  }
  assert_true(e is @alert.Alert(kind=InternalError, ..))
}
