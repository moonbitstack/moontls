// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The handshake messages against the wire structures RFC 8446 §4 defines,
// built separately in Python from the RFC's own prose. Every expected string
// below is that construction, not this package's output.

///|
fn bytes_of(hex_text : String) -> Bytes raise {
  @base16.decode(hex_text)
}

///|
/// The octets 0..31, and 32..63: reproducible stand-ins for a random and a
/// session id.
fn random() -> Bytes raise {
  bytes_of("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
}

///|
fn session() -> Bytes raise {
  bytes_of("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
}

///|
fn key() -> Bytes raise {
  bytes_of("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
}

///|
test "the message types are RFC 8446 §4's" {
  let assigned = [
    (@msg.Kind::ClientHello, 1),
    (@msg.Kind::ServerHello, 2),
    (@msg.Kind::NewSessionTicket, 4),
    (@msg.Kind::EncryptedExtensions, 8),
    (@msg.Kind::Certificate, 11),
    (@msg.Kind::CertificateRequest, 13),
    (@msg.Kind::CertificateVerify, 15),
    (@msg.Kind::Finished, 20),
    (@msg.Kind::KeyUpdate, 24),
  ]
  for pair in assigned {
    assert_eq(pair.0.code(), pair.1)
    assert_eq(@msg.Kind::of(pair.1), pair.0)
  }
  assert_eq(@msg.Kind::of(99), @msg.Kind::Other(99))
  assert_eq(@msg.Kind::Other(99).code(), 99)
}

///|
/// The framing is a type and a 24-bit length, and nothing about the body.
test "a message frames and unframes" {
  let framed = @msg.frame(Finished, b"verify"[:])
  assert_eq(@base16.encode(framed), "14000006766572696679")
  guard @msg.unframe(framed[:]) is Some((kind, body)) else {
    fail("a whole message did not unframe")
  }
  assert_eq(kind, @msg.Kind::Finished)
  assert_eq(body, b"verify")
  // A short view waits rather than failing: more octets may arrive.
  assert_eq(@msg.unframe(framed[0:3]) is None, true)
  assert_eq(@msg.unframe(framed[0:framed.length() - 1]) is None, true)
  // A type with no codec here still unframes, because the transcript covers
  // every message whether or not it was understood.
  let unknown = @msg.frame(Other(99), b"x"[:])
  guard @msg.unframe(unknown[:]) is Some((k, _)) else {
    fail("it should unframe")
  }
  assert_eq(k, @msg.Kind::Other(99))
}

///|
test "a ClientHello is the message another implementation builds" {
  let ch = @msg.Hello::{
    random: random(),
    session_id: session(),
    suites: [0x1301, 0x1302],
    extensions: [
      @ext.Ext::{
        kind: SupportedVersions,
        data: @ext.versions([0x0304, 0x0303][:]),
      },
      @ext.Ext::{
        kind: KeyShare,
        data: @ext.shares([(@ext.x25519, key())][:]),
      },
    ],
  }
  assert_eq(
    @base16.encode(@msg.hello(ch)),
    "010000800303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00041301130201000033002b00050403040303003300260024001d0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  // And it reads back to what it was.
  guard @msg.unframe(@msg.hello(ch)[:]) is Some((kind, body)) else {
    fail("the ClientHello did not unframe")
  }
  assert_eq(kind, @msg.Kind::ClientHello)
  guard @msg.read_hello(body[:]) is Some(back) else {
    fail("the ClientHello did not parse")
  }
  assert_eq(back, ch)
}

///|
test "a ServerHello round-trips through its own shape" {
  let sh = @msg.Server::{
    random: random(),
    session_id: session(),
    suite: 0x1301,
    extensions: [
      @ext.Ext::{
        kind: SupportedVersions,
        data: @ext.selected_version(@ext.version_13),
      },
      @ext.Ext::{
        kind: KeyShare,
        data: @ext.selected_share(@ext.x25519, key()[:]),
      },
    ],
  }
  assert_eq(
    @base16.encode(@msg.server_hello(sh)),
    "020000760303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f130100002e002b0002030400330024001d0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  guard @msg.unframe(@msg.server_hello(sh)[:]) is Some((kind, body)) else {
    fail("the ServerHello did not unframe")
  }
  assert_eq(kind, @msg.Kind::ServerHello)
  guard @msg.read_server_hello(body[:]) is Some(back) else {
    fail("the ServerHello did not parse")
  }
  assert_eq(back, sh)
}

///|
/// A truncated Hello is refused rather than half-read: the lengths inside it
/// describe octets that are not there.
test "a truncated Hello does not parse" {
  let whole = @msg.hello(@msg.Hello::{
    random: random(),
    session_id: session(),
    suites: [0x1301],
    extensions: [],
  })
  guard @msg.unframe(whole[:]) is Some((_, body)) else { fail("unframe") }
  assert_eq(@msg.read_hello(body[0:20]) is None, true)
  assert_eq(@msg.read_hello(body[0:body.length() - 1]) is None, true)
  assert_eq(@msg.read_hello(b""[:]) is None, true)
}

///|
test "EncryptedExtensions is an extension list and nothing else" {
  let exts = [@ext.Ext::{ kind: Alpn, data: @ext.protocols([@ext.h3][:]), }]
  let body = @msg.encrypted_extensions(exts[:])
  assert_eq(body, @ext.encode(exts[:]))
  guard @msg.read_encrypted_extensions(body[:]) is Some(back) else {
    fail("it did not parse")
  }
  assert_eq(back, exts)
}

///|
test "a Certificate carries its DER opaque" {
  let der = bytes_of(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  )
  let body = @msg.certificate([der][:])
  assert_eq(
    @base16.encode(body),
    "00000045000040000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000",
  )
  guard @msg.read_certificate(body[:]) is Some((context, certs)) else {
    fail("the Certificate did not parse")
  }
  assert_eq(context, b"")
  assert_eq(certs.length(), 1)
  assert_eq(certs[0], der)
  // A context is carried when there is one.
  let prompted = @msg.certificate([der][:], context=b"ctx"[:])
  guard @msg.read_certificate(prompted[:]) is Some((ctx2, _)) else {
    fail("the prompted Certificate did not parse")
  }
  assert_eq(ctx2, b"ctx")
  // Two certificates come back in order.
  guard @msg.read_certificate(@msg.certificate([der, b"second"][:])[:])
    is Some((_, two)) else {
    fail("a chain of two did not parse")
  }
  assert_eq(two.length(), 2)
  assert_eq(two[1], b"second")
}

///|
test "a truncated Certificate does not parse" {
  let body = @msg.certificate(
    [
      bytes_of(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      ),
    ][:],
  )
  assert_eq(@msg.read_certificate(body[0:body.length() - 1]) is None, true)
  assert_eq(@msg.read_certificate(b""[:]) is None, true)
}

///|
/// The 64 spaces and the context string are what stop a signature made for one
/// role, or for an older version, from counting as one made for another.
test "what a CertificateVerify signs is RFC 8446 §4.4.3's content" {
  let transcript = bytes_of(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let content = @msg.signed(@msg.server_context, transcript[:])
  assert_eq(
    @base16.encode(content),
    "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020544c5320312e332c2073657276657220436572746966696361746556657269667900000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  assert_eq(content.length(), 64 + 33 + 1 + 32)
  // The client's content differs from the server's in exactly the context.
  let client = @msg.signed(@msg.client_context, transcript[:])
  assert_not_eq(@base16.encode(client), @base16.encode(content))
  assert_eq(client.length(), content.length())
}

///|
test "a CertificateVerify frames its scheme and signature" {
  let sig = bytes_of(
    "464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485",
  )
  let body = @msg.certificate_verify(sig[:], @ext.ecdsa_secp256r1_sha256)
  assert_eq(
    @base16.encode(body),
    "04030040464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485",
  )
  guard @msg.read_certificate_verify(body[:]) is Some((scheme, got)) else {
    fail("the CertificateVerify did not parse")
  }
  assert_eq(scheme, @ext.ecdsa_secp256r1_sha256)
  assert_eq(got, sig)
  // A length that does not describe what is there is refused.
  assert_eq(
    @msg.read_certificate_verify(body[0:body.length() - 1]) is None,
    true,
  )
  assert_eq(@msg.read_certificate_verify(b"\x04\x03\x00"[:]) is None, true)
}

///|
test "a Finished body is the verify_data" {
  assert_eq(@msg.finished(b"0123456789abcdef0123456789abcdef"[:]).length(), 32)
  assert_eq(@msg.finished(b"abc"[:]), b"abc")
}
