// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The extension codec against the wire encodings RFC 8446 §4.2 and RFC 7301
// §3.1 define, built separately in Python from the RFC's own prose. Every
// expected string below is that construction, not this package's output.

///|
fn hex(b : Bytes) -> String {
  @base16.encode(b[:])
}

///|
/// The 32-octet x25519 key used throughout: the octets 0..31.
fn key() -> Bytes {
  Bytes::from_array(Array::makei(32, fn(i) { i.to_byte() }))
}

///|
test "the extension type codes are the registry's" {
  let assigned = [
    (@ext.Kind::ServerName, 0x0000),
    (@ext.Kind::SupportedGroups, 0x000a),
    (@ext.Kind::SignatureAlgorithms, 0x000d),
    (@ext.Kind::Alpn, 0x0010),
    (@ext.Kind::SupportedVersions, 0x002b),
    (@ext.Kind::KeyShare, 0x0033),
    (@ext.Kind::QuicTransportParameters, 0x0039),
  ]
  for pair in assigned {
    assert_eq(pair.0.code(), pair.1)
    assert_eq(@ext.Kind::of(pair.1), pair.0)
  }
  // An extension with no codec here keeps its number rather than vanishing:
  // §4.2 has a receiver carry one it does not recognise.
  assert_eq(@ext.Kind::of(0xff01), @ext.Kind::Other(0xff01))
  assert_eq(@ext.Kind::Other(0xff01).code(), 0xff01)
}

///|
test "supported_versions is a one-octet list going out and one version coming back" {
  assert_eq(hex(@ext.versions([0x0304, 0x0303][:])), "0403040303")
  assert_eq(@ext.read_versions(@base16.decode("0403040303")[:]), [
    0x0304, 0x0303,
  ])
  assert_eq(hex(@ext.selected_version(@ext.version_13)), "0304")
  assert_eq(@ext.read_selected_version(@base16.decode("0304")[:]), Some(0x0304))
  // A ServerHello's payload is exactly two octets; anything else is not one.
  assert_eq(@ext.read_selected_version(b"\x03"[:]), None)
  assert_eq(@ext.read_selected_version(b"\x03\x04\x00"[:]), None)
}

///|
test "supported_groups and signature_algorithms share the u16-list shape" {
  assert_eq(
    hex(@ext.groups([@ext.x25519, @ext.secp256r1, @ext.secp384r1][:])),
    "0006001d00170018",
  )
  assert_eq(@ext.read_groups(@base16.decode("0006001d00170018")[:]), [
    0x001d, 0x0017, 0x0018,
  ])
  assert_eq(
    hex(
      @ext.schemes([@ext.rsa_pss_rsae_sha256, @ext.ecdsa_secp256r1_sha256][:]),
    ),
    "000408040403",
  )
  assert_eq(@ext.read_schemes(@base16.decode("000408040403")[:]), [
    0x0804, 0x0403,
  ])
  // A declared length past what is there stops at what is there.
  assert_eq(@ext.read_groups(b"\x00\xff\x00\x1d"[:]), [0x001d])
  assert_eq(@ext.read_groups(b""[:]), [])
}

///|
test "ALPN names round-trip through RFC 7301's list" {
  let names = [@ext.h3, @ext.h2, @ext.http11]
  assert_eq(hex(@ext.protocols(names[:])), "000f02683302683208687474702f312e31")
  assert_eq(
    @ext.read_protocols(@base16.decode("000f02683302683208687474702f312e31")[:]),
    names,
  )
  assert_eq(@ext.read_protocols(b""[:]), [])
  // A truncated name is dropped rather than read past the end.
  assert_eq(@ext.read_protocols(b"\x00\x09\x08http"[:]), [])
}

///|
test "key_share carries one entry from a server and a list from a client" {
  assert_eq(
    hex(@ext.selected_share(@ext.x25519, key()[:])),
    "001d0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  guard @ext.read_selected_share(
      @base16.decode(
        "001d0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      )[:],
    )
    is Some((group, got)) else {
    fail("a server key_share did not read")
  }
  assert_eq(group, @ext.x25519)
  assert_eq(got, key())
  assert_eq(
    hex(@ext.shares([(@ext.x25519, key())][:])),
    "0024001d0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let shares = @ext.read_shares(
    @base16.decode(
      "0024001d0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    )[:],
  )
  assert_eq(shares.length(), 1)
  assert_eq(shares[0].0, @ext.x25519)
  assert_eq(shares[0].1, key())
  // A partial entry ends the list rather than being guessed at.
  assert_eq(@ext.read_share(b"\x00\x1d\x00\x20\x01"[:]), None)
  assert_eq(@ext.read_shares(b"\x00\x24\x00\x1d\x00\x20\x01"[:]), [])
}

///|
test "an extension block frames every extension in order" {
  let block = [
    @ext.Ext::{
      kind: SupportedVersions,
      data: @ext.versions([0x0304, 0x0303][:]),
    },
    @ext.Ext::{
      kind: SupportedGroups,
      data: @ext.groups([@ext.x25519, @ext.secp256r1, @ext.secp384r1][:]),
    },
    @ext.Ext::{
      kind: Alpn,
      data: @ext.protocols([@ext.h3, @ext.h2, @ext.http11][:]),
    },
    @ext.Ext::{ kind: KeyShare, data: @ext.shares([(@ext.x25519, key())][:]), },
  ]
  assert_eq(
    hex(@ext.encode(block[:])),
    "0054002b00050403040303000a00080006001d0017001800100011000f02683302683208687474702f312e31003300260024001d0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  guard @ext.decode(
      @base16.decode(
        "0054002b00050403040303000a00080006001d0017001800100011000f02683302683208687474702f312e31003300260024001d0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      )[:],
    )
    is Some(back) else {
    fail("the block did not decode")
  }
  assert_eq(back.length(), 4)
  assert_eq(back, block)
}

///|
test "find picks the first extension of a type" {
  guard @ext.decode(
      @base16.decode(
        "0054002b00050403040303000a00080006001d0017001800100011000f02683302683208687474702f312e31003300260024001d0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      )[:],
    )
    is Some(exts) else {
    fail("the block did not decode")
  }
  guard @ext.find(exts[:], Alpn) is Some(found) else {
    fail("ALPN was in the block")
  }
  assert_eq(@ext.read_protocols(found.data[:]), [@ext.h3, @ext.h2, @ext.http11])
  assert_eq(@ext.find(exts[:], ServerName), None)
}

///|
/// A length that overruns the block is a refusal, not a short answer: the block
/// is framed, so an overrun means the message is malformed rather than
/// incomplete.
test "decode refuses a block whose lengths do not fit" {
  assert_eq(@ext.decode(b""[:]), None)
  assert_eq(@ext.decode(b"\x00"[:]), None)
  // Declares four octets of extensions and carries two.
  assert_eq(@ext.decode(b"\x00\x04\x00\x2b"[:]), None)
  // Declares an extension payload longer than the block.
  assert_eq(@ext.decode(b"\x00\x05\x00\x2b\x00\xff\x01"[:]), None)
  // An empty block is a block.
  assert_eq(@ext.decode(b"\x00\x00"[:]), Some([]))
}

///|
/// quic_transport_parameters has a code and no codec on purpose: the payload is
/// QUIC's and this package carries it without claiming to read it.
test "an extension with no codec here still travels" {
  let blob = b"\x01\x02\x03\x04"
  let block = [@ext.Ext::{ kind: QuicTransportParameters, data: blob, }]
  let wire = @ext.encode(block[:])
  assert_eq(hex(wire), "00080039000401020304")
  guard @ext.decode(wire[:]) is Some(back) else { fail("it did not decode") }
  assert_eq(back[0].kind, @ext.Kind::QuicTransportParameters)
  assert_eq(back[0].data, blob)
}
