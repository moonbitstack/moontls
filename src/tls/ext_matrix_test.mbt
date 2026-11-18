// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Every extension codec, fed every extension body this library's own hellos carry, wrong in every
// way a peer can be wrong.
//
// An extension's payload is the least constrained octets in TLS: its type says what it is, and its
// length says nothing about whether it fits. A reader that trusts either one is reached by anyone
// who can open a connection, so these are the decoders most worth exhausting.

///|
/// The extension bodies of one hello message, `body` being a handshake body without its frame.
fn ext_of_hello(
  out : Array[Bytes],
  body : Bytes,
  cookie~ : Bool = false,
) -> Unit {
  guard @msg.read_hello(body, cookie~) is Some(hello) else { return }
  for ext in hello.extensions {
    out.push(ext.data)
  }
}

///|
/// The bodies an extension reader is held to: every extension of two real TLS 1.3 hellos and of
/// RFC 8448's EncryptedExtensions, plus the payloads a server writes and a client never does —
/// a cookie, a session ticket, a record size limit — which a real client hello therefore lacks.
fn ext_corpus() -> Array[Bytes] raise {
  let out : Array[Bytes] = []
  let c = client_with()
  let wire = c.take()
  guard @record.decode(wire[:]) is Some((record, _)) &&
    @msg.unframe(record.fragment[:]) is Some((_, body)) else {
    abort("the client hello did not frame")
  }
  ext_of_hello(out, body)

  let s = server_with(p256_leaf, p256())
  s.receive(wire)
  let answer = s.take()
  guard @record.decode(answer[:]) is Some((record, _)) &&
    @msg.unframe(record.fragment[:]) is Some((_, body)) else {
    abort("the server hello did not frame")
  }
  ext_of_hello(out, body)

  // RFC 8448 §3's EncryptedExtensions: a four-octet frame around an extension block.
  let flight = @base16.decode_lossy(rfc8_flight3)
  guard @msg.read_encrypted_extensions(flight[4:40]) is Some(exts) else {
    abort("RFC 8448's EncryptedExtensions did not read")
  }
  for ext in exts {
    out.push(ext.data)
  }

  // The shapes only a server sends, and the ones a hello carries only under negotiation.
  out.push(@ext.cookie(b"a cookie a server issued"))
  out.push(@ext.session_ticket(b"a ticket"))
  out.push(@ext.record_size_limit(4096))
  out.push(@ext.max_early_data(0xffffffff))
  out.push(@ext.psk_modes([1]))
  out.push(@ext.use_srtp([0x0007, 0x0005], b""))
  out.push(@ext.srp(b"alice"))
  out.push(@ext.server_name("a.example")[2:].to_owned())
  out.push(@ext.renegotiation(b"", b""))
  out.push(@ext.status_request())
  out.push(@ext.compression_algorithms([1, 2]))
  out.push(@ext.point_formats())
  // And the degenerate bodies a length field of zero produces.
  out.push(b"")
  out.push(b"\x00")
  out.push(b"\x00\x00")
  out.push(b"\xff\xff")
  out
}

///|
/// Every extension decoder, called on one body.
fn ext_probe(data : BytesView) -> Unit {
  ignore(@ext.read_block(data))
  ignore(@ext.read_srp(data))
  ignore(@ext.read_versions(data))
  ignore(@ext.read_selected_version(data))
  ignore(@ext.read_groups(data))
  ignore(@ext.read_schemes(data))
  ignore(@ext.read_protocols(data))
  ignore(@ext.read_selected_share(data))
  ignore(@ext.read_shares(data))
  ignore(@ext.read_use_srtp(data))
  ignore(@ext.read_cookie(data))
  ignore(@ext.read_server_names(data))
  ignore(@ext.read_point_formats(data))
  ignore(@ext.read_renegotiation(data))
  ignore(@ext.read_authorities(data))
  ignore(@ext.read_session_ticket(data))
  ignore(@ext.read_psk_modes(data))
  ignore(@ext.read_pre_shared_key(data))
  ignore(@ext.read_max_early_data(data))
  ignore(@ext.read_status_request(data))
  ignore(@ext.read_certificate_status(data))
  ignore(@ext.read_certificate_status12(data))
  ignore(@ext.read_record_size_limit(data))
  ignore(@ext.read_compression_algorithms(data))
}

///|
test "extensions: every prefix of every real payload is answered, never a crash" {
  let corpus = ext_corpus()
  assert_true(corpus.length() >= 12)
  for data in corpus {
    for cut in 0..<(data.length() + 1) {
      ext_probe(data[0:cut])
    }
  }
}

///|
test "extensions: a payload wrong in any one octet is answered, never a crash" {
  for data in ext_corpus() {
    for at in 0..<data.length() {
      for byte in [b'\x00', b'\x01', b'\x7f', b'\xff'] {
        if data[at] == byte {
          continue
        }
        let copy = data.to_array()
        copy[at] = byte
        ext_probe(Bytes::from_array(copy)[:])
      }
    }
  }
}

///|
test "extensions: random octets are answered, never a crash" {
  let source = rng(90210)
  for n in 0..<400 {
    ext_probe(source(n * 13 % 96))
  }
}
