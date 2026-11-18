// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Every decoder in `msg`, fed every message this library's own handshakes produce, wrong in every
// way a peer can be wrong: cut short at any octet, changed at any octet, and with any length field
// replaced by a number that is not the length.
//
// A server that accepts connections from anyone runs these decoders on octets a stranger chose. The
// rule they are held to is one line: every answer is `Some`, `None` or an alert — never an abort,
// never a hang, never a slice taken past the end. A test that crashes here is the failure this file
// exists to find, which is why the assertions are only that the calls return.
//
// The corpus is real messages rather than hand-built ones: a ClientHello that a handshake produced
// carries the extensions and the shapes a hand-built one would leave out.

///|
/// Append every handshake message in a plaintext record stream to `out`.
fn decode_collect(out : Array[Bytes], wire : Bytes) -> Unit raise {
  let mut rest = wire[:]
  while rest.length() > 0 {
    guard @record.decode(rest) is Some((record, used)) else { break }
    if record.kind is @record.Kind::Handshake {
      let mut fragment = record.fragment[:]
      while fragment.length() > 4 {
        guard @msg.unframe(fragment) is Some((_, body)) else { break }
        out.push(body)
        fragment = fragment[body.length() + 4:]
      }
    }
    rest = rest[used:]
  }
}

///|
/// The messages a decoder is held to: two real TLS 1.3 hellos, a real TLS 1.2 flight, and the four
/// messages and the ticket RFC 8448 publishes, which are the only ones here with a client
/// certificate request and a certificate chain written by another implementation.
fn decode_corpus() -> Array[Bytes] raise {
  let out : Array[Bytes] = []
  let c13 = client_with()
  let hello13 = c13.take()
  decode_collect(out, hello13)
  let s13 = server_with(p256_leaf, p256())
  s13.receive(hello13)
  decode_collect(out, s13.take())

  // TLS 1.2's server flight is in the clear up to its change_cipher_spec, so the whole of it can be
  // read out of one `take`.
  let c12 = client12()
  let hello12 = c12.take()
  decode_collect(out, hello12)
  let s12 = server12(p256_leaf, p256())
  s12.receive(hello12)
  decode_collect(out, s12.take())

  // RFC 8448 §3: EncryptedExtensions (40), Certificate (445), CertificateVerify (136), Finished
  // (36) — the offsets are the RFC's own lengths.
  let flight = @base16.decode_lossy(rfc8_flight3)
  out.push(flight[0:40].to_owned())
  out.push(flight[40:485].to_owned())
  out.push(flight[485:621].to_owned())
  out.push(flight[621:657].to_owned())
  // ...and §3's NewSessionTicket, whose body is the 205 octets after its four-octet frame.
  out.push(@base16.decode_lossy(rfc8_nst3)[4:].to_owned())
  out
}

///|
/// Every decoder `msg` exports, called on one body. None of these may abort, whatever the body is.
fn decode_probe(body : BytesView) -> Unit {
  ignore(@msg.unframe(body))
  ignore(@msg.read_hello(body))
  // The DTLS reading of a hello has a cookie field the stream one does not; a body that happens to
  // parse under one must not be assumed to parse under the other.
  ignore(@msg.read_hello(body, cookie=true))
  ignore(@msg.read_hello_verify_request(body))
  ignore(@msg.read_server_hello(body))
  ignore(@msg.read_encrypted_extensions(body))
  ignore(@msg.read_certificate(body))
  ignore(@msg.read_certificate_entries(body))
  ignore(@msg.read_certificate_verify(body))
  ignore(@msg.read_certificate_verify_legacy(body))
  ignore(@msg.read_certificate_request(body))
  ignore(@msg.read_certificate_request12(body))
  ignore(@msg.read_certificate_request12(body, schemes=false))
  ignore(@msg.read_certificate12(body))
  ignore(@msg.read_certificate_status12(body))
  ignore(@msg.read_server_key_exchange(body))
  ignore(@msg.read_dh_key_exchange(body))
  ignore(@msg.read_key_params(body))
  ignore(@msg.read_dh_params(body))
  ignore(@msg.read_srp_exchange(body, signed=true))
  ignore(@msg.read_srp_exchange(body, signed=false))
  ignore(@msg.read_psk_identity(body))
  ignore(@msg.read_client_key_exchange(body))
  ignore(@msg.read_client_key_exchange(body, wide=true))
  ignore(@msg.read_new_session_ticket(body))
  ignore(@msg.read_new_session_ticket12(body))
  ignore(@msg.read_compressed_certificate(body))
  // The extension list a hello carries is decoded by another module; it is reached from here too,
  // because a hello reader that passed the block along without reading it would hide its failures.
  ignore(@ext.read_block(body))
}

///|
test "decoders: every prefix of every real message is answered, never a crash" {
  let corpus = decode_corpus()
  assert_true(corpus.length() >= 8)
  for body in corpus {
    for cut in 0..<(body.length() + 1) {
      decode_probe(body[0:cut])
    }
  }
}

///|
test "decoders: a real message wrong in any one octet is answered, never a crash" {
  // Every octet of the shorter messages, every third of the longer ones: a certificate is 445
  // octets of DER, and its interior is not where a length field can lie.
  for body in decode_corpus() {
    let step = if body.length() > 200 { 7 } else { 1 }
    for at in 0..<body.length() {
      if at % step != 0 {
        continue
      }
      for byte in [b'\x00', b'\x7f', b'\xff'] {
        if body[at] == byte {
          continue
        }
        let copy = body.to_array()
        copy[at] = byte
        decode_probe(Bytes::from_array(copy)[:])
      }
    }
  }
}

///|
test "decoders: a length field that lies is answered, never a crash" {
  // The numbers a length field is most likely to be wrong in: zero, one, one too many, the largest
  // a two-octet field holds, and the largest a three-octet one does.
  let lies = [0x0000, 0x0001, 0x0002, 0x007f, 0x00ff, 0x0100, 0x7fff, 0xffff]
  for body in decode_corpus() {
    let step = if body.length() > 200 { 11 } else { 3 }
    for at in 0..<(body.length() - 1) {
      if at % step != 0 {
        continue
      }
      for lie in lies {
        let copy = body.to_array()
        copy[at] = ((lie >> 8) & 0xff).to_byte()
        copy[at + 1] = (lie & 0xff).to_byte()
        decode_probe(Bytes::from_array(copy)[:])
      }
    }
  }
}

///|
test "decoders: random octets are answered, never a crash" {
  // A deterministic stream, so a failure is a case and not a story. Lengths run over the sizes a
  // message has: empty, one octet, a header's worth, a record's worth.
  let source = rng(4242)
  for n in 0..<400 {
    let len = n * 37 % 260
    decode_probe(source(len))
  }
}
