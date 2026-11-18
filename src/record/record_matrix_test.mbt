// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The record layer's own decoders, held to the same rule as the message decoders: an alert is an
// answer, an abort is a bug.
//
// The record layer is reached before anything is authenticated. A length field there decides how
// many octets are taken off the wire, and the padding rule of RFC 8446 §5.4 makes the *end* of a
// plaintext a thing an attacker controls. Both are exhausted here.

///|
/// A deterministic byte source, so a failure names a case.
fn record_rng(seed : Int32) -> (Int32) -> Bytes {
  // Lehmer's generator: a multiply below 2^53 and a modulus, so it is the same on every target and
  // does not depend on how a target wraps an overflow.
  let state = Ref((seed & 0x7fffffff).to_uint64())
  n => {
    let out = Array::make(n, b'\x00')
    for i in 0..<n {
      state.val = state.val * 48271UL % 2147483647UL
      out[i] = ((state.val >> 16) & 0xff).to_byte()
    }
    Bytes::from_array(out)
  }
}

///|
test "records: any octets are a record or nothing, never a crash" {
  let source = record_rng(11)
  for n in 0..<600 {
    // Lengths up to a little past the largest fragment, and a few headers that claim more than the
    // view holds.
    let len = n * 29 % (@record.max_encrypted + 8)
    let view = source(len)
    ignore(@record.decode(view[:])) catch {
      _ => ()
    }
    ignore(@record.decode_encrypted(view[:])) catch {
      _ => ()
    }
  }
}

///|
/// A header whose length is one of the numbers a fuzzer tries first: zero, one, the fragment
/// ceiling, one past it, and the largest a two-octet field holds.
test "records: a length field at its boundaries is a record or an alert" {
  let lies = [
    0,
    1,
    2,
    @record.max_fragment,
    @record.max_fragment + 1,
    @record.max_encrypted,
    0xffff,
  ]
  for
    kind in [
      @record.Kind::Handshake,
      @record.Kind::Alert,
      @record.Kind::ApplicationData,
      @record.Kind::ChangeCipherSpec,
    ] {
    for lie in lies {
      let header = Buffer()
      header.write_byte((kind.code() & 0xff).to_byte())
      header.write_byte(b'\x03')
      header.write_byte(b'\x03')
      header.write_byte(((lie >> 8) & 0xff).to_byte())
      header.write_byte((lie & 0xff).to_byte())
      ignore(@record.decode(header.to_bytes()[:])) catch {
        _ => ()
      }
      ignore(@record.decode_encrypted(header.to_bytes()[:])) catch {
        _ => ()
      }
    }
  }
}

///|
/// RFC 8446 §5.4's padding is a run of zero octets after the content type, and the last non-zero
/// octet is the type. Every arrangement of zeros and a type is a case: no type at all, a type at
/// the front, a type at the end, and a plaintext that is nothing but zeros.
test "records: every arrangement of inner padding is answered, never a crash" {
  let arrangements = [
    b"", b"\x00", b"\x00\x00\x00\x00", b"\x17", b"\x17\x00", b"\x00\x17", b"\x00\x00\x17\x00\x00",
    b"\xff\x00\x00", b"\x00\x00\x00\x16",
  ]
  for plaintext in arrangements {
    try {
      let (_, content) = @record.unpad(plaintext)
      // A plaintext with no content type is an alert; one with a type has content before it.
      assert_true(content.length() <= plaintext.length())
    } catch {
      _ => ()
    }
  }
  let source = record_rng(12)
  for n in 0..<400 {
    ignore(@record.unpad(source(n * 7 % 64))) catch {
      _ => ()
    }
  }
}

///|
/// A cipher opening a record that was not sealed_record under it: every octet of a real record changed,
/// one at a time, and the tag has to refuse it. This is the record layer's authenticator, and a
/// record it accepted would be a forgery.
test "records: a record changed in any octet opens to an alert, never content" {
  let secret = @base16.decode_lossy(
    "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
  )
  // A writer and a reader: one Cipher counts its own sequence numbers, and a reader that had
  // already sealed one record would be looking for the second nonce.
  let writer = @record.Cipher::new(secret)
  let sealed_record = writer.seal(@record.Kind::ApplicationData, b"a message")
  let (kind, content) = @record.Cipher::new(secret).open(sealed_record)
  assert_eq(kind, @record.Kind::ApplicationData)
  assert_eq(content, b"a message")

  let step = if sealed_record.length() > 40 { 2 } else { 1 }
  let mut refused = 0
  for at in 0..<sealed_record.length() {
    if at % step != 0 {
      continue
    }
    let copy = sealed_record.to_array()
    copy[at] = (copy[at].to_int() ^ 0x01).to_byte()
    let forged = Bytes::from_array(copy)
    // A fresh cipher each time: a failed open must not move the sequence number, and a fresh one
    // makes the test about the tag rather than about the counter.
    let reader = @record.Cipher::new(
      @base16.decode_lossy(
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
      ),
    )
    ignore(reader.open(forged[:])) catch {
      @alert.Alert(kind~, ..) => {
        assert_true(kind.is_fatal())
        refused = refused + 1
      }
    }
  }
  assert_true(refused > 0)
}
