// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The record layer against an independent implementation.
//
// The wrapped records below were produced with Python's AES-GCM over RFC 8446
// §7.3's traffic key calculation and §5.3's nonce, written out separately from
// this package. One matching ciphertext therefore checks the whole chain at
// once: the key and IV derived from the traffic secret, the nonce the sequence
// number makes, the inner plaintext's trailing content type and padding, the
// five header octets chosen as the AEAD's additional data, and the AEAD.

///|
/// The traffic secret: the octets 0..31. Nothing here is secret.
let secret : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

///|
let content : Bytes = b"moontls"

///|
fn hex(b : Bytes) -> String {
  @base16.encode(b[:])
}

///|
test "the traffic keys are RFC 8446 §7.3's" {
  let t = @record.traffic(secret[:])
  assert_eq(hex(t.key), "9c9783cf77ea32d44f369da41f19f3cc")
  assert_eq(hex(t.iv), "2f41c846a431a163814bcd71")
  assert_eq(t.key.length(), @record.key_size)
  assert_eq(t.iv.length(), @record.iv_size)
}

///|
test "the per-record nonce is the sequence number XORed into the IV" {
  let t = @record.traffic(secret[:])
  assert_eq(hex(@record.nonce(t.iv[:], 0UL)), "2f41c846a431a163814bcd71")
  assert_eq(hex(@record.nonce(t.iv[:], 1UL)), "2f41c846a431a163814bcd70")
  // The IV is returned unchanged at sequence zero, which is what makes the
  // sequence the only thing keeping two records apart.
  assert_eq(@record.nonce(t.iv[:], 0UL), t.iv)
}

///|
test "a wrapped record is the one another implementation produces" {
  let cipher = @record.Cipher::new(secret[:])
  assert_eq(cipher.seq(), 0UL)
  assert_eq(
    hex(cipher.seal(Handshake, content[:])),
    "170303001848678850df5a1c8b35d8fed28995d201c1b59c7f2b5cfe29",
  )
  // The sequence advanced, so the next record is wrapped under another nonce.
  assert_eq(cipher.seq(), 1UL)
  assert_eq(
    hex(cipher.seal(Handshake, content[:])),
    "170303001838925171d90e5a8508926b6546e14342b2368bef2d350733",
  )
  assert_eq(cipher.seq(), 2UL)
}

///|
/// §5.4's padding is a knob: zero octets after the inner content type, which
/// change the record's length and nothing else.
test "padding is a knob and lands in the inner plaintext" {
  let cipher = @record.Cipher::new(secret[:])
  assert_eq(
    hex(cipher.seal(ApplicationData, content[:], padding=5)),
    "170303001d48678850df5a1c8ae63df8ddc4e27d3a2584bca1e293478c118187ad91",
  )
  // Without it the same content seals shorter.
  let plain = @record.Cipher::new(secret[:])
  let unpadded = plain.seal(ApplicationData, content[:])
  assert_eq(
    unpadded.length(),
    content.length() + 1 + @record.tag_size + @record.header,
  )
}

///|
test "a record opens back into what was wrapped" {
  let write = @record.Cipher::new(secret[:])
  let read = @record.Cipher::new(secret[:])
  let wrapped = write.seal(Handshake, content[:])
  let (kind, got) = read.open(wrapped[:])
  assert_eq(kind, @record.Kind::Handshake)
  assert_eq(got, content)
  assert_eq(read.seq(), 1UL)
  // Padding is invisible on the way out.
  let padded = write.seal(ApplicationData, content[:], padding=7)
  let (kind2, got2) = read.open(padded[:])
  assert_eq(kind2, @record.Kind::ApplicationData)
  assert_eq(got2, content)
}

///|
/// A tag that does not verify is a bad_record_mac, and the sequence does not
/// move — RFC 8446 §5.2 ends the connection there, so there is no next record.
test "a tampered record is refused and the sequence stays put" {
  let write = @record.Cipher::new(secret[:])
  let read = @record.Cipher::new(secret[:])
  let wrapped = write.seal(Handshake, content[:]).to_array()
  wrapped[wrapped.length() - 1] = (wrapped[wrapped.length() - 1].to_int() ^ 1).to_byte()
  let mut kind = @alert.Kind::CloseNotify
  try {
    let _ = read.open(Bytes::from_array(wrapped)[:])
  } catch {
    Alert(kind=k, ..) => kind = k
  }
  assert_eq(kind, @alert.Kind::BadRecordMac)
  assert_eq(read.seq(), 0UL)
}

///|
/// Rekeying restarts the sequence, because the IV is reused across a
/// generation and a sequence that carried over would reuse a nonce.
test "rekey restarts the sequence at zero" {
  let cipher = @record.Cipher::new(secret[:])
  let _ = cipher.seal(Handshake, content[:])
  assert_eq(cipher.seq(), 1UL)
  cipher.rekey(Bytes::make(32, b'\xaa')[:])
  assert_eq(cipher.seq(), 0UL)
  // And the keys really changed.
  assert_not_eq(hex(cipher.traffic().key), "9c9783cf77ea32d44f369da41f19f3cc")
}

///|
test "a plaintext record frames and parses" {
  let framed = @record.encode(Handshake, content[:])
  assert_eq(framed[0], b'\x16')
  assert_eq(framed[1], b'\x03')
  assert_eq(framed[2], b'\x03')
  assert_eq(@wire.read_u16(framed[:], 3), content.length())
  guard @record.parse(framed[:]) is Some((rec, used)) else {
    fail("a whole record did not parse")
  }
  assert_eq(rec.kind, @record.Kind::Handshake)
  assert_eq(rec.fragment, content)
  assert_eq(used, framed.length())
}

///|
/// A short view is not an error: more octets may still arrive.
test "parse waits for a whole record but refuses an impossible one" {
  let framed = @record.encode(Handshake, content[:])
  assert_eq(@record.parse(framed[0:3]) is None, true)
  assert_eq(@record.parse(framed[0:framed.length() - 1]) is None, true)
  // An unknown content type is not something to skip past.
  let mut kind = @alert.Kind::CloseNotify
  try {
    let _ = @record.parse(b"\xff\x03\x03\x00\x01\x00"[:])
  } catch {
    Alert(kind=k, ..) => kind = k
  }
  assert_eq(kind, @alert.Kind::UnexpectedMessage)
  // And only application_data may be empty (§5.1).
  let mut empty = @alert.Kind::CloseNotify
  try {
    let _ = @record.parse(b"\x16\x03\x03\x00\x00"[:])
  } catch {
    Alert(kind=k, ..) => empty = k
  }
  assert_eq(empty, @alert.Kind::UnexpectedMessage)
  guard @record.parse(b"\x17\x03\x03\x00\x00"[:]) is Some((rec, _)) else {
    fail("an empty application_data record is legal")
  }
  assert_eq(rec.fragment, b"")
}

///|
test "the two ceilings are the RFC's, and encode refuses a fragment past one" {
  assert_eq(@record.max_fragment, 16384)
  assert_eq(@record.max_encrypted, 16640)
  assert_eq(@record.header, 5)
  let mut kind = @alert.Kind::CloseNotify
  try {
    let _ = @record.encode(Handshake, Bytes::make(16385, b'x')[:])
  } catch {
    Alert(kind=k, ..) => kind = k
  }
  assert_eq(kind, @alert.Kind::RecordOverflow)
}

///|
test "an inner plaintext names its type after the content" {
  let plaintext = @record.inner(Handshake, content[:], padding=3)
  assert_eq(plaintext.length(), content.length() + 1 + 3)
  assert_eq(plaintext[content.length()], b'\x16')
  let (kind, got) = @record.unpad(plaintext[:])
  assert_eq(kind, @record.Kind::Handshake)
  assert_eq(got, content)
  // All zeros names no type at all.
  let mut refused = @alert.Kind::CloseNotify
  try {
    let _ = @record.unpad(b"\x00\x00\x00"[:])
  } catch {
    Alert(kind=k, ..) => refused = k
  }
  assert_eq(refused, @alert.Kind::UnexpectedMessage)
}

///|
test "the content types are RFC 8446 §5's" {
  assert_eq(@record.Kind::ChangeCipherSpec.code(), 20)
  assert_eq(@record.Kind::Alert.code(), 21)
  assert_eq(@record.Kind::Handshake.code(), 22)
  assert_eq(@record.Kind::ApplicationData.code(), 23)
  assert_eq(@record.Kind::of(22), Some(@record.Kind::Handshake))
  assert_eq(@record.Kind::of(99), None)
  assert_eq(@record.Kind::Other(99).code(), 99)
}
