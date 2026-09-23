// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The sealed records below were produced by RFC 9147 §4 written out over
// Python's AES-GCM and AES-ECB, which share no code with this package. They
// pin the header bits, the AEAD's additional data, the nonce and the record
// number mask all at once: change any one of them and the octets move.

///|
/// Whether a call refuses. Which alert it raises is RFC 9147 §4.5.2's business
/// and not the caller's: over UDP an invalid record is dropped, so what matters
/// is that it was not accepted.
fn refused(call : () -> Unit raise @alert.Alert) -> Bool {
  try {
    call()
    false
  } catch {
    _ => true
  }
}

///|
/// A fixed traffic secret: the octets 0..31. Nothing here is secret.
let secret : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

///|
test "the traffic and record number keys match an independent implementation" {
  assert_eq(
    @base16.encode(@record.traffic(secret[:]).key),
    "9c9783cf77ea32d44f369da41f19f3cc",
  )
  assert_eq(
    @base16.encode(@record.traffic(secret[:]).iv),
    "2f41c846a431a163814bcd71",
  )
  assert_eq(
    @base16.encode(@dtls.sn_key(secret[:])),
    "501c58bb5433798cc5d789cafabcde6d",
  )
}

///|
/// RFC 9147 §4, Figure 4: the full header is `001 1 1 1 EE` and the minimal one
/// `001 0 0 0 EE`, so the first octet alone says how long the header is.
test "a sealed record is the octets RFC 9147 §4 describes" {
  let c = @dtls.Cipher::new(secret[:], epoch=3UL)
  assert_eq(
    @base16.encode(c.seal(ApplicationData, b"hello dtls")),
    "2fa117001b4d6d8b52c4160be98a4eef809704853837b15ec5403ff31b2c3597",
  )
  // The sequence number advanced, so the same content seals differently — and
  // not only in the header: the nonce moved too.
  assert_eq(
    @base16.encode(c.seal(ApplicationData, b"hello dtls")),
    "2f0405001b3d985273c2424de7e6c3fd6c3f842d4f12710504ba0437506758ba",
  )
}

///|
test "the minimal header drops the length and narrows the sequence number" {
  let c = @dtls.Cipher::new(secret[:], epoch=2UL)
  for _i = 0; _i < 7; _i = _i + 1 {
    c.seal(ApplicationData, b"") |> ignore
  }
  let thin = @dtls.Shell::new(wide=false, length=false)
  assert_eq(
    @base16.encode(c.seal(ApplicationData, b"hi", shape=thin)),
    "220f1aecfed2f7c64e77e3b0b7df3875b7ba686ad0",
  )
}

///|
test "a connection ID goes into the header and into the additional data" {
  let c = @dtls.Cipher::new(secret[:], epoch=1UL)
  for _i = 0; _i < 300; _i = _i + 1 {
    c.seal(ApplicationData, b"") |> ignore
  }
  let with_cid = @dtls.Shell::new(cid=b"\xca\xfe")
  assert_eq(
    @base16.encode(c.seal(ApplicationData, b"with cid", shape=with_cid)),
    "3dcafee85100192b84cd22691808cfd2e2e93caad8e0c3b96b2c5463876c9268",
  )
}

///|
test "a sealed record opens back into what went in" {
  let out = @dtls.Cipher::new(secret[:], epoch=3UL)
  let into = @dtls.Cipher::new(secret[:], epoch=3UL)
  let wire = out.seal(Handshake, b"a handshake fragment")
  let (kind, content, number, used) = into.open(wire[:])
  assert_eq(kind, Handshake)
  assert_eq(content, b"a handshake fragment")
  assert_eq(number, { epoch: 3UL, seq: 0UL, })
  assert_eq(used, wire.length())
}

///|
test "the three header shapes all open" {
  for
    shape in [
      @dtls.shell,
      @dtls.Shell::new(wide=false),
      @dtls.Shell::new(length=false),
      @dtls.Shell::new(wide=false, length=false),
      @dtls.Shell::new(cid=b"\x01\x02\x03"),
    ] {
    let out = @dtls.Cipher::new(secret[:], epoch=1UL)
    let into = @dtls.Cipher::new(secret[:], epoch=1UL)
    let wire = out.seal(ApplicationData, b"round trip", shape~)
    let (kind, content, _, _) = into.open(wire[:], cid=shape.cid.length())
    assert_eq(kind, ApplicationData)
    assert_eq(content, b"round trip")
  }
}

///|
/// RFC 9147 §4.5.2: an invalid record leaves the association as it found it. A
/// receiver that moved its replay window on a forgery could be made to reject
/// the live record that follows.
test "a tampered record is refused and moves nothing" {
  let out = @dtls.Cipher::new(secret[:], epoch=1UL)
  let into = @dtls.Cipher::new(secret[:], epoch=1UL)
  let good = out.seal(ApplicationData, b"authentic")
  let bad = good.to_array()
  bad[bad.length() - 1] = (bad[bad.length() - 1].to_int() ^ 0x01).to_byte()
  let forged = Bytes::from_array(bad)
  assert_true(refused(() => into.open(forged[:]) |> ignore))
  // The real record still opens afterwards.
  let (_, content, _, _) = into.open(good[:])
  assert_eq(content, b"authentic")
}

///|
/// RFC 9147 §4.2.3: the mask needs sixteen octets of ciphertext, so a record
/// shorter than that is refused as if deprotection had failed.
test "a record too short to mask is refused" {
  let into = @dtls.Cipher::new(secret[:], epoch=0UL)
  let short = b"\x2c\x00\x00\x00\x05\x01\x02\x03\x04\x05"
  assert_true(refused(() => into.open(short[:]) |> ignore))
}

///|
test "records arriving out of order all open" {
  let out = @dtls.Cipher::new(secret[:], epoch=1UL)
  let into = @dtls.Cipher::new(secret[:], epoch=1UL)
  let sent = []
  for i = 0; i < 5; i = i + 1 {
    sent.push(out.seal(ApplicationData, b"x"))
  }
  // Delivered 3, 1, 4, 0, 2.
  for at in [3, 1, 4, 0, 2] {
    let (_, content, number, _) = into.open(sent[at][:])
    assert_eq(content, b"x")
    assert_eq(number.seq, at.to_uint64())
  }
  // Every one of them a second time is a replay.
  for at in [3, 1, 4, 0, 2] {
    assert_true(refused(() => into.open(sent[at][:]) |> ignore))
  }
}

///|
/// The first octet is the whole demultiplexer (RFC 9147 §4.1): alert, handshake
/// and ack are plaintext records, `001xxxxx` is a sealed one, and everything
/// else — including DTLS 1.2's application_data — is not ours.
test "the first octet says which of the three shapes a record is" {
  assert_eq(@dtls.shape(b'\x15'), Plain(Alert))
  assert_eq(@dtls.shape(b'\x16'), Plain(Handshake))
  assert_eq(@dtls.shape(b'\x1a'), Plain(Ack))
  assert_eq(@dtls.shape(b'\x20'), Sealed)
  assert_eq(@dtls.shape(b'\x2f'), Sealed)
  assert_eq(@dtls.shape(b'\x3f'), Sealed)
  assert_eq(@dtls.shape(b'\x14'), Foreign)
  assert_eq(@dtls.shape(b'\x17'), Foreign)
  assert_eq(@dtls.shape(b'\x19'), Foreign)
  assert_eq(@dtls.shape(b'\x40'), Foreign)
  assert_eq(@dtls.shape(b'\xff'), Foreign)
}

///|
test "a plaintext record round-trips with its epoch and sequence number" {
  let number : @dtls.Number = { epoch: 0UL, seq: 0x0123456789abUL, }
  let wire = @dtls.encode(Handshake, number, b"client hello")
  assert_eq(wire.length(), @dtls.plaintext_header + 12)
  assert_eq(@base16.encode(wire[0:5].to_owned()), "16fefd0000")
  assert_eq(@base16.encode(wire[5:11].to_owned()), "0123456789ab")
  guard @dtls.decode(wire[:]) is Some((kind, back, fragment, used)) else {
    fail("a whole plaintext record did not read back")
  }
  assert_eq(kind, Handshake)
  assert_eq(back, number)
  assert_eq(fragment, b"client hello")
  assert_eq(used, wire.length())
}

///|
test "a plaintext record short of its fragment is not yet a record" {
  let zero : @dtls.Number = { epoch: 0UL, seq: 0UL, }
  let wire = @dtls.encode(Handshake, zero, b"twelve chars")
  for cut = 0; cut < wire.length(); cut = cut + 1 {
    assert_eq(@dtls.decode(wire[0:cut]), None)
  }
  assert_true(@dtls.decode(wire[:]) is Some(_))
}

///|
/// The sequence number a DTLSPlaintext carries is 48 bits, and a sender that
/// has run past that must rekey rather than wrap (RFC 9147 §4.2.1).
test "a plaintext sequence number past 48 bits is refused" {
  let over : @dtls.Number = { epoch: 0UL, seq: @dtls.max_plaintext_seq + 1UL, }
  assert_true(refused(() => @dtls.encode(Handshake, over, b"x") |> ignore))
  let edge : @dtls.Number = { epoch: 0UL, seq: @dtls.max_plaintext_seq, }
  assert_false(refused(() => @dtls.encode(Handshake, edge, b"x") |> ignore))
}
