// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Cross-verification against pion/dtls.
//
// RFC 9147 prints no vectors of its own, so the only witness to a record
// protected under it is another implementation. These are pion's
// `TestTLS13RecordProtectionKnownVectors`, secret for secret: two counting
// secrets, sequence number 0x0001020304050607, connection ID `cafebabe`,
// epoch 3, application data.
//
// Every stage is checked separately, because a single end-to-end compare says
// only that something differs.

///|
/// pion's client and server secrets for the SHA-256 vectors.
let pion_client : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

///|
let pion_server : Bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"

///|
/// The sequence number every vector protects under.
let pion_seq : UInt64 = 0x0001020304050607UL

///|
test "pion/dtls: the AES-128-GCM traffic keys" {
  assert_eq(
    @keys.expand_label(
      pion_client[:],
      b"key",
      b"",
      len=16,
      prefix=@keys.datagram[:],
    ),
    b"\xcc\x95\xab\xc2\x58\xd3\x09\x42\x4d\xdb\xf7\xcb\xa6\x8b\xd7\x7e",
  )
  assert_eq(
    @keys.expand_label(
      pion_client[:],
      b"iv",
      b"",
      len=12,
      prefix=@keys.datagram[:],
    ),
    b"\x6d\x32\x99\x30\x5d\xd2\x09\xfc\x86\x5c\xf8\xf1",
  )
  assert_eq(
    sn_key(pion_client[:], len=16),
    b"\xc5\xb1\xa0\x64\x9e\xa4\xfd\xaf\xbe\x7e\x25\x66\x65\x06\x82\x22",
  )
  assert_eq(
    @keys.expand_label(
      pion_server[:],
      b"key",
      b"",
      len=16,
      prefix=@keys.datagram[:],
    ),
    b"\x18\xe3\x81\x56\xd5\xa8\x77\xf3\x11\x4a\x35\x9c\x90\xcf\x6b\x1c",
  )
  assert_eq(
    @keys.expand_label(
      pion_server[:],
      b"iv",
      b"",
      len=12,
      prefix=@keys.datagram[:],
    ),
    b"\x0f\xc4\x77\x32\x03\xe0\x1c\xcd\x27\x1e\x62\x9b",
  )
  assert_eq(
    sn_key(pion_server[:], len=16),
    b"\x65\xa4\x19\xe0\xa1\xed\xa1\xc3\x85\x08\x53\xfa\x55\x6a\xde\xe4",
  )
}

///|
/// §5.3: the nonce is the IV XOR the 64-bit sequence number, and the epoch is
/// no part of it. Getting that wrong still decrypts against itself.
test "pion/dtls: the nonce excludes the epoch" {
  assert_eq(
    @record.nonce(
      b"\x6d\x32\x99\x30\x5d\xd2\x09\xfc\x86\x5c\xf8\xf1"[:],
      pion_seq,
    ),
    b"\x6d\x32\x99\x30\x5d\xd3\x0b\xff\x82\x59\xfe\xf6",
  )
}

///|
/// §4: the unified header, which is also the AEAD's additional data.
test "pion/dtls: the unified header, octet for octet" {
  let shape = Shell::new(cid=b"\xca\xfe\xba\xbe", wide=true, length=true)
  let number = { epoch: 3UL, seq: pion_seq, }
  assert_eq(header(shape, number, 42), b"\x3f\xca\xfe\xba\xbe\x06\x07\x00\x2a")
  // And read back: four octets of connection ID, a 16-bit sequence, a length.
  assert_eq(
    measure(b"\x3f\xca\xfe\xba\xbe\x06\x07\x00\x2a"[0], 4),
    Some((9, 5, true)),
  )
}

///|
/// The record itself, under the key the schedule above produced.
test "pion/dtls: the AES-128-GCM record" {
  let key = @keys.expand_label(
    pion_client[:],
    b"key",
    b"",
    len=16,
    prefix=@keys.datagram[:],
  )
  let iv = @keys.expand_label(
    pion_client[:],
    b"iv",
    b"",
    len=12,
    prefix=@keys.datagram[:],
  )
  // TLSInnerPlaintext: the content, then the real content type (§4.1).
  let cipher = aes_128_gcm(key).seal(
    nonce=@record.nonce(iv[:], pion_seq)[:],
    plain=b"\x64\x74\x6c\x73\x31\x33\x20\x61\x65\x73\x2d\x31\x32\x38\x2d\x67\x63\x6d\x20\x76\x65\x63\x74\x6f\x72\x17"[:],
    aad=b"\x3f\xca\xfe\xba\xbe\x06\x07\x00\x2a"[:],
  )
  assert_eq(
    cipher, b"\x82\xba\xcf\xce\xae\x10\x35\x32\x93\x72\xdb\xcb\xdc\xe0\x24\x0f\xaf\x43\x4e\x68\x07\x7f\xb4\xdf\x25\xed\xc7\x1d\xdd\x89\xdb\x18\xb5\x10\xcc\xd2\x51\x8b\x77\x49\x9d\x7e",
  )
  // §4.2.3: the mask is AES-ECB over the first sixteen octets of that.
  let mask = aes_mask(sn_key(pion_client[:], len=16), cipher[:])
  assert_eq(
    mask, b"\xad\xc0\x5a\xc9\xd6\xbe\x3e\x15\x70\xd3\x4d\x94\x45\x7b\xdb\x31",
  )
  // 0x0607 masked by the first two octets of it.
  let masked = (pion_seq & 0xffffUL).to_int() ^
    ((mask[0].to_int() << 8) | mask[1].to_int())
  assert_eq(masked, 0xabc7)
  // The record as it goes on the wire, sequence number masked.
  let wire = Buffer()
  wire.write_bytes(b"\x3f\xca\xfe\xba\xbe")
  wire.write_byte((masked >> 8).to_byte())
  wire.write_byte((masked & 0xff).to_byte())
  wire.write_bytes(b"\x00\x2a")
  wire.write_bytes(cipher)
  assert_eq(
    wire.to_bytes(),
    b"\x3f\xca\xfe\xba\xbe\xab\xc7\x00\x2a\x82\xba\xcf\xce\xae\x10\x35\x32\x93\x72\xdb\xcb\xdc\xe0\x24\x0f\xaf\x43\x4e\x68\x07\x7f\xb4\xdf\x25\xed\xc7\x1d\xdd\x89\xdb\x18\xb5\x10\xcc\xd2\x51\x8b\x77\x49\x9d\x7e",
  )
}

///|
/// The SHA-384 suite, which exercises a second hash through the same schedule.
test "pion/dtls: the AES-256-GCM traffic keys and record" {
  let client : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
  let server : Bytes = b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
  assert_eq(
    @keys.expand_label(
      client[:],
      b"key",
      b"",
      len=32,
      digest=Sha384,
      prefix=@keys.datagram[:],
    ),
    b"\xd6\x73\x2c\x55\xef\xc1\x02\x93\x3f\xfe\x3a\xf6\x92\x2b\xdb\x7f\xe4\x4d\x18\xf2\xb7\x30\x71\x73\x75\x8b\xfe\xb4\x57\xa6\xf9\xbb",
  )
  assert_eq(
    @keys.expand_label(
      client[:],
      b"iv",
      b"",
      len=12,
      digest=Sha384,
      prefix=@keys.datagram[:],
    ),
    b"\x8a\xe6\xb3\x15\xda\xa0\x64\xc6\xdf\xa5\xf1\x0a",
  )
  assert_eq(
    sn_key(client[:], digest=Sha384, len=32),
    b"\xfc\x6f\x78\x15\x60\x52\xe0\x19\x51\x8f\xb3\xea\x0d\x77\xc7\x96\xca\x2d\xa8\x79\x6c\xc2\x6b\x8e\x42\xc5\xb5\x39\x5a\x72\xaf\x1d",
  )
  assert_eq(
    @keys.expand_label(
      server[:],
      b"key",
      b"",
      len=32,
      digest=Sha384,
      prefix=@keys.datagram[:],
    ),
    b"\x7c\x52\x3c\xc5\x34\x69\xc1\x1f\xd6\xca\x9a\xcb\x78\xa0\xbf\x2b\xbe\x34\xf7\x77\x9d\xca\x7a\xb7\x5e\xb6\xfd\x7d\x2d\xc0\xd6\x67",
  )
  assert_eq(
    @keys.expand_label(
      server[:],
      b"iv",
      b"",
      len=12,
      digest=Sha384,
      prefix=@keys.datagram[:],
    ),
    b"\x52\xc8\x5d\xfc\xe3\x3d\xa0\x9b\x62\x29\x5a\xd7",
  )
  assert_eq(
    sn_key(server[:], digest=Sha384, len=32),
    b"\x9a\x7e\xd1\xd0\x37\xe9\x61\xad\x1e\xe0\x2f\xde\x13\x15\xf2\x9e\xbf\xd2\xfc\x8f\x3c\x82\x37\x26\x06\x4b\x93\xf0\xe9\x96\x45\x69",
  )
  let key = @keys.expand_label(
    client[:],
    b"key",
    b"",
    len=32,
    digest=Sha384,
    prefix=@keys.datagram[:],
  )
  let iv = @keys.expand_label(
    client[:],
    b"iv",
    b"",
    len=12,
    digest=Sha384,
    prefix=@keys.datagram[:],
  )
  assert_eq(
    @record.nonce(iv[:], pion_seq),
    b"\x8a\xe6\xb3\x15\xda\xa1\x66\xc5\xdb\xa0\xf7\x0d",
  )
  let block = @aes.Cipher::new(key[:])
  let cipher = @gcm.Gcm::new(block).seal(
    nonce=@record.nonce(iv[:], pion_seq)[:],
    plain=b"\x64\x74\x6c\x73\x31\x33\x20\x61\x65\x73\x2d\x32\x35\x36\x2d\x67\x63\x6d\x20\x76\x65\x63\x74\x6f\x72\x17"[:],
    aad=b"\x3f\xca\xfe\xba\xbe\x06\x07\x00\x2a"[:],
  )
  assert_eq(
    cipher, b"\x79\x99\x36\xbe\xea\x39\x2e\x94\xf7\x3b\x56\xad\x19\xe9\x6f\x5f\xf6\x07\x48\x1e\x8a\xbf\x5a\xa6\x89\x54\x14\xe2\x22\xee\xa4\x6b\x4e\x23\x85\xac\x65\xb6\xfc\x51\x6e\xde",
  )
  assert_eq(
    aes_mask(sn_key(client[:], digest=Sha384, len=32), cipher[:]),
    b"\xcd\xef\xbb\xfb\xc4\x86\x3c\xe5\x60\x22\x13\xc2\x29\x0c\x98\x9e",
  )
}

///|
/// pion's `TestUnifiedRecordWireChoices`: every combination of connection ID,
/// sequence width and length, with the first octet stated rather than derived.
test "pion/dtls: every shape of the unified header" {
  let body = 16
  for cid in [b"", b"\xca\xfe"] {
    for wide in [false, true] {
      for length in [false, true] {
        let form = Shell::new(cid~, wide~, length~)
        let seq : UInt64 = if wide { 0xaabbUL } else { 0x42UL }
        let out = Buffer()
        let mut first = 0x23
        if cid.length() > 0 {
          first = first | 0x10
        }
        if wide {
          first = first | 0x08
        }
        if length {
          first = first | 0x04
        }
        out.write_byte(first.to_byte())
        out.write_bytes(cid)
        if wide {
          out.write_byte(b'\xaa')
          out.write_byte(b'\xbb')
        } else {
          out.write_byte(b'\x42')
        }
        if length {
          out.write_byte(b'\x00')
          out.write_byte(b'\x10')
        }
        let want = out.to_bytes()
        assert_eq(header(form, { epoch: 3UL, seq, }, body), want)
        let taken = measure(want[0], cid.length())
        assert_eq(taken, Some((want.length(), 1 + cid.length(), wide)))
        assert_eq(shape(want[0]), Sealed)
      }
    }
  }
}
