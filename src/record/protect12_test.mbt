// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn cipher12(suite : @record.Suite12, etm~ : Bool) -> @record.Cipher {
  @record.Cipher::of12(
    suite,
    Bytes::make(suite.key_size(), b'\x11')[:],
    Bytes::make(suite.iv_size(), b'\x22')[:],
    mac_key=Bytes::make(suite.mac_size(), b'\x33')[:],
    etm~,
    rand=n => Bytes::make(n, b'\x44'),
  )
}

///|
fn refused(steps : () -> Unit raise) -> @alert.Kind raise {
  try steps() catch {
    @alert.Alert(kind~, ..) => kind
    e => raise e
  } noraise {
    _ => fail("a damaged record opened")
  }
}

///|
test "every suite seals what it opens, at the sizes that matter to padding" {
  for suite in @record.all12 {
    for etm in [false, true] {
      let (seal, open) = (cipher12(suite, etm~), cipher12(suite, etm~))
      for size in [1, 15, 16, 17, 31, 47, 48, 255, 256, 16384] {
        let plain = Bytes::make(size, b'x')
        let record = seal.seal(ApplicationData, plain[:])
        let (kind, got) = open.open(record[:])
        assert_eq(kind, ApplicationData)
        assert_eq(got, plain)
      }
    }
  }
}

///|
test "a record of nothing is allowed through the CBC framing" {
  for suite in @record.all12.filter(s => s.is_cbc()) {
    for etm in [false, true] {
      let record = cipher12(suite, etm~).seal(ApplicationData, b""[:])
      assert_eq(cipher12(suite, etm~).open(record[:]), (ApplicationData, b""))
    }
  }
}

///|
test "a flip anywhere in a record is a bad_record_mac" {
  for suite in @record.all12 {
    for etm in [false, true] {
      let record = cipher12(suite, etm~).seal(ApplicationData, b"hello"[:])
      for at in @record.header..<record.length() {
        let damaged = record.to_array()
        damaged[at] = damaged[at] ^ b'\x01'
        let open = cipher12(suite, etm~)
        assert_eq(
          refused(() => open.open(Bytes::from_array(damaged)[:]) |> ignore),
          BadRecordMac,
        )
      }
    }
  }
}

///|
test "a record out of order is a bad_record_mac" {
  for suite in @record.all12 {
    let seal = cipher12(suite, etm=false)
    seal.seal(ApplicationData, b"first"[:]) |> ignore
    let second = seal.seal(ApplicationData, b"second"[:])
    let open = cipher12(suite, etm=false)
    assert_eq(refused(() => open.open(second[:]) |> ignore), BadRecordMac)
  }
}

///|
test "the record's type is covered" {
  for suite in @record.all12 {
    let record = cipher12(suite, etm=false).seal(Handshake, b"x"[:]).to_array()
    record[0] = b'\x17'
    let open = cipher12(suite, etm=false)
    assert_eq(
      refused(() => open.open(Bytes::from_array(record)[:]) |> ignore),
      BadRecordMac,
    )
  }
}

///|
test "a CBC ciphertext too short to hold its IV and MAC is a bad_record_mac" {
  let suite = @record.Suite12::of(0x002f).unwrap()
  for size in [0, 1, 16, 31, 32, 33] {
    let out = Buffer()
    out.write_byte(b'\x17')
    out.write_byte(b'\x03')
    out.write_byte(b'\x03')
    out.write_byte((size >> 8).to_byte())
    out.write_byte((size & 0xff).to_byte())
    out.write_bytes(Bytes::make(size, b'\x00'))
    let open = cipher12(suite, etm=false)
    assert_eq(
      refused(() => open.open(out.to_bytes()[:]) |> ignore),
      BadRecordMac,
    )
  }
}

///|
test "CBC IVs come from the source given, a fresh one per record" {
  let suite = @record.Suite12::of(0x002f).unwrap()
  let mut next = 0
  let seal = @record.Cipher::of12(
    suite,
    Bytes::make(16, b'\x11')[:],
    b""[:],
    mac_key=Bytes::make(20, b'\x33')[:],
    rand=n => {
      next = next + 1
      Bytes::make(n, next.to_byte())
    },
  )
  let (a, b) = (
    seal.seal(ApplicationData, b"x"[:]),
    seal.seal(ApplicationData, b"x"[:]),
  )
  assert_eq(a[@record.header], b'\x01')
  assert_eq(b[@record.header], b'\x02')
}

///|
test "the key sizes and nonce parts match the RFCs" {
  let row = (code : Int32) => {
    let s = @record.Suite12::of(code).unwrap()
    (s.mac_size(), s.key_size(), s.iv_size())
  }
  assert_eq(row(0x009c), (0, 16, 4))
  assert_eq(row(0x009d), (0, 32, 4))
  assert_eq(row(0xcca8), (0, 32, 12))
  assert_eq(row(0xc09c), (0, 16, 4))
  assert_eq(row(0x002f), (20, 16, 0))
  assert_eq(row(0x0035), (20, 32, 0))
  assert_eq(row(0x003c), (32, 16, 0))
  assert_eq(row(0xc028), (48, 32, 0))
}

///|
test "record: TLS 1.0 chains the CBC IV from one record to the next" {
  let suite = @record.Suite12::of(0xc009).unwrap()
  let key = Bytes::make(16, b'\x11')
  let iv = Bytes::make(16, b'\x22')
  let mac = Bytes::make(20, b'\x33')
  let rand = n => Bytes::make(n, b'\x44')
  let writer = @record.Cipher::of12(
    suite,
    key[:],
    iv[:],
    mac_key=mac[:],
    rand~,
    implicit=true,
  )
  let reader = @record.Cipher::of12(
    suite,
    key[:],
    iv[:],
    mac_key=mac[:],
    rand~,
    implicit=true,
  )
  let first = writer.seal(ApplicationData, b"one"[:])
  let second = writer.seal(ApplicationData, b"two"[:])
  // No IV on the wire: the three octets and their twenty of MAC padded to two blocks.
  assert_eq(first.length(), 5 + 32)
  assert_eq(reader.open(first[:]), (ApplicationData, b"one"))
  assert_eq(reader.open(second[:]), (ApplicationData, b"two"))
}

///|
/// One record under each block cipher `legacy12` adds, as `scripts/gen_legacy_records.py` seals it
/// outside this library: Python's `cryptography` for Camellia, SEED, IDEA and triple DES, OpenSSL's
/// EVP for ARIA, and a GHASH checked against AES-GCM for the two GCM suites.
test "a legacy suite's record is the one another implementation seals" {
  let cases : Array[(Int32, String)] = [
    (
      0x0041, "1703030030444444444444444444444444444444443fe86a5422541c27adb5c4e247c2f9ed0e00c9642505f43880b00556268e56fb",
    ),
    (
      0xc077, "17030300504444444444444444444444444444444444d8c51b7367da5d048173bbc7c9bfd0ed009f9742153edac366fd8bc44ef574c34b0a42906c95b536da4d24853e3336466b93a331662ee3e873a8a4fa862278",
    ),
    (
      0xc03c, "17030300404444444444444444444444444444444403a00203da60697edd56394ac9d0cf274ff723eb98637c518897a748122bee10e3ad4f082bbe06f5558ca4f0929d370f",
    ),
    (
      0x0096, "170303003044444444444444444444444444444444592aeda2b3956cd49c04aa7a7260f0265e490930737040581d134ca0bf80a046",
    ),
    (
      0x0007, "1703030028444444444444444402746950a335a195baa9ab57d1b27af027cdbb8ce4b08ac4dab974d8462eef02",
    ),
    (
      0x000a, "170303002844444444444444440eeacae070063fa2d85b34f5d0779a672f049cb223a5f901aeaf59349e3bf260",
    ),
    (
      0xc07a, "170303001f0000000000000000fcdf831db108f0204f3aa0993855bec05f503cc0972012",
    ),
    (
      0xc051, "170303001f0000000000000000c7495edaf1c542a0c1112d74cea0c0d93b760893abcc01",
    ),
  ]
  for case in cases {
    let (code, expected) = case
    let suite = @record.Suite12::of(code).unwrap()
    let record = cipher12(suite, etm=false).seal(ApplicationData, b"moontls"[:])
    assert_eq(@base16.encode(record), expected)
    assert_eq(
      cipher12(suite, etm=false).open(record[:]),
      (ApplicationData, b"moontls"),
    )
  }
}
