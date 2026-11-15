// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The bound a compressed Certificate is held to (RFC 8879 §4): the length the message promises,
// and not one octet more.

///|
test "compress: a body that unpacks past the length it promised is refused" {
  let body = Bytes::make(2000, b'a')
  let packed = pack(@ext.zlib_compression, body[:]).unwrap()
  // The message says 100 octets; the stream holds 2000.
  let refused = try {
    let _ = unpack(@ext.zlib_compression, packed[:], 100)
    false
  } catch {
    _ => true
  }
  assert_true(refused)
  // The length it really is, and the body comes back whole.
  assert_eq(unpack(@ext.zlib_compression, packed[:], 2000).length(), 2000)
}

///|
test "compress: each algorithm round-trips a certificate-sized body" {
  let body = Bytes::make(1500, b'x')
  for
    algorithm in [
      @ext.zlib_compression, @ext.brotli_compression, @ext.zstd_compression,
    ] {
    let packed = pack(algorithm, body[:]).unwrap()
    assert_true(packed.length() < body.length())
    assert_eq(unpack(algorithm, packed[:], body.length()), body)
  }
}

///|
test "compress: a code point this library does not speak is no algorithm at all" {
  assert_true(pack(0x4242, b"anything"[:]) is None)
  let refused = try {
    let _ = unpack(0x4242, b"anything"[:], 64)
    false
  } catch {
    _ => true
  }
  assert_true(refused)
}
