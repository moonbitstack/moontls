// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The record number is the one field of a DTLS 1.2 header a test has to reach inside the cipher to
// move, which is why these are whitebox: everything else about the layer is driven through a
// connection.

///|
fn refuses(call : () -> Unit raise @alert.Alert) -> Bool {
  try {
    call()
    false
  } catch {
    _ => true
  }
}

///|
/// RFC 6347 §4.1.2.1: a sender must not let its record number wrap. The field is 48 bits, so
/// 2^48-1 is the last number an epoch can use; a connection that reaches it has to renegotiate,
/// and a layer that cannot has to stop rather than repeat a number under the same key.
test "a dtls 1.2 record number does not wrap" {
  let suite = @record.suites12[0]
  let key = Bytes::make(suite.key_size(), b'\x2a')
  let iv = Bytes::make(suite.iv_size(), b'\x2b')
  let cipher = Cipher12::new(
    suite,
    key[:],
    iv[:],
    rand=n => Bytes::make(n, b'\x2c'),
    epoch=1UL,
  )
  cipher.seq = seq12_max
  assert_false(refuses(() => cipher.seal(@record.Handshake, b"x"[:]) |> ignore))
  assert_true(refuses(() => cipher.seal(@record.Handshake, b"x"[:]) |> ignore))
}

///|
/// The number the guard refuses is the one past the last the header can carry, not the last one: a
/// record sealed at 2^48-1 has to say so in its own header.
test "the last record number is written at its full width" {
  let suite = @record.suites12[0]
  let key = Bytes::make(suite.key_size(), b'\x2a')
  let iv = Bytes::make(suite.iv_size(), b'\x2b')
  let cipher = Cipher12::new(
    suite,
    key[:],
    iv[:],
    rand=n => Bytes::make(n, b'\x2c'),
    epoch=1UL,
  )
  cipher.seq = seq12_max
  let record = cipher.seal(@record.Handshake, b"x"[:])
  // Header: type, version, epoch, then the six octets of the sequence number.
  assert_eq(record[5], b'\xff')
  assert_eq(record[6], b'\xff')
  assert_eq(record[7], b'\xff')
  assert_eq(record[8], b'\xff')
  assert_eq(record[9], b'\xff')
  assert_eq(record[10], b'\xff')
}
