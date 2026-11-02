// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
test "msg: a certificate with a stapled status reads back with it" {
  let leaf = Bytes::make(200, b'\x01')
  let tail = Bytes::make(50, b'\x02')
  let response = b"\x30\x03\x0a\x01\x00"
  let body = @msg.certificate_status([leaf, tail][:], response[:])
  let parsed = @msg.read_certificate_entries(body[:])
  if parsed is None {
    fail("did not read, len=\{body.length()}")
  }
  guard parsed is Some((context, certs, entries)) else { fail("x") }
  assert_eq(context.length(), 0)
  assert_eq(certs.length(), 2)
  assert_eq(certs[0], leaf)
  assert_eq(entries.length(), 2)
  guard @ext.find(entries[0][:], StatusRequest) is Some(e) else {
    fail("no status on the leaf")
  }
  assert_eq(@ext.read_certificate_status(e.data[:]), Some(response))
}
