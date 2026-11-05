// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
test "the frozen version is TLS 1.2's octets" {
  assert_eq(@wire.legacy_version, 0x0303)
}

///|
test "the big-endian widths round-trip" {
  let out = Buffer()
  @wire.u16(out, 0x0102)
  @wire.u24(out, 0x030405)
  let b = out.to_bytes()
  assert_eq(b, b"\x01\x02\x03\x04\x05")
  assert_eq(@wire.read_u16(b[:], 0), 0x0102)
  assert_eq(@wire.read_u24(b[:], 2), 0x030405)
  // The widths truncate rather than overflow into the octet before them.
  let wide = Buffer()
  @wire.u16(wide, 0x1FFFF)
  assert_eq(wide.to_bytes(), b"\xff\xff")
}

///|
test "reading is relative to the offset given" {
  let b = b"\x00\x00\xab\xcd"
  assert_eq(@wire.read_u16(b[:], 2), 0xabcd)
  assert_eq(@wire.read_u16(b[:], 0), 0)
}

///|
/// A structure that runs past its lengths is refused, not answered with a short value, and the
/// refusal is what a connection turns into a decode_error.
test "decode refuses octets that do not fit their lengths" {
  let read = fn(r : @wire.Reader) -> Int32 raise @wire.Refused { r.u16() }
  assert_eq(@wire.decode(b"\x01\x02"[:], read), 0x0102)
  let refused = fn(view : BytesView) -> Bool {
    try @wire.decode(view, read) catch {
      @wire.Refused => true
    } noraise {
      _ => false
    }
  }
  assert_true(refused(b"\x01"[:]))
  assert_true(refused(b""[:]))
  // Octets left over mean the length fields did not describe the whole structure.
  assert_true(refused(b"\x01\x02\x03"[:]))
}

///|
/// A payload whose absence is an answer keeps the question: the same rule, answered with `None`.
test "try_decode keeps the question where absence is the answer" {
  let read = fn(r : @wire.Reader) -> Int32 raise @wire.Refused { r.u16() }
  assert_eq(@wire.try_decode(b"\x01\x02"[:], read), Some(0x0102))
  assert_eq(@wire.try_decode(b"\x01"[:], read), None)
  assert_eq(@wire.try_decode(b"\x01\x02\x03"[:], read), None)
}
