// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The version octets TLS 1.3 freezes at TLS 1.2's value, `0x0303`.
///
/// It appears as `TLSPlaintext.legacy_record_version` (RFC 8446 §5.1) and as
/// `ClientHello.legacy_version` (§4.1.2); the real version is negotiated by the
/// `supported_versions` extension. A receiver ignores it, and it is written
/// only so a middlebox watching for a TLS 1.2 handshake sees one.
pub let legacy_version : Int = 0x0303

///|
/// Append a 16-bit big-endian integer.
pub fn u16(out : Buffer, value : Int) -> Unit {
  out.write_byte(((value >> 8) & 0xff).to_byte())
  out.write_byte((value & 0xff).to_byte())
}

///|
/// Read a 16-bit big-endian integer at `at`.
pub fn read_u16(view : BytesView, at : Int) -> Int {
  (view[at].to_int() << 8) | view[at + 1].to_int()
}

///|
/// Append a 24-bit big-endian integer — the width RFC 8446 §4 gives a handshake
/// message's length.
pub fn u24(out : Buffer, value : Int) -> Unit {
  out.write_byte(((value >> 16) & 0xff).to_byte())
  out.write_byte(((value >> 8) & 0xff).to_byte())
  out.write_byte((value & 0xff).to_byte())
}

///|
/// Read a 24-bit big-endian integer at `at`.
pub fn read_u24(view : BytesView, at : Int) -> Int {
  (view[at].to_int() << 16) |
  (view[at + 1].to_int() << 8) |
  view[at + 2].to_int()
}
