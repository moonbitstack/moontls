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

// The arithmetic is `moonvar`'s. These names stay because every structure here reads
// at an offset its length check has already cleared, so they answer a value rather
// than an `Option` two hundred call sites would each unwrap.

///|
/// Append a 16-bit big-endian integer.
pub fn u16(out : Buffer, value : Int) -> Unit {
  @fixed.write_u16(out, value)
}

///|
/// Read a 16-bit big-endian integer at `at`. Past the end of `view` it aborts, as an
/// index out of range does.
pub fn read_u16(view : BytesView, at : Int) -> Int {
  @fixed.read_u16(view, at~).unwrap()
}

///|
/// Append a 24-bit big-endian integer — the width RFC 8446 §4 gives a handshake
/// message's length.
pub fn u24(out : Buffer, value : Int) -> Unit {
  @fixed.write_u24(out, value)
}

///|
/// Read a 24-bit big-endian integer at `at`. Past the end of `view` it aborts, as an
/// index out of range does.
pub fn read_u24(view : BytesView, at : Int) -> Int {
  @fixed.read_u24(view, at~).unwrap()
}

///|
/// Append a 64-bit big-endian integer — the width RFC 9147 §4 gives each half
/// of a DTLS record number.
pub fn u64(out : Buffer, value : UInt64) -> Unit {
  @fixed.write_u64(out, value)
}

///|
/// Read a 64-bit big-endian integer at `at`. Past the end of `view` it aborts, as an
/// index out of range does.
pub fn read_u64(view : BytesView, at : Int) -> UInt64 {
  @fixed.read_u64(view, at~).unwrap()
}
