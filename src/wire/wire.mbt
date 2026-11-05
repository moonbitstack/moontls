// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The version octets TLS 1.3 freezes at TLS 1.2's value, `0x0303`.
///
/// It appears as `TLSPlaintext.legacy_record_version` (RFC 8446 §5.1) and as
/// `ClientHello.legacy_version` (§4.1.2); the real version is negotiated by the
/// `supported_versions` extension. A receiver ignores it, and it is written
/// only so a middlebox watching for a TLS 1.2 handshake sees one.
pub let legacy_version : Int32 = 0x0303

// The arithmetic is `moonvar`'s. These names stay because every structure here reads
// at an offset its length check has already cleared, so they answer a value rather
// than an `Option` two hundred call sites would each unwrap.

///|
/// Append a 16-bit big-endian integer.
pub fn u16(out : Buffer, value : Int32) -> Unit {
  @fixed.write_u16(out, value)
}

///|
/// Read a 16-bit big-endian integer at `at`. Past the end of `view` it aborts, as an
/// index out of range does.
pub fn read_u16(view : BytesView, at : Int32) -> Int32 {
  @fixed.read_u16(view, at~).unwrap()
}

///|
/// Append a 24-bit big-endian integer — the width RFC 8446 §4 gives a handshake
/// message's length.
pub fn u24(out : Buffer, value : Int32) -> Unit {
  @fixed.write_u24(out, value)
}

///|
/// Read a 24-bit big-endian integer at `at`. Past the end of `view` it aborts, as an
/// index out of range does.
pub fn read_u24(view : BytesView, at : Int32) -> Int32 {
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
pub fn read_u64(view : BytesView, at : Int32) -> UInt64 {
  @fixed.read_u64(view, at~).unwrap()
}

///|
/// A structure that does not fit its own lengths (RFC 8446 §3): a length running past the end,
/// a vector outside its bounds or not a whole number of elements, or octets left over. A peer
/// is owed a decode_error for each, which is what a connection turns this into.
#derive(Eq, Debug)
pub(all) suberror Refused

///|
/// A cursor over one encoded structure. Every read checks the length it relies on, so a decoder
/// is a run of reads ending in `end`, with no offset arithmetic of its own to get wrong.
pub struct Reader {
  priv view : BytesView
  priv mut at : Int32
}

///|
pub fn Reader::new(view : BytesView) -> Reader {
  { view, at: 0, }
}

///|
/// The next `n` octets.
pub fn Reader::take(self : Reader, n : Int32) -> BytesView raise Refused {
  if n < 0 || self.at + n > self.view.length() {
    raise Refused
  }
  let out = self.view[self.at:self.at + n]
  self.at = self.at + n
  out
}

///|
pub fn Reader::u8(self : Reader) -> Int32 raise Refused {
  self.take(1)[0].to_int()
}

///|
pub fn Reader::u16(self : Reader) -> Int32 raise Refused {
  read_u16(self.take(2), 0)
}

///|
pub fn Reader::u24(self : Reader) -> Int32 raise Refused {
  read_u24(self.take(3), 0)
}

///|
/// A vector behind a `width`-octet length (RFC 8446 §3), as a cursor of its own. `min` is the
/// least length the structure allows and `unit` the size of one element, which the length must
/// be a whole multiple of.
pub fn Reader::vec(
  self : Reader,
  width : Int32,
  min~ : Int32 = 0,
  unit~ : Int32 = 1,
) -> Reader raise Refused {
  let len = match width {
    1 => self.u8()
    2 => self.u16()
    3 => self.u24()
    _ => abort("moontls: a vector length is one, two or three octets")
  }
  if len < min || len % unit != 0 {
    raise Refused
  }
  Reader::new(self.take(len))
}

///|
/// The 16-bit codes up to the end, the shape of every list of suites, groups, schemes and
/// versions.
pub fn Reader::codes(self : Reader) -> Array[Int32] raise Refused {
  let out = []
  while !self.is_empty() {
    out.push(self.u16())
  }
  out
}

///|
/// Everything not yet read.
pub fn Reader::rest(self : Reader) -> BytesView {
  let out = self.view[self.at:]
  self.at = self.view.length()
  out
}

///|
pub fn Reader::is_empty(self : Reader) -> Bool {
  self.at == self.view.length()
}

///|
/// Read all of `view` as one structure with `read`, refusing it when it does not fit its lengths
/// or leaves octets over.
///
/// The refusal is the answer, not a `None`: every caller of this either turns it into a
/// decode_error for the peer or has nothing better to do with a structure that does not parse.
pub fn[T] decode(
  view : BytesView,
  read : (Reader) -> T raise Refused,
) -> T raise Refused {
  let r = Reader::new(view)
  let out = read(r)
  r.end()
  out
}

///|
/// [`decode`] where a structure that does not parse is `None` rather than a refusal — for the
/// payloads whose absence is itself an answer, such as an optional extension body a hello may
/// simply not carry.
pub fn[T] try_decode(
  view : BytesView,
  read : (Reader) -> T raise Refused,
) -> T? {
  Some(decode(view, read)) catch {
    Refused => None
  }
}

///|
/// Raise when anything is left: a structure ends where its length says.
pub fn Reader::end(self : Reader) -> Unit raise Refused {
  if !self.is_empty() {
    raise Refused
  }
}

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}
