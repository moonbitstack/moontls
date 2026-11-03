// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// DTLS 1.2's record protection (RFC 6347 §4.1.2.1). It is not TLS 1.2's:
// the epoch and the 48-bit sequence number live in the header, the nonce is
// built from them rather than from an explicit eight octets on the wire, and
// the associated data carries DTLS 1.2's frozen version. Everything else — the
// suite's AEAD, the key block the PRF produced — is the same as TLS 1.2's.

///|
/// The DTLS 1.2 record header (RFC 6347 §4.1): type, the frozen version, a
/// 16-bit epoch, a 48-bit sequence number and a 16-bit length.
pub let header12 : Int32 = 13

///|
/// One epoch's DTLS 1.2 record protection.
///
/// One of these per direction per epoch: the sequence space restarts at the
/// change_cipher_spec, and the replay window belongs to the epoch.
pub struct Cipher12 {
  suite : @record.Suite12
  aead : &@spec.Aead
  salt : Bytes
  epoch : UInt64
  mut seq : UInt64
  seen : Window
}

///|
/// Record protection for DTLS 1.2 under one direction's key block slice.
///
/// Only the AEAD suites are carried here: `TLS_ECDHE_*_WITH_AES_*_GCM_*` and
/// `TLS_ECDHE_*_WITH_CHACHA20_POLY1305_SHA256`, which is what `suites12`
/// offers by default. CBC and CCM need their own record framing and their own
/// countermeasures, and a DTLS association that asked for them is refused
/// rather than protected wrongly.
pub fn Cipher12::new(
  suite : @record.Suite12,
  key : BytesView,
  salt : BytesView,
  epoch~ : UInt64,
) -> Cipher12 raise @alert.Alert {
  let bulk = match suite.bulk {
    @record.Aead(one) => one
    _ => raise @alert.fatal(InternalError)
  }
  let aead = aead_of(bulk)(key.to_owned())
  { suite, aead, salt: salt.to_owned(), epoch, seq: 0UL, seen: Window::new(), }
}

///|
/// The epoch these keys protect.
pub fn Cipher12::epoch(self : Cipher12) -> UInt64 {
  self.epoch
}

///|
/// The eight octets a nonce and the associated data both start from: the epoch
/// and the sequence number, RFC 6347 §4.1.2.1's `seq_num`.
fn seq_octets(epoch : UInt64, seq : UInt64) -> Bytes {
  let out = Buffer()
  @wire.u16(out, (epoch & 0xffffUL).to_int())
  for i = 5; i >= 0; i = i - 1 {
    out.write_byte(((seq >> (i * 8)) & 0xffUL).to_byte())
  }
  out.to_bytes()
}

///|
/// The record header, which is also the first part of the AEAD's associated
/// data. `len` is the ciphertext length, tag included.
fn record_header12(
  kind : @record.Kind,
  epoch : UInt64,
  seq : UInt64,
  len : Int32,
) -> Bytes {
  let out = Buffer()
  out.write_byte((kind.code() & 0xff).to_byte())
  @wire.u16(out, legacy_version)
  out.write_bytes(seq_octets(epoch, seq))
  @wire.u16(out, len)
  out.to_bytes()
}

///|
/// The nonce (RFC 6347 §4.1.2.1): four octets of salt and the eight-octet
/// sequence number for GCM and CCM; the twelve-octet IV XORed with the sequence
/// number for ChaCha20-Poly1305 (RFC 7905 §2).
fn Cipher12::nonce(self : Cipher12, epoch : UInt64, seq : UInt64) -> Bytes {
  match self.suite.bulk {
    @record.Aead(@record.ChaCha20Poly1305) => {
      let s = seq_octets(epoch, seq)
      let out = Buffer()
      for i = 0; i < self.salt.length(); i = i + 1 {
        let from_end = self.salt.length() - 1 - i
        let mask = if from_end < 8 { s[7 - from_end].to_int() } else { 0 }
        out.write_byte((self.salt[i].to_int() ^ mask).to_byte())
      }
      out.to_bytes()
    }
    _ => {
      let out = Buffer()
      out.write_bytes(self.salt)
      out.write_bytes(seq_octets(epoch, seq))
      out.to_bytes()
    }
  }
}

///|
/// The AEAD's associated data (RFC 6347 §4.1.2.1): the sequence number, the
/// content type, the frozen version and the plaintext length.
fn aad12(
  kind : @record.Kind,
  epoch : UInt64,
  seq : UInt64,
  len : Int32,
) -> Bytes {
  let out = Buffer()
  out.write_bytes(seq_octets(epoch, seq))
  out.write_byte((kind.code() & 0xff).to_byte())
  @wire.u16(out, legacy_version)
  @wire.u16(out, len)
  out.to_bytes()
}

///|
/// Seal one record (RFC 6347 §4.1.2) and advance the sequence number.
pub fn Cipher12::seal(
  self : Cipher12,
  kind : @record.Kind,
  content : BytesView,
) -> Bytes raise @alert.Alert {
  if content.length() > @record.max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  let len = content.length() + @record.tag_size
  let head = record_header12(kind, self.epoch, self.seq, len)
  let aad = aad12(kind, self.epoch, self.seq, content.length())
  let nonce = self.nonce(self.epoch, self.seq)
  let body = self.aead.seal(nonce=nonce[:], plain=content, aad=aad[:])
  self.seq = self.seq + 1UL
  let out = Buffer()
  out.write_bytes(head)
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// Open one record (RFC 6347 §4.1.2): its content type and content, the record
/// number it carried, and how many octets it took. A record that fails is a
/// `BadRecordMac` and the replay window does not move (§4.1.2.7).
pub fn Cipher12::open(
  self : Cipher12,
  view : BytesView,
) -> (@record.Kind, Bytes, Number, Int32) raise @alert.Alert {
  guard view.length() >= header12 else { raise @alert.fatal(BadRecordMac) }
  guard @record.Kind::of(view[0].to_int()) is Some(kind) else {
    raise @alert.fatal(BadRecordMac)
  }
  let epoch = @wire.read_u16(view, 3).to_uint64()
  let mut seq = 0UL
  for i = 5; i < 11; i = i + 1 {
    seq = (seq << 8) | view[i].to_uint64()
  }
  let len = @wire.read_u16(view, 11)
  let end = header12 + len
  if len < @record.tag_size || view.length() < end {
    raise @alert.fatal(BadRecordMac)
  }
  let plain_len = len - @record.tag_size
  let aad = aad12(kind, epoch, seq, plain_len)
  let nonce = self.nonce(epoch, seq)
  let content = self.aead.open(
    nonce=nonce[:],
    cipher=view[header12:end],
    aad=aad[:],
  ) catch {
    _ => raise @alert.fatal(BadRecordMac)
  }
  if !self.seen.accept(seq) {
    raise @alert.fatal(BadRecordMac)
  }
  (kind, content, { epoch, seq, }, end)
}
