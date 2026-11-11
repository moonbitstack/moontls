// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// DTLS 1.2's record framing (RFC 6347 §4.1.2.1). What differs from TLS 1.2 is the header — an
// explicit epoch, a 48-bit sequence number, and the frozen version in the associated data — and
// the nonce, which is built from that sequence number instead of being written on the wire. The
// protection itself, CBC's padding and its constant-time check included, is `@record`'s: the
// epoch and sequence number are exactly the eight octets a TLS 1.2 record covers, so one cipher
// serves both by being told where to continue.

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
  inner : @record.Cipher
  epoch : UInt64
  mut seq : UInt64
  seen : Window
}

///|
/// Record protection for DTLS 1.2 under one direction's key block slice.
///
/// Every suite `suites12` offers is carried: AES-GCM and ChaCha20-Poly1305, AES-CCM with a 16- or
/// 8-octet tag, and AES-CBC with a MAC before or after the encryption (RFC 7366). `mac_key` is
/// what the CBC suites sign with; the AEAD suites ignore it.
pub fn Cipher12::new(
  suite : @record.Suite12,
  key : BytesView,
  iv : BytesView,
  mac_key~ : BytesView = b""[:],
  etm~ : Bool = false,
  rand~ : (Int32) -> Bytes,
  epoch~ : UInt64,
) -> Cipher12 {
  let inner = @record.Cipher::of12(
    suite,
    key,
    iv,
    mac_key~,
    etm~,
    rand~,
    wire=legacy_version,
    // Every AEAD here but ChaCha20 writes its nonce's variable half into the record: RFC 5288 §3
    // and RFC 6655 §3 keep the `nonce_explicit` TLS 1.2 puts there, and RFC 6347 §4.1.2.4 borrows
    // those suites unchanged. ChaCha20-Poly1305 does not (RFC 7905 §2), and its nonce is the record
    // number over the IV, which the header already carries. A peer and this end agree on the
    // transcript either way, so only a third implementation shows which reading is right.
    explicit=match suite.bulk {
      Aead(ChaCha20Poly1305) => false
      _ => true
    },
  )
  { suite, inner, epoch, seq: 0UL, seen: Window::new(), }
}

///|
/// The epoch these keys protect.
pub fn Cipher12::epoch(self : Cipher12) -> UInt64 {
  self.epoch
}

///|
/// The eight octets a header and the associated data both carry: the epoch and the sequence
/// number, RFC 6347 §4.1.2.1's `seq_num`.
fn seq_octets(epoch : UInt64, seq : UInt64) -> Bytes {
  let out = Buffer()
  @wire.u16(out, (epoch & 0xffffUL).to_int())
  for i = 5; i >= 0; i = i - 1 {
    out.write_byte(((seq >> (i * 8)) & 0xffUL).to_byte())
  }
  out.to_bytes()
}

///|
/// The record header. `len` is the protected length, tag, MAC and IV included.
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
/// Seal one record (RFC 6347 §4.1.2) and advance the sequence number.
pub fn Cipher12::seal(
  self : Cipher12,
  kind : @record.Kind,
  content : BytesView,
) -> Bytes raise @alert.Alert {
  self.inner.seek((self.epoch << 48) | self.seq)
  let body = self.inner.seal_body(kind, content)
  let head = record_header12(kind, self.epoch, self.seq, body.length())
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
  if len == 0 || view.length() < end {
    raise @alert.fatal(BadRecordMac)
  }
  self.inner.seek((epoch << 48) | seq)
  let content = self.inner.open_body(kind, view[header12:end].to_owned())
  if !self.seen.accept(seq) {
    raise @alert.fatal(BadRecordMac)
  }
  (kind, content, { epoch, seq, }, end)
}
