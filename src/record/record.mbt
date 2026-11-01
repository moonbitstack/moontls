// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What a record carries (RFC 8446 §5).
///
/// `Other` keeps a content type the RFC does not define rather than losing it,
/// but the parser refuses one: an unknown type is an `UnexpectedMessage`, not
/// something to skip past.
pub(all) enum Kind {
  /// TLS 1.3 has no change_cipher_spec message. The record survives only so
  /// middleboxes watching for a TLS 1.2 handshake see one.
  ChangeCipherSpec
  /// An alert (RFC 8446 §6).
  Alert
  /// A handshake message (RFC 8446 §4).
  Handshake
  /// Application data — and the outer `opaque_type` of every TLSCiphertext,
  /// whatever the real type sealed inside turns out to be.
  ApplicationData
  /// An ACK (RFC 9147 §7). DTLS only — the TLS record parser here refuses it,
  /// because a reliable transport has nothing to acknowledge. It is in this
  /// enum rather than a second one because the ContentType registry is one
  /// registry, and `moontls/dtls` reads and writes these same records.
  Ack
  /// A content type RFC 8446 §5 does not define.
  Other(Int32)
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The octet this content type goes on the wire as.
pub fn Kind::code(self : Kind) -> Int32 {
  match self {
    ChangeCipherSpec => 20
    Alert => 21
    Handshake => 22
    ApplicationData => 23
    Ack => 26
    Other(code) => code
  }
}

///|
/// The content type an octet names, or `None` for one RFC 8446 §5 does not
/// define — which the record parser turns into an alert rather than tolerating.
pub fn Kind::of(code : Int32) -> Kind? {
  match code {
    20 => Some(ChangeCipherSpec)
    21 => Some(Alert)
    22 => Some(Handshake)
    23 => Some(ApplicationData)
    26 => Some(Ack)
    _ => None
  }
}

///|
/// The largest TLSPlaintext fragment (RFC 8446 §5.1): 2^14 octets.
///
/// The RFC fixes it, so it is a constant and not a parameter: a record past it
/// is not a record.
pub let max_fragment : Int32 = 16384

///|
/// The largest TLSCiphertext encrypted_record (RFC 8446 §5.2): 2^14 + 256 — the
/// fragment limit plus the room the inner content type, the padding and the
/// AEAD tag need.
pub let max_encrypted : Int32 = 16640

///|
/// The record header: content type, legacy_record_version, and a 16-bit length.
pub let header : Int32 = 5

///|
/// One record's content type and fragment (RFC 8446 §5.1).
///
/// For a TLSCiphertext the `kind` is the outer `ApplicationData` and the
/// `fragment` is still sealed.
pub(all) struct Record {
  kind : Kind
  fragment : Bytes
} derive(Eq, Debug)

///|
pub extend Record with Eq::{equal, not_equal}

///|
pub extend Record with Debug::{to_repr}

///|
/// Frame `fragment` as a TLSPlaintext record (RFC 8446 §5.1).
///
/// `legacy_record_version` is `0x0303` whatever the negotiated version is; a
/// receiver ignores it.
pub fn encode(kind : Kind, fragment : BytesView) -> Bytes raise @alert.Alert {
  if fragment.length() > max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  let out = Buffer()
  out.write_byte((kind.code() & 0xff).to_byte())
  @wire.u16(out, @wire.legacy_version)
  @wire.u16(out, fragment.length())
  out.write_bytesview(fragment)
  out.to_bytes()
}

///|
/// Read one record off the front of `view`, capping the fragment at `limit`.
///
/// `None` means the view does not hold a whole record yet. The length is
/// checked before the wait, so an oversized record fails immediately rather
/// than waiting forever for octets that may never come.
fn read(view : BytesView, limit : Int32) -> (Record, Int32)? raise @alert.Alert {
  if view.length() < header {
    return None
  }
  guard Kind::of(view[0].to_int()) is Some(kind) && kind != Ack else {
    raise @alert.fatal(UnexpectedMessage)
  }
  let len = @wire.read_u16(view, 3)
  if len > limit {
    raise @alert.fatal(RecordOverflow)
  }
  // §5.1: only application_data may be sent zero-length, as a traffic-analysis
  // countermeasure. An empty handshake or alert record is a framing error.
  if len == 0 && kind != ApplicationData {
    raise @alert.fatal(UnexpectedMessage)
  }
  let end = header + len
  if view.length() < end {
    return None
  }
  Some(({ kind, fragment: view[header:end].to_owned(), }, end))
}

///|
/// Read one TLSPlaintext record (RFC 8446 §5.1) and how many octets it
/// consumed, or `None` while the view is short of a whole record.
pub fn decode(view : BytesView) -> (Record, Int32)? raise @alert.Alert {
  read(view, max_fragment)
}

///|
/// Read one TLSCiphertext record (RFC 8446 §5.2) and how many octets it
/// consumed.
///
/// The fragment is the still-sealed encrypted_record, so the ceiling is the
/// larger §5.2 one.
pub fn decode_encrypted(
  view : BytesView,
) -> (Record, Int32)? raise @alert.Alert {
  read(view, max_encrypted)
}

///|
/// A TLSInnerPlaintext (RFC 8446 §5.2): the content, then the content type the
/// outer header is hiding, then `padding` zero octets.
///
/// The padding is §5.4's length-hiding knob — a record's length leaks how much
/// was said, and zero octets after the type cost only bandwidth.
pub fn inner(kind : Kind, content : BytesView, padding~ : Int32 = 0) -> Bytes {
  let out = Buffer()
  out.write_bytesview(content)
  out.write_byte((kind.code() & 0xff).to_byte())
  for _i = 0; _i < padding; _i = _i + 1 {
    out.write_byte(b'\x00')
  }
  out.to_bytes()
}

///|
/// Split a TLSInnerPlaintext back into its content type and content
/// (RFC 8446 §5.2).
///
/// Scan back over the zero padding to the last non-zero octet, which is the
/// type. An inner plaintext of nothing but zeros names no type at all, which
/// §5.2 makes an `UnexpectedMessage` rather than an empty record.
pub fn unpad(plaintext : BytesView) -> (Kind, Bytes) raise @alert.Alert {
  let mut i = plaintext.length() - 1
  while i >= 0 && plaintext[i] == b'\x00' {
    i = i - 1
  }
  if i < 0 {
    raise @alert.fatal(UnexpectedMessage)
  }
  guard Kind::of(plaintext[i].to_int()) is Some(kind) else {
    raise @alert.fatal(UnexpectedMessage)
  }
  (kind, plaintext[0:i].to_owned())
}

///|
/// The AEAD key and IV one direction protects its records with
/// (RFC 8446 §7.3), at `TLS_AES_128_GCM_SHA256`'s lengths.
pub(all) struct Traffic {
  key : Bytes
  iv : Bytes
} derive(Eq, Debug)

///|
pub extend Traffic with Eq::{equal, not_equal}

///|
pub extend Traffic with Debug::{to_repr}

///|
/// The key length `TLS_AES_128_GCM_SHA256` fixes: AES-128.
pub let key_size : Int32 = 16

///|
/// The IV length AEAD_AES_128_GCM fixes (RFC 5116 §5.1).
pub let iv_size : Int32 = 12

///|
/// The AEAD tag length AEAD_AES_128_GCM fixes.
pub let tag_size : Int32 = 16

///|
/// Derive a direction's record-protection key and IV from its traffic secret
/// (RFC 8446 §7.3).
///
/// QUIC expands the same secret under `"quic key"`/`"quic iv"` and adds a
/// header-protection key (RFC 9001 §5.1); over TCP the labels are bare and
/// there is no header to protect.
pub fn traffic(
  secret : BytesView,
  digest~ : @keys.Digest = @keys.digest,
  prefix~ : BytesView = @keys.prefix[:],
  len~ : Int32 = key_size,
) -> Traffic {
  {
    key: @keys.expand_label(secret, b"key", b"", len~, digest~, prefix~),
    iv: @keys.expand_label(secret, b"iv", b"", len=iv_size, digest~, prefix~),
  }
}

///|
/// The per-record AEAD nonce (RFC 8446 §5.3): the 64-bit sequence number, big-
/// endian and left-padded with zeros to the IV's length, XORed with the static
/// write IV.
///
/// The IV never changes, so the sequence number alone is what keeps two records
/// under one key from ever sharing a nonce.
pub fn nonce(iv : BytesView, seq : UInt64) -> Bytes {
  let out = Buffer()
  for i = 0; i < iv.length(); i = i + 1 {
    let from_end = iv.length() - 1 - i
    let s = if from_end < 8 {
      (seq >> (from_end * 8)).to_byte().to_int()
    } else {
      0
    }
    out.write_byte((iv[i].to_int() ^ s).to_byte())
  }
  out.to_bytes()
}

///|
/// A TLS 1.3 cipher suite (RFC 8446 §B.4): the AEAD and the hash, which fix the key length.
pub(all) enum Suite {
  Aes128Gcm
  Aes256Gcm
  ChaCha20Poly1305
} derive(Eq, Debug)

///|
/// The suite's code on the wire.
pub fn Suite::code(self : Suite) -> Int32 {
  match self {
    Aes128Gcm => 0x1301
    Aes256Gcm => 0x1302
    ChaCha20Poly1305 => 0x1303
  }
}

///|
/// The suite a code names, `None` for one this library does not implement.
pub fn Suite::of(code : Int32) -> Suite? {
  match code {
    0x1301 => Some(Aes128Gcm)
    0x1302 => Some(Aes256Gcm)
    0x1303 => Some(ChaCha20Poly1305)
    _ => None
  }
}

///|
/// The suite's code in TLS 1.2, where it also names the kind of certificate (RFC 5289, RFC 7905).
/// Only ECDHE: `rsa` says the certificate is RSA, otherwise ECDSA or EdDSA.
pub fn Suite::tls12(self : Suite, rsa~ : Bool) -> Int32 {
  match (self, rsa) {
    (Aes128Gcm, false) => 0xc02b
    (Aes128Gcm, true) => 0xc02f
    (Aes256Gcm, false) => 0xc02c
    (Aes256Gcm, true) => 0xc030
    (ChaCha20Poly1305, false) => 0xcca9
    (ChaCha20Poly1305, true) => 0xcca8
  }
}

///|
/// The suite a TLS 1.2 code names, and whether it is the RSA one.
pub fn Suite::of_tls12(code : Int32) -> (Suite, Bool)? {
  match code {
    0xc02b => Some((Aes128Gcm, false))
    0xc02f => Some((Aes128Gcm, true))
    0xc02c => Some((Aes256Gcm, false))
    0xc030 => Some((Aes256Gcm, true))
    0xcca9 => Some((ChaCha20Poly1305, false))
    0xcca8 => Some((ChaCha20Poly1305, true))
    _ => None
  }
}

///|
/// The hash the suite's key schedule runs.
pub fn Suite::digest(self : Suite) -> @keys.Digest {
  match self {
    Aes256Gcm => Sha384
    Aes128Gcm | ChaCha20Poly1305 => Sha256
  }
}

///|
/// The AEAD key length.
pub fn Suite::key_size(self : Suite) -> Int32 {
  match self {
    Aes128Gcm => 16
    Aes256Gcm | ChaCha20Poly1305 => 32
  }
}

///|
/// The suite's AEAD over `key`. Aborts on a key of the wrong length: every key reaching it came
/// from [`traffic`] at the suite's length.
pub fn Suite::aead(self : Suite, key : Bytes) -> &@spec.Aead {
  match self {
    Aes128Gcm | Aes256Gcm => {
      let block = @aes.Cipher::new(key[:]) catch {
        _ => abort("moontls: AES refused a key of the suite's length")
      }
      let aead : &@spec.Aead = @gcm.Gcm::new(block) catch {
        _ => abort("moontls: GCM refused its block cipher")
      }
      aead
    }
    ChaCha20Poly1305 => {
      let aead : &@spec.Aead = @chachapoly.ChaChaPoly::new(key[:]) catch {
        _ => abort("moontls: ChaCha20-Poly1305 refused a 32-octet key")
      }
      aead
    }
  }
}

///|
/// One direction's record protection: its suite, traffic keys, and the sequence number that keeps
/// their nonces apart. RFC 8446 §5.3 restarts the sequence at zero on every key change.
pub struct Cipher {
  suite : Suite
  mut traffic : Traffic
  mut seq : UInt64
  // TLS 1.2's framing: the content type in the clear, and for GCM an explicit nonce.
  legacy : Bool
}

///|
fn traffic_of(suite : Suite, secret : BytesView) -> Traffic {
  traffic(secret, digest=suite.digest(), len=suite.key_size())
}

///|
/// Record protection under the traffic `secret`, starting at sequence zero.
pub fn Cipher::new(secret : BytesView, suite~ : Suite = Aes128Gcm) -> Cipher {
  { suite, traffic: traffic_of(suite, secret), seq: 0UL, legacy: false, }
}

///|
/// Record protection for TLS 1.2 (RFC 5288, RFC 7905), under keys from the key block rather than
/// a traffic secret.
pub fn Cipher::tls12(
  key : BytesView,
  iv : BytesView,
  suite~ : Suite = Aes128Gcm,
) -> Cipher {
  {
    suite,
    traffic: { key: key.to_owned(), iv: iv.to_owned(), },
    seq: 0UL,
    legacy: true,
  }
}

///|
/// Whether this cipher frames records the TLS 1.2 way.
pub fn Cipher::is_tls12(self : Cipher) -> Bool {
  self.legacy
}

///|
/// The eight octets of the sequence number.
fn seq_octets(seq : UInt64) -> Bytes {
  let out = Buffer()
  for shift = 56; shift >= 0; shift = shift - 8 {
    out.write_byte(((seq >> shift) & 0xffUL).to_byte())
  }
  out.to_bytes()
}

///|
/// A TLS 1.2 record's additional data (RFC 5246 §6.2.3.3): the sequence number, the type, the
/// version and the plaintext's length.
fn aad12(seq : UInt64, kind : Kind, size : Int32) -> Bytes {
  let out = Buffer()
  out.write_bytes(seq_octets(seq))
  out.write_byte((kind.code() & 0xff).to_byte())
  @wire.u16(out, @wire.legacy_version)
  @wire.u16(out, size)
  out.to_bytes()
}

///|
/// How long a record's explicit nonce is: eight octets for GCM, the sequence number sent in the
/// open (RFC 5288 §3), and none for ChaCha20-Poly1305 (RFC 7905 §2).
fn Suite::explicit_size(self : Suite) -> Int32 {
  match self {
    ChaCha20Poly1305 => 0
    _ => 8
  }
}

///|
/// How much of the key block a suite takes for each direction's IV: GCM's four-octet salt, or
/// ChaCha20-Poly1305's twelve.
pub fn Suite::iv12(self : Suite) -> Int32 {
  match self {
    ChaCha20Poly1305 => 12
    _ => 4
  }
}

///|
fn Cipher::nonce12(self : Cipher, explicit : BytesView) -> Bytes {
  match self.suite {
    ChaCha20Poly1305 => nonce(self.traffic.iv[:], self.seq)
    _ => {
      let out = Buffer()
      out.write_bytes(self.traffic.iv)
      out.write_bytesview(explicit)
      out.to_bytes()
    }
  }
}

///|
fn Cipher::seal12(
  self : Cipher,
  kind : Kind,
  content : BytesView,
) -> Bytes raise @alert.Alert {
  if content.length() > max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  let explicit = if self.suite.explicit_size() > 0 {
    seq_octets(self.seq)
  } else {
    b""
  }
  let body = self.suite
    .aead(self.traffic.key)
    .seal(
      nonce=self.nonce12(explicit[:])[:],
      plain=content,
      aad=aad12(self.seq, kind, content.length())[:],
    )
  self.seq = self.seq + 1UL
  let out = Buffer()
  out.write_byte((kind.code() & 0xff).to_byte())
  @wire.u16(out, @wire.legacy_version)
  @wire.u16(out, explicit.length() + body.length())
  out.write_bytes(explicit)
  out.write_bytes(body)
  out.to_bytes()
}

///|
fn Cipher::open12(
  self : Cipher,
  record : BytesView,
) -> (Kind, Bytes) raise @alert.Alert {
  guard read(record, max_encrypted) is Some((rec, _)) else {
    raise @alert.fatal(DecodeError)
  }
  let skip = self.suite.explicit_size()
  let size = rec.fragment.length() - skip - tag_size
  if size < 0 {
    raise @alert.fatal(BadRecordMac)
  }
  let explicit = rec.fragment[0:skip]
  let plain = self.suite
    .aead(self.traffic.key)
    .open(
      nonce=self.nonce12(explicit)[:],
      cipher=rec.fragment[skip:],
      aad=aad12(self.seq, rec.kind, size)[:],
    ) catch {
      _ => raise @alert.fatal(BadRecordMac)
    }
  self.seq = self.seq + 1UL
  if plain.length() > max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  (rec.kind, plain)
}

///|
/// Install a new traffic secret and restart the sequence number at zero (RFC 8446 §5.3).
pub fn Cipher::rekey(self : Cipher, secret : BytesView) -> Unit {
  self.traffic = traffic_of(self.suite, secret)
  self.seq = 0UL
}

///|
/// The traffic keys in force.
pub fn Cipher::traffic(self : Cipher) -> Traffic {
  self.traffic
}

///|
/// The sequence number the next record will use.
pub fn Cipher::seq(self : Cipher) -> UInt64 {
  self.seq
}

///|
/// The nonce the next record will be sealed or opened under (RFC 8446 §5.3).
pub fn Cipher::nonce(self : Cipher) -> Bytes {
  nonce(self.traffic.iv[:], self.seq)
}

///|
/// The five header octets of a TLSCiphertext whose encrypted_record is `len`
/// long.
///
/// They are also the AEAD's additional data (RFC 8446 §5.2), which is why the
/// length has to be settled before the seal rather than measured after it.
fn ciphertext_header(len : Int32) -> Bytes {
  let out = Buffer()
  out.write_byte((Kind::ApplicationData.code() & 0xff).to_byte())
  @wire.u16(out, @wire.legacy_version)
  @wire.u16(out, len)
  out.to_bytes()
}

///|
/// Seal `content` as a TLSCiphertext record (RFC 8446 §5.2) with `padding` zero
/// octets after the inner content type, and advance the sequence number.
pub fn Cipher::seal(
  self : Cipher,
  kind : Kind,
  content : BytesView,
  padding~ : Int32 = 0,
) -> Bytes raise @alert.Alert {
  if self.legacy {
    return self.seal12(kind, content)
  }
  if content.length() > max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  let plaintext = inner(kind, content, padding~)
  let len = plaintext.length() + tag_size
  if len > max_encrypted {
    raise @alert.fatal(RecordOverflow)
  }
  let aad = ciphertext_header(len)
  let body = self.suite
    .aead(self.traffic.key)
    .seal(nonce=self.nonce()[:], plain=plaintext[:], aad=aad[:])
  self.seq = self.seq + 1UL
  let out = Buffer()
  out.write_bytes(aad)
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// Open one whole TLSCiphertext record — header included, since RFC 8446 §5.2
/// makes that header the AEAD's additional data — into the content type and
/// content sealed inside, advancing the sequence number.
///
/// A tag that does not verify is a `BadRecordMac` and the sequence does not
/// move, because §5.2 ends the connection there.
pub fn Cipher::open(
  self : Cipher,
  record : BytesView,
) -> (Kind, Bytes) raise @alert.Alert {
  if self.legacy {
    return self.open12(record)
  }
  guard read(record, max_encrypted) is Some((rec, _)) else {
    raise @alert.fatal(DecodeError)
  }
  let aad = record[0:header].to_owned()
  let plaintext = self.suite
    .aead(self.traffic.key)
    .open(nonce=self.nonce()[:], cipher=rec.fragment[:], aad=aad[:]) catch {
      _ => raise @alert.fatal(BadRecordMac)
    }
  self.seq = self.seq + 1UL
  // §5.4: padding does not stretch the limit; the whole TLSInnerPlaintext is at most 2^14 + 1.
  if plaintext.length() > max_fragment + 1 {
    raise @alert.fatal(RecordOverflow)
  }
  unpad(plaintext[:])
}

///|
pub extend Suite with Eq::{equal, not_equal}

///|
pub extend Suite with Debug::{to_repr}
