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
  /// A content type RFC 8446 §5 does not define.
  Other(Int)
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The octet this content type goes on the wire as.
pub fn Kind::code(self : Kind) -> Int {
  match self {
    ChangeCipherSpec => 20
    Alert => 21
    Handshake => 22
    ApplicationData => 23
    Other(code) => code
  }
}

///|
/// The content type an octet names, or `None` for one RFC 8446 §5 does not
/// define — which the record parser turns into an alert rather than tolerating.
pub fn Kind::of(code : Int) -> Kind? {
  match code {
    20 => Some(ChangeCipherSpec)
    21 => Some(Alert)
    22 => Some(Handshake)
    23 => Some(ApplicationData)
    _ => None
  }
}

///|
/// The largest TLSPlaintext fragment (RFC 8446 §5.1): 2^14 octets.
///
/// The RFC fixes it, so it is a constant and not a parameter: a record past it
/// is not a record.
pub let max_fragment : Int = 16384

///|
/// The largest TLSCiphertext encrypted_record (RFC 8446 §5.2): 2^14 + 256 — the
/// fragment limit plus the room the inner content type, the padding and the
/// AEAD tag need.
pub let max_encrypted : Int = 16640

///|
/// The record header: content type, legacy_record_version, and a 16-bit length.
pub let header : Int = 5

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
fn read(view : BytesView, limit : Int) -> (Record, Int)? raise @alert.Alert {
  if view.length() < header {
    return None
  }
  guard Kind::of(view[0].to_int()) is Some(kind) else {
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
pub fn decode(view : BytesView) -> (Record, Int)? raise @alert.Alert {
  read(view, max_fragment)
}

///|
/// Read one TLSCiphertext record (RFC 8446 §5.2) and how many octets it
/// consumed.
///
/// The fragment is the still-sealed encrypted_record, so the ceiling is the
/// larger §5.2 one.
pub fn decode_encrypted(view : BytesView) -> (Record, Int)? raise @alert.Alert {
  read(view, max_encrypted)
}

///|
/// A TLSInnerPlaintext (RFC 8446 §5.2): the content, then the content type the
/// outer header is hiding, then `padding` zero octets.
///
/// The padding is §5.4's length-hiding knob — a record's length leaks how much
/// was said, and zero octets after the type cost only bandwidth.
pub fn inner(kind : Kind, content : BytesView, padding? : Int = 0) -> Bytes {
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
pub let key_size : Int = 16

///|
/// The IV length AEAD_AES_128_GCM fixes (RFC 5116 §5.1).
pub let iv_size : Int = 12

///|
/// The AEAD tag length AEAD_AES_128_GCM fixes.
pub let tag_size : Int = 16

///|
/// Derive a direction's record-protection key and IV from its traffic secret
/// (RFC 8446 §7.3).
///
/// QUIC expands the same secret under `"quic key"`/`"quic iv"` and adds a
/// header-protection key (RFC 9001 §5.1); over TCP the labels are bare and
/// there is no header to protect.
pub fn traffic(
  secret : BytesView,
  digest? : @keys.Digest = @keys.digest,
) -> Traffic {
  {
    key: @keys.expand_label(secret, b"key", b"", len=key_size, digest~),
    iv: @keys.expand_label(secret, b"iv", b"", len=iv_size, digest~),
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
/// One direction's record protection: its traffic keys, and the sequence number
/// that keeps their nonces apart.
///
/// RFC 8446 §5.3 restarts the sequence at zero on every key change, which is
/// what [`Cipher::rekey`] is for — the IV is reused across a generation, so a
/// sequence that carried over would reuse a nonce under the new key.
pub struct Cipher {
  mut traffic : Traffic
  mut seq : UInt64
  aead : (Bytes) -> &@spec.Aead
}

///|
/// The AEAD `TLS_AES_128_GCM_SHA256` names, built over a key.
///
/// It aborts rather than raising because the only way it fails is a key of the
/// wrong length, and every key reaching it came from [`traffic`], which makes
/// them the right length by construction. A caller with another suite passes
/// its own `aead` to [`Cipher::new`].
fn aes_128_gcm(key : Bytes) -> &@spec.Aead {
  let block = @aes.Cipher::new(key[:]) catch {
    _ => abort("moontls: AES-128 refused a 16-octet key")
  }
  @gcm.Gcm::new(block) catch {
    _ => abort("moontls: AES-128-GCM refused its block cipher")
  }
}

///|
/// Record protection under the traffic `secret`, starting at sequence zero.
///
/// `aead` builds the AEAD from a key; leaving it out gives
/// `TLS_AES_128_GCM_SHA256`'s. It is a parameter because the suite chooses the
/// AEAD as much as it chooses the hash, and a ChaCha20-Poly1305 connection runs
/// this same record layer.
pub fn Cipher::new(
  secret : BytesView,
  digest? : @keys.Digest = @keys.digest,
  aead? : (Bytes) -> &@spec.Aead = aes_128_gcm,
) -> Cipher {
  { traffic: traffic(secret, digest~), seq: 0UL, aead, }
}

///|
/// Install a new traffic secret and restart the sequence number at zero
/// (RFC 8446 §5.3).
pub fn Cipher::rekey(
  self : Cipher,
  secret : BytesView,
  digest? : @keys.Digest = @keys.digest,
) -> Unit {
  self.traffic = traffic(secret, digest~)
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
fn ciphertext_header(len : Int) -> Bytes {
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
  padding? : Int = 0,
) -> Bytes raise @alert.Alert {
  if content.length() > max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  let plaintext = inner(kind, content, padding~)
  let len = plaintext.length() + tag_size
  if len > max_encrypted {
    raise @alert.fatal(RecordOverflow)
  }
  let aad = ciphertext_header(len)
  let body = (self.aead)(self.traffic.key).seal(
    nonce=self.nonce()[:],
    plain=plaintext[:],
    aad=aad[:],
  )
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
  guard read(record, max_encrypted) is Some((rec, _)) else {
    raise @alert.fatal(DecodeError)
  }
  let aad = record[0:header].to_owned()
  let plaintext = (self.aead)(self.traffic.key).open(
    nonce=self.nonce()[:],
    cipher=rec.fragment[:],
    aad=aad[:],
  ) catch {
    _ => raise @alert.fatal(BadRecordMac)
  }
  self.seq = self.seq + 1UL
  let (kind, content) = unpad(plaintext[:])
  if content.length() > max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  (kind, content)
}
