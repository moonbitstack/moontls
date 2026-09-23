// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Where a record sits in the stream: which epoch's keys protect it, and which
/// number it has within that epoch (RFC 9147 §4).
///
/// The RFC calls this a RecordNumber and gives both fields 64 bits. Sequence
/// numbers restart at zero on every epoch, so the pair — not the sequence
/// alone — is what names a record; the ACK message carries exactly this.
pub(all) struct Number {
  epoch : UInt64
  seq : UInt64
} derive(Eq, Compare, Debug)

///|
pub extend Number with Eq::{equal, not_equal}

///|
pub extend Number with Compare::{compare, op_lt, op_le, op_ge, op_gt}

///|
pub extend Number with Debug::{to_repr}

///|
/// The DTLSPlaintext header (RFC 9147 §4): type, legacy version, a 16-bit
/// epoch, a 48-bit sequence number and a 16-bit length.
pub let plaintext_header : Int = 13

///|
/// `{254, 253}` — DTLS 1.2's version number, which every DTLS 1.3 record after
/// the first ClientHello carries and every receiver ignores (RFC 9147 §4).
pub let legacy_version : Int = 0xfefd

///|
/// The largest sequence number a DTLSPlaintext can carry: 2^48 - 1
/// (RFC 9147 §4).
pub let max_plaintext_seq : UInt64 = 0xffff_ffff_ffffUL

// ------------------------------------------------------------------ plaintext

///|
/// Frame `fragment` as a DTLSPlaintext record (RFC 9147 §4).
///
/// Only the records sent before there are keys travel this way: the two Hellos,
/// an alert, and an ACK covering them. Everything after is a
/// [`Cipher::seal`]ed DTLSCiphertext.
pub fn encode(
  kind : @record.Kind,
  number : Number,
  fragment : BytesView,
) -> Bytes raise @alert.Alert {
  if fragment.length() > @record.max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  if number.seq > max_plaintext_seq {
    raise @alert.fatal(InternalError)
  }
  let out = Buffer()
  out.write_byte((kind.code() & 0xff).to_byte())
  @wire.u16(out, legacy_version)
  @wire.u16(out, (number.epoch & 0xffffUL).to_int())
  for i = 5; i >= 0; i = i - 1 {
    out.write_byte(((number.seq >> (i * 8)) & 0xffUL).to_byte())
  }
  @wire.u16(out, fragment.length())
  out.write_bytesview(fragment)
  out.to_bytes()
}

///|
/// Read one DTLSPlaintext record off the front of `view`: its content type, its
/// record number, its fragment, and how many octets it took.
///
/// `None` means the view does not hold a whole record yet — which over UDP
/// means the datagram was truncated, since RFC 9147 §4.3 makes every record fit
/// one datagram.
pub fn decode(
  view : BytesView,
) -> (@record.Kind, Number, Bytes, Int)? raise @alert.Alert {
  if view.length() < plaintext_header {
    return None
  }
  guard @record.Kind::of(view[0].to_int()) is Some(kind) else {
    raise @alert.fatal(UnexpectedMessage)
  }
  let epoch = @wire.read_u16(view, 3).to_uint64()
  let mut seq = 0UL
  for i = 5; i < 11; i = i + 1 {
    seq = (seq << 8) | view[i].to_uint64()
  }
  let len = @wire.read_u16(view, 11)
  if len > @record.max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  let end = plaintext_header + len
  if view.length() < end {
    return None
  }
  Some((kind, { epoch, seq, }, view[plaintext_header:end].to_owned(), end))
}

// ----------------------------------------------------------------- demuxing

///|
/// What the first octet of a datagram says the next record is (RFC 9147 §4.1).
pub(all) enum Shape {
  /// A DTLSPlaintext record of this content type.
  Plain(@record.Kind)
  /// A DTLSCiphertext record: the leading bits are `001` and the real content
  /// type is inside the protected body.
  Sealed
  /// Not a DTLS 1.3 record. §4.1 says to reject it as if deprotection had
  /// failed — which over UDP means dropping it and keeping the association.
  Foreign
} derive(Eq, Debug)

///|
pub extend Shape with Eq::{equal, not_equal}

///|
pub extend Shape with Debug::{to_repr}

///|
/// Which of the three a datagram's next record is, from its first octet alone
/// (RFC 9147 §4.1).
///
/// Only alert, handshake and ack may appear unprotected; application data
/// unprotected is DTLS 1.2's shape, not this one's, and is `Foreign` here.
pub fn shape(first : Byte) -> Shape {
  match first.to_int() {
    21 => Plain(Alert)
    22 => Plain(Handshake)
    26 => Plain(Ack)
    other => if (other & 0xe0) == 0x20 { Sealed } else { Foreign }
  }
}

// ------------------------------------------------------------ unified header

///|
/// How much of the unified header a sender chooses to send (RFC 9147 §4).
///
/// Every field here is a knob because the RFC leaves every one of them to the
/// sender: a connection may mix sequence number widths and may omit the length
/// on the last record of a datagram. The preset is the shape a peer on a plain
/// UDP association sends — no connection ID, a 16-bit sequence number so
/// reordering past 256 records still reconstructs, and the length present so
/// more than one record fits a datagram.
pub(all) struct Shell {
  /// The negotiated connection ID, or empty for none (RFC 9146).
  cid : Bytes
  /// A 16-bit sequence number rather than an 8-bit one.
  wide : Bool
  /// Whether the 16-bit length is written.
  length : Bool
} derive(Eq, Debug)

///|
pub extend Shell with Eq::{equal, not_equal}

///|
pub extend Shell with Debug::{to_repr}

///|
/// The unified header shape a plain UDP association sends.
pub let shell : Shell = { cid: b"", wide: true, length: true, }

///|
/// A `Shell` by name, so a caller changes one field without restating the rest.
pub fn Shell::new(
  cid? : Bytes = shell.cid,
  wide? : Bool = shell.wide,
  length? : Bool = shell.length,
) -> Shell {
  { cid, wide, length, }
}

///|
/// Write the unified header (RFC 9147 §4), with the sequence number still in
/// the clear — [`Cipher::seal`] encrypts it afterwards, and the header as
/// written here is the AEAD's additional data.
fn header(shape : Shell, number : Number, len : Int) -> Bytes {
  let mut first = 0x20 | (number.epoch & 0x3UL).to_int()
  if shape.cid.length() > 0 {
    first = first | 0x10
  }
  if shape.wide {
    first = first | 0x08
  }
  if shape.length {
    first = first | 0x04
  }
  let out = Buffer()
  out.write_byte(first.to_byte())
  out.write_bytes(shape.cid)
  if shape.wide {
    out.write_byte(((number.seq >> 8) & 0xffUL).to_byte())
  }
  out.write_byte((number.seq & 0xffUL).to_byte())
  if shape.length {
    @wire.u16(out, len)
  }
  out.to_bytes()
}

///|
/// How long a unified header is, and where its sequence number starts, given
/// the first octet and the connection ID length the association negotiated.
///
/// `None` means the octet does not begin a DTLSCiphertext.
pub fn measure(first : Byte, cid : Int) -> (Int, Int, Bool)? {
  let bits = first.to_int()
  if (bits & 0xe0) != 0x20 {
    return None
  }
  let cid_len = if (bits & 0x10) != 0 { cid } else { 0 }
  let wide = (bits & 0x08) != 0
  let seq_at = 1 + cid_len
  let seq_len = if wide { 2 } else { 1 }
  let len_len = if (bits & 0x04) != 0 { 2 } else { 0 }
  Some((seq_at + seq_len + len_len, seq_at, wide))
}

// -------------------------------------------------------- record protection

///|
/// The record number encryption key, `HKDF-Expand-Label(Secret, "sn", "",
/// key_length)` (RFC 9147 §4.2.3).
pub fn sn_key(
  secret : BytesView,
  digest? : @keys.Digest = @keys.digest,
  len? : Int = @record.key_size,
) -> Bytes {
  @keys.expand_label(secret, b"sn", b"", len~, digest~)
}

///|
/// The mask that hides a record's sequence number (RFC 9147 §4.2.3): AES-ECB
/// over the first sixteen octets of the ciphertext.
///
/// A ChaCha20 suite masks differently — §4.2.3 gives the block function and its
/// split of those same sixteen octets — which is why [`Cipher::new`] takes this
/// as a parameter rather than fixing it.
pub fn aes_mask(key : Bytes, cipher : BytesView) -> Bytes {
  let block = @aes.Cipher::new(key[:]) catch {
    _ => abort("moontls: AES refused a record number key")
  }
  block.encrypt(cipher[0:16])
}

///|
/// The AEAD `TLS_AES_128_GCM_SHA256` names, built over a key.
fn aes_128_gcm(key : Bytes) -> &@spec.Aead {
  let block = @aes.Cipher::new(key[:]) catch {
    _ => abort("moontls: AES-128 refused a 16-octet key")
  }
  @gcm.Gcm::new(block) catch {
    _ => abort("moontls: AES-128-GCM refused its block cipher")
  }
}

///|
/// One epoch's record protection: its traffic keys, its record number key, the
/// sequence it is writing, and the window of what it has read.
///
/// One of these per epoch per direction. The epoch is fixed at construction
/// because RFC 9147 §4.2 gives each epoch its own sequence space, its own keys
/// and its own replay window — rekeying is a new `Cipher`, not a mutation of
/// this one.
pub struct Cipher {
  epoch : UInt64
  traffic : @record.Traffic
  sn : Bytes
  mut seq : UInt64
  seen : Window
  aead : (Bytes) -> &@spec.Aead
  mask : (Bytes, BytesView) -> Bytes
}

///|
/// Record protection for `epoch` under the traffic `secret`, starting at
/// sequence zero.
///
/// `aead` and `mask` are the suite's: leaving them out gives
/// `TLS_AES_128_GCM_SHA256`'s AEAD and §4.2.3's AES mask. `window` is how far
/// out of order a datagram may arrive and still be accepted.
pub fn Cipher::new(
  secret : BytesView,
  epoch~ : UInt64,
  digest? : @keys.Digest = @keys.digest,
  aead? : (Bytes) -> &@spec.Aead = aes_128_gcm,
  mask? : (Bytes, BytesView) -> Bytes = aes_mask,
  window? : Int = window,
) -> Cipher {
  {
    epoch,
    traffic: @record.traffic(secret, digest~),
    sn: sn_key(secret, digest~),
    seq: 0UL,
    seen: Window::new(size=window),
    aead,
    mask,
  }
}

///|
/// The epoch these keys belong to.
pub fn Cipher::epoch(self : Cipher) -> UInt64 {
  self.epoch
}

///|
/// The number the next sealed record will carry.
pub fn Cipher::next(self : Cipher) -> Number {
  { epoch: self.epoch, seq: self.seq, }
}

///|
/// Seal `content` as a DTLSCiphertext record (RFC 9147 §4) and advance the
/// sequence number.
///
/// `padding` is §4.2.3's requirement in disguise: the mask needs sixteen octets
/// of ciphertext, so a short record under a short-tag suite has to be padded to
/// reach them. With a 16-octet tag — which every suite here has — the tag alone
/// suffices and the default of no padding is correct.
pub fn Cipher::seal(
  self : Cipher,
  kind : @record.Kind,
  content : BytesView,
  shape? : Shell = shell,
  padding? : Int = 0,
) -> Bytes raise @alert.Alert {
  if content.length() > @record.max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  let plaintext = @record.inner(kind, content, padding~)
  let len = plaintext.length() + @record.tag_size
  if len > @record.max_encrypted {
    raise @alert.fatal(RecordOverflow)
  }
  let number = self.next()
  let head = header(shape, number, len)
  let body = (self.aead)(self.traffic.key).seal(
    nonce=@record.nonce(self.traffic.iv[:], number.seq)[:],
    plain=plaintext[:],
    aad=head[:],
  )
  if body.length() < 16 {
    raise @alert.fatal(InternalError)
  }
  self.seq = self.seq + 1UL
  let seq_at = 1 + shape.cid.length()
  let seq_len = if shape.wide { 2 } else { 1 }
  let mask = (self.mask)(self.sn, body[:])
  let out = Buffer()
  for i = 0; i < head.length(); i = i + 1 {
    let byte = if i >= seq_at && i < seq_at + seq_len {
      (head[i].to_int() ^ mask[i - seq_at].to_int()).to_byte()
    } else {
      head[i]
    }
    out.write_byte(byte)
  }
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// Open one DTLSCiphertext record off the front of `view` (RFC 9147 §4): the
/// content type and content sealed inside, its record number, and how many
/// octets the record took.
///
/// `cid` is the connection ID length the association negotiated, which the
/// header does not carry. `latest` is the highest sequence number already
/// deprotected in this epoch, which §4.2.2 reconstructs the truncated number
/// against; a fresh epoch passes zero.
///
/// A record that does not deprotect raises `BadRecordMac` and moves nothing —
/// neither the replay window nor any counter — because §4.5.2 says an invalid
/// record must leave the association exactly as it found it.
pub fn Cipher::open(
  self : Cipher,
  view : BytesView,
  cid? : Int = 0,
) -> (@record.Kind, Bytes, Number, Int) raise @alert.Alert {
  guard view.length() >= 1 &&
    measure(view[0], cid) is Some((head_len, seq_at, wide)) else {
    raise @alert.fatal(BadRecordMac)
  }
  if view.length() < head_len {
    raise @alert.fatal(BadRecordMac)
  }
  let body_at = head_len
  let len = if (view[0].to_int() & 0x04) != 0 {
    @wire.read_u16(view, head_len - 2)
  } else {
    view.length() - head_len
  }
  let end = body_at + len
  if len < 16 || view.length() < end || len > @record.max_encrypted {
    raise @alert.fatal(BadRecordMac)
  }
  let body = view[body_at:end]
  let mask = (self.mask)(self.sn, body)
  let seq_len = if wide { 2 } else { 1 }
  let head = Buffer()
  for i = 0; i < head_len; i = i + 1 {
    let byte = if i >= seq_at && i < seq_at + seq_len {
      (view[i].to_int() ^ mask[i - seq_at].to_int()).to_byte()
    } else {
      view[i]
    }
    head.write_byte(byte)
  }
  let aad = head.to_bytes()
  let mut truncated = 0UL
  for i = 0; i < seq_len; i = i + 1 {
    truncated = (truncated << 8) | aad[seq_at + i].to_uint64()
  }
  let seq = self.seen.expand(truncated, seq_len * 8)
  let plaintext = (self.aead)(self.traffic.key).open(
    nonce=@record.nonce(self.traffic.iv[:], seq)[:],
    cipher=body,
    aad=aad[:],
  ) catch {
    _ => raise @alert.fatal(BadRecordMac)
  }
  if !self.seen.accept(seq) {
    raise @alert.fatal(BadRecordMac)
  }
  let (kind, content) = @record.unpad(plaintext[:])
  if content.length() > @record.max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  (kind, content, { epoch: self.epoch, seq, }, end)
}
