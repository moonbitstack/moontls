// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2's record protection. An AEAD record is the simple one. A CBC record is where the attacks
// lived, so `open_cbc` does the same work whatever is wrong with the record: padding and MAC are
// checked together, and the hash runs the same number of blocks for any padding length, which is
// the Lucky Thirteen countermeasure. RFC 7366's encrypt-then-MAC avoids the question altogether.

///|
/// The longest TLSCiphertext fragment TLS 1.2 allows (RFC 5246 §6.2.3).
pub let max_fragment12 : Int32 = 18432

///|
/// How long a CBC IV and block are.
let aes_block : Int32 = 16

///|
/// How long an AEAD's nonce is on the wire.
let explicit_size : Int32 = 8

///|
/// Read a TLS 1.2 record, whose ciphertext may run past what 1.3 allows.
pub fn decode12(view : BytesView) -> (Record, Int32)? raise @alert.Alert {
  read(view, max_fragment12)
}

///|
/// What a TLS 1.2 cipher does, besides the keys it holds.
priv enum Frame {
  Aead
  Ccm(tag~ : Int32)
  Cbc(mac_key~ : Bytes, mac~ : Mac, etm~ : Bool, rand~ : (Int32) -> Bytes)
}

///|
/// Record protection for TLS 1.2 under keys from the key block. `etm` is whether RFC 7366 was
/// agreed, and `rand` is where CBC's per-record IVs come from.
pub fn Cipher::of12(
  suite : Suite12,
  key : BytesView,
  iv : BytesView,
  mac_key~ : BytesView = b""[:],
  etm~ : Bool = false,
  rand~ : (Int32) -> Bytes,
  implicit~ : Bool = false,
  wire~ : Int32 = @wire.legacy_version,
  explicit~ : Bool = true,
) -> Cipher {
  let (aead, frame) : (Suite, Frame) = match suite.bulk {
    Aead(aead) => (aead, Aead)
    Ccm(tag~, ..) => (Aes128Gcm, Ccm(tag~))
    Cbc(mac~, ..) =>
      (Aes128Gcm, Cbc(mac_key=mac_key.to_owned(), mac~, etm~, rand~))
  }
  {
    suite: aead,
    traffic: { key: key.to_owned(), iv: iv.to_owned(), },
    seq: 0UL,
    frame: Some(frame),
    // RFC 2246 §6.2.3.2: TLS 1.0's first record uses the key block's IV and every later one the
    // ciphertext block before it.
    chain: if implicit {
      iv.to_owned()
    } else {
      b""
    },
    implicit,
    wire,
    explicit,
  }
}

///|
/// Whether this cipher frames records the TLS 1.2 way.
pub fn Cipher::is_tls12(self : Cipher) -> Bool {
  self.frame is Some(_)
}

///|
/// The eight octets of a sequence number.
fn seq_octets(seq : UInt64) -> Bytes {
  let out = Buffer()
  for shift = 56; shift >= 0; shift = shift - 8 {
    out.write_byte(((seq >> shift) & 0xffUL).to_byte())
  }
  out.to_bytes()
}

///|
/// What a TLS 1.2 record's AEAD or MAC covers ahead of the data (RFC 5246 §6.2.3): the sequence
/// number, the type, the version and a length.
fn aad12(seq : UInt64, kind : Kind, size : Int32, version : Int32) -> Bytes {
  let out = Buffer()
  out.write_bytes(seq_octets(seq))
  out.write_byte((kind.code() & 0xff).to_byte())
  @wire.u16(out, version)
  @wire.u16(out, size)
  out.to_bytes()
}

///|
fn aes_key(key : Bytes) -> @aes.Cipher {
  @aes.Cipher::new(key[:]) catch {
    _ => abort("moontls: AES refused a key of the suite's length")
  }
}

///|
/// The nonce of an AEAD record: for ChaCha20-Poly1305 the sequence number over the IV (RFC 7905),
/// otherwise the salt and the explicit part (RFC 5288 §3).
fn Cipher::nonce12(self : Cipher, explicit : BytesView) -> Bytes {
  match (self.frame, self.suite) {
    (Some(Aead), ChaCha20Poly1305) => nonce(self.traffic.iv[:], self.seq)
    _ => {
      // Where the eight octets are not on the wire they are still the sequence number: a frame
      // that carries it in its header — DTLS 1.2 — hands the same value to the nonce.
      let tail = if self.explicit { explicit } else { seq_octets(self.seq) }
      let out = Buffer()
      out.write_bytes(self.traffic.iv)
      out.write_bytesview(tail)
      out.to_bytes()
    }
  }
}

///|
fn Cipher::seal_aead(
  self : Cipher,
  kind : Kind,
  content : BytesView,
  tag : Int32?,
) -> Bytes {
  let chacha = self.suite is ChaCha20Poly1305 && self.frame is Some(Aead)
  let explicit = if chacha || !self.explicit {
    b""
  } else {
    seq_octets(self.seq)
  }
  let aad = aad12(self.seq, kind, content.length(), self.wire)
  let nonce = self.nonce12(explicit[:])
  let body = match tag {
    Some(tag) => {
      let ccm = @ccm.Ccm::new(aes_key(self.traffic.key), tag~) catch {
        _ => abort("moontls: CCM refused its tag length")
      }
      ccm.seal(nonce=nonce[:], plain=content, aad=aad[:])
    }
    None =>
      self.suite
      .aead(self.traffic.key)
      .seal(nonce=nonce[:], plain=content, aad=aad[:])
  }
  let out = Buffer()
  out.write_bytes(explicit)
  out.write_bytes(body)
  out.to_bytes()
}

///|
fn Cipher::open_aead(
  self : Cipher,
  kind : Kind,
  fragment : Bytes,
  tag : Int32?,
) -> Bytes raise @alert.Alert {
  let chacha = self.suite is ChaCha20Poly1305 && self.frame is Some(Aead)
  let skip = if chacha || !self.explicit { 0 } else { explicit_size }
  let size = fragment.length() - skip - tag.unwrap_or(tag_size)
  if size < 0 {
    raise @alert.fatal(BadRecordMac)
  }
  let aad = aad12(self.seq, kind, size, self.wire)
  let nonce = self.nonce12(fragment[0:skip])
  match tag {
    Some(tag) => {
      let ccm = @ccm.Ccm::new(aes_key(self.traffic.key), tag~) catch {
        _ => abort("moontls: CCM refused its tag length")
      }
      ccm.open(nonce=nonce[:], cipher=fragment[skip:], aad=aad[:]) catch {
        _ => raise @alert.fatal(BadRecordMac)
      }
    }
    None =>
      self.suite
      .aead(self.traffic.key)
      .open(nonce=nonce[:], cipher=fragment[skip:], aad=aad[:]) catch {
        _ => raise @alert.fatal(BadRecordMac)
      }
  }
}

///|
/// The padding that brings `size` octets up to a whole number of blocks, its length octet included
/// (RFC 5246 §6.2.3.2).
fn padding(size : Int32) -> Bytes {
  let n = aes_block - size % aes_block
  Bytes::make(n, (n - 1).to_byte())
}

///|
fn cbc(key : Bytes, iv : BytesView) -> @mode.Cbc {
  @mode.Cbc::new(aes_key(key), iv) catch {
    _ => abort("moontls: CBC refused an IV of the block's length")
  }
}

///|
fn Cipher::seal_cbc(
  self : Cipher,
  kind : Kind,
  content : BytesView,
  mac_key : Bytes,
  mac : Mac,
  etm : Bool,
  rand : (Int32) -> Bytes,
) -> Bytes {
  let iv = if self.implicit { self.chain } else { rand(aes_block) }
  let out = Buffer()
  if !self.implicit {
    out.write_bytes(iv)
  }
  if etm {
    let plain = Buffer()
    plain.write_bytesview(content)
    plain.write_bytes(padding(content.length()))
    let body = cbc(self.traffic.key, iv[:]).encrypt(plain.to_bytes()[:])
    out.write_bytes(body)
    let signed = Buffer()
    let covered = if self.implicit {
      body.length()
    } else {
      iv.length() + body.length()
    }
    signed.write_bytes(aad12(self.seq, kind, covered, self.wire))
    if !self.implicit {
      signed.write_bytes(iv)
    }
    signed.write_bytes(body)
    out.write_bytes(@hmac.mac(mac_key[:], signed.to_bytes()[:], mac.hasher()))
    self.chained(body)
    return out.to_bytes()
  }
  let signed = Buffer()
  signed.write_bytes(aad12(self.seq, kind, content.length(), self.wire))
  signed.write_bytesview(content)
  let tag = @hmac.mac(mac_key[:], signed.to_bytes()[:], mac.hasher())
  let plain = Buffer()
  plain.write_bytesview(content)
  plain.write_bytes(tag)
  plain.write_bytes(padding(content.length() + tag.length()))
  let body = cbc(self.traffic.key, iv[:]).encrypt(plain.to_bytes()[:])
  out.write_bytes(body)
  self.chained(body)
  out.to_bytes()
}

///|
/// Remember the last ciphertext block as the next record's IV, which is the only place TLS 1.0
/// keeps an IV — a receiver reconstructs it from the ciphertext the same way.
fn Cipher::chained(self : Cipher, ciphertext : BytesView) -> Unit {
  if self.implicit && ciphertext.length() >= aes_block {
    self.chain = ciphertext[ciphertext.length() - aes_block:].to_owned()
  }
}

///|
/// Run `blocks` compression blocks through a hash and throw the result away.
fn burn(mac : Mac, blocks : Int32) -> Unit {
  guard blocks > 0 else { return }
  let h = mac.hasher()()
  h.write(Bytes::make(blocks * h.block(), b'\x36')[:])
  h.finish() |> ignore
}

///|
/// How many compression blocks hashing `size` octets takes, the length encoding included.
fn blocks_of(size : Int32, block : Int32) -> Int32 {
  let tail = if block == 128 { 17 } else { 9 }
  (size + tail + block - 1) / block
}

///|
/// A CBC record, MAC-then-encrypt. Every way of being wrong ends in the same `bad_record_mac` after
/// the same work.
fn Cipher::open_cbc(
  self : Cipher,
  kind : Kind,
  fragment : Bytes,
  mac_key : Bytes,
  mac : Mac,
) -> Bytes raise @alert.Alert {
  let size = mac.size()
  let skip = if self.implicit { 0 } else { aes_block }
  let body = fragment.length() - skip
  if body < aes_block || body % aes_block != 0 || body < size + 1 {
    raise @alert.fatal(BadRecordMac)
  }
  let iv = if self.implicit {
    self.chain
  } else {
    fragment[0:aes_block].to_owned()
  }
  self.chained(fragment)
  let plain = cbc(self.traffic.key, iv).decrypt(fragment[skip:])
  let last = plain[body - 1].to_int()
  // Every candidate padding octet is looked at whatever `last` says, and the masks below are all
  // ones or all zeros, so no branch depends on the padding.
  let mut wrong = 0
  let reach = if body - size < 256 { body - size } else { 256 }
  for i = 0; i < reach; i = i + 1 {
    let inside = (i - last - 1) >> 31
    wrong = wrong | ((plain[body - 1 - i].to_int() ^ last) & inside)
  }
  let bad = ((body - size - last - 1) >> 31) | ((0 - wrong) >> 31)
  let content = body - size - ((last + 1) & bad.lnot())
  let signed = Buffer()
  signed.write_bytes(aad12(self.seq, kind, content, self.wire))
  signed.write_bytesview(plain[0:content])
  let tag = @hmac.mac(mac_key[:], signed.to_bytes()[:], mac.hasher())
  // HMAC's outer pass is fixed, so the inner one is what differs with the padding.
  let block = if mac is Sha384 { 128 } else { 64 }
  let most = blocks_of(block + 13 + body - size, block)
  burn(mac, most - blocks_of(block + 13 + content, block))
  let good = @spec.eq(tag[:], plain[content:content + size])
  if bad != 0 || !good {
    raise @alert.fatal(BadRecordMac)
  }
  plain[0:content].to_owned()
}

///|
/// A CBC record, encrypt-then-MAC: nothing is decrypted until the MAC has been checked.
fn Cipher::open_etm(
  self : Cipher,
  kind : Kind,
  fragment : Bytes,
  mac_key : Bytes,
  mac : Mac,
) -> Bytes raise @alert.Alert {
  let size = mac.size()
  let skip = if self.implicit { 0 } else { aes_block }
  let covered = fragment.length() - size
  let body = covered - skip
  if body < aes_block || body % aes_block != 0 {
    raise @alert.fatal(BadRecordMac)
  }
  let signed = Buffer()
  signed.write_bytes(aad12(self.seq, kind, covered, self.wire))
  signed.write_bytesview(fragment[0:covered])
  let tag = @hmac.mac(mac_key[:], signed.to_bytes()[:], mac.hasher())
  if !@spec.eq(tag[:], fragment[covered:]) {
    raise @alert.fatal(BadRecordMac)
  }
  let iv = if self.implicit {
    self.chain
  } else {
    fragment[0:aes_block].to_owned()
  }
  self.chained(fragment[0:covered])
  let plain = cbc(self.traffic.key, iv).decrypt(fragment[skip:covered])
  let last = plain[body - 1].to_int()
  if last + 1 > body {
    raise @alert.fatal(BadRecordMac)
  }
  for i = 0; i <= last; i = i + 1 {
    if plain[body - 1 - i].to_int() != last {
      raise @alert.fatal(BadRecordMac)
    }
  }
  plain[0:body - last - 1].to_owned()
}

///|
fn Cipher::seal12(
  self : Cipher,
  frame : Frame,
  kind : Kind,
  content : BytesView,
) -> Bytes raise @alert.Alert {
  let _ = frame
  let body = self.seal_body(kind, content)
  let out = Buffer()
  out.write_byte((kind.code() & 0xff).to_byte())
  @wire.u16(out, self.wire)
  @wire.u16(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// Seal one record's payload and advance to the next sequence number: everything a TLS 1.2 record
/// covers, without the five-octet header, which is what a frame that is not TLS 1.2's — a DTLS 1.2
/// datagram, whose header carries an epoch — writes for itself.
pub fn Cipher::seal_body(
  self : Cipher,
  kind : Kind,
  content : BytesView,
) -> Bytes raise @alert.Alert {
  if content.length() > max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  guard self.frame is Some(frame) else { raise @alert.fatal(InternalError) }
  let body = match frame {
    Aead => self.seal_aead(kind, content, None)
    Ccm(tag~) => self.seal_aead(kind, content, Some(tag))
    Cbc(mac_key~, mac~, etm~, rand~) =>
      self.seal_cbc(kind, content, mac_key, mac, etm, rand)
  }
  self.seq = self.seq + 1UL
  body
}

///|
fn Cipher::open12(
  self : Cipher,
  frame : Frame,
  record : BytesView,
) -> (Kind, Bytes) raise @alert.Alert {
  guard read(record, max_fragment12) is Some((rec, _)) else {
    raise @alert.fatal(DecodeError)
  }
  let _ = frame
  let plain = self.open_body(rec.kind, rec.fragment)
  (rec.kind, plain)
}

///|
/// Open one record's payload and advance to the next sequence number, for a frame that reads its
/// own header.
pub fn Cipher::open_body(
  self : Cipher,
  kind : Kind,
  fragment : Bytes,
) -> Bytes raise @alert.Alert {
  guard self.frame is Some(frame) else { raise @alert.fatal(InternalError) }
  let plain = match frame {
    Aead => self.open_aead(kind, fragment, None)
    Ccm(tag~) => self.open_aead(kind, fragment, Some(tag))
    Cbc(mac_key~, mac~, etm=false, ..) =>
      self.open_cbc(kind, fragment, mac_key, mac)
    Cbc(mac_key~, mac~, etm=true, ..) =>
      self.open_etm(kind, fragment, mac_key, mac)
  }
  self.seq = self.seq + 1UL
  if plain.length() > max_fragment {
    raise @alert.fatal(RecordOverflow)
  }
  plain
}

///|
/// Continue the sequence at `seq`. DTLS 1.2 numbers a record with an epoch and a sequence number
/// inside one epoch, which is exactly the eight octets a TLS 1.2 record puts in its associated
/// data: an epoch-shifted value is what makes one cipher serve a datagram header.
pub fn Cipher::seek(self : Cipher, seq : UInt64) -> Unit {
  self.seq = seq
}
