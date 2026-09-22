// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The hash a cipher suite fixes the key schedule to.
///
/// RFC 8446 §7.1 writes the whole ladder over `Hash`, the hash named in the
/// negotiated cipher suite — SHA-256 for `TLS_AES_128_GCM_SHA256` and
/// `TLS_CHACHA20_POLY1305_SHA256`, SHA-384 for `TLS_AES_256_GCM_SHA384`. Every
/// output length in the schedule is that hash's, so it is one parameter rather
/// than a number repeated down the file.
pub(all) enum Digest {
  Sha256
  Sha384
} derive(Eq, Debug)

///|
pub extend Digest with Eq::{equal, not_equal}

///|
pub extend Digest with Debug::{to_repr}

///|
/// The digest of the suite TLS 1.3 makes mandatory (RFC 8446 §9.1:
/// `TLS_AES_128_GCM_SHA256` must be implemented), so leaving it out is the
/// common case rather than a guess.
pub let digest : Digest = Sha256

///|
/// How many octets this hash, and so every secret in the schedule, occupies.
pub fn Digest::size(self : Digest) -> Int {
  match self {
    Sha256 => 32
    Sha384 => 48
  }
}

///|
/// The hash as `mooncrypt` wants it: a factory it can run more than once.
pub fn Digest::hasher(self : Digest) -> () -> &@spec.Hash {
  match self {
    Sha256 => fn() { @sha2.Hasher::new() }
    Sha384 => fn() { @sha2.Hasher::new(kind=Sha384) }
  }
}

///|
/// This hash over one message.
pub fn Digest::hash(self : Digest, message : BytesView) -> Bytes {
  match self {
    Sha256 => @sha2.hash(message)
    Sha384 => @sha2.hash(message, kind=Sha384)
  }
}

// ----------------------------------------------------------------------- HKDF

///|
/// HKDF-Extract (RFC 5869 §2.2). An empty salt becomes `HashLen` zero octets,
/// which is what the RFC says and what `mooncrypt` already does.
pub fn extract(
  salt : BytesView,
  ikm : BytesView,
  digest? : Digest = digest,
) -> Bytes {
  @hkdf.extract(ikm, digest.hasher(), salt~)
}

///|
/// HKDF-Expand (RFC 5869 §2.3).
pub fn expand(
  prk : BytesView,
  info : BytesView,
  len~ : Int,
  digest? : Digest = digest,
) -> Bytes {
  @hkdf.expand(prk, digest.hasher(), info~, len~)
}

///|
/// HKDF-Expand-Label (RFC 8446 §7.1): expand under the structured HkdfLabel
///
///     struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
///
/// where the label is prefixed with `"tls13 "`. QUIC reuses it unchanged
/// (RFC 9001 §5.2), which is why it sits here rather than in the KDF: the
/// prefix and the framing are the protocol's, not HKDF's.
pub fn expand_label(
  secret : BytesView,
  label : BytesView,
  context : BytesView,
  len~ : Int,
  digest? : Digest = digest,
) -> Bytes {
  let name = Buffer()
  name.write_bytes(b"tls13 ")
  name.write_bytesview(label)
  let full = name.to_bytes()
  let info = Buffer()
  info.write_byte(((len >> 8) & 0xff).to_byte())
  info.write_byte((len & 0xff).to_byte())
  info.write_byte(full.length().to_byte())
  info.write_bytes(full)
  info.write_byte(context.length().to_byte())
  info.write_bytesview(context)
  expand(secret, info.to_bytes()[:], len~, digest~)
}

// ------------------------------------------------------------------- schedule

///|
/// Derive-Secret(Secret, Label, Messages) (RFC 8446 §7.1): HKDF-Expand-Label
/// with the transcript hash as context and the hash length as output.
///
/// `transcript` is the Transcript-Hash of the messages — [`Transcript::hash`],
/// or the hash of the empty string for the `"derived"` steps.
pub fn derive_secret(
  secret : BytesView,
  label : BytesView,
  transcript : BytesView,
  digest? : Digest = digest,
) -> Bytes {
  expand_label(secret, label, transcript, len=digest.size(), digest~)
}

///|
/// The Early Secret: `HKDF-Extract(0, PSK)`, with an all-zero PSK when none is
/// used — which is the only case until session resumption lands.
pub fn early(psk? : BytesView, digest? : Digest = digest) -> Bytes {
  let zero = Bytes::make(digest.size(), b'\x00')
  let ikm = match psk {
    Some(psk) => psk
    None => zero[:]
  }
  extract(zero[:], ikm, digest~)
}

///|
/// The Handshake Secret: `HKDF-Extract` over the ECDHE shared secret, salted by
/// the Early Secret run through the `"derived"` step (RFC 8446 §7.1).
pub fn handshake(
  early : BytesView,
  ecdhe : BytesView,
  digest? : Digest = digest,
) -> Bytes {
  let salt = derive_secret(early, b"derived", digest.hash(b""), digest~)
  extract(salt[:], ecdhe, digest~)
}

///|
/// The Master Secret: `HKDF-Extract` over an all-zero IKM, salted by the
/// Handshake Secret run through the `"derived"` step (RFC 8446 §7.1).
pub fn master(handshake : BytesView, digest? : Digest = digest) -> Bytes {
  let salt = derive_secret(handshake, b"derived", digest.hash(b""), digest~)
  extract(salt[:], Bytes::make(digest.size(), b'\x00')[:], digest~)
}

///|
/// The client handshake traffic secret, `Derive-Secret(Handshake Secret,
/// "c hs traffic", ClientHello..ServerHello)` (RFC 8446 §7.1).
pub fn client_handshake(
  handshake : BytesView,
  transcript : BytesView,
  digest? : Digest = digest,
) -> Bytes {
  derive_secret(handshake, b"c hs traffic", transcript, digest~)
}

///|
/// The server handshake traffic secret, `Derive-Secret(Handshake Secret,
/// "s hs traffic", ClientHello..ServerHello)`.
pub fn server_handshake(
  handshake : BytesView,
  transcript : BytesView,
  digest? : Digest = digest,
) -> Bytes {
  derive_secret(handshake, b"s hs traffic", transcript, digest~)
}

///|
/// The client application (1-RTT) traffic secret, `Derive-Secret(Master Secret,
/// "c ap traffic", ClientHello..server Finished)`.
pub fn client_application(
  master : BytesView,
  transcript : BytesView,
  digest? : Digest = digest,
) -> Bytes {
  derive_secret(master, b"c ap traffic", transcript, digest~)
}

///|
/// The server application (1-RTT) traffic secret, `Derive-Secret(Master Secret,
/// "s ap traffic", ClientHello..server Finished)`.
pub fn server_application(
  master : BytesView,
  transcript : BytesView,
  digest? : Digest = digest,
) -> Bytes {
  derive_secret(master, b"s ap traffic", transcript, digest~)
}

// ----------------------------------------------------------------- transcript

///|
/// A running transcript hash over the handshake messages seen so far
/// (RFC 8446 §4.4.1).
///
/// A handshake progresses by feeding each message into it; where a Finished is
/// sent or checked, [`finished`] MACs this hash.
pub struct Transcript {
  messages : Buffer
  digest : Digest
}

///|
/// A fresh, empty transcript.
pub fn Transcript::new(digest? : Digest = digest) -> Transcript {
  { messages: Buffer(), digest, }
}

///|
/// Append a handshake message — its full `HandshakeType ‖ Length ‖ body`
/// encoding, which is what the transcript is defined over.
pub fn Transcript::add(self : Transcript, message : BytesView) -> Unit {
  self.messages.write_bytesview(message)
}

///|
/// The transcript hash over every message added so far.
pub fn Transcript::hash(self : Transcript) -> Bytes {
  self.digest.hash(self.messages.to_bytes()[:])
}

///|
/// The Finished key: `HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)`
/// (RFC 8446 §4.4.4), the key that MACs a Finished message's `verify_data`.
pub fn finished_key(base : BytesView, digest? : Digest = digest) -> Bytes {
  expand_label(base, b"finished", b"", len=digest.size(), digest~)
}

///|
/// A Finished message's `verify_data` (RFC 8446 §4.4.4):
/// `HMAC(finished_key, transcript_hash)`.
pub fn finished(
  base : BytesView,
  transcript : BytesView,
  digest? : Digest = digest,
) -> Bytes {
  @hmac.mac(finished_key(base, digest~)[:], transcript, digest.hasher())
}

///|
/// Whether a received Finished carries the `verify_data` expected for `base`
/// over `transcript`.
///
/// The comparison is constant-time. A Finished is an authenticator, and an
/// early-exit `==` on an authenticator tells an attacker how many leading
/// octets it guessed right.
pub fn finished_ok(
  base : BytesView,
  transcript : BytesView,
  verify_data : BytesView,
  digest? : Digest = digest,
) -> Bool {
  @spec.eq(finished(base, transcript, digest~)[:], verify_data)
}
