// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An SRTP protection profile (RFC 5764 §4.1.2, RFC 7714 §14.2): which
/// transform the two ends will protect RTP with, and therefore how much keying
/// material the handshake has to export.
///
/// The `Null` profiles authenticate without encrypting. They exist for
/// diagnosis, and a peer that offers nothing else is asking for RTP in the
/// clear — this package will negotiate one only if a caller puts it in
/// `supported`, which the default does not.
pub(all) enum Profile {
  /// AES-128 counter mode with an 80-bit HMAC-SHA1 tag — the profile every
  /// WebRTC implementation has spoken since the beginning.
  Aes128CmSha1Tag80
  /// The same, with the tag truncated to 32 bits to save bandwidth.
  Aes128CmSha1Tag32
  /// No encryption, 80-bit HMAC-SHA1 tag.
  NullSha1Tag80
  /// No encryption, 32-bit HMAC-SHA1 tag.
  NullSha1Tag32
  /// AES-128-GCM (RFC 7714): one pass for confidentiality and integrity.
  Aead128Gcm
  /// AES-256-GCM (RFC 7714).
  Aead256Gcm
} derive(Eq, Debug)

///|
pub extend Profile with Eq::{equal, not_equal}

///|
pub extend Profile with Debug::{to_repr}

///|
/// The two octets this profile goes on the wire as (RFC 5764 §4.1.2).
pub fn Profile::code(self : Profile) -> Int {
  match self {
    Aes128CmSha1Tag80 => 0x0001
    Aes128CmSha1Tag32 => 0x0002
    NullSha1Tag80 => 0x0005
    NullSha1Tag32 => 0x0006
    Aead128Gcm => 0x0007
    Aead256Gcm => 0x0008
  }
}

///|
/// The profile a code names, or `None` for one this package has no lengths for.
///
/// Unlike an extension type, an unknown profile cannot be carried through: the
/// whole point of the negotiation is to fix the key and salt lengths, and a
/// profile whose lengths are unknown fixes nothing.
pub fn Profile::of(code : Int) -> Profile? {
  match code {
    0x0001 => Some(Aes128CmSha1Tag80)
    0x0002 => Some(Aes128CmSha1Tag32)
    0x0005 => Some(NullSha1Tag80)
    0x0006 => Some(NullSha1Tag32)
    0x0007 => Some(Aead128Gcm)
    0x0008 => Some(Aead256Gcm)
    _ => None
  }
}

///|
/// The SRTP master key length this profile fixes, in octets.
pub fn Profile::key_size(self : Profile) -> Int {
  match self {
    Aead256Gcm => 32
    _ => 16
  }
}

///|
/// The SRTP master salt length this profile fixes, in octets.
///
/// The counter-mode profiles carry a 112-bit salt (RFC 5764 §4.1.2); the GCM
/// ones carry 96 bits, because RFC 7714 §8.1 builds the nonce from the salt and
/// the 96-bit AEAD nonce leaves no room for more.
pub fn Profile::salt_size(self : Profile) -> Int {
  match self {
    Aead128Gcm | Aead256Gcm => 12
    _ => 14
  }
}

///|
/// The profiles this package will negotiate, strongest first.
///
/// The order is Chrome's and Firefox's offer order, which is also the order
/// libwebrtc prefers: the AEAD profiles before the counter-mode one, and the
/// truncated-tag and null profiles not at all. A caller wanting a different
/// order or a wider set passes its own list to [`select`].
pub let supported : Array[Profile] = [Aead256Gcm, Aead128Gcm, Aes128CmSha1Tag80]

///|
/// The profile to answer an offer with, by the answerer's preference rather
/// than the offerer's (RFC 5764 §4.1.1).
///
/// `offered` is the wire codes a peer sent. The first entry of `supported` that
/// appears in the offer wins; `None` means nothing overlapped, which
/// RFC 5764 §4.1.1 makes a handshake failure rather than a connection without
/// SRTP.
pub fn select(
  offered : ArrayView[Int],
  supported? : ArrayView[Profile] = supported[:],
) -> Profile? {
  for mine in supported {
    for code in offered {
      if code == mine.code() {
        return Some(mine)
      }
    }
  }
  None
}

///|
/// The label RFC 5764 §4.2 exports SRTP keying material under.
pub let label : Bytes = b"EXTRACTOR-dtls_srtp"

///|
/// The four pieces of keying material a DTLS-SRTP handshake produces
/// (RFC 5764 §4.2).
///
/// Which side is "client" is the DTLS side, not the RTP side: the peer that
/// sent the ClientHello uses `client_key` and `client_salt` to protect what it
/// sends, whichever end of the media stream it turns out to be.
pub(all) struct Keys {
  client_key : Bytes
  server_key : Bytes
  client_salt : Bytes
  server_salt : Bytes
} derive(Eq, Debug)

///|
pub extend Keys with Eq::{equal, not_equal}

///|
pub extend Keys with Debug::{to_repr}

///|
/// Export this profile's SRTP keying material from the exporter master secret
/// (RFC 5764 §4.2).
///
/// `secret` is [`@keys.exporter_master`]'s output. §4.2 exports one block and
/// cuts it into four: both master keys first, then both salts — not key, salt,
/// key, salt, which is the mistake that produces a connection where each end
/// decrypts its own traffic and neither decrypts the other's.
pub fn keys(
  secret : BytesView,
  profile : Profile,
  digest? : @keys.Digest = @keys.digest,
) -> Keys {
  let key = profile.key_size()
  let salt = profile.salt_size()
  let block = @keys.exporter(
    secret,
    label[:],
    b""[:],
    len=(key + salt) * 2,
    digest~,
  )
  {
    client_key: block[0:key].to_owned(),
    server_key: block[key:key * 2].to_owned(),
    client_salt: block[key * 2:key * 2 + salt].to_owned(),
    server_salt: block[key * 2 + salt:(key + salt) * 2].to_owned(),
  }
}
