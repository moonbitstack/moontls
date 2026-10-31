// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which extension this is (RFC 8446 §4.2, and IANA's TLS ExtensionType
/// registry).
///
/// `Other` keeps a type this package has no codec for. An extension is
/// self-describing — a type and a length — so one it does not understand can be
/// carried, forwarded and counted without being parsed, which is what
/// RFC 8446 §4.2 asks a receiver to do with an extension it does not recognise.
pub(all) enum Kind {
  /// server_name, the SNI a client asks a virtual host by (RFC 6066 §3).
  ServerName
  /// supported_groups, the named groups offered for key exchange (§4.2.7).
  SupportedGroups
  /// signature_algorithms, the schemes offered for CertificateVerify (§4.2.3).
  SignatureAlgorithms
  /// application_layer_protocol_negotiation (RFC 7301 §3.1).
  Alpn
  /// supported_versions, which is what actually negotiates TLS 1.3 (§4.2.1).
  SupportedVersions
  /// key_share, the ephemeral public keys (§4.2.8).
  KeyShare
  /// quic_transport_parameters (RFC 9001 §8.2). The payload is QUIC's and is
  /// carried here without being read.
  QuicTransportParameters
  /// use_srtp, the SRTP protection profiles a DTLS-SRTP peer offers
  /// (RFC 5764 §4.1.1).
  UseSrtp
  /// padding, the filler some clients add to the ClientHello (RFC 7685).
  Padding
  /// pre_shared_key, the PSK identities offered and the one chosen (§4.2.11).
  PreSharedKey
  /// early_data, a client's 0-RTT offer (§4.2.10).
  EarlyData
  /// cookie, which a HelloRetryRequest hands back to prove the client can
  /// receive at the address it claimed (§4.2.2). DTLS leans on it as its
  /// denial-of-service countermeasure (RFC 9147 §5.1).
  Cookie
  /// A type this package has no codec for, kept as its number.
  Other(Int32)
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The two octets this extension type goes on the wire as.
pub fn Kind::code(self : Kind) -> Int32 {
  match self {
    ServerName => 0x0000
    SupportedGroups => 0x000a
    SignatureAlgorithms => 0x000d
    Alpn => 0x0010
    SupportedVersions => 0x002b
    KeyShare => 0x0033
    QuicTransportParameters => 0x0039
    UseSrtp => 0x000e
    Padding => 0x0015
    PreSharedKey => 0x0029
    EarlyData => 0x002a
    Cookie => 0x002c
    Other(code) => code
  }
}

///|
/// The extension type a code names. Never fails: one without a codec here
/// becomes `Other`.
pub fn Kind::of(code : Int32) -> Kind {
  match code {
    0x0000 => ServerName
    0x000a => SupportedGroups
    0x000d => SignatureAlgorithms
    0x0010 => Alpn
    0x002b => SupportedVersions
    0x0033 => KeyShare
    0x0039 => QuicTransportParameters
    0x000e => UseSrtp
    0x0015 => Padding
    0x0029 => PreSharedKey
    0x002a => EarlyData
    0x002c => Cookie
    other => Other(other)
  }
}

///|
/// One extension: its type and its still-unparsed payload (RFC 8446 §4.2).
pub(all) struct Ext {
  kind : Kind
  data : Bytes
} derive(Eq, Debug)

///|
pub extend Ext with Eq::{equal, not_equal}

///|
pub extend Ext with Debug::{to_repr}

///|
/// The TLS 1.3 version code `supported_versions` selects (RFC 8446 §4.2.1).
pub let version_13 : Int32 = 0x0304

///|
/// x25519, the group RFC 8446 §4.2.7 lists first and TLS 1.3 offers first.
pub let x25519 : Int32 = 0x001d

///|
/// secp256r1 (NIST P-256).
pub let secp256r1 : Int32 = 0x0017

///|
/// secp384r1 (NIST P-384).
pub let secp384r1 : Int32 = 0x0018

///|
/// secp521r1 (NIST P-521).
pub let secp521r1 : Int32 = 0x0019

///|
/// x448 (RFC 7748).
pub let x448 : Int32 = 0x001e

///|
/// The five finite-field groups of RFC 7919, by size.
pub let ffdhe2048 : Int32 = 0x0100

///|
pub let ffdhe3072 : Int32 = 0x0101

///|
pub let ffdhe4096 : Int32 = 0x0102

///|
pub let ffdhe6144 : Int32 = 0x0103

///|
pub let ffdhe8192 : Int32 = 0x0104

///|
/// rsa_pss_rsae_sha256, the signature scheme RFC 8446 §9.1 requires.
pub let rsa_pss_rsae_sha256 : Int32 = 0x0804

///|
/// ecdsa_secp256r1_sha256, the other scheme §9.1 requires.
pub let ecdsa_secp256r1_sha256 : Int32 = 0x0403

///|
/// ecdsa_secp384r1_sha384 (RFC 8446 §4.2.3).
pub let ecdsa_secp384r1_sha384 : Int32 = 0x0503

///|
/// ecdsa_secp521r1_sha512.
pub let ecdsa_secp521r1_sha512 : Int32 = 0x0603

///|
/// rsa_pss_rsae_sha384.
pub let rsa_pss_rsae_sha384 : Int32 = 0x0805

///|
/// rsa_pss_rsae_sha512.
pub let rsa_pss_rsae_sha512 : Int32 = 0x0806

///|
/// ed25519.
pub let ed25519 : Int32 = 0x0807

///|
/// rsa_pkcs1_sha256: not for a TLS 1.3 handshake signature (RFC 8446 §4.2.3), but what most
/// certificate chains are signed with, which the same list speaks for when no
/// signature_algorithms_cert is sent.
pub let rsa_pkcs1_sha256 : Int32 = 0x0401

///|
/// rsa_pkcs1_sha384, for certificates only.
pub let rsa_pkcs1_sha384 : Int32 = 0x0501

///|
/// rsa_pkcs1_sha512, for certificates only.
pub let rsa_pkcs1_sha512 : Int32 = 0x0601

///|
/// HTTP/3's ALPN identifier (RFC 9114 §3.1).
pub let h3 : String = "h3"

///|
/// HTTP/2 over TLS's ALPN identifier (RFC 7540 §3.3).
pub let h2 : String = "h2"

///|
/// HTTP/1.1's ALPN identifier (RFC 7301 §6).
pub let http11 : String = "http/1.1"

// ---------------------------------------------------------------- the list

///|
/// Encode an extension block: a two-octet total length, then each extension as
/// a two-octet type, a two-octet length, and its payload.
pub fn encode(exts : ArrayView[Ext]) -> Bytes {
  let inner = Buffer()
  for e in exts {
    @wire.u16(inner, e.kind.code())
    @wire.u16(inner, e.data.length())
    inner.write_bytes(e.data)
  }
  let body = inner.to_bytes()
  let out = Buffer()
  @wire.u16(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// Decode an extension block, or `None` when it does not fit its lengths or carries one type
/// twice, which RFC 8446 §4.2 forbids: nothing says which of the two to believe.
pub fn decode(view : BytesView) -> Array[Ext]? {
  @wire.decode(view, r => {
    let list = r.vec(2)
    let out : Array[Ext] = []
    let seen : Map[Int32, Unit] = Map([])
    while !list.is_empty() {
      let code = list.u16()
      if seen.contains(code) {
        raise @wire.Malformed
      }
      seen[code] = ()
      out.push({ kind: Kind::of(code), data: list.vec(2).rest().to_owned(), })
    }
    out
  })
}

///|
/// The first extension of a given type, or `None`.
pub fn find(exts : ArrayView[Ext], kind : Kind) -> Ext? {
  exts.iter().find_first(fn(e) { e.kind == kind })
}

// ------------------------------------------------------------- the payloads

///|
/// A two-octet-length-prefixed list of 16-bit codes — the body shape
/// `supported_groups` and `signature_algorithms` share.
fn u16_list(values : ArrayView[Int32]) -> Bytes {
  let inner = Buffer()
  for v in values {
    @wire.u16(inner, v)
  }
  let body = inner.to_bytes()
  let out = Buffer()
  @wire.u16(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// The codes in such a list: at least one, and a whole number of them.
fn read_u16_list(view : BytesView) -> Array[Int32]? {
  @wire.decode(view, r => r.vec(2, min=2, unit=2).codes())
}

///|
/// A ClientHello's `supported_versions` payload (RFC 8446 §4.2.1): a one-octet
/// length, then each version as two octets, most preferred first.
pub fn versions(offered : ArrayView[Int32]) -> Bytes {
  let inner = Buffer()
  for v in offered {
    @wire.u16(inner, v)
  }
  let body = inner.to_bytes()
  let out = Buffer()
  out.write_byte((body.length() & 0xff).to_byte())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// The versions such a payload offers, in order (`versions<2..254>`).
pub fn read_versions(view : BytesView) -> Array[Int32]? {
  @wire.decode(view, r => r.vec(1, min=2, unit=2).codes())
}

///|
/// A ServerHello's `supported_versions` payload: the selected version alone,
/// with no list prefix (RFC 8446 §4.2.1).
pub fn selected_version(version : Int32) -> Bytes {
  let out = Buffer()
  @wire.u16(out, version)
  out.to_bytes()
}

///|
/// The version such a payload selected, or `None` if it is not two octets.
pub fn read_selected_version(view : BytesView) -> Int32? {
  if view.length() != 2 {
    return None
  }
  Some(@wire.read_u16(view, 0))
}

///|
/// A `supported_groups` payload (RFC 8446 §4.2.7).
pub fn groups(offered : ArrayView[Int32]) -> Bytes {
  u16_list(offered)
}

///|
/// The groups such a payload offers.
pub fn read_groups(view : BytesView) -> Array[Int32]? {
  read_u16_list(view)
}

///|
/// A `signature_algorithms` payload (RFC 8446 §4.2.3).
pub fn schemes(offered : ArrayView[Int32]) -> Bytes {
  u16_list(offered)
}

///|
/// The schemes such a payload offers.
pub fn read_schemes(view : BytesView) -> Array[Int32]? {
  read_u16_list(view)
}

///|
/// An ALPN `ProtocolNameList` payload (RFC 7301 §3.1): a two-octet length of
/// the name list, then each protocol as a one-octet length and its octets.
pub fn protocols(names : ArrayView[String]) -> Bytes {
  let inner = Buffer()
  for name in names {
    let octets = @utf8.encode(name)
    inner.write_byte((octets.length() & 0xff).to_byte())
    inner.write_bytes(octets)
  }
  let body = inner.to_bytes()
  let out = Buffer()
  @wire.u16(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// The protocol names such a payload carries: at least one, none empty (RFC 7301 §3.1).
pub fn read_protocols(view : BytesView) -> Array[String]? {
  @wire.decode(view, r => {
    let list = r.vec(2, min=2)
    let names = []
    while !list.is_empty() {
      names.push(@utf8.decode_lossy(list.vec(1, min=1).rest()))
    }
    names
  })
}

///|
/// One `KeyShareEntry`: the named group, the key's length, then the key
/// (RFC 8446 §4.2.8).
pub fn share(group : Int32, key : BytesView) -> Bytes {
  let out = Buffer()
  @wire.u16(out, group)
  @wire.u16(out, key.length())
  out.write_bytesview(key)
  out.to_bytes()
}

///|
/// One `KeyShareEntry` off `r`: the group and its key. An empty key is read rather than refused
/// here: it is not a valid key for any group, and RFC 8446 §4.2.8 makes that the group's
/// illegal_parameter, which is what OpenSSL and tlsfuzzer have, not a decode_error.
fn read_entry(r : @wire.Reader) -> (Int32, Bytes) raise @wire.Malformed {
  let group = r.u16()
  (group, r.vec(2).rest().to_owned())
}

///|
/// A ServerHello's `key_share` payload: one `KeyShareEntry`.
pub fn selected_share(group : Int32, key : BytesView) -> Bytes {
  share(group, key)
}

///|
/// The group and key such a payload selected: one entry and nothing after it.
pub fn read_selected_share(view : BytesView) -> (Int32, Bytes)? {
  @wire.decode(view, read_entry)
}

///|
/// A ClientHello's `key_share` payload: the `client_shares` length, then the
/// `KeyShareEntry` list.
pub fn shares(entries : ArrayView[(Int32, Bytes)]) -> Bytes {
  let inner = Buffer()
  for e in entries {
    inner.write_bytes(share(e.0, e.1[:]))
  }
  let body = inner.to_bytes()
  let out = Buffer()
  @wire.u16(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// The shares such a payload offers, in order; an empty list asks the server to pick a group
/// and retry (RFC 8446 §4.2.8).
pub fn read_shares(view : BytesView) -> Array[(Int32, Bytes)]? {
  @wire.decode(view, r => {
    let list = r.vec(2)
    let out = []
    while !list.is_empty() {
      out.push(read_entry(list))
    }
    out
  })
}

///|
/// A `use_srtp` payload (RFC 5764 §4.1.2): the protection profiles offered,
/// then the master key identifier.
///
/// A client sends every profile it will accept; a server answers with exactly
/// one, which is why the same codec serves both ends and the count is left to
/// the caller. The MKI is empty in every profile this family implements —
/// RFC 5764 §4.1.2 allows one, and nothing here needs it.
pub fn use_srtp(profiles : ArrayView[Int32], mki : BytesView) -> Bytes {
  let out = Buffer()
  @wire.u16(out, profiles.length() * 2)
  for p in profiles {
    @wire.u16(out, p)
  }
  out.write_byte(mki.length().to_byte())
  out.write_bytesview(mki)
  out.to_bytes()
}

///|
/// The profiles and MKI such a payload carries, or `None` when it does not fit its lengths.
///
/// A profile list of odd length is a decode failure rather than a list with the
/// last octet dropped: RFC 5764 §4.1.2 makes each profile two octets, so an odd
/// length means the sender and the receiver disagree about the structure.
pub fn read_use_srtp(view : BytesView) -> (Array[Int32], Bytes)? {
  @wire.decode(view, r => {
    let profiles = r.vec(2, min=2, unit=2).codes()
    (profiles, r.vec(1).rest().to_owned())
  })
}

///|
/// A `cookie` payload (RFC 8446 §4.2.2): opaque octets, length-prefixed.
///
/// The server puts whatever it needs into it and the client hands it back
/// untouched. Over datagrams that round trip is the whole defence
/// (RFC 9147 §5.1): a server that answers a ClientHello with a cookie has
/// committed no memory, and an address that cannot receive never comes back.
pub fn cookie(value : BytesView) -> Bytes {
  let out = Buffer()
  @wire.u16(out, value.length())
  out.write_bytesview(value)
  out.to_bytes()
}

///|
/// The octets such a payload carries, or `None` when it does not fit its lengths.
///
/// An empty cookie is refused rather than read as an empty one: §4.2.2 gives
/// the field a minimum of one octet, and a cookie proving nothing is worse than
/// no cookie, because it looks like proof.
pub fn read_cookie(view : BytesView) -> Bytes? {
  @wire.decode(view, r => r.vec(2, min=1).rest().to_owned())
}

///|
/// A server_name payload (RFC 6066 §3): one host_name entry. TLS carries no IP literal here.
pub fn server_name(host : String) -> Bytes {
  let name = @utf8.encode(host)
  let entry = Buffer()
  entry.write_byte(b'\x00')
  @wire.u16(entry, name.length())
  entry.write_bytes(name)
  let body = entry.to_bytes()
  let out = Buffer()
  @wire.u16(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// The host_name a server_name payload carries, or `None` when it is malformed. RFC 6066 §3
/// defines no other name type, and gives one no length a reader could skip it by, so an entry
/// of another type is malformed too.
pub fn read_server_name(data : BytesView) -> String? {
  @wire.decode(data, r => {
    let list = r.vec(2, min=1)
    if list.u8() != 0 {
      raise @wire.Malformed
    }
    let name = @utf8.decode_lossy(list.vec(2, min=1).rest())
    list.end()
    name
  })
}
