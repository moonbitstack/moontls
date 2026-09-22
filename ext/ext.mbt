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
  /// A type this package has no codec for, kept as its number.
  Other(Int)
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The two octets this extension type goes on the wire as.
pub fn Kind::code(self : Kind) -> Int {
  match self {
    ServerName => 0x0000
    SupportedGroups => 0x000a
    SignatureAlgorithms => 0x000d
    Alpn => 0x0010
    SupportedVersions => 0x002b
    KeyShare => 0x0033
    QuicTransportParameters => 0x0039
    Other(code) => code
  }
}

///|
/// The extension type a code names. Never fails: one without a codec here
/// becomes `Other`.
pub fn Kind::of(code : Int) -> Kind {
  match code {
    0x0000 => ServerName
    0x000a => SupportedGroups
    0x000d => SignatureAlgorithms
    0x0010 => Alpn
    0x002b => SupportedVersions
    0x0033 => KeyShare
    0x0039 => QuicTransportParameters
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
pub let version_13 : Int = 0x0304

///|
/// x25519, the group RFC 8446 §4.2.7 lists first and TLS 1.3 offers first.
pub let x25519 : Int = 0x001d

///|
/// secp256r1 (NIST P-256).
pub let secp256r1 : Int = 0x0017

///|
/// secp384r1 (NIST P-384).
pub let secp384r1 : Int = 0x0018

///|
/// rsa_pss_rsae_sha256, the signature scheme RFC 8446 §9.1 requires.
pub let rsa_pss_rsae_sha256 : Int = 0x0804

///|
/// ecdsa_secp256r1_sha256, the other scheme §9.1 requires.
pub let ecdsa_secp256r1_sha256 : Int = 0x0403

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
/// Decode an extension block, or `None` if a length overruns what is there.
///
/// A length that does not fit is a refusal rather than a truncated answer: an
/// extension block is framed, so an overrun means the message is malformed and
/// not that more octets are coming.
pub fn decode(view : BytesView) -> Array[Ext]? {
  if view.length() < 2 {
    return None
  }
  let end = 2 + @wire.read_u16(view, 0)
  if view.length() < end {
    return None
  }
  let out : Array[Ext] = []
  let mut at = 2
  while at < end {
    if at + 4 > end {
      return None
    }
    let kind = Kind::of(@wire.read_u16(view, at))
    let len = @wire.read_u16(view, at + 2)
    at = at + 4
    if at + len > end {
      return None
    }
    out.push({ kind, data: view[at:at + len].to_owned(), })
    at = at + len
  }
  Some(out)
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
fn u16_list(values : ArrayView[Int]) -> Bytes {
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
/// The codes in such a list, stopping at the declared length or a truncated
/// entry.
fn read_u16_list(view : BytesView) -> Array[Int] {
  let values : Array[Int] = []
  if view.length() < 2 {
    return values
  }
  let declared = 2 + @wire.read_u16(view, 0)
  let end = if declared < view.length() { declared } else { view.length() }
  let mut at = 2
  while at + 2 <= end {
    values.push(@wire.read_u16(view, at))
    at = at + 2
  }
  values
}

///|
/// A ClientHello's `supported_versions` payload (RFC 8446 §4.2.1): a one-octet
/// length, then each version as two octets, most preferred first.
pub fn versions(offered : ArrayView[Int]) -> Bytes {
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
/// The versions such a payload offers, in order.
pub fn read_versions(view : BytesView) -> Array[Int] {
  let out : Array[Int] = []
  if view.length() < 1 {
    return out
  }
  let declared = 1 + view[0].to_int()
  let end = if declared < view.length() { declared } else { view.length() }
  let mut at = 1
  while at + 2 <= end {
    out.push(@wire.read_u16(view, at))
    at = at + 2
  }
  out
}

///|
/// A ServerHello's `supported_versions` payload: the selected version alone,
/// with no list prefix (RFC 8446 §4.2.1).
pub fn selected_version(version : Int) -> Bytes {
  let out = Buffer()
  @wire.u16(out, version)
  out.to_bytes()
}

///|
/// The version such a payload selected, or `None` if it is not two octets.
pub fn read_selected_version(view : BytesView) -> Int? {
  if view.length() != 2 {
    return None
  }
  Some(@wire.read_u16(view, 0))
}

///|
/// A `supported_groups` payload (RFC 8446 §4.2.7).
pub fn groups(offered : ArrayView[Int]) -> Bytes {
  u16_list(offered)
}

///|
/// The groups such a payload offers.
pub fn read_groups(view : BytesView) -> Array[Int] {
  read_u16_list(view)
}

///|
/// A `signature_algorithms` payload (RFC 8446 §4.2.3).
pub fn schemes(offered : ArrayView[Int]) -> Bytes {
  u16_list(offered)
}

///|
/// The schemes such a payload offers.
pub fn read_schemes(view : BytesView) -> Array[Int] {
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
/// The protocol names such a payload carries, stopping at the declared list
/// length or a truncated entry.
pub fn read_protocols(view : BytesView) -> Array[String] {
  let names : Array[String] = []
  if view.length() < 2 {
    return names
  }
  let end = 2 + @wire.read_u16(view, 0)
  let mut at = 2
  while at < end && at < view.length() {
    let n = view[at].to_int()
    at = at + 1
    if at + n > view.length() {
      break
    }
    names.push(@utf8.decode_lossy(view[at:at + n]))
    at = at + n
  }
  names
}

///|
/// One `KeyShareEntry`: the named group, the key's length, then the key
/// (RFC 8446 §4.2.8).
pub fn share(group : Int, key : BytesView) -> Bytes {
  let out = Buffer()
  @wire.u16(out, group)
  @wire.u16(out, key.length())
  out.write_bytesview(key)
  out.to_bytes()
}

///|
/// One `KeyShareEntry` off the front of `view`, with how many octets it took,
/// or `None` on a partial read.
pub fn read_share(view : BytesView) -> (Int, Bytes, Int)? {
  if view.length() < 4 {
    return None
  }
  let group = @wire.read_u16(view, 0)
  let len = @wire.read_u16(view, 2)
  if view.length() < 4 + len {
    return None
  }
  Some((group, view[4:4 + len].to_owned(), 4 + len))
}

///|
/// A ServerHello's `key_share` payload: one `KeyShareEntry`.
pub fn selected_share(group : Int, key : BytesView) -> Bytes {
  share(group, key)
}

///|
/// The group and key such a payload selected.
pub fn read_selected_share(view : BytesView) -> (Int, Bytes)? {
  match read_share(view) {
    Some((group, key, _)) => Some((group, key))
    None => None
  }
}

///|
/// A ClientHello's `key_share` payload: the `client_shares` length, then the
/// `KeyShareEntry` list.
pub fn shares(entries : ArrayView[(Int, Bytes)]) -> Bytes {
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
/// The shares such a payload offers, in order.
pub fn read_shares(view : BytesView) -> Array[(Int, Bytes)] {
  let out : Array[(Int, Bytes)] = []
  if view.length() < 2 {
    return out
  }
  let end = 2 + @wire.read_u16(view, 0)
  let mut at = 2
  while at < end && at < view.length() {
    match read_share(view[at:]) {
      Some((group, key, used)) => {
        out.push((group, key))
        at = at + used
      }
      None => break
    }
  }
  out
}
