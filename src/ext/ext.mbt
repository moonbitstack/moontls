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
#derive(Eq, Debug)
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
  /// psk_key_exchange_modes, which says whether a PSK is bound to a key exchange (§4.2.9).
  PskKeyExchangeModes
  /// ec_point_formats (RFC 8422 §5.1.2), which only TLS 1.2 sends.
  EcPointFormats
  /// extended_master_secret (RFC 7627 §5.1).
  ExtendedMasterSecret
  /// renegotiation_info (RFC 5746 §3.2).
  RenegotiationInfo
  /// encrypt_then_mac (RFC 7366 §2), which only CBC suites have a use for.
  EncryptThenMac
  /// session_ticket, a TLS 1.2 ticket the server reads and the client hands back (RFC 5077 §3.2).
  SessionTicket
  /// status_request, the certificate's revocation status stapled to the handshake (RFC 6066 §8).
  StatusRequest
  /// record_size_limit, the largest record this end will read (RFC 8449 §4).
  RecordSizeLimit
  /// heartbeat, which this library refuses: see `Conn`'s handling of a heartbeat record.
  Heartbeat
  /// compress_certificate, the algorithms a client will take a Certificate compressed with
  /// (RFC 8879 §3).
  CompressCertificate
  /// cookie, which a HelloRetryRequest hands back to prove the client can
  /// receive at the address it claimed (§4.2.2). DTLS leans on it as its
  /// denial-of-service countermeasure (RFC 9147 §5.1).
  Cookie
  /// certificate_authorities, the anchors a server will take a client
  /// certificate from (§4.2.4).
  CertificateAuthorities
  /// post_handshake_auth, a client saying it will answer a CertificateRequest
  /// that arrives after the handshake (§4.2.6).
  PostHandshakeAuth
  /// A type this package has no codec for, kept as its number.
  Other(Int32)
}

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
    EcPointFormats => 0x000b
    EncryptThenMac => 0x0016
    SessionTicket => 0x0023
    StatusRequest => 0x0005
    RecordSizeLimit => 0x001c
    Heartbeat => 0x000f
    CompressCertificate => 0x001b
    ExtendedMasterSecret => 0x0017
    RenegotiationInfo => 0xff01
    Padding => 0x0015
    PreSharedKey => 0x0029
    EarlyData => 0x002a
    PskKeyExchangeModes => 0x002d
    Cookie => 0x002c
    CertificateAuthorities => 0x002f
    PostHandshakeAuth => 0x0031
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
    0x000b => EcPointFormats
    0x0016 => EncryptThenMac
    0x0023 => SessionTicket
    0x0005 => StatusRequest
    0x001c => RecordSizeLimit
    0x000f => Heartbeat
    0x001b => CompressCertificate
    0x0017 => ExtendedMasterSecret
    0xff01 => RenegotiationInfo
    0x0015 => Padding
    0x0029 => PreSharedKey
    0x002a => EarlyData
    0x002d => PskKeyExchangeModes
    0x002c => Cookie
    0x002f => CertificateAuthorities
    0x0031 => PostHandshakeAuth
    other => Other(other)
  }
}

///|
/// One extension: its type and its still-unparsed payload (RFC 8446 §4.2).
#derive(Eq, Debug)
pub(all) struct Ext {
  kind : Kind
  data : Bytes
}

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
/// X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem): ML-KEM-768 and X25519 in one share, the ML-KEM
/// half first. What browsers offer first.
pub let x25519mlkem768 : Int32 = 0x11ec

///|
/// SecP256r1MLKEM768: P-256 and ML-KEM-768, the curve half first.
pub let secp256r1mlkem768 : Int32 = 0x11eb

///|
/// SecP384r1MLKEM1024: P-384 and ML-KEM-1024, the curve half first.
pub let secp384r1mlkem1024 : Int32 = 0x11ed

///|
/// ML-KEM alone (draft-ietf-tls-mlkem), by parameter set.
pub let mlkem512 : Int32 = 0x0200

///|
pub let mlkem768 : Int32 = 0x0201

///|
pub let mlkem1024 : Int32 = 0x0202

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
/// rsa_pkcs1_sha224, which TLS 1.2 alone has.
pub let rsa_pkcs1_sha224 : Int32 = 0x0301

///|
/// rsa_pkcs1_sha1: what a TLS 1.2 client means by leaving signature_algorithms out. RFC 9155 forbids
/// it in new work.
pub let rsa_pkcs1_sha1 : Int32 = 0x0201

///|
/// ecdsa_sha224, which TLS 1.2 alone has.
pub let ecdsa_sha224 : Int32 = 0x0303

///|
/// ecdsa_sha1, `rsa_pkcs1_sha1`'s counterpart.
pub let ecdsa_sha1 : Int32 = 0x0203

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
    let len = r.u16()
    match read_block(r.take(len)) {
      Some(exts) => exts
      None => raise @wire.Malformed
    }
  })
}

///|
/// Decode an extension block whose two-octet total length has already been read — what a structure
/// that frames the block itself, like a TLS 1.3 Certificate entry, needs.
pub fn read_block(view : BytesView) -> Array[Ext]? {
  @wire.decode(view, list => {
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
pub fn read_server_names(data : BytesView) -> Array[String]? {
  @wire.decode(data, r => {
    let list = r.vec(2, min=1)
    let names : Array[String] = []
    while !list.is_empty() {
      let kind = list.u8()
      let name = list.vec(2, min=1).rest()
      if kind == 0 {
        names.push(@utf8.decode_lossy(name))
      }
    }
    names
  })
}

///|
/// ec_point_formats naming the uncompressed form, the only one RFC 8422 §5.1.2 leaves.
pub fn point_formats() -> Bytes {
  b"\x01\x00"
}

///|
/// The formats in an ec_point_formats body, or `None` when it does not fit its length or names none.
pub fn read_point_formats(data : BytesView) -> Bytes? {
  @wire.decode(data, r => r.vec(1, min=1).rest().to_owned())
}

///|
/// renegotiation_info for an initial handshake: the empty `renegotiated_connection` (RFC 5746 §3.4).
pub fn no_renegotiation() -> Bytes {
  b"\x00"
}

///|
/// renegotiation_info for a renegotiation (RFC 5746 §3.4): the previous handshake's client and
/// server Finished verify_data, one after the other.
///
/// The two values are what makes a renegotiation safe: they tie the new handshake to the old one,
/// so a ClientHello recorded from another connection cannot be spliced in.
pub fn renegotiation(client : BytesView, server : BytesView) -> Bytes {
  let out = Buffer()
  out.write_byte(((client.length() + server.length()) & 0xff).to_byte())
  out.write_bytesview(client)
  out.write_bytesview(server)
  out.to_bytes()
}

///|
/// The two verify_data a renegotiation_info payload carries, either of which may be empty, or
/// `None` when it does not fit its length.
pub fn read_renegotiation(view : BytesView) -> (Bytes, Bytes)? {
  @wire.decode(view, r => {
    let body = r.vec(1).rest().to_owned()
    // §3.4: the two are each twelve octets, or the whole thing is empty on an initial handshake.
    if body.length() == 0 {
      (b"", b"")
    } else if body.length() == 24 {
      (body[0:12].to_owned(), body[12:24].to_owned())
    } else {
      raise @wire.Malformed
    }
  })
}

///|
/// A certificate_authorities payload (RFC 8446 §4.2.4, RFC 5246 §7.4.4): the
/// DER names of the anchors this endpoint takes a certificate from.
///
/// The names are carried opaque. What a distinguished name says is the
/// certificate library's question, and a client that cannot name one from the
/// list is free to send a certificate anyway — the list is a hint.
pub fn authorities(names : ArrayView[Bytes]) -> Bytes {
  let inner = Buffer()
  for name in names {
    @wire.u16(inner, name.length())
    inner.write_bytes(name)
  }
  let body = inner.to_bytes()
  let out = Buffer()
  @wire.u16(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// The names such a payload carries: at least one, each at least one octet
/// (`DistinguishedName<1..2^16-1>`), or `None` when it does not fit its lengths.
pub fn read_authorities(view : BytesView) -> Array[Bytes]? {
  @wire.decode(view, r => {
    let list = r.vec(2, min=1)
    let names : Array[Bytes] = []
    while !list.is_empty() {
      names.push(list.vec(2, min=1).rest().to_owned())
    }
    names
  })
}

// ------------------------------------------------------------- resumption

///|
/// A `session_ticket` payload (RFC 5077 §3.2): the ticket the client hands back, or nothing at all,
/// which is a server saying it will send one.
pub fn session_ticket(ticket : BytesView) -> Bytes {
  let out = Buffer()
  @wire.u16(out, ticket.length())
  out.write_bytesview(ticket)
  out.to_bytes()
}

///|
/// The ticket such a payload carries: empty is a legitimate value, and `None` means only that it
/// does not fit its own length.
pub fn read_session_ticket(view : BytesView) -> Bytes? {
  @wire.decode(view, r => r.vec(2).rest().to_owned())
}

///|
/// `psk_ke`, the mode where a PSK alone keys the handshake, with no Diffie-Hellman
/// (RFC 8446 §4.2.9). This library does not offer it: without a key exchange there is
/// no forward secrecy at all, and a stolen ticket would open every connection made
/// with it.
pub let psk_ke : Int32 = 0

///|
/// `psk_dhe_ke`, the mode RFC 8446 §4.2.9 expects: the PSK authenticates the handshake
/// and a key exchange gives it forward secrecy.
pub let psk_dhe_ke : Int32 = 1

///|
/// A `psk_key_exchange_modes` payload: one length octet, then the modes (RFC 8446 §4.2.9).
pub fn psk_modes(modes : ArrayView[Int32]) -> Bytes {
  let out = Buffer()
  out.write_byte((modes.length() & 0xff).to_byte())
  for mode in modes {
    out.write_byte((mode & 0xff).to_byte())
  }
  out.to_bytes()
}

///|
/// The modes such a payload offers, or `None` when it names none or does not fit its length.
pub fn read_psk_modes(view : BytesView) -> Array[Int32]? {
  @wire.decode(view, r => {
    let list = r.vec(1, min=1)
    let out = []
    while !list.is_empty() {
      out.push(list.u8())
    }
    out
  })
}

///|
/// One `PskIdentity`: an opaque identity and the age the client reports for it, obfuscated
/// by adding the ticket's own `ticket_age_add` (RFC 8446 §4.2.11.1).
#derive(Eq, Debug)
pub(all) struct Identity {
  identity : Bytes
  age : Int32
}

///|
pub extend Identity with Eq::{equal, not_equal}

///|
pub extend Identity with Debug::{to_repr}

///|
/// An `OfferedPsks` payload (RFC 8446 §4.2.11): the identities, then one binder per
/// identity, in the same order.
///
/// The binders are the authentication, and they cover a truncated ClientHello — see
/// [`binder_offset`] for where that truncation falls.
pub fn pre_shared_key(
  identities : ArrayView[Identity],
  binders : ArrayView[Bytes],
) -> Bytes {
  let list = Buffer()
  for one in identities {
    @wire.u16(list, one.identity.length())
    list.write_bytes(one.identity)
    let age = one.age
    list.write_byte(((age >> 24) & 0xff).to_byte())
    list.write_byte(((age >> 16) & 0xff).to_byte())
    list.write_byte(((age >> 8) & 0xff).to_byte())
    list.write_byte((age & 0xff).to_byte())
  }
  let offered = list.to_bytes()
  let out = Buffer()
  @wire.u16(out, offered.length())
  out.write_bytes(offered)
  let tail = Buffer()
  for binder in binders {
    tail.write_byte((binder.length() & 0xff).to_byte())
    tail.write_bytes(binder)
  }
  let body = tail.to_bytes()
  @wire.u16(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// The identities and binders such a payload carries: at least one of each, the same number of
/// both, each identity at least one octet and each binder in `32..255` (§4.2.11), or `None`.
pub fn read_pre_shared_key(
  view : BytesView,
) -> (Array[Identity], Array[Bytes])? {
  match
    @wire.decode(view, r => {
      let list = r.vec(2, min=7)
      let identities : Array[Identity] = []
      while !list.is_empty() {
        let identity = list.vec(2, min=1).rest().to_owned()
        let mut age = 0
        for _ in 0..<4 {
          age = (age << 8) | list.u8()
        }
        identities.push({ identity, age, })
      }
      let binders = r.vec(2, min=33)
      let proofs : Array[Bytes] = []
      while !binders.is_empty() {
        proofs.push(binders.vec(1, min=32).rest().to_owned())
      }
      (identities, proofs)
    }) {
    Some((identities, proofs)) =>
      if identities.length() == proofs.length() {
        Some((identities, proofs))
      } else {
        None
      }
    None => None
  }
}

///|
/// Where a ClientHello's binders start, given a whole ClientHello handshake message whose
/// `pre_shared_key` extension is last, a binder of `hash` octets, and `n` binders offered
/// (RFC 8446 §4.2.11.2).
///
/// The binder covers the ClientHello up to this offset, which is where the binders list begins —
/// its two-octet length field included in what follows, excluded from what is hashed. The message's
/// own length fields are as if the binders were there, which is what makes the offset a subtraction
/// from the end rather than a field to search for: a server has the whole message and knows how
/// long a binder for its suite is.
pub fn binder_offset(hello : BytesView, hash : Int32, n~ : Int32 = 1) -> Int32? {
  let tail = 2 + n * (1 + hash)
  if hello.length() < tail {
    return None
  }
  Some(hello.length() - tail)
}

///|
/// `early_data` in a ClientHello or an EncryptedExtensions: no payload at all
/// (RFC 8446 §4.2.10).
pub fn early_data() -> Bytes {
  b""
}

///|
/// `early_data` in a NewSessionTicket: the `max_early_data_size` a client may send under it
/// (§4.6.1). The ticket's own name is what says the field is a number rather than nothing.
pub fn max_early_data(size : Int32) -> Bytes {
  let out = Buffer()
  out.write_byte(((size >> 24) & 0xff).to_byte())
  out.write_byte(((size >> 16) & 0xff).to_byte())
  out.write_byte(((size >> 8) & 0xff).to_byte())
  out.write_byte((size & 0xff).to_byte())
  out.to_bytes()
}

///|
/// The `max_early_data_size` such a payload carries, or `None` when it is not four octets.
pub fn read_max_early_data(view : BytesView) -> Int32? {
  guard view.length() == 4 else { return None }
  Some(
    (view[0].to_int() << 24) |
    (view[1].to_int() << 16) |
    (view[2].to_int() << 8) |
    view[3].to_int(),
  )
}

// -------------------------------------------------------- status and limits

///|
/// A ClientHello's `status_request` (RFC 6066 §8): the OCSP status of the leaf, please. The two
/// empty vectors are the ones that extension gives a client that has no preferences to state.
pub fn status_request() -> Bytes {
  b"\x01\x00\x00\x00\x00"
}

///|
/// Whether such a payload asks for OCSP at all, and `None` when it does not parse. The responder
/// list and the request extensions are read and dropped: this server staples one response.
pub fn read_status_request(view : BytesView) -> Bool? {
  @wire.decode(view, r => {
    let kind = r.u8()
    r.vec(2).rest() |> ignore
    r.vec(2).rest() |> ignore
    kind == 1
  })
}

///|
/// The `status_request` extension a TLS 1.3 Certificate entry carries (RFC 8446 §4.4.2.1): the
/// OCSP response, length-prefixed.
pub fn certificate_status(response : BytesView) -> Bytes {
  let out = Buffer()
  out.write_byte(b'\x01')
  @wire.u24(out, response.length())
  out.write_bytesview(response)
  out.to_bytes()
}

///|
/// The OCSP response such an extension carries, or `None` when it does not fit its length.
pub fn read_certificate_status(view : BytesView) -> Bytes? {
  @wire.decode(view, r => {
    if r.u8() != 1 {
      raise @wire.Malformed
    }
    r.vec(3, min=1).rest().to_owned()
  })
}

///|
/// A TLS 1.2 CertificateStatus body (RFC 6066 §8): the same shape without the extension framing.
pub fn certificate_status12(response : BytesView) -> Bytes {
  let out = Buffer()
  out.write_byte(b'\x01')
  @wire.u24(out, response.length())
  out.write_bytesview(response)
  out.to_bytes()
}

///|
/// The response a TLS 1.2 CertificateStatus carries.
pub fn read_certificate_status12(view : BytesView) -> Bytes? {
  read_certificate_status(view)
}

///|
/// A `record_size_limit` payload (RFC 8449 §4): the largest record, header and tag included, this
/// end will read.
///
/// The extension is not a negotiation: each end states its own and applies the other's. A limit
/// below 64 is refused by the receiver (§4), since a record that small cannot carry anything.
pub fn record_size_limit(limit : Int32) -> Bytes {
  let out = Buffer()
  @wire.u16(out, limit)
  out.to_bytes()
}

///|
/// The limit such a payload states, or `None` when it is not two octets in 64..2^14+1.
pub fn read_record_size_limit(view : BytesView) -> Int32? {
  guard view.length() == 2 else { return None }
  let limit = @wire.read_u16(view, 0)
  Some(limit)
}

// ------------------------------------------------------ certificate compression

///|
/// zlib, the one certificate compression algorithm this library speaks (RFC 8879 §4.2). Brotli and
/// zstd are the registry's other two, and neither is in this repository's dependencies.
pub let zlib_compression : Int32 = 1

///|
/// A `compress_certificate` payload (RFC 8879 §3): the algorithms a client will accept, best first.
pub fn compression_algorithms(ids : ArrayView[Int32]) -> Bytes {
  let out = Buffer()
  out.write_byte(((ids.length() * 2) & 0xff).to_byte())
  for id in ids {
    @wire.u16(out, id)
  }
  out.to_bytes()
}

///|
/// The algorithms such a payload names: at least one, each two octets, or `None` when it does not
/// fit its own length.
pub fn read_compression_algorithms(view : BytesView) -> Array[Int32]? {
  @wire.decode(view, r => r.vec(1, min=2, unit=2).codes())
}
