// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which handshake message this is (RFC 8446 §4, and IANA's TLS
/// HandshakeType registry).
///
/// `Other` keeps a type this package has no codec for. A handshake message is
/// framed by a type and a 24-bit length, so one it does not understand can
/// still be measured, skipped and fed to the transcript — which is what a
/// receiver has to do, since the transcript hash covers every message whether
/// or not it was understood.
#derive(Eq, Debug)
pub(all) enum Kind {
  ClientHello
  ServerHello
  NewSessionTicket
  /// end_of_early_data, which closes a client's 0-RTT data (RFC 8446 §4.5).
  EndOfEarlyData
  /// compressed_certificate, a Certificate under one of RFC 8879's algorithms.
  CompressedCertificate
  EncryptedExtensions
  Certificate
  CertificateRequest
  CertificateVerify
  Finished
  KeyUpdate
  /// TLS 1.2's three (RFC 5246 §7.3); 1.3 folded them into the rest.
  ServerKeyExchange
  ServerHelloDone
  ClientKeyExchange
  /// A type this package has no codec for, kept as its number.
  Other(Int32)
}

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The octet this message type goes on the wire as.
pub fn Kind::code(self : Kind) -> Int32 {
  match self {
    ClientHello => 1
    ServerHello => 2
    NewSessionTicket => 4
    EndOfEarlyData => 5
    CompressedCertificate => 25
    EncryptedExtensions => 8
    Certificate => 11
    CertificateRequest => 13
    CertificateVerify => 15
    Finished => 20
    KeyUpdate => 24
    ServerKeyExchange => 12
    ServerHelloDone => 14
    ClientKeyExchange => 16
    Other(code) => code
  }
}

///|
/// The message type an octet names. Never fails: one without a codec here
/// becomes `Other`.
pub fn Kind::of(code : Int32) -> Kind {
  match code {
    1 => ClientHello
    2 => ServerHello
    4 => NewSessionTicket
    5 => EndOfEarlyData
    25 => CompressedCertificate
    8 => EncryptedExtensions
    11 => Certificate
    13 => CertificateRequest
    15 => CertificateVerify
    20 => Finished
    24 => KeyUpdate
    12 => ServerKeyExchange
    14 => ServerHelloDone
    16 => ClientKeyExchange
    other => Other(other)
  }
}

// -------------------------------------------------------------- the framing

///|
/// Frame a handshake body: the message type, then a 24-bit big-endian length
/// (RFC 8446 §4).
pub fn frame(kind : Kind, body : BytesView) -> Bytes {
  let out = Buffer()
  out.write_byte(kind.code().to_byte())
  @wire.u24(out, body.length())
  out.write_bytesview(body)
  out.to_bytes()
}

///|
/// One handshake message's type and body, or `None` while the view is short of
/// a whole message.
///
/// The framing is all this reads. What a body means is the codec for that type,
/// below — which is why a message this package has no codec for still comes
/// back rather than failing.
pub fn unframe(view : BytesView) -> (Kind, Bytes)? {
  if view.length() < 4 {
    return None
  }
  let len = @wire.read_u24(view, 1)
  if view.length() < 4 + len {
    return None
  }
  Some((Kind::of(view[0].to_int()), view[4:4 + len].to_owned()))
}

// -------------------------------------------------------------- the messages

///|
/// A ClientHello (RFC 8446 §4.1.2; RFC 5246 §7.4.1.2 for TLS 1.2).
///
/// `version` is the legacy_version: `0x0303` from a TLS 1.3 client, whose real offer is in
/// supported_versions, and the highest version a TLS 1.2 client speaks. `compression` is the
/// list of compression methods, which TLS 1.3 fixes at the null method alone.
#derive(Eq, Debug)
pub(all) struct Hello {
  version : Int32
  random : Bytes
  session_id : Bytes
  suites : Array[Int32]
  compression : Bytes
  extensions : Array[@ext.Ext]
}

///|
pub extend Hello with Eq::{equal, not_equal}

///|
pub extend Hello with Debug::{to_repr}

///|
/// Encode a ClientHello as a whole handshake message.
pub fn hello(ch : Hello) -> Bytes {
  let body = Buffer()
  @wire.u16(body, ch.version)
  body.write_bytes(ch.random)
  body.write_byte(ch.session_id.length().to_byte())
  body.write_bytes(ch.session_id)
  @wire.u16(body, ch.suites.length() * 2)
  for suite in ch.suites {
    @wire.u16(body, suite)
  }
  body.write_byte(ch.compression.length().to_byte())
  body.write_bytes(ch.compression)
  body.write_bytes(@ext.encode(ch.extensions[:]))
  frame(ClientHello, body.to_bytes()[:])
}

///|
/// A legacy_session_id: at most 32 octets in every version.
fn read_session_id(r : @wire.Reader) -> Bytes raise @wire.Malformed {
  let id = r.vec(1).rest()
  if id.length() > 32 {
    raise @wire.Malformed
  }
  id.to_owned()
}

///|
/// The extension block that ends a hello, or none at all: a TLS 1.2 hello may stop before it.
fn read_tail(r : @wire.Reader) -> Array[@ext.Ext] raise @wire.Malformed {
  if r.is_empty() {
    return []
  }
  match @ext.decode(r.rest()) {
    Some(exts) => exts
    None => raise @wire.Malformed
  }
}

///|
/// Decode a ClientHello from a handshake body, or `None` when it does not fit its lengths: a
/// suite list empty or of odd length, no compression method, a session_id past 32 octets.
pub fn read_hello(body : BytesView) -> Hello? {
  @wire.decode(body, r => {
    let version = r.u16()
    let random = r.take(32).to_owned()
    let session_id = read_session_id(r)
    let suites = r.vec(2, min=2, unit=2).codes()
    let compression = r.vec(1, min=1).rest().to_owned()
    let extensions = read_tail(r)
    { version, random, session_id, suites, compression, extensions, }
  })
}

///|
/// A ServerHello (RFC 8446 §4.1.3): one chosen cipher suite and one compression method, both
/// of which TLS 1.3 fixes, the version at `0x0303` and the method at null.
#derive(Eq, Debug)
pub(all) struct Server {
  version : Int32
  random : Bytes
  session_id : Bytes
  suite : Int32
  compression : Int32
  extensions : Array[@ext.Ext]
}

///|
pub extend Server with Eq::{equal, not_equal}

///|
pub extend Server with Debug::{to_repr}

///|
/// Encode a ServerHello as a whole handshake message.
pub fn server_hello(sh : Server) -> Bytes {
  let body = Buffer()
  @wire.u16(body, sh.version)
  body.write_bytes(sh.random)
  body.write_byte(sh.session_id.length().to_byte())
  body.write_bytes(sh.session_id)
  @wire.u16(body, sh.suite)
  body.write_byte(sh.compression.to_byte())
  body.write_bytes(@ext.encode(sh.extensions[:]))
  frame(ServerHello, body.to_bytes()[:])
}

///|
/// Decode a ServerHello from a handshake body, or `None` when it does not fit its lengths.
pub fn read_server_hello(body : BytesView) -> Server? {
  @wire.decode(body, r => {
    let version = r.u16()
    let random = r.take(32).to_owned()
    let session_id = read_session_id(r)
    let suite = r.u16()
    let compression = r.u8()
    let extensions = read_tail(r)
    { version, random, session_id, suite, compression, extensions, }
  })
}

///|
/// An EncryptedExtensions body (RFC 8446 §4.3.1): an extension list, and the
/// first message the server sends under handshake encryption.
///
/// It carries every negotiated extension not needed to establish the
/// cryptographic context — the selected ALPN protocol, and for a QUIC server
/// the `quic_transport_parameters` RFC 9001 §8.2 requires.
pub fn encrypted_extensions(exts : ArrayView[@ext.Ext]) -> Bytes {
  @ext.encode(exts)
}

///|
/// Decode an EncryptedExtensions body, or `None` if it is truncated.
pub fn read_encrypted_extensions(body : BytesView) -> Array[@ext.Ext]? {
  @ext.decode(body)
}

///|
/// Encode a Certificate body (RFC 8446 §4.4.2): the
/// `certificate_request_context`, then the `certificate_list` — each entry a
/// three-octet-length DER certificate and a two-octet-length extensions block.
///
/// `context` is empty when a server sends its certificate unprompted, which is
/// every case until client certificates land. The DER is carried opaque: what
/// is in a certificate is `mooncred`'s question, not the handshake's.
pub fn certificate(
  certs : ArrayView[Bytes],
  context~ : BytesView = b""[:],
) -> Bytes {
  let list = Buffer()
  for cert in certs {
    @wire.u24(list, cert.length())
    list.write_bytes(cert)
    @wire.u16(list, 0)
  }
  let body = list.to_bytes()
  let out = Buffer()
  out.write_byte((context.length() & 0xff).to_byte())
  out.write_bytesview(context)
  @wire.u24(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// Decode a Certificate body into its `certificate_request_context` and the DER certificates,
/// skipping each entry's extensions, or `None` when it does not fit its lengths: an empty
/// certificate is not one (`cert_data<1..2^24-1>`).
pub fn read_certificate(body : BytesView) -> (Bytes, Array[Bytes])? {
  @wire.decode(body, r => {
    let context = r.vec(1).rest().to_owned()
    let list = r.vec(3)
    let certs = []
    while !list.is_empty() {
      certs.push(list.vec(3, min=1).rest().to_owned())
      list.vec(2).rest() |> ignore
    }
    (context, certs)
  })
}

///|
/// The server's CertificateVerify context string (RFC 8446 §4.4.3).
pub let server_context : String = "TLS 1.3, server CertificateVerify"

///|
/// The client's CertificateVerify context string (RFC 8446 §4.4.3).
pub let client_context : String = "TLS 1.3, client CertificateVerify"

///|
/// What a CertificateVerify signs (RFC 8446 §4.4.3): 64 octets of `0x20`, the
/// context string, a single `0x00` separator, then the transcript hash through
/// the Certificate message.
///
/// The 64 spaces and the context string are what stop a signature made for one
/// role, or for an earlier version of the protocol, from counting as one made
/// for another.
pub fn signed(context : String, transcript : BytesView) -> Bytes {
  let out = Buffer()
  out.write_bytes(Bytes::make(64, b'\x20'))
  out.write_bytes(@utf8.encode(context))
  out.write_byte(0)
  out.write_bytesview(transcript)
  out.to_bytes()
}

///|
/// Encode a CertificateVerify body: the SignatureScheme and the two-octet-
/// length-prefixed signature (RFC 8446 §4.4.3).
///
/// `scheme` is the code the signature was made under, which the verifier reads
/// back to decide what to check it with; it is a parameter because the
/// certificate's key decides it, not this package.
pub fn certificate_verify(signature : BytesView, scheme : Int32) -> Bytes {
  let out = Buffer()
  @wire.u16(out, scheme)
  @wire.u16(out, signature.length())
  out.write_bytesview(signature)
  out.to_bytes()
}

///|
/// Decode a CertificateVerify body into its scheme and signature, or `None` when it does not
/// fit its lengths.
pub fn read_certificate_verify(body : BytesView) -> (Int32, Bytes)? {
  @wire.decode(body, r => {
    let scheme = r.u16()
    (scheme, r.vec(2).rest().to_owned())
  })
}

///|
/// A Finished body (RFC 8446 §4.4.4): the `verify_data` and nothing else.
///
/// Computing it is `keys`' job — `@keys.finished` — because it is the key
/// schedule that says what is MACed under what.
pub fn finished(verify_data : BytesView) -> Bytes {
  verify_data.to_owned()
}

///|
/// A CertificateRequest body (RFC 8446 §4.4.2): the context the client's
/// Certificate must echo, and the extensions that say what it may answer with.
///
/// `signature_algorithms` is mandatory in one of these (§4.4.2.2), and a
/// `certificate_authorities` list is a hint about which anchors the server
/// takes. A post-handshake request carries a fresh context of its own.
pub fn certificate_request(
  context : BytesView,
  exts : ArrayView[@ext.Ext],
) -> Bytes {
  let out = Buffer()
  out.write_byte((context.length() & 0xff).to_byte())
  out.write_bytesview(context)
  out.write_bytes(@ext.encode(exts))
  out.to_bytes()
}

///|
/// Decode a CertificateRequest body into its context and extensions, or `None`
/// when it does not fit its lengths.
pub fn read_certificate_request(body : BytesView) -> (Bytes, Array[@ext.Ext])? {
  @wire.decode(body, r => {
    let context = r.vec(1).rest().to_owned()
    let exts = match @ext.decode(r.rest()) {
      Some(exts) => exts
      None => raise @wire.Malformed
    }
    (context, exts)
  })
}

// -------------------------------------------------------------- TLS 1.2 ---

///|
/// A TLS 1.2 Certificate body (RFC 5246 §7.4.2): the chain with no context and no extensions.
pub fn certificate12(certs : ArrayView[Bytes]) -> Bytes {
  let list = Buffer()
  for cert in certs {
    @wire.u24(list, cert.length())
    list.write_bytes(cert)
  }
  let out = Buffer()
  @wire.u24(out, list.length())
  out.write_bytes(list.to_bytes())
  out.to_bytes()
}

///|
/// A TLS 1.2 Certificate body as DER certificates, or `None` when it does not fit its lengths.
pub fn read_certificate12(body : BytesView) -> Array[Bytes]? {
  let r = @wire.Reader::new(body)
  let certs : Array[Bytes] = []
  try {
    let list = r.vec(3)
    r.end()
    while !list.is_empty() {
      certs.push(list.vec(3, min=1).rest().to_owned())
    }
  } catch {
    _ => return None
  }
  Some(certs)
}

///|
/// What a ServerKeyExchange's signature covers besides the two randoms (RFC 8422 §5.4): the curve
/// type, the named curve, and the server's public value.
pub fn key_params(group : Int32, public : BytesView) -> Bytes {
  let out = Buffer()
  out.write_byte(b'\x03')
  @wire.u16(out, group)
  out.write_byte((public.length() & 0xff).to_byte())
  out.write_bytesview(public)
  out.to_bytes()
}

///|
/// What a DHE ServerKeyExchange's signature covers besides the two randoms (RFC 5246 §7.4.3): the
/// prime, the generator and the server's public value.
pub fn dh_params(
  prime : BytesView,
  generator : BytesView,
  public : BytesView,
) -> Bytes {
  let out = Buffer()
  for value in [prime, generator, public] {
    @wire.u16(out, value.length())
    out.write_bytesview(value)
  }
  out.to_bytes()
}

///|
/// A ServerKeyExchange body: the parameters, the signature scheme and the signature.
pub fn server_key_exchange(
  params : BytesView,
  scheme : Int32,
  signature : BytesView,
) -> Bytes {
  let out = Buffer()
  out.write_bytesview(params)
  @wire.u16(out, scheme)
  @wire.u16(out, signature.length())
  out.write_bytesview(signature)
  out.to_bytes()
}

///|
/// An ECDHE ServerKeyExchange's group, public value, signature scheme and signature, or `None`
/// for anything else: a named curve is the only `curve_type` TLS still has.
pub fn read_server_key_exchange(
  body : BytesView,
) -> (Int32, Bytes, Int32, Bytes)? {
  let r = @wire.Reader::new(body)
  try {
    guard r.u8() == 3 else { return None }
    let group = r.u16()
    let public = r.vec(1, min=1).rest().to_owned()
    let scheme = r.u16()
    let signature = r.vec(2, min=1).rest().to_owned()
    r.end()
    Some((group, public, scheme, signature))
  } catch {
    _ => None
  }
}

///|
/// A DHE ServerKeyExchange's prime, generator, public value, signature scheme and signature, as
/// they were written, since the signature covers them that way.
pub fn read_dh_key_exchange(
  body : BytesView,
) -> (Bytes, Bytes, Bytes, Int32, Bytes)? {
  let r = @wire.Reader::new(body)
  try {
    let prime = r.vec(2, min=1).rest().to_owned()
    let generator = r.vec(2, min=1).rest().to_owned()
    let public = r.vec(2, min=1).rest().to_owned()
    let scheme = r.u16()
    let signature = r.vec(2, min=1).rest().to_owned()
    r.end()
    Some((prime, generator, public, scheme, signature))
  } catch {
    _ => None
  }
}

///|
/// A ClientKeyExchange body. `wide` is the two-octet length DHE and RSA use; ECDHE's is one octet
/// (RFC 5246 §7.4.7, RFC 8422 §5.7).
pub fn client_key_exchange(public : BytesView, wide~ : Bool = false) -> Bytes {
  let out = Buffer()
  if wide {
    @wire.u16(out, public.length())
  } else {
    out.write_byte((public.length() & 0xff).to_byte())
  }
  out.write_bytesview(public)
  out.to_bytes()
}

///|
/// The value in a ClientKeyExchange body, `wide` as in `client_key_exchange`.
pub fn read_client_key_exchange(
  body : BytesView,
  wide~ : Bool = false,
) -> Bytes? {
  let r = @wire.Reader::new(body)
  try {
    let public = r.vec(if wide { 2 } else { 1 }, min=1).rest().to_owned()
    r.end()
    Some(public)
  } catch {
    _ => None
  }
}

// ------------------------------------------------------ TLS 1.2 client auth

///|
/// `rsa_sign`, the client certificate type of an RSA key (RFC 5246 §7.4.4).
pub let rsa_sign : Int32 = 1

///|
/// `ecdsa_sign`, the client certificate type of an ECDSA key (RFC 8422 §5.8).
pub let ecdsa_sign : Int32 = 64

///|
/// A TLS 1.2 CertificateRequest body (RFC 5246 §7.4.4): the certificate types
/// accepted, optionally the signature and hash algorithms, then the anchors.
///
/// `schemes` is absent for TLS 1.0 and 1.1, which have no
/// supported_signature_algorithms: there the pair is fixed by the certificate
/// type, and a sender that wrote a list anyway would be writing a field the
/// peer reads as its first anchor.
pub fn certificate_request12(
  types : ArrayView[Int32],
  names~ : ArrayView[Bytes] = [][:],
  schemes? : ArrayView[Int32],
) -> Bytes {
  let out = Buffer()
  out.write_byte((types.length() & 0xff).to_byte())
  for t in types {
    out.write_byte((t & 0xff).to_byte())
  }
  match schemes {
    Some(schemes) => {
      let inner = Buffer()
      for s in schemes {
        @wire.u16(inner, s)
      }
      let body = inner.to_bytes()
      @wire.u16(out, body.length())
      out.write_bytes(body)
    }
    None => ()
  }
  let anchors = Buffer()
  for name in names {
    @wire.u16(anchors, name.length())
    anchors.write_bytes(name)
  }
  let body = anchors.to_bytes()
  @wire.u16(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// Decode a TLS 1.2 CertificateRequest body into its types, schemes and anchors,
/// or `None` when it does not fit its lengths.
///
/// `schemes` is false for a request written by TLS 1.0 or 1.1, which has no
/// field there; the scheme such a peer will sign under follows from the type.
pub fn read_certificate_request12(
  body : BytesView,
  schemes~ : Bool = true,
) -> (Array[Int32], Array[Int32], Array[Bytes])? {
  @wire.decode(body, r => {
    let types = []
    let list = r.vec(1, min=1)
    while !list.is_empty() {
      types.push(list.u8())
    }
    let accepted = if schemes { r.vec(2, min=2, unit=2).codes() } else { [] }
    let anchors = []
    let names = r.vec(2)
    while !names.is_empty() {
      anchors.push(names.vec(2, min=1).rest().to_owned())
    }
    (types, accepted, anchors)
  })
}

// -------------------------------------------------------------- resumption

///|
/// A TLS 1.3 NewSessionTicket (RFC 8446 §4.6.1): how long the ticket lasts, the number that hides
/// a client's own clock from the server, the nonce that makes this ticket's PSK its own, the
/// opaque ticket, and the extensions — of which `early_data` is the one that matters.
#derive(Eq, Debug)
pub(all) struct Ticket {
  lifetime : Int32
  age_add : Int32
  nonce : Bytes
  ticket : Bytes
  extensions : Array[@ext.Ext]
}

///|
pub extend Ticket with Eq::{equal, not_equal}

///|
pub extend Ticket with Debug::{to_repr}

///|
/// Encode a NewSessionTicket as a whole handshake message.
pub fn new_session_ticket(t : Ticket) -> Bytes {
  let out = Buffer()
  out.write_byte(((t.lifetime >> 24) & 0xff).to_byte())
  out.write_byte(((t.lifetime >> 16) & 0xff).to_byte())
  out.write_byte(((t.lifetime >> 8) & 0xff).to_byte())
  out.write_byte((t.lifetime & 0xff).to_byte())
  out.write_byte(((t.age_add >> 24) & 0xff).to_byte())
  out.write_byte(((t.age_add >> 16) & 0xff).to_byte())
  out.write_byte(((t.age_add >> 8) & 0xff).to_byte())
  out.write_byte((t.age_add & 0xff).to_byte())
  out.write_byte((t.nonce.length() & 0xff).to_byte())
  out.write_bytes(t.nonce)
  @wire.u16(out, t.ticket.length())
  out.write_bytes(t.ticket)
  out.write_bytes(@ext.encode(t.extensions[:]))
  frame(NewSessionTicket, out.to_bytes()[:])
}

///|
/// Decode a NewSessionTicket body, or `None` when it does not fit its lengths: a ticket of no
/// octets is not one (`ticket<1..2^16-1>`).
pub fn read_new_session_ticket(body : BytesView) -> Ticket? {
  @wire.decode(body, r => {
    let mut lifetime = 0
    for _ in 0..<4 {
      lifetime = (lifetime << 8) | r.u8()
    }
    let mut age_add = 0
    for _ in 0..<4 {
      age_add = (age_add << 8) | r.u8()
    }
    let nonce = r.vec(1).rest().to_owned()
    let ticket = r.vec(2, min=1).rest().to_owned()
    let tail = if r.is_empty() { Some([]) } else { @ext.decode(r.rest()) }
    let extensions = match tail {
      Some(exts) => exts
      None => raise @wire.Malformed
    }
    { lifetime, age_add, nonce, ticket, extensions, }
  })
}

///|
/// A TLS 1.2 NewSessionTicket (RFC 5077 §3.3): the lifetime in seconds, and the ticket.
pub fn new_session_ticket12(lifetime : Int32, ticket : BytesView) -> Bytes {
  let out = Buffer()
  out.write_byte(((lifetime >> 24) & 0xff).to_byte())
  out.write_byte(((lifetime >> 16) & 0xff).to_byte())
  out.write_byte(((lifetime >> 8) & 0xff).to_byte())
  out.write_byte((lifetime & 0xff).to_byte())
  @wire.u16(out, ticket.length())
  out.write_bytesview(ticket)
  frame(NewSessionTicket, out.to_bytes()[:])
}

///|
/// The lifetime and ticket a TLS 1.2 NewSessionTicket carries, or `None` when it does not fit its
/// lengths.
pub fn read_new_session_ticket12(body : BytesView) -> (Int32, Bytes)? {
  @wire.decode(body, r => {
    let mut lifetime = 0
    for _ in 0..<4 {
      lifetime = (lifetime << 8) | r.u8()
    }
    (lifetime, r.vec(2).rest().to_owned())
  })
}

///|
/// An EndOfEarlyData body: nothing at all (RFC 8446 §4.5). The message exists so the server knows
/// where a client's 0-RTT data stops, and so the transcript has a point to fold it in.
pub fn end_of_early_data() -> Bytes {
  b""
}

///|
/// A TLS 1.0 or 1.1 CertificateVerify body (RFC 2246 §7.4.8): the signature with no scheme in
/// front of it, because there is no signature_algorithms to name one — the certificate type fixes
/// it.
pub fn certificate_verify_legacy(signature : BytesView) -> Bytes {
  let out = Buffer()
  @wire.u16(out, signature.length())
  out.write_bytesview(signature)
  out.to_bytes()
}

///|
/// The signature such a body carries, or `None` when it does not fit its own length.
pub fn read_certificate_verify_legacy(body : BytesView) -> Bytes? {
  @wire.decode(body, r => r.vec(2, min=1).rest().to_owned())
}

// --------------------------------------------------------- certificate status

///|
/// A Certificate body whose leaf entry carries extensions — which is how TLS 1.3 staples an OCSP
/// response to it (RFC 8446 §4.4.2.1).
pub fn certificate_status(
  certs : ArrayView[Bytes],
  status : BytesView,
) -> Bytes {
  let list = Buffer()
  for i, cert in certs {
    @wire.u24(list, cert.length())
    list.write_bytes(cert)
    if i == 0 {
      let exts : Array[@ext.Ext] = [
        { kind: StatusRequest, data: @ext.certificate_status(status), },
      ]
      list.write_bytes(@ext.encode(exts[:]))
    } else {
      @wire.u16(list, 0)
    }
  }
  let body = list.to_bytes()
  let out = Buffer()
  out.write_byte(0)
  @wire.u24(out, body.length())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// A Certificate body's context, its chain, and the extensions of each entry — which is what a
/// client needs to find the OCSP response stapled to the leaf.
pub fn read_certificate_entries(
  body : BytesView,
) -> (Bytes, Array[Bytes], Array[Array[@ext.Ext]])? {
  @wire.decode(body, r => {
    let context = r.vec(1).rest().to_owned()
    let list = r.vec(3)
    let certs = []
    let all : Array[Array[@ext.Ext]] = []
    while !list.is_empty() {
      certs.push(list.vec(3, min=1).rest().to_owned())
      let tail = list.vec(2).rest()
      let parsed = if tail.length() == 0 {
        Some([])
      } else {
        @ext.read_block(tail)
      }
      let exts = match parsed {
        Some(exts) => exts
        None => raise @wire.Malformed
      }
      all.push(exts)
    }
    (context, certs, all)
  })
}

///|
/// A TLS 1.2 CertificateStatus message body (RFC 6066 §8).
pub fn certificate_status12(response : BytesView) -> Bytes {
  @ext.certificate_status12(response)
}

///|
/// The response a TLS 1.2 CertificateStatus carries.
pub fn read_certificate_status12(body : BytesView) -> Bytes? {
  @ext.read_certificate_status12(body)
}

///|
/// A CompressedCertificate body (RFC 8879 §4): the algorithm, the length the Certificate will have
/// once decompressed, and the compressed octets.
///
/// The uncompressed length is what lets a receiver refuse a decompression bomb before it happens,
/// so it is a promise the sender is held to rather than a hint.
pub fn compressed_certificate(
  algorithm : Int32,
  uncompressed : Int32,
  compressed : BytesView,
) -> Bytes {
  let out = Buffer()
  @wire.u16(out, algorithm)
  @wire.u24(out, uncompressed)
  @wire.u24(out, compressed.length())
  out.write_bytesview(compressed)
  out.to_bytes()
}

///|
/// The algorithm, uncompressed length and compressed octets such a body carries, or `None` when it
/// does not fit its lengths.
pub fn read_compressed_certificate(body : BytesView) -> (Int32, Int32, Bytes)? {
  @wire.decode(body, r => {
    let algorithm = r.u16()
    let uncompressed = r.u24()
    (algorithm, uncompressed, r.vec(3, min=1).rest().to_owned())
  })
}
