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
pub(all) enum Kind {
  ClientHello
  ServerHello
  NewSessionTicket
  EncryptedExtensions
  Certificate
  CertificateRequest
  CertificateVerify
  Finished
  KeyUpdate
  /// A type this package has no codec for, kept as its number.
  Other(Int32)
} derive(Eq, Debug)

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
    EncryptedExtensions => 8
    Certificate => 11
    CertificateRequest => 13
    CertificateVerify => 15
    Finished => 20
    KeyUpdate => 24
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
    8 => EncryptedExtensions
    11 => Certificate
    13 => CertificateRequest
    15 => CertificateVerify
    20 => Finished
    24 => KeyUpdate
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
pub(all) struct Hello {
  version : Int32
  random : Bytes
  session_id : Bytes
  suites : Array[Int32]
  compression : Bytes
  extensions : Array[@ext.Ext]
} derive(Eq, Debug)

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
pub(all) struct Server {
  version : Int32
  random : Bytes
  session_id : Bytes
  suite : Int32
  compression : Int32
  extensions : Array[@ext.Ext]
} derive(Eq, Debug)

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
