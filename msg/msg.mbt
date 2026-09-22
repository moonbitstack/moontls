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
  Other(Int)
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The octet this message type goes on the wire as.
pub fn Kind::code(self : Kind) -> Int {
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
pub fn Kind::of(code : Int) -> Kind {
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
/// A ClientHello (RFC 8446 §4.1.2), less the fixed legacy fields.
///
/// `legacy_version` and `legacy_compression_methods` are not carried because
/// TLS 1.3 fixes them: the version is `0x0303` whatever is negotiated (the
/// `supported_versions` extension does the negotiating) and the only
/// compression method is null. Writing them out would be four fields that can
/// never differ.
pub(all) struct Hello {
  random : Bytes
  session_id : Bytes
  suites : Array[Int]
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
  @wire.u16(body, @wire.legacy_version)
  body.write_bytes(ch.random)
  body.write_byte(ch.session_id.length().to_byte())
  body.write_bytes(ch.session_id)
  @wire.u16(body, ch.suites.length() * 2)
  for suite in ch.suites {
    @wire.u16(body, suite)
  }
  // legacy_compression_methods: the single null method.
  body.write_byte(b'\x01')
  body.write_byte(b'\x00')
  body.write_bytes(@ext.encode(ch.extensions[:]))
  frame(ClientHello, body.to_bytes()[:])
}

///|
/// Decode a ClientHello from a handshake body (RFC 8446 §4.1.2).
pub fn read_hello(body : BytesView) -> Hello? {
  if body.length() < 35 {
    return None
  }
  let random = body[2:34].to_owned()
  let id_len = body[34].to_int()
  let mut at = 35
  if body.length() < at + id_len {
    return None
  }
  let session_id = body[at:at + id_len].to_owned()
  at = at + id_len
  if body.length() < at + 2 {
    return None
  }
  let suites_len = @wire.read_u16(body, at)
  at = at + 2
  if body.length() < at + suites_len {
    return None
  }
  let suites : Array[Int] = []
  for i = 0; i + 1 < suites_len; i = i + 2 {
    suites.push(@wire.read_u16(body, at + i))
  }
  at = at + suites_len
  if body.length() < at + 1 {
    return None
  }
  at = at + 1 + body[at].to_int()
  guard @ext.decode(body[at:]) is Some(extensions) else { return None }
  Some({ random, session_id, suites, extensions, })
}

///|
/// A ServerHello (RFC 8446 §4.1.3): one chosen cipher suite, no compression.
pub(all) struct Server {
  random : Bytes
  session_id : Bytes
  suite : Int
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
  @wire.u16(body, @wire.legacy_version)
  body.write_bytes(sh.random)
  body.write_byte(sh.session_id.length().to_byte())
  body.write_bytes(sh.session_id)
  @wire.u16(body, sh.suite)
  body.write_byte(b'\x00')
  body.write_bytes(@ext.encode(sh.extensions[:]))
  frame(ServerHello, body.to_bytes()[:])
}

///|
/// Decode a ServerHello from a handshake body (RFC 8446 §4.1.3).
pub fn read_server_hello(body : BytesView) -> Server? {
  if body.length() < 35 {
    return None
  }
  let random = body[2:34].to_owned()
  let id_len = body[34].to_int()
  let mut at = 35
  if body.length() < at + id_len {
    return None
  }
  let session_id = body[at:at + id_len].to_owned()
  at = at + id_len
  if body.length() < at + 3 {
    return None
  }
  let suite = @wire.read_u16(body, at)
  // The suite is two octets; the third is the legacy compression method.
  at = at + 3
  guard @ext.decode(body[at:]) is Some(extensions) else { return None }
  Some({ random, session_id, suite, extensions, })
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
  context? : BytesView = b""[:],
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
/// Decode a Certificate body into its `certificate_request_context` and the DER
/// certificates, skipping each entry's extensions. `None` on a truncated
/// message.
pub fn read_certificate(body : BytesView) -> (Bytes, Array[Bytes])? {
  if body.length() < 1 {
    return None
  }
  let ctx_len = body[0].to_int()
  let mut at = 1
  if body.length() < at + ctx_len {
    return None
  }
  let context = body[at:at + ctx_len].to_owned()
  at = at + ctx_len
  if body.length() < at + 3 {
    return None
  }
  let list_len = @wire.read_u24(body, at)
  at = at + 3
  let end = at + list_len
  if body.length() < end {
    return None
  }
  let certs : Array[Bytes] = []
  while at < end {
    if end < at + 3 {
      return None
    }
    let cert_len = @wire.read_u24(body, at)
    at = at + 3
    if end < at + cert_len {
      return None
    }
    certs.push(body[at:at + cert_len].to_owned())
    at = at + cert_len
    if end < at + 2 {
      return None
    }
    let ext_len = @wire.read_u16(body, at)
    at = at + 2
    if end < at + ext_len {
      return None
    }
    at = at + ext_len
  }
  Some((context, certs))
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
pub fn certificate_verify(signature : BytesView, scheme : Int) -> Bytes {
  let out = Buffer()
  @wire.u16(out, scheme)
  @wire.u16(out, signature.length())
  out.write_bytesview(signature)
  out.to_bytes()
}

///|
/// Decode a CertificateVerify body into its scheme and signature, or `None` if
/// the length does not describe what is there.
pub fn read_certificate_verify(body : BytesView) -> (Int, Bytes)? {
  if body.length() < 4 {
    return None
  }
  let scheme = @wire.read_u16(body, 0)
  let len = @wire.read_u16(body, 2)
  if body.length() != 4 + len {
    return None
  }
  Some((scheme, body[4:4 + len].to_owned()))
}

///|
/// A Finished body (RFC 8446 §4.4.4): the `verify_data` and nothing else.
///
/// Computing it is `keys`' job — `@keys.finished` — because it is the key
/// schedule that says what is MACed under what.
pub fn finished(verify_data : BytesView) -> Bytes {
  verify_data.to_owned()
}
