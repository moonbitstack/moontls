// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Client authentication (RFC 8446 §4.4.2, RFC 5246 §7.4.6): the server asks, the client answers
// with its chain and a CertificateVerify, and the server judges both. TLS 1.3 asks in the
// handshake or after it; TLS 1.2 asks before its ServerHelloDone and reads the answer between
// ClientKeyExchange and the change_cipher_spec.

///|
/// The signature schemes a CertificateVerify over this key may use, in the order this library
/// prefers them: TLS 1.3 ties an ECDSA scheme to the key's own curve, so a key has one.
fn proof_schemes(key : @x509.PrivateKey) -> Array[Int32] {
  schemes(key)
}

///|
/// The first scheme in `accepted` that `key` can prove itself under, or `None` when the peer
/// accepts none of them. The peer's order wins: it is the one that has to verify the signature.
fn pick_proof(key : @x509.PrivateKey, accepted : ArrayView[Int32]) -> Int32? {
  let mine = proof_schemes(key)
  accepted.iter().find_first(s => mine.contains(s))
}

///|
/// The client certificate type a key answers a TLS 1.2 CertificateRequest with (RFC 5246 §7.4.4,
/// RFC 8422 §5.8).
fn certificate_type(key : @x509.PrivateKey) -> Int32? {
  match key {
    Rsa(_) => Some(@msg.rsa_sign)
    Ec(_) | Ed25519(_) => Some(@msg.ecdsa_sign)
    // TLS 1.2 has no scheme for ML-DSA, so a request there cannot be answered with one.
    MlDsa(_) => None
  }
}

///|
/// Whether a TLS 1.2 request's `certificate_types` admits this key.
fn type_admits(types : ArrayView[Int32], key : @x509.PrivateKey) -> Bool {
  guard certificate_type(key) is Some(kind) else { return false }
  types.contains(kind)
}

///|
/// The scheme to answer a TLS 1.2 request with: the peer's first that this key has, and that this
/// client is willing to use. A request that names none — which only TLS 1.0 and 1.1 write — leaves
/// the scheme to the key, and SHA-1's pair is what those versions mean (RFC 5246 §7.4.1.4.1).
fn pick_proof12(
  key : @x509.PrivateKey,
  accepted : ArrayView[Int32],
  ours : ArrayView[Int32],
) -> Int32? {
  let mine = key_schemes12(key).filter(s => ours.contains(s))
  if accepted.length() == 0 {
    return mine
      .iter()
      .find_first(s => s == @ext.rsa_pkcs1_sha1 || s == @ext.ecdsa_sha1)
  }
  accepted.iter().find_first(s => mine.contains(s))
}

///|
/// Judge the chain a client showed, to the anchors the server named, with the client usage.
fn Conn::check_client_chain(
  self : Conn,
  config : ClientAuth,
  certs : Array[Bytes],
) -> Unit raise @alert.Alert {
  self.peer = certs
  guard config.roots is Some(roots) else { raise @alert.fatal(InternalError) }
  let _ = @x509.verify(certs[:], roots, now=self.now, policy=config.policy) catch {
    e => {
      self.refused = Some(e)
      raise @alert.fatal(alert_of(e))
    }
  }
}

///|
/// The CertificateRequest a TLS 1.3 server sends: a fresh context, the schemes it can verify, and
/// the anchors it takes (RFC 8446 §4.4.2.2). Post-handshake requests reuse it with a context of
/// their own, so an answer to an old request cannot be replayed as one to a new request.
fn Conn::ask_certificate(
  self : Conn,
  config : Server,
  required : Bool,
  post~ : Bool = false,
) -> Bytes {
  // §4.3.2: the context is empty in the handshake and non-empty after it, which is what stops an
  // answer to an old request being replayed as one to a new request. BoringSSL refuses a handshake
  // CertificateRequest that carries one; OpenSSL lets it through.
  let context = if post { (self.rand)(32) } else { b"" }
  let exts : Array[@ext.Ext] = [
    { kind: SignatureAlgorithms, data: @ext.schemes(verifiable[:]), },
  ]
  match config.client_auth.roots {
    Some(roots) => {
      let names : Array[Bytes] = []
      for cert in roots.iter() {
        names.push(cert.issuer.raw)
      }
      exts.push({
        kind: CertificateAuthorities,
        data: @ext.authorities(names[:]),
      })
    }
    None => ()
  }
  self.asked = Some({ context, schemes: verifiable, types: [], required, })
  @msg.frame(
    CertificateRequest,
    @msg.certificate_request(context[:], exts[:])[:],
  )
}

///|
/// The client's answer to a TLS 1.3 CertificateRequest: its chain, then the CertificateVerify that
/// shows it holds the key. A client with nothing to show, or with no scheme the server takes, sends
/// an empty Certificate — which is an answer, and is what a `Requested` server accepts.
fn Conn::send_proof13(self : Conn, config : Client) -> Unit raise @alert.Alert {
  guard self.asked is Some(asked) else { return }
  let scheme = if config.cert.length() > 0 {
    match config.cert_key {
      Some(key) => pick_proof(key, asked.schemes[:])
      None => None
    }
  } else {
    None
  }
  match scheme {
    None => {
      let empty = @msg.frame(
        Certificate,
        @msg.certificate([][:], context=asked.context[:])[:],
      )
      self.record(empty[:])
      self.send_handshake(empty)
      self.proved = false
    }
    Some(scheme) => {
      let key = config.cert_key.unwrap()
      let chain = @msg.frame(
        Certificate,
        @msg.certificate(config.cert[:], context=asked.context[:])[:],
      )
      self.record(chain[:])
      self.send_handshake(chain)
      let signature = sign(
        key,
        scheme,
        @msg.signed(@msg.client_context, self.th()[:]),
      )
      let proof = @msg.frame(
        CertificateVerify,
        @msg.certificate_verify(signature[:], scheme)[:],
      )
      self.record(proof[:])
      self.send_handshake(proof)
      self.proved = true
    }
  }
}

///|
/// The client's answer to a TLS 1.3 CertificateRequest that arrived once the connection was open
/// (RFC 8446 §4.6.2): the two messages above, then a Finished under the application traffic secret.
///
/// Answering is only allowed when the ClientHello offered post_handshake_auth (§4.2.6); a client
/// that did not must treat the request as an unexpected_message, which is what a server that
/// ignores this would see as a plain alert.
fn Conn::answer_post_auth(
  self : Conn,
  config : Client,
) -> Unit raise @alert.Alert {
  guard self.asked is Some(_) else { raise @alert.fatal(UnexpectedMessage) }
  self.send_proof13(config)
  let d = self.digest()
  let fin = @msg.frame(
    Finished,
    @keys.finished(
      self.client_app[:],
      self.th()[:],
      digest=d,
      prefix=self.prefix(),
    )[:],
  )
  self.record(fin[:])
  self.send_handshake(fin)
}

///|
/// Read a TLS 1.3 CertificateRequest and keep what answers it (RFC 8446 §4.4.2).
///
/// `signature_algorithms` is the one extension the message cannot do without. §4.3.2 has a client
/// ignore what it does not recognise, and a server may say more here: MySQL 8 on OpenSSL 3.5 sends
/// compress_certificate. §4.2 refuses only what is known to belong to another message.
fn Conn::note_request(self : Conn, body : Bytes) -> Unit raise @alert.Alert {
  guard @msg.read_certificate_request(body[:]) is Some((context, exts)) else {
    raise @alert.fatal(DecodeError)
  }
  for i, e in exts {
    if exts[:i].iter().any(x => x.kind == e.kind) {
      raise @alert.fatal(DecodeError)
    }
  }
  guard @ext.find(exts[:], SignatureAlgorithms) is Some(e) else {
    raise @alert.fatal(MissingExtension)
  }
  for e in exts {
    match e.kind {
      ServerName
      | SupportedGroups
      | Alpn
      | KeyShare
      | PreSharedKey
      | PskKeyExchangeModes
      | EarlyData
      | Cookie
      | SupportedVersions
      | PostHandshakeAuth
      | RecordSizeLimit
      | UseSrtp => raise @alert.fatal(IllegalParameter)
      _ => ()
    }
  }
  match @ext.find(exts[:], CertificateAuthorities) {
    Some(e) =>
      if @ext.read_authorities(e.data[:]) is None {
        raise @alert.fatal(DecodeError)
      }
    None => ()
  }
  self.asked = Some({
    context,
    schemes: @alert.decoded(@ext.read_schemes(e.data[:])),
    types: [],
    required: false,
  })
}

///|
/// A CertificateRequest that arrives on an open connection (RFC 8446 §4.6.2), answered at once: a
/// certificate, its proof, and a Finished under the application traffic secret.
fn Conn::on_post_auth(
  self : Conn,
  config : Client,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  // §4.2.6: a client that did not offer post_handshake_auth is not to be asked.
  if config.cert.length() == 0 || self.version != Some(Tls13) {
    raise @alert.fatal(UnexpectedMessage)
  }
  self.note_request(body)
  self.record(raw[:])
  self.answer_post_auth(config)
}

///|
/// Ask the client for its certificate after the handshake (RFC 8446 §4.6.2), so a server can admit
/// a request without holding up the connection it came in on — this is how HTTP/2 and HTTP/3 do
/// certificate-based client authentication.
///
/// The answer arrives as three messages, a Certificate, a CertificateVerify and a Finished, which
/// `receive` reads in that order, and `peer` then holds the chain that was verified.
pub fn Conn::request_certificate(self : Conn) -> Unit raise @alert.Alert {
  guard self.phase is Open && !(self.version is Some(Tls10 | Tls11 | Tls12)) else {
    raise @alert.fatal(InternalError)
  }
  guard self.side is Server(config) else { raise @alert.fatal(InternalError) }
  if config.client_auth.mode is Off {
    raise @alert.fatal(InternalError)
  }
  if self.now == 0L {
    raise @alert.fatal(InternalError)
  }
  self.aligned()
  let request = self.ask_certificate(
    config,
    config.client_auth.mode is Required,
    post=true,
  )
  self.record(request[:])
  self.send_handshake(request)
  self.phase = Renewing(Chain)
}

// ------------------------------------------------------------ the server side

///|
/// The client's Certificate, in answer to a request either in the handshake or after it. An empty
/// one is an answer: `Requested` takes it, `Required` gives certificate_required.
fn Conn::on_client_chain(
  self : Conn,
  config : Server,
  body : Bytes,
  raw : Bytes,
  renewed~ : Bool,
) -> Unit raise @alert.Alert {
  guard @msg.read_certificate(body[:]) is Some((context, certs)) else {
    raise @alert.fatal(DecodeError)
  }
  guard self.asked is Some(asked) else { raise @alert.fatal(UnexpectedMessage) }
  // §4.4.2: the context is what ties an answer to the request it answers.
  if context != asked.context {
    raise @alert.fatal(IllegalParameter)
  }
  if certs.length() == 0 {
    if asked.required {
      raise @alert.fatal(CertificateRequired)
    }
    self.record(raw[:])
    self.proved = false
    // A handshake-time request leaves only the client's Finished; a post-handshake one ends with
    // its own Finished, which carries no chain either.
    self.phase = if renewed { Renewing(Proof) } else { Finishing }
    return
  }
  self.check_client_chain(config.client_auth, certs)
  self.record(raw[:])
  self.phase = if renewed { Renewing(Proof) } else { Certifying(Proof) }
}

///|
/// The client's CertificateVerify: the signature that shows the key behind the chain it showed is
/// its own, over this handshake's transcript and the client's context string (RFC 8446 §4.4.3).
fn Conn::on_client_proof(
  self : Conn,
  body : Bytes,
  raw : Bytes,
  renewed~ : Bool,
) -> Unit raise @alert.Alert {
  guard @msg.read_certificate_verify(body[:]) is Some((scheme, signature)) else {
    raise @alert.fatal(DecodeError)
  }
  guard self.asked is Some(asked) else { raise @alert.fatal(UnexpectedMessage) }
  if !asked.schemes.contains(scheme) {
    raise @alert.fatal(IllegalParameter)
  }
  guard self.peer is [leaf, ..] else { raise @alert.fatal(UnexpectedMessage) }
  let cert = @x509.parse(leaf[:]) catch {
    _ => raise @alert.fatal(BadCertificate)
  }
  let content = @msg.signed(@msg.client_context, self.th()[:])
  if !verified(cert, scheme, content, signature) {
    raise @alert.fatal(DecryptError)
  }
  self.record(raw[:])
  self.proved = true
  self.phase = if renewed { Renewing(Proof) } else { Finishing }
}

///|
/// The Finished that closes a post-handshake authentication (RFC 8446 §4.6.2): the client proves
/// it has the application traffic secret as well, so an answer lifted from another connection
/// would not do.
fn Conn::on_renewed(
  self : Conn,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  if self.peer.length() > 0 && !self.proved {
    raise @alert.fatal(UnexpectedMessage)
  }
  self.check_finished(self.client_app, body)
  self.record(raw[:])
  self.phase = Open
}

// ------------------------------------------------------------------ TLS 1.2

///|
/// The client's Certificate in a TLS 1.2 handshake (RFC 5246 §7.4.6), and the scheme its
/// CertificateVerify will use, which is `None` when this client has nothing the request admits.
///
/// A request that names a certificate type this key is not, or schemes none of which it can sign
/// under, is answered with an empty Certificate: §7.4.6 makes that the way to say "nothing to
/// show", and a server that required one says certificate_required.
fn Conn::send_certificate12(
  self : Conn,
  config : Client,
) -> Unit raise @alert.Alert {
  guard self.asked is Some(asked) else { return }
  let chosen = match config.cert_key {
    Some(key) =>
      if !type_admits(asked.types[:], key) {
        None
      } else if self.version is Some(Tls10 | Tls11) {
        // RFC 2246 §7.4.8: with no signature_algorithms to name one, the pair follows from the
        // certificate type, and for both of them it is SHA-1's.
        Some(if key is Rsa(_) { @ext.rsa_pkcs1_sha1 } else { @ext.ecdsa_sha1 })
      } else {
        pick_proof12(key, asked.schemes[:], config.schemes12[:])
      }
    None => None
  }
  let certs = if chosen is Some(_) { config.cert } else { [] }
  let message = @msg.frame(Certificate, @msg.certificate12(certs[:])[:])
  self.record_sent(message[:])
  self.send_handshake(message)
  self.proof12 = chosen
}

///|
/// The client's CertificateVerify in a TLS 1.2 handshake (RFC 5246 §7.4.8): the signature covers
/// every handshake message so far, unhashed, from the ClientHello through the ClientKeyExchange.
fn Conn::send_proof12(self : Conn, config : Client) -> Unit raise @alert.Alert {
  guard self.proof12 is Some(scheme) else { return }
  guard config.cert_key is Some(key) else { raise @alert.fatal(InternalError) }
  guard self.transcript is Some(t) else { raise @alert.fatal(InternalError) }
  let signature = sign12(key, scheme, t.messages())
  // RFC 2246 §7.4.8: 1.0 and 1.1 name no scheme on the wire; the certificate type is the scheme.
  let body = if self.version is Some(Tls10 | Tls11) {
    @msg.certificate_verify_legacy(signature[:])
  } else {
    @msg.certificate_verify(signature[:], scheme)
  }
  let message = @msg.frame(CertificateVerify, body[:])
  self.record_sent(message[:])
  self.send_handshake(message)
}

///|
/// The client's Certificate in a TLS 1.2 handshake, judged by the server to the anchors it named
/// (RFC 5246 §7.4.6, RFC 5280 §4.2.1.12).
fn Conn::on_client_chain12(
  self : Conn,
  config : Server,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  guard @msg.read_certificate12(body[:]) is Some(certs) else {
    raise @alert.fatal(DecodeError)
  }
  guard self.asked is Some(asked) else { raise @alert.fatal(UnexpectedMessage) }
  if certs.length() == 0 {
    if asked.required {
      raise @alert.fatal(CertificateRequired)
    }
    self.record(raw[:])
    return
  }
  self.check_client_chain(config.client_auth, certs)
  self.record(raw[:])
}

///|
/// The client's CertificateVerify in a TLS 1.2 handshake: the signature over the handshake
/// messages, checked against the leaf it showed.
fn Conn::on_client_proof12(
  self : Conn,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  let legacy = self.version is Some(Tls10 | Tls11)
  let (scheme, signature) = if legacy {
    guard @msg.read_certificate_verify_legacy(body[:]) is Some(sig) else {
      raise @alert.fatal(DecodeError)
    }
    // RFC 2246 §7.4.8: with no scheme on the wire, the client's key type says which pair it is.
    let rsa = match self.peer {
      [leaf, ..] =>
        try (@x509.parse(leaf[:]).spki.key() is Rsa(_)) catch {
          _ => false
        }
      _ => false
    }
    (if rsa { @ext.rsa_pkcs1_sha1 } else { @ext.ecdsa_sha1 }, sig)
  } else {
    guard @msg.read_certificate_verify(body[:]) is Some(parsed) else {
      raise @alert.fatal(DecodeError)
    }
    parsed
  }
  guard self.asked is Some(asked) else { raise @alert.fatal(UnexpectedMessage) }
  if !legacy && !asked.schemes.contains(scheme) {
    raise @alert.fatal(IllegalParameter)
  }
  guard self.peer is [leaf, ..] else { raise @alert.fatal(UnexpectedMessage) }
  let cert = @x509.parse(leaf[:]) catch {
    _ => raise @alert.fatal(BadCertificate)
  }
  guard self.transcript is Some(t) else { raise @alert.fatal(InternalError) }
  if !verified12(cert, scheme, t.messages(), signature) {
    raise @alert.fatal(DecryptError)
  }
  self.record(raw[:])
  self.proved = true
}

///|
/// Read the TLS 1.2 CertificateRequest and keep what answers it (RFC 5246 §7.4.4). The context
/// field is TLS 1.3's; a 1.2 request has none, and an empty one is what the answer echoes.
fn Conn::note_request12(self : Conn, body : Bytes) -> Unit raise @alert.Alert {
  guard @msg.read_certificate_request12(body[:]) is Some((types, schemes, _)) else {
    raise @alert.fatal(DecodeError)
  }
  if types.length() == 0 {
    raise @alert.fatal(DecodeError)
  }
  self.asked = Some({ context: b"", schemes, types, required: false, })
}

///|
/// The CertificateRequest a TLS 1.2 server sends before its ServerHelloDone (RFC 5246 §7.4.4):
/// both certificate types this library can verify, the schemes it accepts, and the anchors.
fn Conn::ask_certificate12(
  self : Conn,
  config : Server,
  required : Bool,
) -> Bytes {
  let types : Array[Int32] = [@msg.rsa_sign, @msg.ecdsa_sign]
  let names : Array[Bytes] = []
  match config.client_auth.roots {
    Some(roots) =>
      for cert in roots.iter() {
        names.push(cert.issuer.raw)
      }
    None => ()
  }
  self.asked = Some({
    context: b"",
    schemes: config.schemes12,
    types,
    required,
  })
  @msg.frame(
    CertificateRequest,
    @msg.certificate_request12(
      types[:],
      names=names[:],
      schemes=config.schemes12[:],
    )[:],
  )
}
