// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Queue a ClientHello carrying `shares`, and the server's cookie when it sent one.
fn Conn::send_hello(
  self : Conn,
  shares : Array[(Int32, Bytes)],
  cookie : Bytes?,
) -> Unit raise @alert.Alert {
  guard self.side is Client(config, host) else { return }
  let exts : Array[@ext.Ext] = []
  if !is_address(host) {
    exts.push({ kind: ServerName, data: @ext.server_name(host), })
  }
  let versions = self.spoken(config.versions)
  exts.push({
    kind: SupportedVersions,
    data: @ext.versions(versions.map(v => v.code())[:]),
  })
  exts.push({ kind: SupportedGroups, data: @ext.groups(config.groups[:]), })
  exts.push({ kind: SignatureAlgorithms, data: @ext.schemes(offered[:]), })
  if versions.contains(Tls13) {
    exts.push({ kind: KeyShare, data: @ext.shares(shares[:]), })
  }
  if versions.contains(Tls12) {
    exts.push({ kind: EcPointFormats, data: @ext.point_formats(), })
    exts.push({ kind: ExtendedMasterSecret, data: b"", })
    exts.push({ kind: RenegotiationInfo, data: @ext.no_renegotiation(), })
  }
  if config.alpn.length() > 0 {
    exts.push({ kind: Alpn, data: @ext.protocols(config.alpn[:]), })
  }
  if cookie is Some(c) {
    exts.push({ kind: Cookie, data: @ext.cookie(c[:]), })
  }
  if self.quic is Some(q) {
    exts.push({ kind: QuicTransportParameters, data: q.params, })
  }
  let raw = @msg.hello({
    version: @wire.legacy_version,
    random: self.client_random,
    session_id: self.session,
    suites: suite_codes(config.suites, versions),
    compression: b"\x00",
    extensions: exts,
  })
  if self.first_hello.length() == 0 {
    self.first_hello = raw
  } else {
    self.record(raw[:])
    self.send_change_cipher_spec()
  }
  self.send_handshake(raw)
}

///|
/// The versions this connection may use: QUIC is TLS 1.3 alone (RFC 9001 §4.2).
fn Conn::spoken(self : Conn, versions : Array[Version]) -> Array[Version] {
  if self.quic is Some(_) {
    versions.filter(v => v == Tls13)
  } else {
    versions
  }
}

///|
/// A ClientHello's cipher_suites: TLS 1.3's, then TLS 1.2's, each suite twice for the two kinds of
/// certificate.
fn suite_codes(
  suites : Array[@record.Suite],
  versions : Array[Version],
) -> Array[Int32] {
  let out : Array[Int32] = []
  if versions.contains(Tls13) {
    out.push_iter(suites.iter().map(s => s.code()))
  }
  if versions.contains(Tls12) {
    out.push_iter(suites.iter().map(s => s.tls12(rsa=false)))
    out.push_iter(suites.iter().map(s => s.tls12(rsa=true)))
  }
  out
}

///|
/// Whether `host` is an IP literal, which RFC 6066 §3 keeps out of server_name.
fn is_address(host : String) -> Bool {
  host.contains(":") || host.iter().all(c => c == '.' || (c >= '0' && c <= '9'))
}

///|
/// A handshake message on a client. `@hs.Client::recv` holds the order (RFC 8446 A.1): the
/// server's Certificate cannot be skipped, nor its CertificateVerify, and none comes twice.
fn Conn::on_client(
  self : Conn,
  config : Client,
  host : String,
  kind : @msg.Kind,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  if self.phase is Legacy(step) {
    return self.on_client12(config, host, step, kind, body, raw)
  }
  guard self.phase is Expect(state) else {
    match (self.phase, kind) {
      // A HelloRequest (RFC 5246 §7.4.1.1).
      (Open, Other(0)) if self.version == Some(Tls12) =>
        return self.decline_renegotiation()
      (Open, NewSessionTicket) => return
      (Open, KeyUpdate) => return self.on_update(body)
      _ => raise @alert.fatal(UnexpectedMessage)
    }
  }
  self.phase = Expect(state.recv(kind))
  match kind {
    ServerHello => self.on_server_hello(config, body, raw)
    EncryptedExtensions => {
      guard @msg.read_encrypted_extensions(body[:]) is Some(exts) else {
        raise @alert.fatal(DecodeError)
      }
      self.on_encrypted_extensions(config, host, exts)
      self.record(raw[:])
    }
    CertificateRequest => {
      self.requested = true
      self.record(raw[:])
    }
    Certificate => {
      guard @msg.read_certificate(body[:]) is Some((context, certs)) else {
        raise @alert.fatal(DecodeError)
      }
      if context.length() > 0 {
        raise @alert.fatal(IllegalParameter)
      }
      if certs.length() == 0 {
        raise @alert.fatal(DecodeError)
      }
      self.check_chain(config, host, certs)
      self.record(raw[:])
    }
    CertificateVerify => {
      guard @msg.read_certificate_verify(body[:]) is Some((scheme, sig)) else {
        raise @alert.fatal(DecodeError)
      }
      if !offered.contains(scheme) {
        raise @alert.fatal(IllegalParameter)
      }
      let leaf = @x509.parse(self.peer[0][:]) catch {
        _ => raise @alert.fatal(BadCertificate)
      }
      let content = @msg.signed(@msg.server_context, self.th()[:])
      if !verified(leaf, scheme, content, sig) {
        raise @alert.fatal(DecryptError)
      }
      self.record(raw[:])
    }
    Finished => {
      if self.quic is Some({ peer_params: None, .. }) {
        raise @alert.fatal(MissingExtension)
      }
      self.check_finished(self.server_secret, body)
      self.aligned()
      let d = self.digest()
      self.record(raw[:])
      self.open_application()
      self.send_change_cipher_spec()
      if self.requested {
        let empty = @msg.frame(Certificate, @msg.certificate([][:])[:])
        self.record(empty[:])
        self.send_handshake(empty)
      }
      let fin = @msg.frame(
        Finished,
        @keys.finished(self.client_secret[:], self.th()[:], digest=d)[:],
      )
      self.record(fin[:])
      self.send_handshake(fin)
      self.writer = Some(
        @record.Cipher::new(self.client_app[:], suite=self.suite.unwrap()),
      )
      self.keyed(Application)
      self.phase = Open
    }
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}

///|
/// Judge the server's chain, by whichever way the configuration says, and keep it.
fn Conn::check_chain(
  self : Conn,
  config : Client,
  host : String,
  certs : Array[Bytes],
) -> Unit raise @alert.Alert {
  self.peer = certs
  match config.verify {
    Chain => {
      let _ = @x509.verify(
        certs[:],
        config.roots,
        now=self.now,
        host~,
        policy=config.policy,
      ) catch {
        e => {
          self.refused = Some(e)
          raise @alert.fatal(alert_of(e))
        }
      }
    }
    Custom(judge) =>
      judge(certs, host) catch {
        _ => raise @alert.fatal(BadCertificate)
      }
  }
}

///|
/// What a server may put in EncryptedExtensions in answer to this client's ClientHello
/// (RFC 8446 §4.2): ALPN when it was offered, an empty server_name when SNI was sent, and
/// supported_groups as a hint. An extension the client offered that belongs in another message is
/// an illegal_parameter; one it never offered is an unsupported_extension; any twice is a
/// decode_error, since nothing says which to believe.
fn Conn::on_encrypted_extensions(
  self : Conn,
  config : Client,
  host : String,
  exts : Array[@ext.Ext],
) -> Unit raise @alert.Alert {
  for i, e in exts {
    if exts[:i].iter().any(x => x.kind == e.kind) {
      raise @alert.fatal(DecodeError)
    }
    match e.kind {
      Alpn if config.alpn.length() > 0 =>
        match @alert.decoded(@ext.read_protocols(e.data[:])) {
          [p] if config.alpn.contains(p) => self.alpn = Some(p)
          _ => raise @alert.fatal(IllegalParameter)
        }
      ServerName if !is_address(host) =>
        if e.data.length() > 0 {
          raise @alert.fatal(DecodeError)
        }
      SupportedGroups => ()
      QuicTransportParameters if self.quic is Some(q) =>
        q.peer_params = Some(e.data)
      SupportedVersions | KeyShare | SignatureAlgorithms | Cookie =>
        raise @alert.fatal(IllegalParameter)
      _ => raise @alert.fatal(UnsupportedExtension)
    }
  }
}

///|
fn Conn::on_server_hello(
  self : Conn,
  config : Client,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  let sh = @alert.decoded(@msg.read_server_hello(body[:]))
  if !@hs.is_retry(sh) &&
    self.spoken(config.versions).contains(Tls12) &&
    !selects13(sh) {
    return self.hello12(config, sh, raw)
  }
  server_hello_extensions(sh)
  guard @ext.find(sh.extensions[:], SupportedVersions) is Some(v) &&
    @ext.read_selected_version(v.data[:]) == Some(@ext.version_13) else {
    raise @alert.fatal(ProtocolVersion)
  }
  guard @record.Suite::of(sh.suite) is Some(suite) &&
    config.suites.contains(suite) else {
    raise @alert.fatal(IllegalParameter)
  }
  if sh.version != @wire.legacy_version ||
    sh.compression != 0 ||
    sh.session_id != self.session ||
    (self.retried && self.suite != Some(suite)) {
    raise @alert.fatal(IllegalParameter)
  }
  self.suite = Some(suite)
  self.version = Some(Tls13)
  if @hs.is_retry(sh) {
    if self.retried {
      raise @alert.fatal(UnexpectedMessage)
    }
    guard @hs.retry_group(sh) is Some(group) &&
      config.groups.contains(group) &&
      !self.shares.iter().any(s => s.0 == group) else {
      raise @alert.fatal(IllegalParameter)
    }
    self.retried = true
    self.phase = Expect(@hs.Client::new())
    self.begin_transcript(Some(raw))
    let (secret, public) = share(group, self.rand)
    self.shares = [(group, secret)]
    let cookie = match @ext.find(sh.extensions[:], Cookie) {
      Some(e) => @ext.read_cookie(e.data[:])
      None => None
    }
    self.send_hello([(group, public)], cookie)
    return
  }
  guard @ext.find(sh.extensions[:], KeyShare) is Some(ks) &&
    @ext.read_selected_share(ks.data[:]) is Some((group, public)) else {
    raise @alert.fatal(MissingExtension)
  }
  guard self.shares.iter().find_first(s => s.0 == group) is Some((_, secret)) else {
    raise @alert.fatal(IllegalParameter)
  }
  if self.transcript is None {
    self.begin_transcript(None)
    self.record(self.first_hello[:])
  }
  self.aligned()
  self.record(raw[:])
  self.open_handshake(agree(group, secret, public))
  self.writer = Some(@record.Cipher::new(self.client_secret[:], suite~))
  self.reader = Some(@record.Cipher::new(self.server_secret[:], suite~))
  self.keyed(Handshake)
}

///|
/// Whether a ServerHello picked TLS 1.3, which is only ever said in supported_versions.
fn selects13(sh : @msg.Server) -> Bool {
  match @ext.find(sh.extensions[:], SupportedVersions) {
    Some(v) => @ext.read_selected_version(v.data[:]) == Some(@ext.version_13)
    None => false
  }
}

///|
/// A ServerHello carries supported_versions and key_share, and a HelloRetryRequest a cookie as
/// well (RFC 8446 §4.2). One this client offered for another message is an illegal_parameter,
/// one it never offered an unsupported_extension, and any twice a decode_error.
fn server_hello_extensions(sh : @msg.Server) -> Unit raise @alert.Alert {
  let retry = @hs.is_retry(sh)
  for i, e in sh.extensions {
    if sh.extensions[:i].iter().any(x => x.kind == e.kind) {
      raise @alert.fatal(DecodeError)
    }
    match e.kind {
      SupportedVersions | KeyShare => ()
      Cookie if retry => ()
      ServerName | SupportedGroups | SignatureAlgorithms | Alpn | Cookie =>
        raise @alert.fatal(IllegalParameter)
      _ => raise @alert.fatal(UnsupportedExtension)
    }
  }
}

///|
/// The handshake secrets from the shared secret, over the transcript through ServerHello.
fn Conn::open_handshake(self : Conn, shared : Bytes) -> Unit {
  let d = self.digest()
  let early = @keys.early(digest=d)
  self.handshake_secret = @keys.handshake(early[:], shared[:], digest=d)
  let th = self.th()
  self.client_secret = @keys.client_handshake(
    self.handshake_secret[:],
    th[:],
    digest=d,
  )
  self.server_secret = @keys.server_handshake(
    self.handshake_secret[:],
    th[:],
    digest=d,
  )
}

///|
/// The application secrets, over the transcript through the server Finished; the side that reads
/// the server's traffic switches its reader here.
fn Conn::open_application(self : Conn) -> Unit {
  let d = self.digest()
  let master = @keys.master(self.handshake_secret[:], digest=d)
  let th = self.th()
  self.client_app = @keys.client_application(master[:], th[:], digest=d)
  self.server_app = @keys.server_application(master[:], th[:], digest=d)
  if self.side is Client(_, _) {
    self.reader = Some(
      @record.Cipher::new(self.server_app[:], suite=self.suite.unwrap()),
    )
  }
}

///|
fn alert_of(e : @x509.Refused) -> @alert.Kind {
  match e {
    Expired(..) | Premature(..) => CertificateExpired
    Issuer => UnknownCa
    Algorithm(..) | Weak(..) => UnsupportedCertificate
    _ => BadCertificate
  }
}
