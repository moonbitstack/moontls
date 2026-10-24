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
  exts.push({
    kind: SupportedVersions,
    data: @ext.versions([@ext.version_13][:]),
  })
  exts.push({ kind: SupportedGroups, data: @ext.groups(config.groups[:]), })
  exts.push({ kind: SignatureAlgorithms, data: @ext.schemes(offered[:]), })
  exts.push({ kind: KeyShare, data: @ext.shares(shares[:]), })
  if config.alpn.length() > 0 {
    exts.push({ kind: Alpn, data: @ext.protocols(config.alpn[:]), })
  }
  if cookie is Some(c) {
    exts.push({ kind: Cookie, data: @ext.cookie(c[:]), })
  }
  let raw = @msg.hello({
    random: (self.rand)(32),
    session_id: self.session,
    suites: config.suites.map(s => s.code()),
    extensions: exts,
  })
  if self.first_hello.length() == 0 {
    self.first_hello = raw
  } else {
    self.record(raw[:])
  }
  self.send_handshake(raw)
}

///|
/// Whether `host` is an IP literal, which RFC 6066 §3 keeps out of server_name.
fn is_address(host : String) -> Bool {
  host.contains(":") || host.iter().all(c => c == '.' || (c >= '0' && c <= '9'))
}

///|
fn Conn::on_client(
  self : Conn,
  config : Client,
  host : String,
  kind : @msg.Kind,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  match (self.phase, kind) {
    (Hello, ServerHello) => self.on_server_hello(config, body, raw)
    (Flight, EncryptedExtensions) => {
      guard @msg.read_encrypted_extensions(body[:]) is Some(exts) else {
        raise @alert.fatal(DecodeError)
      }
      if @ext.find(exts[:], Alpn) is Some(e) {
        match @ext.read_protocols(e.data[:]) {
          [p] if config.alpn.contains(p) => self.alpn = Some(p)
          _ => raise @alert.fatal(IllegalParameter)
        }
      }
      self.record(raw[:])
    }
    (Flight, CertificateRequest) => {
      self.requested = true
      self.record(raw[:])
    }
    (Flight, Certificate) => {
      guard @msg.read_certificate(body[:]) is Some((_, certs)) &&
        certs.length() > 0 else {
        raise @alert.fatal(DecodeError)
      }
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
      self.record(raw[:])
    }
    (Flight, CertificateVerify) => {
      guard self.peer.get(0) is Some(der) else {
        raise @alert.fatal(UnexpectedMessage)
      }
      guard @msg.read_certificate_verify(body[:]) is Some((scheme, sig)) else {
        raise @alert.fatal(DecodeError)
      }
      let leaf = @x509.parse(der[:]) catch {
        _ => raise @alert.fatal(BadCertificate)
      }
      let content = @msg.signed(@msg.server_context, self.th()[:])
      if !offered.contains(scheme) || !verified(leaf, scheme, content, sig) {
        raise @alert.fatal(DecryptError)
      }
      self.record(raw[:])
    }
    (Flight, Finished) => {
      if self.peer.length() == 0 {
        raise @alert.fatal(UnexpectedMessage)
      }
      let d = self.digest()
      if !@keys.finished_ok(
          self.server_secret[:],
          self.th()[:],
          body[:],
          digest=d,
        ) {
        raise @alert.fatal(DecryptError)
      }
      self.record(raw[:])
      self.open_application()
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
      self.phase = Open
    }
    (Open, NewSessionTicket) => ()
    (Open, KeyUpdate) => self.on_update(body)
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}

///|
fn Conn::on_server_hello(
  self : Conn,
  config : Client,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  guard @msg.read_server_hello(body[:]) is Some(sh) else {
    raise @alert.fatal(DecodeError)
  }
  guard @ext.find(sh.extensions[:], SupportedVersions) is Some(v) &&
    @ext.read_selected_version(v.data[:]) == Some(@ext.version_13) else {
    raise @alert.fatal(ProtocolVersion)
  }
  guard @record.Suite::of(sh.suite) is Some(suite) &&
    config.suites.contains(suite) else {
    raise @alert.fatal(IllegalParameter)
  }
  if sh.session_id != self.session ||
    (self.retried && self.suite != Some(suite)) {
    raise @alert.fatal(IllegalParameter)
  }
  self.suite = Some(suite)
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
  self.record(raw[:])
  self.open_handshake(agree(group, secret, public))
  self.writer = Some(@record.Cipher::new(self.client_secret[:], suite~))
  self.reader = Some(@record.Cipher::new(self.server_secret[:], suite~))
  self.phase = Flight
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
