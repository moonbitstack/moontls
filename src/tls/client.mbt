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
  // A TLS 1.2 session this client still has: its id goes in the session_id field, a ticket in an
  // extension, and either way the master secret is what the handshake would start from.
  if versions.contains(Tls12) {
    self.offer_session12(config, host)
  }
  exts.push({
    kind: SupportedVersions,
    data: @ext.versions(versions.map(v => v.code())[:]),
  })
  exts.push({ kind: SupportedGroups, data: @ext.groups(config.groups[:]), })
  let legacy = versions.iter().any(v => v.is_legacy())
  let schemes = if legacy {
    [..offered, ..config.schemes12.filter(s => !offered.contains(s))]
  } else {
    offered
  }
  exts.push({ kind: SignatureAlgorithms, data: @ext.schemes(schemes[:]), })
  if versions.contains(Tls13) {
    exts.push({ kind: KeyShare, data: @ext.shares(shares[:]), })
  }
  if legacy {
    exts.push({ kind: EcPointFormats, data: @ext.point_formats(), })
    exts.push({ kind: ExtendedMasterSecret, data: b"", })
    exts.push({ kind: RenegotiationInfo, data: self.renegotiation_info(), })
    if config.suites12.iter().any(s => s.is_cbc()) {
      exts.push({ kind: EncryptThenMac, data: b"", })
    }
    if self.ticket12.length() > 0 {
      exts.push({
        kind: SessionTicket,
        data: @ext.session_ticket(self.ticket12[:]),
      })
    }
  }
  if config.alpn.length() > 0 {
    exts.push({ kind: Alpn, data: @ext.protocols(config.alpn[:]), })
  }
  if config.srtp.length() > 0 {
    exts.push({
      kind: UseSrtp,
      data: @ext.use_srtp(config.srtp.map(p => p.code())[:], b""),
    })
  }
  if config.ocsp {
    exts.push({ kind: StatusRequest, data: @ext.status_request(), })
  }
  if config.compress && versions.contains(Tls13) {
    exts.push({
      kind: CompressCertificate,
      data: @ext.compression_algorithms([@ext.zlib_compression][:]),
    })
  }
  if config.record_limit > 0 {
    exts.push({
      kind: RecordSizeLimit,
      data: @ext.record_size_limit(config.record_limit),
    })
    self.our_limit = config.record_limit
  }
  if config.cert.length() > 0 && versions.contains(Tls13) {
    // RFC 8446 §4.2.6: a request that arrives after the handshake is only allowed when the
    // ClientHello said the client would answer one.
    exts.push({ kind: PostHandshakeAuth, data: b"", })
  }
  if cookie is Some(c) {
    exts.push({ kind: Cookie, data: @ext.cookie(c[:]), })
  }
  if self.quic is Some(q) {
    exts.push({ kind: QuicTransportParameters, data: q.params, })
  }
  // RFC 8446 §4.2.9: a resumption states that the PSK comes with a key exchange, which is the
  // only mode this library offers — see `@ext.psk_ke`.
  let session = if versions.contains(Tls13) {
    self.pick_session(config, host, Tls13)
  } else {
    None
  }
  let mut early = false
  match session {
    Some(s) => {
      exts.push({
        kind: PskKeyExchangeModes,
        data: @ext.psk_modes([@ext.psk_dhe_ke][:]),
      })
      // Not `> 0`: a QUIC ticket says 0xffffffff, which reads as -1 here.
      if s.early != 0 && config.early && self.hrr.length() == 0 {
        exts.push({ kind: EarlyData, data: @ext.early_data(), })
        early = true
      }
    }
    None => ()
  }
  let base : @msg.Hello = {
    version: if self.datagram {
      datagram_version
    } else {
      client_version(versions)
    },
    random: self.client_random,
    session_id: self.session,
    suites: suite_codes(config, versions),
    compression: b"\x00",
    extensions: exts,
  }
  let raw = match session {
    Some(s) => self.hello_with_psk(base, s)
    None => @msg.hello(base)
  }
  if early {
    match @record.Suite::of(self.psk_suite) {
      Some(suite) => {
        let d = suite.digest()
        self.early_secret = @keys.early(psk=self.psk[:], digest=d)
        // §7.1: the early traffic secret's context is the ClientHello itself, which is why this can
        // only be computed once the message with its binder exists.
        if self.first_hello.length() == 0 {
          let secret = @keys.client_early(
            self.early_secret[:],
            d.hash(raw),
            digest=d,
            prefix=self.prefix(),
          )
          self.early_writer = Some(@record.Cipher::new(secret[:], suite~))
          if self.quic is Some(q) {
            q.steps.push(Early(secret~, suite~))
          }
        }
      }
      None => ()
    }
  }
  if self.first_hello.length() == 0 {
    self.first_hello = raw
  } else {
    self.record(raw[:])
    self.send_change_cipher_spec()
  }
  self.send_handshake(raw)
}

///|
/// The `legacy_version` a ClientHello carries: the highest version offered, except that 1.2 and 1.3
/// both write 0x0303 there (RFC 8446 §4.1.2 freezes it, and 1.2's own number is the same).
fn client_version(versions : Array[Version]) -> Int32 {
  if versions.contains(Tls12) || versions.contains(Tls13) {
    @wire.legacy_version
  } else if versions.contains(Tls11) {
    Tls11.code()
  } else if versions.contains(Tls10) {
    Tls10.code()
  } else {
    @wire.legacy_version
  }
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
/// A ClientHello's cipher_suites: TLS 1.3's, then TLS 1.2's.
fn suite_codes(config : Client, versions : Array[Version]) -> Array[Int32] {
  let out : Array[Int32] = []
  if versions.contains(Tls13) {
    out.push_iter(config.suites.iter().map(s => s.code()))
  }
  if versions.iter().any(v => v.is_legacy()) {
    out.push_iter(config.suites12.iter().map(s => s.code))
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
      (Open, Other(0)) if self.version is Some(Tls10 | Tls11 | Tls12) =>
        return if config.renegotiation {
          self.start_renegotiation(config)
        } else {
          self.decline_renegotiation()
        }
      (Open, NewSessionTicket) =>
        return if self.version is Some(Tls10 | Tls11 | Tls12) {
          self.on_ticket12(config, host, body)
        } else {
          self.on_ticket(config, host, body)
        }
      (Open, KeyUpdate) => return self.on_update(body)
      // RFC 8446 §4.6.2: a server asking for a certificate once the connection is open.
      (Open, CertificateRequest) => return self.on_post_auth(config, body, raw)
      _ => raise @alert.fatal(UnexpectedMessage)
    }
  }
  self.phase = Expect(state.recv(kind, resumed=self.resumed))
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
      self.note_request(body)
      self.record(raw[:])
    }
    Certificate => self.on_certificate(config, host, body, raw)
    CompressedCertificate => {
      // RFC 8879 §4: the promise of the uncompressed length is what a decompression bomb has to
      // keep to, so it is checked rather than trusted.
      guard @msg.read_compressed_certificate(body[:])
        is Some((algorithm, uncompressed, compressed)) else {
        raise @alert.fatal(DecodeError)
      }
      if algorithm != @ext.zlib_compression || !config.compress {
        raise @alert.fatal(IllegalParameter)
      }
      let cert = @zlib.unzlib(compressed[:], limit=uncompressed) catch {
        _ => raise @alert.fatal(DecodeError)
      }
      if cert.length() != uncompressed {
        raise @alert.fatal(DecodeError)
      }
      self.on_certificate(config, host, cert, raw)
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
      // §4.5: the client's flight starts with EndOfEarlyData when its 0-RTT data was taken, and
      // only then — otherwise what follows would look like it came under the early key.
      // RFC 9001 §8.3: over QUIC the transport ends 0-RTT, and this message is never sent.
      if self.early_ok && self.quic is None {
        let end = @msg.frame(EndOfEarlyData, @msg.end_of_early_data())
        self.record(end[:])
        self.send_handshake(end)
      }
      if self.asked is Some(_) {
        self.send_proof13(config)
      }
      let fin = @msg.frame(
        Finished,
        @keys.finished(
          self.client_secret[:],
          self.th()[:],
          digest=d,
          prefix=self.prefix(),
        )[:],
      )
      self.record(fin[:])
      self.send_handshake(fin)
      self.writer = Some(
        @record.Cipher::new(self.client_app[:], suite=self.suite.unwrap()),
      )
      self.keyed(Application)
      self.phase = Open
      self.close_transcript()
      self.early_writer = None
      // §4.2.10: data the server declined goes out again as ordinary data, so a caller that wrote
      // it early sees it arrive once either way.
      if !self.early_ok && self.early_sent.length() > 0 {
        let w = self.writer.unwrap()
        let mut at = 0
        while at < self.early_sent.length() {
          let end = @cmp.minimum(
            at + @record.max_fragment,
            self.early_sent.length(),
          )
          self.outbox.write_bytes(
            w.seal(ApplicationData, self.early_sent[at:end]),
          )
          at = end
        }
      }
    }
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}

///|
/// The server's Certificate, compressed or not: its chain judged, and any status stapled to the
/// leaf kept. `raw` is the message as it arrived, which for a compressed one is the
/// CompressedCertificate — the transcript covers what was sent, not what it decompressed to.
fn Conn::on_certificate(
  self : Conn,
  config : Client,
  host : String,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  guard @msg.read_certificate_entries(body[:])
    is Some((context, certs, entries)) else {
    raise @alert.fatal(DecodeError)
  }
  if context.length() > 0 {
    raise @alert.fatal(IllegalParameter)
  }
  if certs.length() == 0 {
    raise @alert.fatal(DecodeError)
  }
  // RFC 8446 §4.4.2.1: the leaf's entry is where a stapled status lives.
  match entries.get(0) {
    Some(exts) =>
      match @ext.find(exts[:], StatusRequest) {
        Some(e) => {
          guard @ext.read_certificate_status(e.data[:]) is Some(response) else {
            raise @alert.fatal(DecodeError)
          }
          self.ocsp = Some(response)
        }
        None => ()
      }
    None => ()
  }
  self.check_chain(config, host, certs)
  self.record(raw[:])
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
/// The SRTP profile a server answered `use_srtp` with, which must be one this
/// client offered (RFC 5764 §4.1.1).
fn Conn::on_srtp_answer(
  self : Conn,
  config : Client,
  data : Bytes,
) -> Unit raise @alert.Alert {
  guard @ext.read_use_srtp(data[:]) is Some((profiles, _)) else {
    raise @alert.fatal(DecodeError)
  }
  guard profiles.length() == 1 else { raise @alert.fatal(DecodeError) }
  guard @srtp.Profile::of(profiles[0]) is Some(profile) &&
    config.srtp.contains(profile) else {
    raise @alert.fatal(IllegalParameter)
  }
  self.srtp_profile = Some(profile)
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
      // RFC 8449 §4: how much this server will read, which is what caps what is written to it.
      RecordSizeLimit => {
        guard @ext.read_record_size_limit(e.data[:]) is Some(limit) else {
          raise @alert.fatal(DecodeError)
        }
        if limit < 64 || limit > @record.max_fragment + 1 {
          raise @alert.fatal(IllegalParameter)
        }
        self.peer_limit = limit
      }
      // §4.2.10: the server says here whether it took the 0-RTT data it was offered.
      EarlyData => {
        if !self.offered_early || e.data.length() > 0 {
          raise @alert.fatal(UnsupportedExtension)
        }
        self.early_ok = true
      }
      UseSrtp if config.srtp.length() > 0 => self.on_srtp_answer(config, e.data)
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
    self.spoken(config.versions).iter().any(v => v.is_legacy()) &&
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
  self.accept_resumption(sh)
  // §4.2.11: a PSK is tied to one hash, so a suite with another one cannot be the resumption this
  // client offered.
  if self.resumed && suite.code() != self.psk_suite {
    raise @alert.fatal(IllegalParameter)
  }
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
    self.hrr = raw
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
  self.group = Some(group)
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
      // §4.2.11: the answer to a PSK offer, checked where the offer's outcome is decided.
      PreSharedKey => ()
      Cookie if retry => ()
      ServerName
      | SupportedGroups
      | SignatureAlgorithms
      | Alpn
      | Cookie
      | PskKeyExchangeModes
      | EarlyData
      | PostHandshakeAuth => raise @alert.fatal(IllegalParameter)
      _ => raise @alert.fatal(UnsupportedExtension)
    }
  }
}

///|
/// The handshake secrets from the shared secret, over the transcript through ServerHello.
fn Conn::open_handshake(self : Conn, shared : Bytes) -> Unit {
  let d = self.digest()
  let early = if self.resumed {
    @keys.early(psk=self.psk[:], digest=d)
  } else {
    @keys.early(digest=d)
  }
  self.handshake_secret = @keys.handshake(
    early[:],
    shared[:],
    digest=d,
    prefix=self.prefix(),
  )
  let th = self.th()
  self.client_secret = @keys.client_handshake(
    self.handshake_secret[:],
    th[:],
    digest=d,
    prefix=self.prefix(),
  )
  self.server_secret = @keys.server_handshake(
    self.handshake_secret[:],
    th[:],
    digest=d,
    prefix=self.prefix(),
  )
}

///|
/// The application secrets, over the transcript through the server Finished; the side that reads
/// the server's traffic switches its reader here.
fn Conn::open_application(self : Conn) -> Unit {
  let d = self.digest()
  let master = @keys.master(
    self.handshake_secret[:],
    digest=d,
    prefix=self.prefix(),
  )
  self.master13 = master
  let th = self.th()
  self.client_app = @keys.client_application(
    master[:],
    th[:],
    digest=d,
    prefix=self.prefix(),
  )
  self.server_app = @keys.server_application(
    master[:],
    th[:],
    digest=d,
    prefix=self.prefix(),
  )
  self.exporter = @keys.exporter_master(
    master[:],
    th[:],
    digest=d,
    prefix=self.prefix(),
  )
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
