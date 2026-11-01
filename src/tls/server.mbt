// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn Conn::on_server(
  self : Conn,
  config : Server,
  kind : @msg.Kind,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  match (self.phase, kind) {
    (Legacy(step), _) => self.on_server12(config, step, kind, body, raw)
    (Open, ClientHello) if self.version == Some(Tls12) =>
      self.decline_renegotiation()
    (Waiting, ClientHello) => self.on_client_hello(config, body, raw)
    (Finishing, Finished) => {
      self.check_finished(self.client_secret, body)
      self.aligned()
      self.record(raw[:])
      self.reader = Some(
        @record.Cipher::new(self.client_app[:], suite=self.suite.unwrap()),
      )
      self.phase = Open
      if self.quic is Some(q) {
        q.reading = Application
      }
    }
    (Open, KeyUpdate) => self.on_update(body)
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}

///|
fn Conn::on_client_hello(
  self : Conn,
  config : Server,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  let hello = @alert.decoded(@msg.read_hello(body[:]))
  self.aligned()
  if self.quic is Some(q) {
    q.on_hello(hello)
  } else if !self.retried &&
    config.versions.contains(Tls12) &&
    !offers13(config, hello) {
    return self.client_hello12(config, hello, raw)
  }
  if self.retried && !same_hello(self.first_hello, hello) {
    raise @alert.fatal(IllegalParameter)
  }
  let schemes = schemes(config.key)
  let choice = @hs.negotiate(hello, groups=config.groups[:], schemes=schemes[:])
  guard config.suites.iter().find_first(s => hello.suites.contains(s.code()))
    is Some(suite) else {
    raise @alert.fatal(HandshakeFailure)
  }
  let early = @ext.find(hello.extensions[:], EarlyData) is Some(_)
  // §4.1.2: the ClientHello after a HelloRetryRequest offers no early data.
  if self.retried && (self.suite != Some(suite) || early) {
    raise @alert.fatal(IllegalParameter)
  }
  self.suite = Some(suite)
  self.version = Some(Tls13)
  self.early = if early { config.early_limit } else { 0 }
  match choice {
    Retry(group) => {
      if self.retried {
        raise @alert.fatal(IllegalParameter)
      }
      self.retried = true
      self.retry_group = group
      self.first_hello = raw
      let hrr = @msg.server_hello(
        @hs.retry(hello.session_id[:], suite.code(), group),
      )
      self.begin_transcript(Some(hrr))
      self.send_handshake(hrr)
      if hello.session_id.length() > 0 {
        self.send_change_cipher_spec()
      }
    }
    Chosen(group~, key~, scheme~) => {
      if self.retried && group != self.retry_group {
        raise @alert.fatal(IllegalParameter)
      }
      if self.transcript is None {
        self.begin_transcript(None)
      }
      self.record(raw[:])
      self.note_server_name(hello)
      let encrypted : Array[@ext.Ext] = []
      if self.pick_alpn(config, hello) is Some(p) {
        encrypted.push({ kind: Alpn, data: @ext.protocols([p][:]), })
      }
      if self.quic is Some(q) {
        encrypted.push({ kind: QuicTransportParameters, data: q.params, })
      }
      let (secret, public) = share(group, self.rand)
      let shared = agree(group, secret, key)
      let random = (self.rand)(32)
      let extensions : Array[@ext.Ext] = [
        { kind: KeyShare, data: @ext.selected_share(group, public[:]), },
      ]
      let sh = @msg.server_hello(
        @hs.server_hello(
          random[:],
          hello.session_id[:],
          suite.code(),
          extensions=extensions[:],
        ),
      )
      self.send_handshake(sh)
      if hello.session_id.length() > 0 {
        self.send_change_cipher_spec()
      }
      self.record(sh[:])
      self.open_handshake(shared)
      self.writer = Some(@record.Cipher::new(self.server_secret[:], suite~))
      self.reader = Some(@record.Cipher::new(self.client_secret[:], suite~))
      self.keyed(Handshake)
      let flight = Buffer()
      let ee = @msg.frame(
        EncryptedExtensions,
        @msg.encrypted_extensions(encrypted[:])[:],
      )
      self.record(ee[:])
      flight.write_bytes(ee)
      let cert = @msg.frame(Certificate, @msg.certificate(config.chain[:])[:])
      self.record(cert[:])
      flight.write_bytes(cert)
      let signature = sign(
        config.key,
        scheme,
        @msg.signed(@msg.server_context, self.th()[:]),
      )
      let cv = @msg.frame(
        CertificateVerify,
        @msg.certificate_verify(signature[:], scheme)[:],
      )
      self.record(cv[:])
      flight.write_bytes(cv)
      let fin = @msg.frame(
        Finished,
        @keys.finished(
          self.server_secret[:],
          self.th()[:],
          digest=self.digest(),
        )[:],
      )
      self.record(fin[:])
      flight.write_bytes(fin)
      self.send_handshake(flight.to_bytes())
      self.open_application()
      self.writer = Some(@record.Cipher::new(self.server_app[:], suite~))
      self.keyed(Application)
      self.phase = Finishing
    }
  }
}

///|
/// Keep the name a client asked for by SNI, and say whether it asked.
fn Conn::note_server_name(
  self : Conn,
  hello : @msg.Hello,
) -> Unit raise @alert.Alert {
  guard @ext.find(hello.extensions[:], ServerName) is Some(e) else { return }
  // RFC 6066 §3: an entry of another type is passed over, and two host names are forbidden.
  match @alert.decoded(@ext.read_server_names(e.data[:])) {
    [] => ()
    [name] => {
      // RFC 6066 §3: a host name is ASCII, and a name with control characters in it is an attempt
      // on whatever logs or routes by it.
      if !name.iter().all(c => c > ' ' && c <= '~') {
        raise @alert.fatal(IllegalParameter)
      }
      self.sni = Some(name)
    }
    _ => raise @alert.fatal(IllegalParameter)
  }
}

///|
/// The application protocol to settle on, this server's preference winning (RFC 7301 §3.2). A
/// client that offers ALPN with nothing in common gets no_application_protocol.
fn Conn::pick_alpn(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
) -> String? raise @alert.Alert {
  guard @ext.find(hello.extensions[:], Alpn) is Some(e) &&
    config.alpn.length() > 0 else {
    return None
  }
  let wanted = @alert.decoded(@ext.read_protocols(e.data[:]))
  guard config.alpn.iter().find_first(p => wanted.contains(p)) is Some(p) else {
    raise @alert.fatal(NoApplicationProtocol)
  }
  self.alpn = Some(p)
  Some(p)
}

///|
/// RFC 8446 §4.1.2: the ClientHello after a HelloRetryRequest is the first one again, in the same
/// order, but for a new key_share, no early_data, a cookie, an updated pre_shared_key and
/// different padding.
fn same_hello(first_raw : Bytes, second : @msg.Hello) -> Bool {
  guard @msg.read_hello(first_raw[4:]) is Some(first) else { return false }
  let kept = (h : @msg.Hello) => {
    h.extensions.filter(e => {
      !(e.kind is (KeyShare | EarlyData | Cookie | PreSharedKey | Padding))
    })
  }
  first.version == second.version &&
  first.random == second.random &&
  first.session_id == second.session_id &&
  first.suites == second.suites &&
  first.compression == second.compression &&
  kept(first) == kept(second)
}
