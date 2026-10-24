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
    (Waiting, ClientHello) => self.on_client_hello(config, body, raw)
    (Finishing, Finished) => {
      let d = self.digest()
      if !@keys.finished_ok(
          self.client_secret[:],
          self.th()[:],
          body[:],
          digest=d,
        ) {
        raise @alert.fatal(DecryptError)
      }
      self.record(raw[:])
      self.reader = Some(
        @record.Cipher::new(self.client_app[:], suite=self.suite.unwrap()),
      )
      self.phase = Open
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
  guard @msg.read_hello(body[:]) is Some(hello) else {
    raise @alert.fatal(DecodeError)
  }
  let schemes = config.key.schemes()
  let choice = @hs.negotiate(hello, groups=config.groups[:], schemes=schemes[:])
  guard config.suites.iter().find_first(s => hello.suites.contains(s.code()))
    is Some(suite) else {
    raise @alert.fatal(HandshakeFailure)
  }
  if self.retried && self.suite != Some(suite) {
    raise @alert.fatal(IllegalParameter)
  }
  self.suite = Some(suite)
  match choice {
    Retry(group) => {
      if self.retried {
        raise @alert.fatal(IllegalParameter)
      }
      self.retried = true
      self.first_hello = raw
      let hrr = @msg.server_hello(
        @hs.retry(hello.session_id[:], suite.code(), group),
      )
      self.begin_transcript(Some(hrr))
      self.send_handshake(hrr)
    }
    Chosen(group~, key~, scheme~) => {
      if self.transcript is None {
        self.begin_transcript(None)
      }
      self.record(raw[:])
      if @ext.find(hello.extensions[:], ServerName) is Some(e) {
        self.sni = @ext.read_server_name(e.data[:])
      }
      let encrypted : Array[@ext.Ext] = []
      if @ext.find(hello.extensions[:], Alpn) is Some(e) &&
        config.alpn.length() > 0 {
        let wanted = @ext.read_protocols(e.data[:])
        guard config.alpn.iter().find_first(p => wanted.contains(p)) is Some(p) else {
          raise @alert.fatal(NoApplicationProtocol)
        }
        self.alpn = Some(p)
        encrypted.push({ kind: Alpn, data: @ext.protocols([p][:]), })
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
      self.record(sh[:])
      self.open_handshake(shared)
      self.writer = Some(@record.Cipher::new(self.server_secret[:], suite~))
      self.reader = Some(@record.Cipher::new(self.client_secret[:], suite~))
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
      let signature = config.key.sign(
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
      self.phase = Finishing
    }
  }
}
