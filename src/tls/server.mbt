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
    (Open, ClientHello) if self.version is Some(Tls10 | Tls11 | Tls12) =>
      if config.renegotiation {
        self.accept_renegotiation(
          config,
          @alert.decoded(@msg.read_hello(body[:])),
          raw,
        )
      } else {
        self.decline_renegotiation()
      }
    (Waiting, ClientHello) => self.on_client_hello(config, body, raw)
    (Certifying(Chain), Certificate) =>
      self.on_client_chain(config, body, raw, renewed=false)
    (Certifying(Proof), CertificateVerify) =>
      self.on_client_proof(body, raw, renewed=false)
    (Renewing(Chain), Certificate) =>
      self.on_client_chain(config, body, raw, renewed=true)
    (Renewing(Proof), CertificateVerify) =>
      self.on_client_proof(body, raw, renewed=true)
    (Renewing(Proof), Finished) => self.on_renewed(body, raw)
    (Finishing | Certifying(_), EndOfEarlyData) => {
      // §4.5: the message is the client saying its 0-RTT data is over, and it comes before
      // anything under the handshake key.
      if !self.early_ok || body.length() > 0 {
        raise @alert.fatal(UnexpectedMessage)
      }
      self.early_reader = None
      self.record(raw[:])
    }
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
      // §4.6.1: the resumption secret is over the transcript through the client's Finished, and
      // every ticket handed out stands for it.
      self.close_transcript()
      self.issue_tickets(config)
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
    config.versions.iter().any(v => v.is_legacy()) &&
    !offers13(config, hello) {
    return self.client_hello12(config, hello, raw)
  }
  if self.retried && !same_hello(self.first_hello, hello) {
    raise @alert.fatal(IllegalParameter)
  }
  // §4.2.11: the PSK decides the suite before anything is negotiated, and the binder covers this
  // very message, which is why the raw octets are read here rather than after a decision.
  if !self.retried {
    self.first_hello = raw
    self.accept_psk(config, hello, raw)
  }
  let schemes = schemes(config.key)
  self.note_requests(hello)
  let choice = @hs.negotiate(hello, groups=config.groups[:], schemes=schemes[:])
  let suite = if self.resumed {
    self.suite.unwrap()
  } else {
    guard config.suites.iter().find_first(s => hello.suites.contains(s.code()))
      is Some(suite) else {
      raise @alert.fatal(HandshakeFailure)
    }
    suite
  }
  // A retry after a PSK was taken would need a second binder this library does not build: drop
  // the resumption and run the handshake in full, which is always allowed.
  if self.resumed && choice is Retry(_) {
    self.resumed = false
    self.psk = b""
    self.early_ok = false
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
      if self.early_ok {
        encrypted.push({ kind: EarlyData, data: @ext.early_data(), })
      }
      self.answered12(config, encrypted)
      let (public, shared) = respond(group, key, self.rand)
      self.group = Some(group)
      let random = (self.rand)(32)
      let extensions : Array[@ext.Ext] = [
        { kind: KeyShare, data: @ext.selected_share(group, public[:]), },
      ]
      if self.resumed {
        // §4.2.11: the ServerHello answers with the index of the identity it took.
        let chosen = Bytes::from_array([b'\x00', b'\x00'])
        extensions.push({ kind: PreSharedKey, data: chosen, })
      }
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
      self.open_early(self.first_hello)
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
      // RFC 8446 §4.4.2: the request comes after EncryptedExtensions and before the server's own
      // Certificate, so a client answers it in the same flight.
      let asked = config.client_auth.mode is (Requested | Required)
      if asked {
        if self.now == 0L {
          raise @alert.fatal(InternalError)
        }
        let request = self.ask_certificate(
          config,
          config.client_auth.mode is Required,
        )
        self.record(request[:])
        flight.write_bytes(request)
      }
      // §4.4.2: a resumed handshake proves nothing with a certificate — the ticket is the
      // authentication — so these two messages are simply absent.
      if !self.resumed {
        // RFC 8446 §4.4.2.1: the status travels in the leaf's entry of the Certificate message.
        let stapled = if @ext.find(hello.extensions[:], StatusRequest)
          is Some(_) {
          self.staple(config)
        } else {
          None
        }
        let body = match stapled {
          Some(response) =>
            @msg.certificate_status(config.chain[:], response[:])
          None => @msg.certificate(config.chain[:])
        }
        // RFC 8879 §4: a Certificate may travel compressed when the client named an algorithm and
        // the result is actually shorter; the uncompressed length rides in front of it.
        let zlib_offered = match
          @ext.find(hello.extensions[:], CompressCertificate) {
          Some(e) =>
            match @ext.read_compression_algorithms(e.data[:]) {
              Some(ids) => ids.contains(@ext.zlib_compression)
              None => false
            }
          None => false
        }
        let message = if config.compress && zlib_offered {
          let packed = @zlib.zlib(body[:])
          if packed.length() + 9 < body.length() {
            @msg.frame(
              CompressedCertificate,
              @msg.compressed_certificate(
                @ext.zlib_compression,
                body.length(),
                packed[:],
              )[:],
            )
          } else {
            @msg.frame(Certificate, body[:])
          }
        } else {
          @msg.frame(Certificate, body[:])
        }
        self.record(message[:])
        flight.write_bytes(message)
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
      }
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
      self.phase = if asked { Certifying(Chain) } else { Finishing }
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
