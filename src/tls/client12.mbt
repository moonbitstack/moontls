// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A ServerHello that picked TLS 1.2. Everything a 1.3 hello carries differently is checked here:
/// the suite's code names the certificate type too, the version is in the frozen field, the
/// extensions are a different set, and a server that speaks 1.3 and answered 1.2 anyway says so in
/// its random, which is how a client that also speaks 1.3 notices a downgrade (RFC 8446 §4.1.3).
fn Conn::hello12(
  self : Conn,
  config : Client,
  sh : @msg.Server,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  if sh.version != @wire.legacy_version {
    raise @alert.fatal(ProtocolVersion)
  }
  if self.retried || sh.compression != 0 {
    raise @alert.fatal(IllegalParameter)
  }
  guard @record.Suite::of_tls12(sh.suite) is Some((suite, _)) &&
    config.suites.contains(suite) else {
    raise @alert.fatal(IllegalParameter)
  }
  if config.versions.contains(Tls13) && sh.random[24:32] == downgrade[:] {
    raise @alert.fatal(IllegalParameter)
  }
  self.hello_extensions12(config, sh.extensions)
  // RFC 5746 §4.1: a server that does not say it knows about renegotiation may be replaying this
  // handshake into someone else's session.
  if !self.indicated {
    raise @alert.fatal(HandshakeFailure)
  }
  self.version = Some(Tls12)
  self.suite = Some(suite)
  self.server_random = sh.random
  self.begin_transcript(None)
  self.record(self.first_hello[:])
  self.record(raw[:])
  self.phase = Legacy(Chain)
}

///|
/// What a TLS 1.2 ServerHello may carry, all of it answers to what this client offered.
fn Conn::hello_extensions12(
  self : Conn,
  config : Client,
  exts : Array[@ext.Ext],
) -> Unit raise @alert.Alert {
  for i, e in exts {
    if exts[:i].iter().any(x => x.kind == e.kind) {
      raise @alert.fatal(DecodeError)
    }
    match e.kind {
      ExtendedMasterSecret => {
        if e.data.length() > 0 {
          raise @alert.fatal(DecodeError)
        }
        self.extended = true
      }
      // RFC 5746 §3.4: on an initial handshake the verify_data it carries is empty.
      RenegotiationInfo => {
        if e.data != @ext.no_renegotiation() {
          raise @alert.fatal(HandshakeFailure)
        }
        self.indicated = true
      }
      EcPointFormats =>
        if !@ext.has_uncompressed(e.data[:]) {
          raise @alert.fatal(IllegalParameter)
        }
      Alpn if config.alpn.length() > 0 =>
        match @alert.decoded(@ext.read_protocols(e.data[:])) {
          [p] if config.alpn.contains(p) => self.alpn = Some(p)
          _ => raise @alert.fatal(IllegalParameter)
        }
      ServerName => if e.data.length() > 0 { raise @alert.fatal(DecodeError) }
      _ => raise @alert.fatal(UnsupportedExtension)
    }
  }
}

///|
/// A handshake message on a TLS 1.2 client, in the only order RFC 5246 §7.3 allows.
fn Conn::on_client12(
  self : Conn,
  config : Client,
  host : String,
  step : Step12,
  kind : @msg.Kind,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  match (step, kind) {
    // RFC 5246 §7.4.1.1: a HelloRequest during a handshake is ignored.
    (_, Other(0)) => ()
    (Chain, Certificate) => {
      guard @msg.read_certificate12(body[:]) is Some(certs) else {
        raise @alert.fatal(DecodeError)
      }
      if certs.length() == 0 {
        raise @alert.fatal(DecodeError)
      }
      self.check_chain(config, host, certs)
      self.record(raw[:])
      self.phase = Legacy(Exchange)
    }
    (Exchange, ServerKeyExchange) => {
      guard @msg.read_server_key_exchange(body[:])
        is Some((group, public, scheme, signature)) else {
        raise @alert.fatal(DecodeError)
      }
      if !config.groups.contains(group) || !offered.contains(scheme) {
        raise @alert.fatal(IllegalParameter)
      }
      let leaf = @x509.parse(self.peer[0][:]) catch {
        _ => raise @alert.fatal(BadCertificate)
      }
      let signed = Buffer()
      signed.write_bytes(self.client_random)
      signed.write_bytes(self.server_random)
      signed.write_bytes(@msg.key_params(group, public[:]))
      if !verified12(leaf, scheme, signed.to_bytes(), signature) {
        raise @alert.fatal(DecryptError)
      }
      self.record(raw[:])
      self.shares = [(group, public)]
      self.phase = Legacy(Done)
    }
    (Done, CertificateRequest) => {
      self.requested = true
      self.record(raw[:])
    }
    (Done, ServerHelloDone) => {
      if body.length() > 0 {
        raise @alert.fatal(DecodeError)
      }
      self.record(raw[:])
      self.finish_flight12()
    }
    (Closing, Finished) => {
      self.check_finished12(body, client=false)
      self.record(raw[:])
      self.phase = Open
    }
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}

///|
/// The client's flight: an empty Certificate if one was asked for, ClientKeyExchange, then
/// change_cipher_spec and a Finished under the new keys (RFC 5246 §7.3).
fn Conn::finish_flight12(self : Conn) -> Unit raise @alert.Alert {
  let (group, theirs) = self.shares[0]
  let (secret, public) = share(group, self.rand)
  let shared = agree(group, secret, theirs)
  if self.requested {
    let empty = @msg.frame(Certificate, @msg.certificate12([][:])[:])
    self.record(empty[:])
    self.send_handshake(empty)
  }
  let exchange = @msg.frame(
    ClientKeyExchange,
    @msg.client_key_exchange(public[:])[:],
  )
  self.record(exchange[:])
  self.send_handshake(exchange)
  self.master_from(shared)
  let (mine, theirs_cipher) = self.ciphers12()
  self.send_change_cipher_spec()
  self.writer = Some(mine)
  self.send_finished12(client=true)
  self.waiting = Some(theirs_cipher)
  self.phase = Legacy(Cipher)
}
