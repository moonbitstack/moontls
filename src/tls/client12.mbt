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
  guard @record.Suite12::of(sh.suite) is Some(suite) &&
    config.suites12.contains(suite) else {
    raise @alert.fatal(IllegalParameter)
  }
  if config.versions.contains(Tls13) && sh.random[24:32] == downgrade[:] {
    raise @alert.fatal(IllegalParameter)
  }
  self.hello_extensions12(config, suite, sh.extensions)
  // RFC 5746 §4.1: a server that does not say it knows about renegotiation may be replaying this
  // handshake into someone else's session.
  if !self.indicated {
    raise @alert.fatal(HandshakeFailure)
  }
  self.version = Some(Tls12)
  self.suite12 = Some(suite)
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
  suite : @record.Suite12,
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
      EcPointFormats => {
        guard @ext.read_point_formats(e.data[:]) is Some(formats) else {
          raise @alert.fatal(DecodeError)
        }
        if !formats.iter().any(b => b == b'\x00') {
          raise @alert.fatal(IllegalParameter)
        }
      }
      // RFC 7366 §3: a server that picked an AEAD does not answer it.
      EncryptThenMac if config.suites12.iter().any(s => s.is_cbc()) => {
        if e.data.length() > 0 {
          raise @alert.fatal(DecodeError)
        }
        if !suite.is_cbc() {
          raise @alert.fatal(IllegalParameter)
        }
        self.etm = true
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
      let suite = self.suite12.unwrap()
      check_leaf12(self.leaf12(), suite)
      self.record(raw[:])
      self.phase = Legacy(if suite.exchange is Rsa { Done } else { Exchange })
    }
    (Exchange, ServerKeyExchange) => {
      let (params, scheme, signature) = if self.suite12.unwrap().exchange is Dhe {
        self.dh_exchange12(config, body)
      } else {
        self.curve_exchange12(config, body)
      }
      if !config.schemes12.contains(scheme) {
        raise @alert.fatal(IllegalParameter)
      }
      let signed = Buffer()
      signed.write_bytes(self.client_random)
      signed.write_bytes(self.server_random)
      signed.write_bytes(params)
      if !verified12(self.leaf12(), scheme, signed.to_bytes(), signature) {
        raise @alert.fatal(DecryptError)
      }
      self.record(raw[:])
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
/// The server's certificate as this connection judged it.
fn Conn::leaf12(self : Conn) -> @x509.Cert raise @alert.Alert {
  @x509.parse(self.peer[0][:]) catch {
    _ => raise @alert.fatal(BadCertificate)
  }
}

///|
/// RFC 5246 §7.4.2: the certificate has to be the kind the suite names, and an RSA exchange encrypts
/// to it, which a key restricted to signing does not allow (RFC 5280 §4.2.1.3).
fn check_leaf12(
  leaf : @x509.Cert,
  suite : @record.Suite12,
) -> Unit raise @alert.Alert {
  let key = leaf.spki.key() catch { _ => raise @alert.fatal(BadCertificate) }
  let fits = match (suite.auth, key) {
    (Rsa, Rsa(_)) | (Ecdsa, Ec(_) | Ed25519(_)) => true
    _ => false
  }
  if !fits {
    raise @alert.fatal(UnsupportedCertificate)
  }
  if suite.exchange is Rsa &&
    leaf.exts.key_usage is Some(usage) &&
    !usage.get(2) {
    raise @alert.fatal(BadCertificate)
  }
}

///|
/// An ECDHE ServerKeyExchange, held for the client's flight. What comes back is what the signature
/// covers, the scheme and the signature.
fn Conn::curve_exchange12(
  self : Conn,
  config : Client,
  body : Bytes,
) -> (Bytes, Int32, Bytes) raise @alert.Alert {
  guard @msg.read_server_key_exchange(body[:])
    is Some((group, public, scheme, signature)) else {
    raise @alert.fatal(DecodeError)
  }
  if !config.groups.contains(group) {
    raise @alert.fatal(IllegalParameter)
  }
  self.shares = [(group, public)]
  (@msg.key_params(group, public[:]), scheme, signature)
}

///|
/// A DHE ServerKeyExchange. The server wrote the group itself, so it is judged here: a small prime
/// is Logjam, and an even one or a generator of 0 or 1 gives a secret anyone can compute.
fn Conn::dh_exchange12(
  self : Conn,
  config : Client,
  body : Bytes,
) -> (Bytes, Int32, Bytes) raise @alert.Alert {
  guard @msg.read_dh_key_exchange(body[:])
    is Some((prime, generator, public, scheme, signature)) else {
    raise @alert.fatal(DecodeError)
  }
  let p = BigInt::from_octets(prime[:])
  let g = BigInt::from_octets(generator[:])
  if p < 1N << (config.dh_bits - 1) {
    raise @alert.fatal(InsufficientSecurity)
  }
  if p % 2N == 0N || g < 2N || g > p - 2N {
    raise @alert.fatal(IllegalParameter)
  }
  self.dh = Some((prime, generator, public))
  (@msg.dh_params(prime[:], generator[:], public[:]), scheme, signature)
}

///|
/// This end's half of the key exchange: the premaster secret, and the ClientKeyExchange body that
/// gets it to the server.
fn Conn::client_exchange12(self : Conn) -> (Bytes, Bytes) raise @alert.Alert {
  match self.suite12.unwrap().exchange {
    Ecdhe => {
      let (group, theirs) = self.shares[0]
      let (secret, public) = share(group, self.rand)
      (agree(group, secret, theirs), @msg.client_key_exchange(public[:]))
    }
    Dhe => {
      guard self.dh is Some((prime, generator, theirs)) else {
        raise @alert.fatal(InternalError)
      }
      let secret = (self.rand)(prime.length())
      try {
        let public = @dh.public_with(prime[:], generator[:], secret[:])
        let shared = @dh.shared_with(prime[:], secret[:], theirs[:])
        (strip_zeros(shared), @msg.client_key_exchange(public[:], wide=true))
      } catch {
        _ => raise @alert.fatal(IllegalParameter)
      }
    }
    // RFC 5246 §7.4.7.1: the version in here is the one the hello offered, not the one agreed.
    Rsa => {
      let key = self.leaf12().spki.key() catch {
        _ => raise @alert.fatal(BadCertificate)
      }
      guard key is Rsa(key) else { raise @alert.fatal(UnsupportedCertificate) }
      let premaster = Buffer()
      @wire.u16(premaster, @wire.legacy_version)
      premaster.write_bytes((self.rand)(46))
      let secret = premaster.to_bytes()
      let wrapped = @keys.wrap_premaster(key, secret[:], rand=self.rand) catch {
        _ => raise @alert.fatal(UnsupportedCertificate)
      }
      (secret, @msg.client_key_exchange(wrapped[:], wide=true))
    }
  }
}

///|
/// The client's flight: an empty Certificate if one was asked for, ClientKeyExchange, then
/// change_cipher_spec and a Finished under the new keys (RFC 5246 §7.3).
fn Conn::finish_flight12(self : Conn) -> Unit raise @alert.Alert {
  let (premaster, body) = self.client_exchange12()
  if self.requested {
    let empty = @msg.frame(Certificate, @msg.certificate12([][:])[:])
    self.record(empty[:])
    self.send_handshake(empty)
  }
  let exchange = @msg.frame(ClientKeyExchange, body[:])
  self.record(exchange[:])
  self.send_handshake(exchange)
  self.master_from(premaster)
  let (mine, theirs) = self.ciphers12()
  self.send_change_cipher_spec()
  self.writer = Some(mine)
  self.send_finished12(client=true)
  self.waiting = Some(theirs)
  self.phase = Legacy(Cipher)
}
