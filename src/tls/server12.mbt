// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Whether a ClientHello offers TLS 1.3 to a server that speaks it, which settles the version
/// before anything else is looked at (RFC 8446 §4.2.1).
fn offers13(config : Server, hello : @msg.Hello) -> Bool raise @alert.Alert {
  guard config.versions.contains(Tls13) else { return false }
  match @ext.find(hello.extensions[:], SupportedVersions) {
    Some(e) => @alert.decoded(@ext.read_versions(e.data[:])).contains(0x0304)
    None => false
  }
}

///|
/// Whether a ClientHello offers TLS 1.2: in supported_versions when it has one, which overrides the
/// frozen field, otherwise there (RFC 8446 §4.2.1).
fn offers12(hello : @msg.Hello) -> Bool raise @alert.Alert {
  match @ext.find(hello.extensions[:], SupportedVersions) {
    Some(e) => @alert.decoded(@ext.read_versions(e.data[:])).contains(0x0303)
    None => hello.version >= 0x0303
  }
}

///|
/// The first of this server's suites the client offers with the certificate type this key signs for.
fn pick_suite12(config : Server, hello : @msg.Hello) -> @record.Suite? {
  let rsa = config.key is Rsa(_)
  config.suites.iter().find_first(s => hello.suites.contains(s.tls12(rsa~)))
}

///|
/// The curve for the exchange: the client's first that this server takes. A client that names none
/// takes P-256 (RFC 8422 §4). The finite-field groups are out: this is ECDHE.
fn pick_group12(
  config : Server,
  hello : @msg.Hello,
) -> Int32 raise @alert.Alert {
  let curves = config.groups.filter(g => g < 0x0100)
  let offered = match @ext.find(hello.extensions[:], SupportedGroups) {
    Some(e) => @alert.decoded(@ext.read_groups(e.data[:]))
    None => [@ext.secp256r1]
  }
  guard offered.iter().find_first(g => curves.contains(g)) is Some(group) else {
    raise @alert.fatal(HandshakeFailure)
  }
  group
}

///|
/// The named group of an ECDSA key's curve.
fn group_of(key : @x509.PrivateKey) -> Int32? {
  guard key is Ec(k) else { return None }
  match k.curve() {
    P256 => Some(@ext.secp256r1)
    P384 => Some(@ext.secp384r1)
    P521 => Some(@ext.secp521r1)
    Secp256k1 => None
  }
}

///|
/// RFC 8422 §5.1: in TLS 1.2 supported_groups speaks for the certificate as well, so an ECDSA key on
/// a curve the client left out is one it will refuse.
fn check_curve12(
  config : Server,
  hello : @msg.Hello,
) -> Unit raise @alert.Alert {
  guard group_of(config.key) is Some(group) &&
    @ext.find(hello.extensions[:], SupportedGroups) is Some(e) else {
    return
  }
  if !@alert.decoded(@ext.read_groups(e.data[:])).contains(group) {
    raise @alert.fatal(HandshakeFailure)
  }
}

///|
/// The scheme to sign the exchange under: the client's first that this key has. TLS 1.2 lets a
/// client leave signature_algorithms out, meaning SHA-1, which this library does not sign with.
fn pick_scheme12(
  config : Server,
  hello : @msg.Hello,
) -> Int32 raise @alert.Alert {
  guard @ext.find(hello.extensions[:], SignatureAlgorithms) is Some(e) else {
    raise @alert.fatal(HandshakeFailure)
  }
  let mine = schemes12(config.key)
  guard @alert.decoded(@ext.read_schemes(e.data[:]))
    .iter()
    .find_first(s => mine.contains(s))
    is Some(scheme) else {
    raise @alert.fatal(HandshakeFailure)
  }
  scheme
}

///|
/// A ClientHello settling on TLS 1.2: the whole server flight goes out at once (RFC 5246 §7.3).
fn Conn::client_hello12(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  // RFC 7507 §3: a client falling back from a version this server would have spoken. It comes
  // before the version check, or a retry at TLS 1.1 would only hear that 1.1 is not spoken.
  let best = if config.versions.contains(Tls13) { 0x0304 } else { 0x0303 }
  if hello.suites.contains(fallback_scsv) && hello.version < best {
    raise @alert.fatal(InappropriateFallback)
  }
  if !offers12(hello) || hello.version <= 0x0300 {
    raise @alert.fatal(ProtocolVersion)
  }
  if !hello.compression.iter().any(b => b == b'\x00') {
    raise @alert.fatal(IllegalParameter)
  }
  // Everything the client wrote is read before anything it offered is judged, so a malformed hello
  // is called that rather than a mismatch.
  let extensions = self.server_extensions12(config, hello)
  guard pick_suite12(config, hello) is Some(suite) else {
    raise @alert.fatal(HandshakeFailure)
  }
  check_curve12(config, hello)
  let group = pick_group12(config, hello)
  let scheme = pick_scheme12(config, hello)
  self.version = Some(Tls12)
  self.suite = Some(suite)
  self.client_random = hello.random
  let random = (self.rand)(32).to_array()
  if config.versions.contains(Tls13) {
    for i, b in downgrade {
      random[24 + i] = b
    }
  }
  self.server_random = Bytes::from_array(random)
  self.begin_transcript(None)
  self.record(raw[:])
  let sh = @msg.server_hello({
    version: @wire.legacy_version,
    random: self.server_random,
    session_id: b"",
    suite: suite.tls12(rsa=config.key is Rsa(_)),
    compression: 0,
    extensions,
  })
  self.record(sh[:])
  let certificate = @msg.frame(
    Certificate,
    @msg.certificate12(config.chain[:])[:],
  )
  self.record(certificate[:])
  let (secret, public) = share(group, self.rand)
  self.shares = [(group, secret)]
  let signed = Buffer()
  signed.write_bytes(self.client_random)
  signed.write_bytes(self.server_random)
  signed.write_bytes(@msg.key_params(group, public[:]))
  let signature = sign(config.key, scheme, signed.to_bytes())
  let exchange = @msg.frame(
    ServerKeyExchange,
    @msg.server_key_exchange(group, public[:], scheme, signature[:])[:],
  )
  self.record(exchange[:])
  let done = @msg.frame(ServerHelloDone, b""[:])
  self.record(done[:])
  let flight = Buffer()
  flight.write_bytes(sh)
  flight.write_bytes(certificate)
  flight.write_bytes(exchange)
  flight.write_bytes(done)
  self.send_handshake(flight.to_bytes())
  self.phase = Legacy(ClientKey)
}

///|
/// The ServerHello's extensions: an answer to each the client sent that this server honours.
fn Conn::server_extensions12(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
) -> Array[@ext.Ext] raise @alert.Alert {
  // RFC 5746 §3.6: a first ClientHello carries an empty renegotiated_connection.
  if @ext.find(hello.extensions[:], RenegotiationInfo) is Some(e) &&
    e.data != @ext.no_renegotiation() {
    raise @alert.fatal(HandshakeFailure)
  }
  // RFC 5746 §3.6: answered when the client asked, by the extension or by the SCSV, and only then.
  let out : Array[@ext.Ext] = []
  if @ext.find(hello.extensions[:], RenegotiationInfo) is Some(_) ||
    hello.suites.contains(renegotiation_scsv) {
    out.push({ kind: RenegotiationInfo, data: @ext.no_renegotiation(), })
  }
  if @ext.find(hello.extensions[:], ExtendedMasterSecret) is Some(e) {
    if e.data.length() > 0 {
      raise @alert.fatal(DecodeError)
    }
    self.extended = true
    out.push({ kind: ExtendedMasterSecret, data: b"", })
  }
  if @ext.find(hello.extensions[:], EcPointFormats) is Some(e) {
    if !@ext.has_uncompressed(e.data[:]) {
      raise @alert.fatal(IllegalParameter)
    }
    out.push({ kind: EcPointFormats, data: @ext.point_formats(), })
  }
  if self.note_server_name(hello) {
    out.push({ kind: ServerName, data: b"", })
  }
  if self.pick_alpn(config, hello) is Some(p) {
    out.push({ kind: Alpn, data: @ext.protocols([p][:]), })
  }
  out
}

///|
/// A handshake message on a TLS 1.2 server.
fn Conn::on_server12(
  self : Conn,
  step : Step12,
  kind : @msg.Kind,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  match (step, kind) {
    (ClientKey, ClientKeyExchange) => {
      guard @msg.read_client_key_exchange(body[:]) is Some(public) else {
        raise @alert.fatal(DecodeError)
      }
      let (group, secret) = self.shares[0]
      let shared = agree(group, secret, public)
      self.record(raw[:])
      self.master_from(shared)
      let (theirs, mine) = self.ciphers12()
      self.waiting = Some(theirs)
      self.writer = None
      self.outgoing = Some(mine)
      self.phase = Legacy(Cipher)
    }
    (Closing, Finished) => {
      self.check_finished12(body, client=true)
      self.record(raw[:])
      self.send_change_cipher_spec()
      self.writer = self.outgoing
      self.outgoing = None
      self.send_finished12(client=false)
      self.phase = Open
    }
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}
