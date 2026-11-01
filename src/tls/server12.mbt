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
/// The curve for an ECDHE exchange: the client's first that this server takes. A client that names
/// none takes P-256 (RFC 8422 §4).
fn pick_curve12(
  config : Server,
  hello : @msg.Hello,
) -> Int32? raise @alert.Alert {
  let curves = config.groups.filter(g => g < 0x0100)
  let offered = match @ext.find(hello.extensions[:], SupportedGroups) {
    Some(e) => @alert.decoded(@ext.read_groups(e.data[:]))
    None => [@ext.secp256r1]
  }
  offered.iter().find_first(g => curves.contains(g))
}

///|
/// The group for a DHE exchange, the cheapest that will do. RFC 7919 §4: a client that names any
/// finite-field group is held to those, and DHE is off the table when none is known here; one that
/// names none takes what it is given.
fn pick_finite12(hello : @msg.Hello) -> Int32? raise @alert.Alert {
  let offered = match @ext.find(hello.extensions[:], SupportedGroups) {
    Some(e) =>
      @alert.decoded(@ext.read_groups(e.data[:])).filter(g => {
        g >= 0x0100 && g <= 0x01ff
      })
    None => []
  }
  if offered.is_empty() {
    return Some(0x0100)
  }
  [0x0100, 0x0101, 0x0102, 0x0103, 0x0104]
  .iter()
  .find_first(g => offered.contains(g))
}

///|
/// The named group of an ECDSA key's curve.
fn group_of(key : @x509.PrivateKey) -> Int32? {
  guard key is Ec(k) else { return None }
  match k.curve() {
    P256 => Some(@ext.secp256r1)
    P384 => Some(@ext.secp384r1)
    P521 => Some(@ext.secp521r1)
    _ => None
  }
}

///|
/// RFC 8422 §5.1: in TLS 1.2 supported_groups speaks for the certificate as well, so an ECDSA key on
/// a curve the client left out is one it will refuse.
fn curve_named12(
  config : Server,
  hello : @msg.Hello,
) -> Bool raise @alert.Alert {
  guard group_of(config.key) is Some(group) &&
    @ext.find(hello.extensions[:], SupportedGroups) is Some(e) else {
    return true
  }
  @alert.decoded(@ext.read_groups(e.data[:])).contains(group)
}

///|
/// The scheme to sign the exchange under: the client's first that this key has. TLS 1.2 lets a
/// client leave signature_algorithms out, meaning SHA-1, which this library does not sign with.
fn pick_scheme12(
  config : Server,
  hello : @msg.Hello,
) -> Int32? raise @alert.Alert {
  guard @ext.find(hello.extensions[:], SignatureAlgorithms) is Some(e) else {
    return None
  }
  let mine = schemes12(config.key)
  @alert.decoded(@ext.read_schemes(e.data[:]))
  .iter()
  .find_first(s => mine.contains(s))
}

///|
/// The first of this server's suites that this hello leaves possible, with the group and scheme of
/// its signed exchange. An RSA exchange has neither: the client encrypts to the certificate.
fn pick12(
  config : Server,
  hello : @msg.Hello,
) -> (@record.Suite12, (Int32, Int32)?) raise @alert.Alert {
  let curve = pick_curve12(config, hello)
  let finite = pick_finite12(hello)
  let scheme = pick_scheme12(config, hello)
  let named = curve_named12(config, hello)
  for suite in config.suites12 {
    let fits = match (suite.auth, config.key) {
      (Rsa, Rsa(_)) => true
      (Ecdsa, Ec(_) | Ed25519(_)) => named
      _ => false
    }
    if !fits || !hello.suites.contains(suite.code) {
      continue
    }
    match (suite.exchange, curve, finite, scheme) {
      (Rsa, _, _, _) => return (suite, None)
      (Ecdhe, Some(group), _, Some(scheme))
      | (Dhe, _, Some(group), Some(scheme)) =>
        return (suite, Some((group, scheme)))
      _ => ()
    }
  }
  raise @alert.fatal(HandshakeFailure)
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
  let (suite, signed) = pick12(config, hello)
  // RFC 7366 §3: answered only when the suite is a CBC one.
  if suite.is_cbc() && @ext.find(hello.extensions[:], EncryptThenMac) is Some(_) {
    self.etm = true
    extensions.push({ kind: EncryptThenMac, data: b"", })
  }
  self.version = Some(Tls12)
  self.suite12 = Some(suite)
  self.client_version = hello.version
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
    suite: suite.code,
    compression: 0,
    extensions,
  })
  self.record(sh[:])
  let certificate = @msg.frame(
    Certificate,
    @msg.certificate12(config.chain[:])[:],
  )
  self.record(certificate[:])
  let flight = Buffer()
  flight.write_bytes(sh)
  flight.write_bytes(certificate)
  if signed is Some((group, scheme)) {
    let exchange = self.server_exchange12(config, group, scheme)
    self.record(exchange[:])
    flight.write_bytes(exchange)
  }
  let done = @msg.frame(ServerHelloDone, b""[:])
  self.record(done[:])
  flight.write_bytes(done)
  self.send_handshake(flight.to_bytes())
  self.phase = Legacy(ClientKey)
}

///|
/// A ServerKeyExchange: the ephemeral half of the exchange, signed along with the two randoms.
fn Conn::server_exchange12(
  self : Conn,
  config : Server,
  group : Int32,
  scheme : Int32,
) -> Bytes raise @alert.Alert {
  let (secret, public) = share(group, self.rand)
  self.shares = [(group, secret)]
  let params = match kx_of(group) {
    Finite(g) => {
      let prime = g.prime().to_octets(length=g.size())
      @msg.dh_params(prime[:], b"\x02"[:], public[:])
    }
    _ => @msg.key_params(group, public[:])
  }
  let signed = Buffer()
  signed.write_bytes(self.client_random)
  signed.write_bytes(self.server_random)
  signed.write_bytes(params)
  let signature = sign(config.key, scheme, signed.to_bytes())
  @msg.frame(
    ServerKeyExchange,
    @msg.server_key_exchange(params[:], scheme, signature[:])[:],
  )
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
  if @ext.find(hello.extensions[:], EncryptThenMac) is Some(e) &&
    e.data.length() > 0 {
    raise @alert.fatal(DecodeError)
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
/// The client's half of the key exchange, as a premaster secret.
fn Conn::client_key12(
  self : Conn,
  config : Server,
  body : Bytes,
) -> Bytes raise @alert.Alert {
  let exchange = self.suite12.unwrap().exchange
  guard @msg.read_client_key_exchange(body[:], wide=!(exchange is Ecdhe))
    is Some(value) else {
    raise @alert.fatal(DecodeError)
  }
  match (exchange, config.key) {
    (Rsa, Rsa(key)) =>
      @keys.unwrap_premaster(
        key,
        value[:],
        version=self.client_version,
        rand=self.rand,
      )
    (Dhe, _) => {
      let (group, secret) = self.shares[0]
      strip_zeros(agree(group, secret, value))
    }
    _ => {
      let (group, secret) = self.shares[0]
      agree(group, secret, value)
    }
  }
}

///|
/// A handshake message on a TLS 1.2 server.
fn Conn::on_server12(
  self : Conn,
  config : Server,
  step : Step12,
  kind : @msg.Kind,
  body : Bytes,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  match (step, kind) {
    (ClientKey, ClientKeyExchange) => {
      let premaster = self.client_key12(config, body)
      self.record(raw[:])
      self.master_from(premaster)
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
