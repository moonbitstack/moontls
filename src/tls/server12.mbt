// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Whether a ClientHello offers TLS 1.3 to a server that speaks it, which settles the version
/// before anything else is looked at (RFC 8446 §4.2.1).
fn offers13(
  config : Server,
  hello : @msg.Hello,
  datagram~ : Bool = false,
) -> Bool raise @alert.Alert {
  guard config.versions.contains(Tls13) else { return false }
  let code = supported(Tls13, datagram~)
  match @ext.find(hello.extensions[:], SupportedVersions) {
    Some(e) => @alert.decoded(@ext.read_versions(e.data[:])).contains(code)
    None => false
  }
}

///|
/// The highest version below 1.3 that both ends speak: `supported_versions` when the client sent
/// one, since it overrides the frozen field (RFC 8446 §4.2.1), and otherwise the ClientHello's own
/// version, which is the highest the client offered.
fn pick_legacy(
  config : Server,
  hello : @msg.Hello,
  datagram~ : Bool = false,
) -> Version? raise @alert.Alert {
  let offered = match @ext.find(hello.extensions[:], SupportedVersions) {
    Some(e) => @alert.decoded(@ext.read_versions(e.data[:]))
    None => []
  }
  for v in [Tls12, Tls11, Tls10] {
    if !config.versions.contains(v) {
      continue
    }
    let fits = if offered.length() > 0 {
      offered.contains(supported(v, datagram~))
    } else {
      hello.version >= v.code()
    }
    if fits {
      return Some(v)
    }
  }
  None
}

///|
/// The curve for an ECDHE exchange: the client's first that this server takes. A client that names
/// none takes P-256 (RFC 8422 §4).
fn pick_curve12(
  config : Server,
  hello : @msg.Hello,
) -> Int32? raise @alert.Alert {
  let curves = config.groups.filter(curve12)
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
/// The scheme to sign the exchange under: the client's first that this key has and this server
/// allows. A TLS 1.2 client that leaves signature_algorithms out means SHA-1 (RFC 5246
/// §7.4.1.4.1), which is only on offer when `schemes12` says so. TLS 1.0 and 1.1 have no scheme
/// to negotiate: the hash is the version's, and naming the version in `versions` is the consent.
fn pick_scheme12(
  config : Server,
  hello : @msg.Hello,
  version : Version,
) -> Int32? raise @alert.Alert {
  let rsa = RsaKind::of_chain(config.chain)
  if version is (Tls10 | Tls11) {
    return key_schemes12(config.key, rsa~)
      .iter()
      .find_first(s => s == @ext.rsa_pkcs1_sha1 || s == @ext.ecdsa_sha1)
  }
  let mine = key_schemes12(config.key, rsa~).filter(s => {
    config.schemes12.contains(s)
  })
  match @ext.find(hello.extensions[:], SignatureAlgorithms) {
    None =>
      mine
      .iter()
      .find_first(s => s == @ext.rsa_pkcs1_sha1 || s == @ext.ecdsa_sha1)
    Some(e) =>
      @alert.decoded(@ext.read_schemes(e.data[:]))
      .iter()
      .find_first(s => mine.contains(s))
  }
}

///|
/// The first of this server's suites that this hello leaves possible, with the group of its
/// exchange and the scheme that signs it. An RSA exchange has neither: the client encrypts to the
/// certificate. A PSK exchange has a group when it has one and never a scheme: the key
/// authenticates it, and a suite that takes a key is only possible with one configured.
fn pick12(
  config : Server,
  hello : @msg.Hello,
  version : Version,
) -> (@record.Suite12, Int32?, Int32?) raise @alert.Alert {
  let curve = pick_curve12(config, hello)
  let finite = pick_finite12(hello)
  let scheme = pick_scheme12(config, hello, version)
  let named = curve_named12(config, hello)
  let rsa = RsaKind::of_chain(config.chain)
  let keyed = config.psk.length() > 0
  for suite in config.suites12 {
    // A static DH suite is for a DH key, whoever signed its certificate (RFC 5246 §7.4.2).
    let fits = match (suite.exchange, suite.auth, config.key) {
      (Dh, _, Dh(..)) => true
      (Dh, _, _) => false
      (_, Rsa, Rsa(_)) => true
      (_, Ecdsa, Ec(_) | Ed25519(_)) => named
      (_, Shared, _) => true
      (_, Dss, Dsa(_)) => true
      _ => false
    }
    if !fits ||
      !hello.suites.contains(suite.code) ||
      (suite.exchange.takes_psk() && !keyed) ||
      (suite.exchange is Srp && config.srp.is_empty()) {
      continue
    }
    match (suite.exchange, curve, finite, scheme) {
      // RFC 4055 §1.2: an RSASSA-PSS key signs and is not encrypted to.
      (Rsa | RsaPsk, _, _, _) if rsa is Rsae => return (suite, None, None)
      (Psk | Dh, _, _, _) => return (suite, None, None)
      (Ecdhe, Some(group), _, Some(scheme))
      | (Dhe, _, Some(group), Some(scheme)) =>
        return (suite, Some(group), Some(scheme))
      (EcdhePsk, Some(group), _, _) | (DhePsk, _, Some(group), _) =>
        return (suite, Some(group), None)
      (Srp, _, _, _) if suite.auth is Shared => return (suite, None, None)
      (Srp, _, _, Some(scheme)) => return (suite, None, Some(scheme))
      _ => ()
    }
  }
  // RFC 7919 §4: finite-field groups named, none known, and nothing else to pick.
  raise @alert.fatal(
    if finite is None {
      InsufficientSecurity
    } else {
      HandshakeFailure
    },
  )
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
  guard pick_legacy(config, hello, datagram=self.datagram) is Some(version) else {
    raise @alert.fatal(ProtocolVersion)
  }
  if hello.version <= 0x0300 {
    raise @alert.fatal(ProtocolVersion)
  }
  // RFC 5246 §7.3, RFC 5077 §3.4: a hello naming a session this server still has skips the
  // certificate and the key exchange.
  if self.prior_session12(config, hello) is Some((session, _)) {
    if hello.compression.iter().any(b => b == b'\x00') {
      return self.resume_server12(hello, raw, session)
    }
  }
  // A server names the session it just agreed to, so the client can bring the name back. RFC 5246
  // §7.3 leaves the field empty for a server that will not cache anything, and RFC 5077's ticket
  // makes caching unnecessary — but the name is what a peer recognises a resumption by: OpenSSL
  // decides `s->hit` by comparing the ServerHello's session id with the one it stored, and an empty
  // one there makes every ticket resumption look like a full handshake to it, whatever the ticket
  // says. Issuing a name costs 32 octets and is what a server with tickets has to do as well.
  if config.sessions is Some(_) || config.tickets.is_on() {
    self.session = self.issue_id12()
  }
  if !hello.compression.iter().any(b => b == b'\x00') {
    raise @alert.fatal(IllegalParameter)
  }
  // Everything the client wrote is read before anything it offered is judged, so a malformed hello
  // is called that rather than a mismatch.
  self.note_requests(hello)
  let config = self.choose(config, hello, c => {
    try pick12(c, hello, version) catch {
      _ => false
    } noraise {
      _ => true
    }
  })
  let extensions = self.server_extensions12(config, hello)
  let (suite, group, scheme) = pick12(config, hello, version)
  // RFC 5054 §2.5.1.2: an SRP suite without a user to log in as ends here, before any reply.
  let user = if suite.exchange is Srp {
    Some(srp_user(config, hello))
  } else {
    None
  }
  // RFC 7366 §3: answered only when the suite is a CBC one, and only in TLS 1.2 — the extension
  // did not exist before it, and the two versions read a CBC record differently.
  if suite.is_cbc() &&
    version is Tls12 &&
    @ext.find(hello.extensions[:], EncryptThenMac) is Some(_) {
    self.etm = true
    extensions.push({ kind: EncryptThenMac, data: b"", })
  }
  self.version = Some(version)
  self.suite12 = Some(suite)
  self.wire = version.code()
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
    // RFC 6347 §4.2.1: a DTLS ServerHello names the DTLS version, 0xfefd, where a TLS one names
    // 0x0303. pion's client checks it and refuses the handshake; OpenSSL does not.
    version: supported(version, datagram=self.datagram),
    random: self.server_random,
    session_id: self.session,
    suite: suite.code,
    compression: 0,
    extensions,
  })
  self.record_sent(sh[:])
  let flight = Buffer()
  flight.write_bytes(sh)
  // A suite whose key authenticates the exchange has no certificate to show (RFC 4279 §2).
  let shown = !(suite.auth is Shared)
  if shown {
    let certificate = @msg.frame(
      Certificate,
      @msg.certificate12(config.chain[:])[:],
    )
    self.record_sent(certificate[:])
    flight.write_bytes(certificate)
  }
  // RFC 6066 §8: a server that staples says so in its ServerHello and then sends the status right
  // after the certificate.
  if shown && @ext.find(hello.extensions[:], StatusRequest) is Some(_) {
    match self.staple(config) {
      Some(response) => {
        let status = @msg.frame(
          Other(22),
          @msg.certificate_status12(response[:])[:],
        )
        self.record_sent(status[:])
        flight.write_bytes(status)
      }
      None => ()
    }
  }
  let exchange = match (user, group, scheme) {
    (Some(user), _, _) => Some(self.srp_exchange12(config, user, scheme))
    (_, Some(group), Some(scheme)) =>
      Some(self.server_exchange12(config, group, scheme))
    (_, Some(group), None) => Some(self.psk_exchange12(group))
    _ => None
  }
  if exchange is Some(message) {
    self.record_sent(message[:])
    flight.write_bytes(message)
  }
  // RFC 5246 §7.4.4: a request for the client's certificate comes before the ServerHelloDone, so
  // the answer arrives in the client's flight. A server that showed none cannot ask (§7.4.4).
  if shown && config.client_auth.mode is (Requested | Required) {
    if self.now == 0L {
      raise @alert.fatal(InternalError)
    }
    let request = self.ask_certificate12(
      config,
      config.client_auth.mode is Required,
    )
    self.record_sent(request[:])
    flight.write_bytes(request)
  }
  let done = @msg.frame(ServerHelloDone, b""[:])
  self.record_sent(done[:])
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
  let params = self.offer12(group)
  let signed = Buffer()
  signed.write_bytes(self.client_random)
  signed.write_bytes(self.server_random)
  signed.write_bytes(params)
  let signature = sign12(config.key, scheme, signed.to_bytes())
  @msg.frame(
    ServerKeyExchange,
    @msg.server_key_exchange(params[:], scheme, signature[:])[:],
  )
}

///|
/// This server's half of an ephemeral exchange in `group`, kept for the ClientKeyExchange, and the
/// parameters a ServerKeyExchange carries it in.
fn Conn::offer12(self : Conn, group : Int32) -> Bytes raise @alert.Alert {
  let (secret, public) = share(group, self.rand)
  self.shares = [(group, secret)]
  self.group = Some(group)
  match kx_of(group) {
    Finite(g) => {
      let prime = g.prime().to_octets(length=g.size())
      @msg.dh_params(prime[:], b"\x02"[:], public[:])
    }
    _ => @msg.key_params(group, public[:])
  }
}

///|
/// The ServerHello's extensions: an answer to each the client sent that this server honours.
fn Conn::server_extensions12(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
) -> Array[@ext.Ext] raise @alert.Alert {
  // RFC 5746 §3.6: an empty renegotiated_connection on a first handshake, the previous
  // handshake's two verify_data on a renegotiation.
  if @ext.find(hello.extensions[:], RenegotiationInfo) is Some(e) &&
    !self.renews_hello(e.data) {
    raise @alert.fatal(HandshakeFailure)
  }
  // RFC 5746 §3.6: answered when the client asked, by the extension or by the SCSV, and only then.
  let out : Array[@ext.Ext] = []
  if @ext.find(hello.extensions[:], RenegotiationInfo) is Some(_) ||
    hello.suites.contains(renegotiation_scsv) {
    out.push({ kind: RenegotiationInfo, data: self.renegotiation_reply(), })
  }
  if @ext.find(hello.extensions[:], ExtendedMasterSecret) is Some(e) {
    if e.data.length() > 0 {
      raise @alert.fatal(DecodeError)
    }
    self.extended = true
    out.push({ kind: ExtendedMasterSecret, data: b"", })
  }
  if @ext.find(hello.extensions[:], EcPointFormats) is Some(e) {
    guard @ext.read_point_formats(e.data[:]) is Some(formats) else {
      raise @alert.fatal(DecodeError)
    }
    if !formats.iter().any(b => b == b'\x00') {
      raise @alert.fatal(IllegalParameter)
    }
    out.push({ kind: EcPointFormats, data: @ext.point_formats(), })
  }
  if @ext.find(hello.extensions[:], EncryptThenMac) is Some(e) &&
    e.data.length() > 0 {
    raise @alert.fatal(DecodeError)
  }
  // RFC 5077 §3.2: a server that will hand out a ticket answers with the extension empty — its
  // `extension_data` is of length zero, not a vector of length zero — which is how a client learns
  // a NewSessionTicket is coming.
  //
  // The extension is not empty in a ClientHello that brings a ticket back: that is a resumption
  // attempt, and the ticket is the extension's `opaque ticket<0..2^16-1>`. Reading a non-empty one
  // as malformed refused every resumption OpenSSL ever attempted, before the ticket was even
  // looked at, which is why the second connection answered decode_error and then fell back to a
  // full handshake.
  if config.tickets.is_on() &&
    @ext.find(hello.extensions[:], SessionTicket) is Some(_) {
    out.push({ kind: SessionTicket, data: b"", })
  }
  self.note_server_name(hello)
  // RFC 6066 §3: answered, empty, when the name chose the certificate. A renegotiation keeps the
  // certificate, and answers only a hello that asked by name again.
  if self.by_name && @ext.find(hello.extensions[:], ServerName) is Some(_) {
    out.push({ kind: ServerName, data: b"", })
  }
  if self.pick_alpn(config, hello) is Some(p) {
    out.push({ kind: Alpn, data: @ext.protocols([p][:]), })
  }
  self.answer_srtp(config, hello)
  match self.srtp_profile {
    Some(profile) =>
      out.push({ kind: UseSrtp, data: @ext.use_srtp([profile.code()][:], b""), })
    None => ()
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
  if exchange is Srp {
    return self.srp_premaster12(body)
  }
  // RFC 4279 §2: a PSK exchange's ClientKeyExchange names the key first, and plain PSK carries
  // nothing after it.
  let (psk, rest) = if exchange.takes_psk() {
    guard @msg.read_psk_identity(body[:]) is Some((identity, rest)) else {
      raise @alert.fatal(DecodeError)
    }
    (Some(known_psk(config, identity)), rest)
  } else {
    (None, body[:])
  }
  if psk is Some(psk) && exchange is Psk {
    if rest.length() > 0 {
      raise @alert.fatal(DecodeError)
    }
    return psk_premaster(Bytes::make(psk.key.length(), b'\x00')[:], psk.key[:])
  }
  guard @msg.read_client_key_exchange(
      rest,
      wide=!(exchange is (Ecdhe | EcdhePsk)),
    )
    is Some(value) else {
    raise @alert.fatal(DecodeError)
  }
  let other = match (exchange, config.key) {
    // RFC 5246 §7.4.7.2: the client's public value, explicit, against the certificate's key.
    (Dh, Dh(prime~, secret~, ..)) =>
      strip_zeros(
        @dh.shared_with(prime[:], secret[:], value[:]) catch {
          _ => raise @alert.fatal(IllegalParameter)
        },
      )
    (Rsa | RsaPsk, Rsa(key)) =>
      @keys.unwrap_premaster(
        key,
        value[:],
        version=self.client_version,
        rand=self.rand,
      )
    (Dhe | DhePsk, _) => {
      let (group, secret) = self.shares[0]
      strip_zeros(agree(group, secret, value))
    }
    _ => {
      let (group, secret) = self.shares[0]
      agree(group, secret, value)
    }
  }
  match psk {
    Some(psk) => psk_premaster(other[:], psk.key[:])
    None => other
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
    (ClientKey, Certificate) => self.on_client_chain12(config, body, raw)
    (ClientKey, ClientKeyExchange) => {
      let premaster = self.client_key12(config, body)
      self.record(raw[:])
      self.master_from(premaster)
      let (theirs, mine) = self.ciphers12()
      self.waiting = Some(theirs)
      // The writer stays as it is: RFC 5246 §6.1 keeps the current state in force until a
      // change_cipher_spec makes the pending one current, so on a renegotiation the rest of this
      // flight — and that change_cipher_spec itself — travels under the keys the connection has
      // been using. A first handshake has no writer and the question does not arise.
      self.outgoing = Some(mine)
      // §7.4.8: a client that showed a certificate proves the key before its change_cipher_spec.
      self.phase = if self.peer.length() > 0 {
        Legacy(Proof)
      } else {
        Legacy(Cipher)
      }
    }
    (Proof, CertificateVerify) => {
      self.on_client_proof12(body, raw)
      self.phase = Legacy(Cipher)
    }
    (Closing, Finished) => {
      self.check_finished12(body, client=true)
      self.record(raw[:])
      if self.resumed {
        // An abbreviated handshake: the server's Finished went out with its first flight.
        self.phase = Open
      } else {
        // RFC 5077 §3.4: the ticket goes out between the client's Finished and the server's
        // change_cipher_spec, so it travels in the clear like the rest of the handshake.
        self.remember12(config, self.sni.unwrap_or(""))
        self.send_change_cipher_spec()
        self.writer = self.outgoing
        self.outgoing = None
        self.send_finished12(client=false)
        self.phase = Open
      }
    }
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}
