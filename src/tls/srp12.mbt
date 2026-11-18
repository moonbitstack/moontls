// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2's SRP exchange (RFC 5054): the client names the user in its hello, the server answers
// with the user's group, salt and its public value, and both reach a premaster only a client
// knowing the password and a server holding the verifier can compute.

///|
/// The user a hello logs in as. A hello without the srp extension is `unknown_psk_identity`
/// (§2.5.1.2), and so is a name this server holds no verifier for (§2.5.1.3).
fn srp_user(config : Server, hello : @msg.Hello) -> SrpUser raise @alert.Alert {
  guard @ext.find(hello.extensions[:], Srp) is Some(e) else {
    raise @alert.fatal(UnknownPskIdentity)
  }
  guard @ext.read_srp(e.data[:]) is Some(identity) else {
    raise @alert.fatal(DecodeError)
  }
  guard config.srp.iter().find_first(u => u.identity == identity) is Some(user) else {
    raise @alert.fatal(UnknownPskIdentity)
  }
  user
}

///|
/// The server's ServerKeyExchange (§2.8.2): the user's group and salt and the server's public value
/// B, signed when the suite shows a certificate.
fn Conn::srp_exchange12(
  self : Conn,
  config : Server,
  user : SrpUser,
  scheme : Int32?,
) -> Bytes raise @alert.Alert {
  let server = @srp.Server::new(
    user.group,
    user.verifier[:],
    (self.rand)(32)[:],
  ) catch {
    _ => raise @alert.fatal(InternalError)
  }
  self.srp_server = Some(server)
  let params = @msg.srp_params(
    user.group.prime().to_octets()[:],
    user.group.generator().to_octets()[:],
    user.salt[:],
    server.public()[:],
  )
  let body = match scheme {
    Some(scheme) => {
      let signed = Buffer()
      signed.write_bytes(self.client_random)
      signed.write_bytes(self.server_random)
      signed.write_bytes(params)
      let signature = sign12(config.key, scheme, signed.to_bytes())
      @msg.server_key_exchange(params[:], scheme, signature[:])
    }
    None => params
  }
  @msg.frame(ServerKeyExchange, body[:])
}

///|
/// The premaster from the client's public value A. A value that is 0 modulo N is
/// `illegal_parameter` (§2.5.4).
fn Conn::srp_premaster12(self : Conn, body : Bytes) -> Bytes raise @alert.Alert {
  guard self.srp_server is Some(server) else {
    raise @alert.fatal(InternalError)
  }
  guard @msg.read_client_key_exchange(body[:], wide=true) is Some(a) else {
    raise @alert.fatal(DecodeError)
  }
  server.premaster(a[:]) catch {
    _ => raise @alert.fatal(IllegalParameter)
  }
}

///|
/// The client's reading of an SRP ServerKeyExchange (§2.5.3): parameters outside RFC 5054's
/// appendix, or a prime smaller than `dh_bits`, are `insufficient_security`; a signed one is
/// checked against the certificate.
fn Conn::read_srp_exchange12(
  self : Conn,
  config : Client,
  body : Bytes,
) -> Unit raise @alert.Alert {
  let signed = !(self.suite12.unwrap().auth is Shared)
  guard @msg.read_srp_exchange(body[:], signed~)
    is Some((prime, generator, salt, public, scheme, signature)) else {
    raise @alert.fatal(DecodeError)
  }
  guard @srp.Group::of(prime[:], generator[:]) is Some(group) &&
    group.bits() >= config.dh_bits else {
    raise @alert.fatal(InsufficientSecurity)
  }
  if signed {
    if !config.schemes12.contains(scheme) {
      raise @alert.fatal(IllegalParameter)
    }
    let covered = Buffer()
    covered.write_bytes(self.client_random)
    covered.write_bytes(self.server_random)
    covered.write_bytes(
      @msg.srp_params(prime[:], generator[:], salt[:], public[:]),
    )
    if !verified12(self.leaf12(), scheme, covered.to_bytes(), signature) {
      raise @alert.fatal(DecryptError)
    }
  }
  self.srp_offer = Some((group, salt, public))
}

///|
/// The client's premaster and ClientKeyExchange body (§2.6): A, and the secret the password and
/// the server's offer give. A server value that is 0 modulo N is `illegal_parameter` (§2.5.3).
fn Conn::srp_client12(
  self : Conn,
  config : Client,
) -> (Bytes, Bytes) raise @alert.Alert {
  guard config.srp is Some(login) && self.srp_offer is Some((group, salt, b)) else {
    raise @alert.fatal(InternalError)
  }
  let client = @srp.Client::new(group, (self.rand)(32)[:]) catch {
    _ => raise @alert.fatal(InternalError)
  }
  let premaster = client.premaster(
    b[:],
    salt=salt[:],
    identity=login.identity[:],
    password=login.password[:],
  ) catch {
    _ => raise @alert.fatal(IllegalParameter)
  }
  (premaster, @msg.client_key_exchange(client.public()[:], wide=true))
}
