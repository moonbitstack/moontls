// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2's pre-shared key exchanges (RFC 4279, RFC 5489): the key both ends hold goes into the
// premaster beside whatever the exchange agrees, and the client names it by identity in its
// ClientKeyExchange.

///|
/// The premaster of a PSK exchange (RFC 4279 §2): the other secret and the key, each behind a
/// two-octet length. Plain PSK's other secret is as many zeros as the key is long.
fn psk_premaster(other : BytesView, key : BytesView) -> Bytes {
  let out = Buffer()
  @wire.u16(out, other.length())
  out.write_bytesview(other)
  @wire.u16(out, key.length())
  out.write_bytesview(key)
  out.to_bytes()
}

///|
/// The key a ClientKeyExchange names. RFC 4279 §2 lets a server answer an identity it does not know
/// with `unknown_psk_identity`, which is what this one does.
fn known_psk(config : Server, identity : Bytes) -> Psk raise @alert.Alert {
  guard config.psk.iter().find_first(p => p.identity == identity) is Some(psk) else {
    raise @alert.fatal(UnknownPskIdentity)
  }
  psk
}

///|
/// The first message a TLS 1.2 client waits for after the ServerHello. A suite without a
/// certificate skips the Certificate; plain PSK has no exchange to send either, though a server
/// may still send a ServerKeyExchange to carry a hint.
fn first_step12(suite : @record.Suite12) -> Step12 {
  match (suite.auth, suite.exchange) {
    (Shared, Psk) => Done
    (Shared, _) => Exchange
    _ => Chain
  }
}

///|
/// A ServerKeyExchange of a PSK suite: an empty identity hint, which RFC 4279 §5.2 has servers
/// leave out without an application profile asking for one, and for DHE_PSK and ECDHE_PSK the
/// parameters, unsigned, since the key authenticates them.
fn Conn::psk_exchange12(self : Conn, group : Int32) -> Bytes raise @alert.Alert {
  let params = self.offer12(group)
  @msg.frame(ServerKeyExchange, @msg.psk_identity(b""[:], params[:])[:])
}

///|
/// A PSK suite's ServerKeyExchange on the client: the hint is passed over (RFC 4279 §5.2), and the
/// parameters after it are judged as a signed exchange's would be.
fn Conn::read_psk_exchange12(
  self : Conn,
  config : Client,
  body : Bytes,
) -> Unit raise @alert.Alert {
  guard @msg.read_psk_identity(body[:]) is Some((_, rest)) else {
    raise @alert.fatal(DecodeError)
  }
  match self.suite12.unwrap().exchange {
    DhePsk => {
      guard @msg.read_dh_params(rest) is Some((prime, generator, public)) else {
        raise @alert.fatal(DecodeError)
      }
      self.accept_dh12(config, prime, generator, public) |> ignore
    }
    EcdhePsk => {
      guard @msg.read_key_params(rest) is Some((group, public)) else {
        raise @alert.fatal(DecodeError)
      }
      self.accept_curve12(config, group, public) |> ignore
    }
    _ => if rest.length() > 0 { raise @alert.fatal(DecodeError) }
  }
}
