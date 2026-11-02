// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Renegotiation (RFC 5746, RFC 5246 §7.4.1.1): a second handshake on an open TLS 1.2 connection,
// started by the server's HelloRequest.
//
// What makes it safe is renegotiation_info: both ends put the previous handshake's Finished
// verify_data into the new ClientHello and ServerHello, so a recorded hello cannot be spliced into
// someone else's session. That is also why the previous handshake's Finished values are kept after
// it ends. This library refuses renegotiation unless the configuration asks for it — a warning
// either way, so a connection that neither side wants to renegotiate simply goes on.

///|
/// The `renegotiated_connection` this end would send: the previous handshake's verify_data, or
/// nothing at all on a first handshake (RFC 5746 §3.4).
fn Conn::renegotiation_info(self : Conn) -> Bytes {
  if self.client_finished.length() == 0 && self.server_finished.length() == 0 {
    return @ext.no_renegotiation()
  }
  @ext.renegotiation(self.client_finished[:], self.server_finished[:])
}

///|
/// Whether a `renegotiation_info` payload names the handshake that came before this one.
fn Conn::renews_fine(self : Conn, data : Bytes) -> Bool raise @alert.Alert {
  // A payload that is not one of the two shapes is a handshake_failure rather than a decode_error:
  // §4.4 is about a peer that did not follow the rule, and the message itself parsed.
  guard @ext.read_renegotiation(data[:]) is Some((client, server)) else {
    return false
  }
  let fresh = self.client_finished.length() == 0 &&
    self.server_finished.length() == 0
  if fresh {
    // §3.4: an initial handshake carries an empty one, and anything else is an attempt at
    // something this connection never agreed to.
    if client.length() > 0 || server.length() > 0 {
      raise @alert.fatal(HandshakeFailure)
    }
    return true
  }
  client == self.client_finished && server == self.server_finished
}

///|
/// Throw away the handshake half of the connection, keeping the keys the old one left in force:
/// what a new ClientHello begins from.
fn Conn::restart_handshake(self : Conn) -> Unit {
  self.transcript = None
  self.suite12 = None
  self.master = b""
  self.waiting = None
  self.outgoing = None
  self.asked = None
  self.proved = false
  self.proof12 = None
  self.resumed = false
  self.psk12 = b""
  self.resume12 = None
  self.ticket12 = b""
  // The new handshake has its own change_cipher_spec, and its ServerHello has to say it knows
  // about renegotiation again.
  self.ccs_sent = false
  self.ccs_read = false
  self.indicated = false
}

///|
/// Ask the peer for a new handshake (RFC 5246 §7.4.1.1). Only a server may: a HelloRequest is the
/// server's message, and one arriving at a server is an unexpected_message.
///
/// The new handshake begins when the client answers with its ClientHello; until then the connection
/// is open and both ends may keep writing. Nothing happens unless `renegotiation` was asked for on
/// both sides, and the request itself is refused with a warning when it was not.
pub fn Conn::renegotiate(self : Conn) -> Unit raise @alert.Alert {
  guard self.phase is Open && self.version == Some(Tls12) else {
    raise @alert.fatal(InternalError)
  }
  guard self.side is Server(config) else { raise @alert.fatal(InternalError) }
  if !config.renegotiation {
    raise @alert.fatal(InternalError)
  }
  if self.quic is Some(_) {
    raise @alert.fatal(InternalError)
  }
  self.aligned()
  self.send_handshake(@msg.frame(Other(0), b""[:]))
}

///|
/// The client's answer to a HelloRequest: a new ClientHello carrying the previous handshake's
/// verify_data, over a transcript that starts again from nothing.
fn Conn::start_renegotiation(
  self : Conn,
  config : Client,
) -> Unit raise @alert.Alert {
  self.restart_handshake()
  self.client_random = (self.rand)(32)
  self.session = (self.rand)(32)
  self.shares = []
  self.retried = false
  self.hrr = b""
  self.first_hello = b""
  self.phase = Legacy(Chain)
  self.send_hello(self.opening_shares(config), None)
}

///|
/// The server's side: a ClientHello that arrived on an open connection, accepted only when it
/// carries the verify_data of the handshake that opened the connection (RFC 5746 §4.4).
fn Conn::accept_renegotiation(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  guard @ext.find(hello.extensions[:], RenegotiationInfo) is Some(e) else {
    // §4.4: a renegotiation without it is a spliced handshake, and the connection ends.
    raise @alert.fatal(HandshakeFailure)
  }
  if !self.renews_fine(e.data) {
    raise @alert.fatal(HandshakeFailure)
  }
  self.restart_handshake()
  // The new hello is judged as a first one would be, with the previous handshake's secrets gone
  // and the old keys still in force until the new change_cipher_spec.
  self.client_hello12(config, hello, raw)
}
