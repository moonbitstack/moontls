// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A DTLS 1.2 connection (RFC 6347), client or server, without I/O.
///
/// The shape of the API is [`Conn13`]'s — datagrams in through [`receive`],
/// datagrams out of [`take`], a caller-supplied clock — because a caller should
/// not have to care which DTLS it got. What differs is underneath, and it is
/// all of the record layer: DTLS 1.2 has its own header (an explicit epoch and
/// a 48-bit sequence number, no unified header), explicit-IV AEAD and CBC
/// rather than 1.3's inner-content-type construction, and whole-flight
/// retransmission without ACKs.
///
/// The handshake messages, the TLS 1.2 suite table and the PRF are shared with
/// `@tls`; only the way they travel is here.
pub struct Conn12 {
  priv handshake : @tls.Handshake
}

///|
/// A client connection to `host`. `now` is the time, in seconds since the Unix
/// epoch, the server's certificate is judged at.
pub fn Conn12::client(
  config : @tls.Client,
  host : String,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
) -> Conn12 raise @alert.Alert {
  let _ = (config, host, rand, now)
  raise @alert.fatal(InternalError)
}

///|
/// A server connection awaiting a ClientHello. `cookie` decides whether the
/// first answer is a HelloVerifyRequest (RFC 6347 §4.2.1).
pub fn Conn12::server(
  config : @tls.Server,
  rand~ : (Int32) -> Bytes,
  now? : Int64,
  cookie~ : Cookie = Off,
) -> Conn12 {
  let _ = cookie
  { handshake: @tls.Handshake::server(config, rand~, now?), }
}

///|
/// Take one datagram from the peer and process every record in it. `now` is
/// the caller's clock, in milliseconds.
pub fn Conn12::receive(
  self : Conn12,
  datagram : BytesView,
  now~ : Int64,
) -> Unit raise @alert.Alert {
  let _ = (self, datagram, now)
  raise @alert.fatal(InternalError)
}

///|
/// One datagram for the peer, emptied by the call.
pub fn Conn12::take(self : Conn12) -> Bytes {
  let _ = self
  abort("moontls: the DTLS 1.2 connection, implemented after its interface")
}

///|
/// Queue application data, cut to fit the path's datagram size.
pub fn Conn12::write(
  self : Conn12,
  data : BytesView,
  now~ : Int64,
) -> Unit raise @alert.Alert {
  let _ = (self, data, now)
  raise @alert.fatal(InternalError)
}

///|
/// Application data received, emptied by the call.
pub fn Conn12::read(self : Conn12) -> Bytes {
  let _ = self
  abort("moontls: the DTLS 1.2 connection, implemented after its interface")
}

///|
/// Queue close_notify and stop accepting data.
pub fn Conn12::close(self : Conn12, now~ : Int64) -> Unit {
  let _ = (self, now)
  abort("moontls: the DTLS 1.2 connection, implemented after its interface")
}

///|
/// When [`tick`] is next due, in the same milliseconds `now` is given in, or
/// `None` when no flight is outstanding.
pub fn Conn12::deadline(self : Conn12) -> Int64? {
  let _ = self
  abort("moontls: the DTLS 1.2 connection, implemented after its interface")
}

///|
/// Report the clock and resend an unacknowledged flight when it is due
/// (RFC 6347 §4.2.4). DTLS 1.2 has no ACK message: a flight is acknowledged by
/// the answer to it, and nothing else.
pub fn Conn12::tick(self : Conn12, now~ : Int64) -> Unit raise @alert.Alert {
  let _ = (self, now)
  raise @alert.fatal(InternalError)
}

///|
/// Whether the handshake has completed and the connection is open.
pub fn Conn12::is_connected(self : Conn12) -> Bool {
  self.handshake.is_connected()
}

///|
/// Whether the connection has ended.
pub fn Conn12::is_closed(self : Conn12) -> Bool {
  self.handshake.is_closed()
}

///|
/// The application protocol ALPN settled on (RFC 7301).
pub fn Conn12::alpn(self : Conn12) -> String? {
  self.handshake.alpn()
}

///|
/// The peer's certificate chain, DER, leaf first.
pub fn Conn12::peer(self : Conn12) -> Array[Bytes] {
  self.handshake.peer()
}

///|
/// The host name a client asked for by SNI (RFC 6066 §3), on a server.
pub fn Conn12::server_name(self : Conn12) -> String? {
  self.handshake.server_name()
}

///|
/// The key-exchange group the handshake ran; `None` for RSA key exchange.
pub fn Conn12::group(self : Conn12) -> Int32? {
  self.handshake.group()
}

///|
/// The version negotiated, which for this connection is TLS 1.2.
pub fn Conn12::version(self : Conn12) -> @tls.Version? {
  self.handshake.version()
}

///|
/// The TLS 1.2 suite negotiated.
pub fn Conn12::suite(self : Conn12) -> @record.Suite12? {
  self.handshake.suite12()
}

///|
/// Why a client refused the server's chain, when it did.
pub fn Conn12::refused(self : Conn12) -> @x509.Refused? {
  self.handshake.refused()
}

///|
/// The keying material a DTLS-SRTP handshake exported (RFC 5764 §4.2), or
/// `None` when `use_srtp` was not negotiated.
pub fn Conn12::srtp(self : Conn12) -> @srtp.Keys? {
  self.handshake.srtp()
}
