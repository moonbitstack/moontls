// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A DTLS 1.3 connection (RFC 9147), client or server, without I/O.
///
/// Datagrams from the peer go in through [`receive`]; datagrams for the peer
/// come out of [`take`], one per call because that is what a socket sends.
/// Application data is read with [`read`] and written with [`write`].
///
/// The handshake itself is [`@tls.Handshake`] — DTLS 1.3 runs the TLS 1.3
/// handshake unchanged. What this adds is everything a datagram forces: an
/// epoch per direction, record number encryption, the anti-replay window, and
/// the ACK and retransmission bookkeeping of `Driver`.
///
/// **There is no clock in here.** A datagram transport has to retransmit, and
/// when to do so is a policy. So every call takes `now`, in milliseconds on the
/// caller's own monotonic clock, and [`deadline`] says when the next call to
/// [`tick`] is due. A caller with a socket multiplexes that deadline with its
/// own; a caller without one calls `tick` on a timer it already has.
pub struct Conn13 {
  priv handshake : @tls.Handshake
}

///|
/// A client connection to `host`. `now` is the time, in seconds since the Unix
/// epoch, the server's certificate is judged at.
pub fn Conn13::client(
  config : @tls.Client,
  host : String,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
) -> Conn13 raise @alert.Alert {
  let _ = (config, host, rand, now)
  raise @alert.fatal(InternalError)
}

///|
/// A server connection awaiting a ClientHello. `now` is the time a client
/// certificate is judged at; `cookie` decides whether the first answer is a
/// HelloRetryRequest carrying a stateless cookie (RFC 9147 §4.2).
pub fn Conn13::server(
  config : @tls.Server,
  rand~ : (Int32) -> Bytes,
  now? : Int64,
  cookie~ : Cookie = Off,
) -> Conn13 {
  let _ = cookie
  { handshake: @tls.Handshake::server(config, rand~, now?), }
}

///|
/// Take one datagram from the peer and process every record in it.
///
/// A datagram that is not DTLS, or one whose records do not deprotect, is
/// dropped as RFC 9147 §4.1 and §4.5.2 require — the association survives, and
/// no state moves for a record that failed. `now` is the caller's clock, in
/// milliseconds, and only advances the retransmission state.
pub fn Conn13::receive(
  self : Conn13,
  datagram : BytesView,
  now~ : Int64,
) -> Unit raise @alert.Alert {
  let _ = (self, datagram, now)
  raise @alert.fatal(InternalError)
}

///|
/// One datagram for the peer, emptied by the call. Empty means nothing is
/// waiting to be sent.
pub fn Conn13::take(self : Conn13) -> Bytes {
  let _ = self
  abort("moontls: the DTLS 1.3 connection, implemented after its interface")
}

///|
/// Queue application data, cut to fit the path's datagram size.
pub fn Conn13::write(
  self : Conn13,
  data : BytesView,
  now~ : Int64,
) -> Unit raise @alert.Alert {
  let _ = (self, data, now)
  raise @alert.fatal(InternalError)
}

///|
/// Application data received, emptied by the call.
pub fn Conn13::read(self : Conn13) -> Bytes {
  let _ = self
  abort("moontls: the DTLS 1.3 connection, implemented after its interface")
}

///|
/// Queue close_notify and stop accepting data.
pub fn Conn13::close(self : Conn13, now~ : Int64) -> Unit {
  let _ = (self, now)
  abort("moontls: the DTLS 1.3 connection, implemented after its interface")
}

///|
/// When [`tick`] is next due, in the same milliseconds `now` is given in, or
/// `None` when nothing is outstanding. A caller multiplies its socket wait by
/// this; a caller without one sleeps until it.
pub fn Conn13::deadline(self : Conn13) -> Int64? {
  let _ = self
  abort("moontls: the DTLS 1.3 connection, implemented after its interface")
}

///|
/// Report the clock and let the connection retransmit what is overdue. Called
/// when `now` has reached [`deadline`]; harmless at any other time.
pub fn Conn13::tick(self : Conn13, now~ : Int64) -> Unit raise @alert.Alert {
  let _ = (self, now)
  raise @alert.fatal(InternalError)
}

///|
/// Whether the handshake has completed and the connection is open.
pub fn Conn13::is_connected(self : Conn13) -> Bool {
  self.handshake.is_connected()
}

///|
/// Whether the connection has ended.
pub fn Conn13::is_closed(self : Conn13) -> Bool {
  self.handshake.is_closed()
}

///|
/// The application protocol ALPN settled on (RFC 7301).
pub fn Conn13::alpn(self : Conn13) -> String? {
  self.handshake.alpn()
}

///|
/// The peer's certificate chain, DER, leaf first.
pub fn Conn13::peer(self : Conn13) -> Array[Bytes] {
  self.handshake.peer()
}

///|
/// The host name a client asked for by SNI (RFC 6066 §3), on a server.
pub fn Conn13::server_name(self : Conn13) -> String? {
  self.handshake.server_name()
}

///|
/// The key-exchange group the handshake ran.
pub fn Conn13::group(self : Conn13) -> Int32? {
  self.handshake.group()
}

///|
/// The version negotiated, which for this connection is TLS 1.3.
pub fn Conn13::version(self : Conn13) -> @tls.Version? {
  self.handshake.version()
}

///|
/// The TLS 1.3 suite negotiated.
pub fn Conn13::suite(self : Conn13) -> @record.Suite? {
  self.handshake.suite()
}

///|
/// Why a client refused the server's chain, when it did.
pub fn Conn13::refused(self : Conn13) -> @x509.Refused? {
  self.handshake.refused()
}

///|
/// The keying material a DTLS-SRTP handshake exported (RFC 5764 §4.2), or
/// `None` when `use_srtp` was not negotiated.
pub fn Conn13::srtp(self : Conn13) -> @srtp.Keys? {
  self.handshake.srtp()
}
