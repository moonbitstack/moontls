// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The TLS 1.3 handshake with the record layer taken out.
//
// It turns whole handshake messages into the next ones and into key installs,
// and knows nothing about records, datagrams, epochs, flight numbering or a
// clock. The three connections — `tls::Conn`, `dtls::Conn13`, `dtls::Conn12`
// — own a record layer and drive this one, which is what lets the same
// negotiation, key schedule, certificate handling and message order serve a
// stream and a datagram transport without a second copy.
//
// The seam is `Layer`: the handshake calls `send` for content and `install` for
// keys, in the order it wants them on the wire. The layer decides how those
// become records, and it alone knows whether messages are numbered, fragmented
// and acknowledged.

///|
/// A handshake that has not yet seen a record layer.
///
/// Construct it with [`client`] or [`server`], then drive it through a [`Layer`]:
///
/// ```mbt nocheck
/// let mut conn = @tls.Conn::client(config, "example.com", rand~, now~)
/// conn.receive(socket.read()[:])   // ciphertext in
/// socket.write(conn.take())        // ciphertext out
/// ```
///
/// A `Handshake` on its own is not a connection: it has no buffer for
/// ciphertext, no sequence number and no notion of a datagram. Those belong to
/// the layer.
pub struct Handshake {
  priv phase : Phase
}

///|
/// A client handshake, its ClientHello and key shares prepared. `now` is the
/// time, in seconds since the Unix epoch, the server's certificate is judged
/// at.
pub fn Handshake::client(
  config : Client,
  host : String,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
) -> Handshake raise @alert.Alert {
  let _ = (config, host, rand, now)
  raise @alert.fatal(InternalError)
}

///|
/// A server handshake awaiting a ClientHello. `now` is the time a client
/// certificate is judged at; a server that asks for one and gives no clock
/// stops where the CertificateRequest would have gone.
pub fn Handshake::server(
  config : Server,
  rand~ : (Int32) -> Bytes,
  now? : Int64,
) -> Handshake {
  let _ = (config, rand, now)
  { phase: Waiting, }
}

///|
/// Queue the opening flight: a client's ClientHello, or nothing on a server.
pub fn[L : Layer] Handshake::opening(
  self : Handshake,
  layer : L,
) -> Unit raise @alert.Alert {
  let _ = self
  ignore(layer.datagram())
  raise @alert.fatal(InternalError)
}

///|
/// Take one whole handshake message — type, 24-bit length, body, without the
/// record or DTLSHandshake framing — and drive the handshake on it.
///
/// Content the handshake wants sent goes to `layer.send`, keys go to
/// `layer.install`, and a fatal alert is raised after it has been queued for
/// the peer, so a caller only has to close its side.
pub fn[L : Layer] Handshake::receive(
  self : Handshake,
  layer : L,
  message : BytesView,
) -> Unit raise @alert.Alert {
  let _ = (self, message)
  ignore(layer.datagram())
  raise @alert.fatal(InternalError)
}

///|
/// Queue application data, in records the layer is free to split. Before the
/// handshake has application keys this is the early (0-RTT) data path; after,
/// the ordinary one.
pub fn[L : Layer] Handshake::write(
  self : Handshake,
  layer : L,
  data : BytesView,
) -> Unit raise @alert.Alert {
  let _ = (self, data)
  ignore(layer.datagram())
  raise @alert.fatal(InternalError)
}

///|
/// Queue close_notify (RFC 8446 §6.1) and stop accepting data.
pub fn[L : Layer] Handshake::close(self : Handshake, layer : L) -> Unit {
  let _ = self
  ignore(layer.datagram())
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}

///|
/// Ask for new traffic keys in both directions (RFC 8446 §4.6.3).
pub fn[L : Layer] Handshake::update(
  self : Handshake,
  layer : L,
  request~ : Bool = true,
) -> Unit raise @alert.Alert {
  let _ = (self, request)
  ignore(layer.datagram())
  raise @alert.fatal(InternalError)
}

///|
/// Whether the handshake has completed and application data may flow.
pub fn Handshake::is_connected(self : Handshake) -> Bool {
  self.phase is Open
}

///|
/// Whether the connection has ended, by close_notify either way or by an alert.
pub fn Handshake::is_closed(self : Handshake) -> Bool {
  self.phase is Closed
}

///|
/// The version negotiated, `None` before the hellos have settled it.
pub fn Handshake::version(self : Handshake) -> Version? {
  let _ = self
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}

///|
/// The application protocol ALPN settled on (RFC 7301).
pub fn Handshake::alpn(self : Handshake) -> String? {
  let _ = self
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}

///|
/// The peer's certificate chain, DER, leaf first.
pub fn Handshake::peer(self : Handshake) -> Array[Bytes] {
  let _ = self
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}

///|
/// The host name a client asked for by SNI (RFC 6066 §3), on a server.
pub fn Handshake::server_name(self : Handshake) -> String? {
  let _ = self
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}

///|
/// The key-exchange group the handshake ran, one of the `@ext` code points;
/// `None` before it is settled, and for RSA key exchange, which has none.
pub fn Handshake::group(self : Handshake) -> Int32? {
  let _ = self
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}

///|
/// The TLS 1.3 suite negotiated.
pub fn Handshake::suite(self : Handshake) -> @record.Suite? {
  let _ = self
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}

///|
/// The TLS 1.2 suite negotiated.
pub fn Handshake::suite12(self : Handshake) -> @record.Suite12? {
  let _ = self
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}

///|
/// Why a client refused the server's chain, when it did.
pub fn Handshake::refused(self : Handshake) -> @x509.Refused? {
  let _ = self
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}

///|
/// TLS-Exporter (RFC 8446 §7.5): key material another protocol derives from
/// this connection. `len` is part of the label, not a cut taken afterwards.
pub fn Handshake::exporter(
  self : Handshake,
  label : BytesView,
  context : BytesView,
  len~ : Int32,
) -> Bytes raise @alert.Alert {
  let _ = (self, label, context, len)
  raise @alert.fatal(InternalError)
}

///|
/// The keying material a DTLS-SRTP handshake exported (RFC 5764 §4.2), once
/// both ends named a `use_srtp` profile. `None` when SRTP was not negotiated.
pub fn Handshake::srtp(self : Handshake) -> @srtp.Keys? {
  let _ = self
  abort(
    "moontls: the handshake core, implemented in the change after its interface",
  )
}
