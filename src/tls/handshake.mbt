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
/// Construct it with [`client`] or [`server`], then drive it through a [`Layer`].
/// A `Handshake` on its own is not a connection: it has no buffer for
/// ciphertext, no sequence number and no notion of a datagram.
pub struct Handshake {
  priv conn : Conn
}

///|
/// A client handshake, its ClientHello and key shares prepared and queued. `now`
/// is the time, in seconds since the Unix epoch, the server's certificate is
/// judged at.
pub fn Handshake::client(
  config : Client,
  host : String,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
) -> Handshake raise @alert.Alert {
  { conn: Conn::pipe_client(config, host, rand~, now~), }
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
  { conn: Conn::pipe_server(config, rand~, now?), }
}

///|
/// Queue the opening flight: a client's ClientHello, or nothing on a server.
pub fn[L : Layer] Handshake::opening(
  self : Handshake,
  layer : L,
) -> Unit raise @alert.Alert {
  self.drain(layer)
}

///|
/// Take one whole handshake message — type, 24-bit length, body, without the
/// record or DTLSHandshake framing — and drive the handshake on it.
///
/// Content the handshake wants sent goes to `layer.send`, keys go to
/// `layer.install`, and a fatal alert is queued for the peer before it is
/// raised, so a caller only has to close its side.
pub fn[L : Layer] Handshake::receive(
  self : Handshake,
  layer : L,
  message : BytesView,
) -> Unit raise @alert.Alert {
  let failed = try {
    self.conn.feed_message(message)
    None
  } catch {
    e => Some(e)
  }
  self.drain(layer)
  match failed {
    Some(e) => raise e
    None => ()
  }
}

///|
/// A change_cipher_spec arrived (DTLS 1.2). It is not a handshake message and
/// never enters the transcript, but it is what moves a direction to the new
/// keys and advances the 1.2 state machine.
pub fn Handshake::change_cipher_spec(self : Handshake) -> Unit raise @alert.Alert {
  self.conn.on_change_cipher_spec(b"\x01")
}

///|
/// Queue application data, cut into records the layer is free to frame. The
/// handshake must have opened; DTLS carries no 0-RTT here, and the connections
/// seal application data with the layer's own keys.
pub fn[L : Layer] Handshake::write(
  self : Handshake,
  layer : L,
  data : BytesView,
) -> Unit raise @alert.Alert {
  if !self.conn.is_connected() {
    raise @alert.fatal(InternalError)
  }
  let mut at = 0
  while at < data.length() {
    let end = @cmp.minimum(at + @record.max_fragment, data.length())
    layer.send(ApplicationData, data[at:end])
    at = end
  }
}

///|
/// Queue close_notify (RFC 8446 §6.1) and stop accepting data.
pub fn[L : Layer] Handshake::close(self : Handshake, layer : L) -> Unit {
  self.conn.close()
  self.drain(layer) catch {
    _ => ()
  }
}

///|
/// Ask for new traffic keys in both directions (RFC 8446 §4.6.3). A datagram
/// transport makes this a new epoch, which the DTLS connections do not yet
/// carry; only a stream has it.
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
  self.conn.is_connected()
}

///|
/// Whether the connection has ended, by close_notify either way or by an alert.
pub fn Handshake::is_closed(self : Handshake) -> Bool {
  self.conn.is_closed()
}

///|
/// The version negotiated, `None` before the hellos have settled it.
pub fn Handshake::version(self : Handshake) -> Version? {
  self.conn.version()
}

///|
/// The application protocol ALPN settled on (RFC 7301).
pub fn Handshake::alpn(self : Handshake) -> String? {
  self.conn.alpn()
}

///|
/// The peer's certificate chain, DER, leaf first.
pub fn Handshake::peer(self : Handshake) -> Array[Bytes] {
  self.conn.peer()
}

///|
/// The host name a client asked for by SNI (RFC 6066 §3), on a server.
pub fn Handshake::server_name(self : Handshake) -> String? {
  self.conn.server_name()
}

///|
/// The key-exchange group the handshake ran, one of the `@ext` code points;
/// `None` before it is settled, and for RSA key exchange, which has none.
pub fn Handshake::group(self : Handshake) -> Int32? {
  self.conn.group()
}

///|
/// The TLS 1.3 suite negotiated.
pub fn Handshake::suite(self : Handshake) -> @record.Suite? {
  self.conn.suite()
}

///|
/// The TLS 1.2 suite negotiated.
pub fn Handshake::suite12(self : Handshake) -> @record.Suite12? {
  self.conn.suite12()
}

///|
/// Why a client refused the server's chain, when it did.
pub fn Handshake::refused(self : Handshake) -> @x509.Refused? {
  self.conn.refused()
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
  if self.conn.exporter.length() == 0 {
    raise @alert.fatal(InternalError)
  }
  @keys.exporter(
    self.conn.exporter[:],
    label,
    context,
    len~,
    digest=self.conn.digest(),
    prefix=self.conn.prefix(),
  )
}

///|
/// The keying material a DTLS-SRTP handshake exported (RFC 5764 §4.2), once
/// both ends named a `use_srtp` profile. `None` when SRTP was not negotiated.
pub fn Handshake::srtp(self : Handshake) -> @srtp.Keys? {
  match self.conn.srtp_profile {
    Some(profile) =>
      match self.conn.version() {
        Some(Tls12) =>
          Some(
            @srtp.keys12(
              self.conn.master[:],
              self.conn.client_random[:],
              self.conn.server_random[:],
              profile,
              digest=self.conn.digest(),
            ),
          )
        _ =>
          Some(
            @srtp.keys(
              self.conn.exporter[:],
              profile,
              digest=self.conn.digest(),
            ),
          )
      }
    None => None
  }
}

///|
/// Apply what the handshake has queued since the last call, in order, through
/// the record layer's contract.
fn[L : Layer] Handshake::drain(
  self : Handshake,
  layer : L,
) -> Unit raise @alert.Alert {
  let client = self.conn.is_client()
  for one in self.conn.take_pipe() {
    match one {
      Message(message) => layer.send(Handshake, message[:])
      Alert(body) => layer.send(Alert, body[:])
      ChangeCipherSpec => layer.change_cipher_spec()
      Keys13(level, client_secret, server_secret) => {
        let epoch = match level {
          Initial => 0UL
          Handshake => 2UL
          Application => 3UL
        }
        guard self.conn.suite() is Some(suite) else {
          raise @alert.fatal(InternalError)
        }
        if client {
          layer.install(Write, epoch, Traffic(suite, client_secret))
          layer.install(Read, epoch, Traffic(suite, server_secret))
        } else {
          layer.install(Read, epoch, Traffic(suite, client_secret))
          layer.install(Write, epoch, Traffic(suite, server_secret))
        }
      }
      Keys12(suite, ck, civ, cm, sk, siv, sm, etm) =>
        if client {
          layer.install(Write, 1UL, Block(suite, ck, civ, cm, etm))
          layer.install(Read, 1UL, Block(suite, sk, siv, sm, etm))
        } else {
          layer.install(Read, 1UL, Block(suite, ck, civ, cm, etm))
          layer.install(Write, 1UL, Block(suite, sk, siv, sm, etm))
        }
    }
  }
}
