// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An encryption level of a QUIC connection (RFC 9001 §4.1.4).
#derive(Eq, Debug)
pub(all) enum Level {
  Initial
  Handshake
  Application
}

///|
pub extend Level with Eq::{equal, not_equal}

///|
pub extend Level with Debug::{to_repr}

///|
/// What a QUIC handshake asks of its transport, in the order it must happen (RFC 9001 §4.1.3).
#derive(Eq, Debug)
pub(all) enum Step {
  /// Handshake bytes to send in CRYPTO frames at a level.
  Send(Level, Bytes)
  /// The traffic secrets of a level, which from here on has keys.
  Keys(Level, client~ : Bytes, server~ : Bytes)
  /// The client's early traffic secret and the suite it belongs to (RFC 9001 §4.6): a client that
  /// offered 0-RTT has it before its ClientHello goes out, a server once it has taken the offer.
  /// There is no level for it because 0-RTT carries no CRYPTO frames.
  Early(secret~ : Bytes, suite~ : @record.Suite)
}

///|
pub extend Step with Eq::{equal, not_equal}

///|
pub extend Step with Debug::{to_repr}

///|
/// The QUIC side of a connection: TLS messages travel in CRYPTO frames, so there are no records,
/// no change_cipher_spec and no alerts on the wire (RFC 9001 §4, §8.4).
priv struct Quic {
  params : Bytes
  steps : Array[Step]
  mut writing : Level
  mut reading : Level
  mut peer_params : Bytes?
}

///|
fn Quic::new(params : Bytes) -> Quic {
  { params, steps: [], writing: Initial, reading: Initial, peer_params: None, }
}

///|
/// A QUIC server connection awaiting a ClientHello. `params` is the encoded transport parameters
/// it declares (RFC 9001 §8.2). The handshake goes in through `crypto` and what it asks for comes
/// out of `steps`; `take`, `read` and `write` have no part in it.
///
/// `now` is the time in seconds since the Unix epoch, as for `Conn::server`: tickets and client
/// certificates are judged at it, and a server that leaves it out neither issues nor takes a
/// ticket.
pub fn Conn::quic_server(
  config : Server,
  params~ : Bytes,
  rand~ : (Int32) -> Bytes,
  now? : Int64,
) -> Conn {
  Conn::make(
    Server(config),
    rand,
    now.unwrap_or(0L),
    Waiting,
    quic=Quic::new(params),
  )
}

///|
/// A QUIC client connection to `host`, its ClientHello already in `steps`.
pub fn Conn::quic_client(
  config : Client,
  host : String,
  params~ : Bytes,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
) -> Conn raise @alert.Alert {
  let conn = Conn::make(
    Client(config, host),
    rand,
    now,
    Expect(@hs.Client::new()),
    quic=Quic::new(params),
  )
  conn.hello_first(config)
  conn
}

///|
/// Feed CRYPTO bytes that arrived at `level`, contiguous and in order. Bytes at a level the
/// handshake is not reading are an unexpected_message (RFC 9001 §4.1.3). A fatal alert is raised
/// for the transport to close with (RFC 9001 §4.8); nothing is queued, since QUIC carries no alerts.
pub fn Conn::crypto(
  self : Conn,
  level : Level,
  data : BytesView,
) -> Unit raise @alert.Alert {
  guard self.quic is Some(q) else { raise @alert.fatal(InternalError) }
  if self.phase is Closed {
    return
  }
  errdefer {
    self.phase = Closed
  }
  if level != q.reading {
    raise @alert.fatal(UnexpectedMessage)
  }
  for b in data {
    self.messages.push(b)
  }
  self.handshake()
}

///|
/// What the handshake has asked of the transport since the last call, in order, emptied by it.
pub fn Conn::steps(self : Conn) -> Array[Step] {
  guard self.quic is Some(q) else { return [] }
  let out = q.steps.copy()
  q.steps.clear()
  out
}

///|
/// The transport parameters the peer declared (RFC 9001 §8.2): on a server from the ClientHello, on
/// a client from EncryptedExtensions. `None` before they arrive.
pub fn Conn::peer_params(self : Conn) -> Bytes? {
  match self.quic {
    Some(q) => q.peer_params
    None => None
  }
}

///|
/// Hold a ClientHello to what QUIC requires of it: no legacy_session_id (RFC 9001 §8.4), transport
/// parameters (§8.2), and ALPN (§8.1).
fn Quic::on_hello(self : Quic, hello : @msg.Hello) -> Unit raise @alert.Alert {
  if hello.session_id.length() > 0 {
    raise @alert.fatal(IllegalParameter)
  }
  guard @ext.find(hello.extensions[:], QuicTransportParameters) is Some(e) else {
    raise @alert.fatal(MissingExtension)
  }
  guard @ext.find(hello.extensions[:], Alpn) is Some(_) else {
    raise @alert.fatal(NoApplicationProtocol)
  }
  self.peer_params = Some(e.data)
}

///|
/// A level has keys. It writes there from now on; it reads there too, but for the application
/// level on a server, which reads the client's Finished at the handshake level first.
fn Conn::keyed(self : Conn, level : Level) -> Unit {
  match self.pipe {
    Some(p) => {
      match level {
        Initial => ()
        Handshake =>
          p.push(Keys13(Handshake, self.client_secret, self.server_secret))
        Application =>
          p.push(Keys13(Application, self.client_app, self.server_app))
      }
      return
    }
    None => ()
  }
  guard self.quic is Some(q) else { return }
  match level {
    Initial => ()
    Handshake => {
      q.steps.push(
        Keys(Handshake, client=self.client_secret, server=self.server_secret),
      )
      q.writing = Handshake
      q.reading = Handshake
    }
    Application => {
      q.steps.push(
        Keys(Application, client=self.client_app, server=self.server_app),
      )
      q.writing = Application
      if self.side is Client(_, _) {
        q.reading = Application
      }
    }
  }
}
