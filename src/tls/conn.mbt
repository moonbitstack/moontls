// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
priv enum Side {
  Client(Client, String)
  Server(Server)
}

///|
priv enum Phase {
  /// Client: ClientHello sent, the server's reply not yet in.
  Hello
  /// Client: ServerHello in, the encrypted flight being read.
  Flight
  /// Server: ClientHello awaited (again, after a HelloRetryRequest).
  Waiting
  /// Server: flight sent, the client's Finished awaited.
  Finishing
  Open
  Closed
}

///|
/// A TLS 1.3 connection (RFC 8446), client or server, without I/O: ciphertext from the peer goes
/// in through `receive`, ciphertext for the peer comes out of `take`, application data is read
/// with `read` and written with `write`. Randomness and the time come from the caller.
pub struct Conn {
  priv side : Side
  priv rand : (Int32) -> Bytes
  priv now : Int64
  priv mut phase : Phase
  priv inbox : Array[Byte]
  priv messages : Array[Byte]
  priv outbox : Buffer
  priv plain : Buffer
  priv mut suite : @record.Suite?
  priv mut transcript : @keys.Transcript?
  priv mut first_hello : Bytes
  priv mut retried : Bool
  priv mut shares : Array[(Int32, Bytes)]
  priv mut session : Bytes
  priv mut handshake_secret : Bytes
  priv mut client_secret : Bytes
  priv mut server_secret : Bytes
  priv mut client_app : Bytes
  priv mut server_app : Bytes
  priv mut reader : @record.Cipher?
  priv mut writer : @record.Cipher?
  priv mut alpn : String?
  priv mut sni : String?
  priv mut peer : Array[Bytes]
  priv mut refused : @x509.Refused?
  priv mut requested : Bool
}

///|
fn Conn::make(
  side : Side,
  rand : (Int32) -> Bytes,
  now : Int64,
  phase : Phase,
) -> Conn {
  {
    side,
    rand,
    now,
    phase,
    inbox: [],
    messages: [],
    outbox: Buffer(),
    plain: Buffer(),
    suite: None,
    transcript: None,
    first_hello: b"",
    retried: false,
    shares: [],
    session: b"",
    handshake_secret: b"",
    client_secret: b"",
    server_secret: b"",
    client_app: b"",
    server_app: b"",
    reader: None,
    writer: None,
    alpn: None,
    sni: None,
    peer: [],
    refused: None,
    requested: false,
  }
}

///|
/// A server connection awaiting a ClientHello.
pub fn Conn::server(config : Server, rand~ : (Int32) -> Bytes) -> Conn {
  Conn::make(Server(config), rand, 0L, Waiting)
}

///|
/// A client connection to `host`, its ClientHello already queued for `take`. `now` is the time,
/// in seconds since the Unix epoch, the server's certificate is judged at.
pub fn Conn::client(
  config : Client,
  host : String,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
) -> Conn raise @alert.Alert {
  let conn = Conn::make(Client(config, host), rand, now, Hello)
  conn.session = rand(32)
  let group = config.groups.get(0).unwrap_or(@ext.x25519)
  let (secret, public) = share(group, rand)
  conn.shares = [(group, secret)]
  conn.send_hello([(group, public)], None)
  conn
}

///|
/// Feed ciphertext from the peer. A fatal alert raised here has also been queued for `take`, so
/// the peer is told why before the connection is dropped.
pub fn Conn::receive(self : Conn, data : BytesView) -> Unit raise @alert.Alert {
  if self.phase is Closed {
    return
  }
  for b in data {
    self.inbox.push(b)
  }
  self.pump() catch {
    @alert.Alert(level~, kind~) => {
      self.fail(kind)
      raise @alert.Alert(level~, kind~)
    }
  }
}

///|
/// Ciphertext for the peer, emptied by the call.
pub fn Conn::take(self : Conn) -> Bytes {
  let out = self.outbox.to_bytes()
  self.outbox.reset()
  out
}

///|
/// Application data received, emptied by the call.
pub fn Conn::read(self : Conn) -> Bytes {
  let out = self.plain.to_bytes()
  self.plain.reset()
  out
}

///|
/// Queue application data for the peer, in records of at most 2^14 octets.
pub fn Conn::write(self : Conn, data : BytesView) -> Unit raise @alert.Alert {
  guard self.phase is Open && self.writer is Some(w) else {
    raise @alert.fatal(InternalError)
  }
  let mut at = 0
  while at < data.length() {
    let end = @cmp.minimum(at + @record.max_fragment, data.length())
    self.outbox.write_bytes(w.seal(ApplicationData, data[at:end]))
    at = end
  }
}

///|
/// Queue close_notify (RFC 8446 §6.1) and stop accepting data.
pub fn Conn::close(self : Conn) -> Unit {
  if self.phase is Closed {
    return
  }
  self.send_alert(@alert.warning(CloseNotify))
  self.phase = Closed
}

///|
/// Ask for new traffic keys in both directions (RFC 8446 §4.6.3).
pub fn Conn::update(
  self : Conn,
  request~ : Bool = true,
) -> Unit raise @alert.Alert {
  guard self.phase is Open else { raise @alert.fatal(InternalError) }
  self.send_update(request)
}

///|
/// Whether the handshake has completed and the connection is open.
pub fn Conn::is_connected(self : Conn) -> Bool {
  self.phase is Open
}

///|
/// Whether the connection has ended, by close_notify either way or by an alert.
pub fn Conn::is_closed(self : Conn) -> Bool {
  self.phase is Closed
}

///|
/// The application protocol ALPN settled on (RFC 7301).
pub fn Conn::alpn(self : Conn) -> String? {
  self.alpn
}

///|
/// The peer's certificate chain, DER, leaf first.
pub fn Conn::peer(self : Conn) -> Array[Bytes] {
  self.peer
}

///|
/// The host name a client asked for by SNI (RFC 6066 §3), on a server.
pub fn Conn::server_name(self : Conn) -> String? {
  self.sni
}

///|
/// The suite negotiated.
pub fn Conn::suite(self : Conn) -> @record.Suite? {
  self.suite
}

///|
/// Why a client refused the server's chain, when it did.
pub fn Conn::refused(self : Conn) -> @x509.Refused? {
  self.refused
}

///|
fn Conn::fail(self : Conn, kind : @alert.Kind) -> Unit {
  if self.phase is Closed {
    return
  }
  self.send_alert(@alert.fatal(kind))
  self.phase = Closed
}

///|
fn Conn::send_alert(self : Conn, alert : @alert.Alert) -> Unit {
  let body = @alert.encode(alert)
  match self.writer {
    Some(w) =>
      self.outbox.write_bytes(w.seal(Alert, body[:]) catch { _ => return })
    None =>
      self.outbox.write_bytes(
        @record.encode(Alert, body[:]) catch {
          _ => return
        },
      )
  }
}

///|
/// Queue handshake messages: in the clear before keys, sealed after.
fn Conn::send_handshake(self : Conn, data : Bytes) -> Unit raise @alert.Alert {
  let mut at = 0
  while at < data.length() {
    let end = @cmp.minimum(at + @record.max_fragment, data.length())
    let part = data[at:end]
    match self.writer {
      Some(w) => self.outbox.write_bytes(w.seal(Handshake, part))
      None => self.outbox.write_bytes(@record.encode(Handshake, part))
    }
    at = end
  }
}

///|
fn Conn::digest(self : Conn) -> @keys.Digest {
  match self.suite {
    Some(s) => s.digest()
    None => Sha256
  }
}

///|
fn Conn::record(self : Conn, message : BytesView) -> Unit {
  if self.transcript is Some(t) {
    t.add(message)
  }
}

///|
fn Conn::th(self : Conn) -> Bytes {
  match self.transcript {
    Some(t) => t.hash()
    None => b""
  }
}

///|
/// Start the transcript once the suite fixes its hash. After a HelloRetryRequest the first
/// ClientHello enters as its hash in a synthetic message_hash message (RFC 8446 §4.4.1).
fn Conn::begin_transcript(self : Conn, retry : Bytes?) -> Unit {
  let t = @keys.Transcript::new(digest=self.digest())
  match retry {
    Some(hrr) => {
      let hash = self.digest().hash(self.first_hello[:])
      t.add(@msg.frame(Other(254), hash[:])[:])
      t.add(hrr[:])
    }
    None => ()
  }
  self.transcript = Some(t)
}

///|
/// Read every whole record in the inbox, and every whole handshake message they complete.
fn Conn::pump(self : Conn) -> Unit raise @alert.Alert {
  while self.phase is (Hello | Flight | Waiting | Finishing | Open) {
    let view = Bytes::from_array(self.inbox)
    guard @record.decode_encrypted(view[:]) is Some((rec, used)) else { break }
    let raw = view[0:used].to_owned()
    self.inbox.drain(0, used) |> ignore
    match rec.kind {
      // RFC 8446 §5: a middlebox-compatibility change_cipher_spec may arrive during the
      // handshake and is dropped; after it, one is an error.
      ChangeCipherSpec =>
        if self.phase is Open {
          raise @alert.fatal(UnexpectedMessage)
        }
      _ =>
        match self.reader {
          None => self.dispatch(rec.kind, rec.fragment)
          Some(r) => {
            if rec.kind != ApplicationData {
              raise @alert.fatal(UnexpectedMessage)
            }
            let (kind, content) = r.open(raw[:])
            self.dispatch(kind, content)
          }
        }
    }
  }
}

///|
fn Conn::dispatch(
  self : Conn,
  kind : @record.Kind,
  content : Bytes,
) -> Unit raise @alert.Alert {
  match kind {
    Handshake => {
      for b in content {
        self.messages.push(b)
      }
      self.handshake()
    }
    Alert => {
      guard @alert.decode(content[:]) is Some(alert) else {
        raise @alert.fatal(DecodeError)
      }
      let @alert.Alert(kind~, ..) = alert
      if kind is CloseNotify {
        self.phase = Closed
      } else {
        self.phase = Closed
        raise alert
      }
    }
    ApplicationData => {
      guard self.phase is Open else { raise @alert.fatal(UnexpectedMessage) }
      self.plain.write_bytes(content)
    }
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}

///|
/// Every whole handshake message buffered, in order.
fn Conn::handshake(self : Conn) -> Unit raise @alert.Alert {
  while self.messages.length() >= 4 {
    let len = (self.messages[1].to_int() << 16) |
      (self.messages[2].to_int() << 8) |
      self.messages[3].to_int()
    if self.messages.length() < 4 + len {
      break
    }
    let raw = Bytes::from_array(self.messages[0:4 + len])
    self.messages.drain(0, 4 + len) |> ignore
    let kind = @msg.Kind::of(raw[0].to_int())
    let body = raw[4:].to_owned()
    match self.side {
      Client(config, host) => self.on_client(config, host, kind, body, raw)
      Server(config) => self.on_server(config, kind, body, raw)
    }
  }
}

///|
/// A KeyUpdate from the peer (RFC 8446 §4.6.3): new read keys, and new write keys too when asked.
fn Conn::on_update(self : Conn, body : Bytes) -> Unit raise @alert.Alert {
  if self.messages.length() > 0 {
    raise @alert.fatal(UnexpectedMessage)
  }
  let requested = match body.to_array() {
    [b'\x00'] => false
    [b'\x01'] => true
    _ => raise @alert.fatal(DecodeError)
  }
  let client = self.side is Client(_, _)
  if client {
    self.server_app = next_secret(self.server_app, self.digest())
    self.reader.unwrap().rekey(self.server_app[:])
  } else {
    self.client_app = next_secret(self.client_app, self.digest())
    self.reader.unwrap().rekey(self.client_app[:])
  }
  if requested {
    self.send_update(false)
  }
}

///|
fn Conn::send_update(self : Conn, request : Bool) -> Unit raise @alert.Alert {
  let body = if request { b"\x01" } else { b"\x00" }
  self.send_handshake(@msg.frame(KeyUpdate, body[:]))
  if self.side is Client(_, _) {
    self.client_app = next_secret(self.client_app, self.digest())
    self.writer.unwrap().rekey(self.client_app[:])
  } else {
    self.server_app = next_secret(self.server_app, self.digest())
    self.writer.unwrap().rekey(self.server_app[:])
  }
}

///|
fn next_secret(secret : Bytes, digest : @keys.Digest) -> Bytes {
  @keys.expand_label(secret[:], b"traffic upd", b"", len=digest.size(), digest~)
}
