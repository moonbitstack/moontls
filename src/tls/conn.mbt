// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
priv enum Side {
  Client(Client, String)
  Server(Server)
}

///|
priv enum Phase {
  /// Client: the message it waits for next, from the ServerHello to the server's Finished
  /// (RFC 8446 A.1). Anything else is an unexpected_message.
  Expect(@hs.Client)
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
  priv mut client_random : Bytes
  priv mut retried : Bool
  priv mut retry_group : Int32
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
  priv mut ccs_sent : Bool
  priv mut ccs_read : Bool
  priv mut early : Int32
  priv quic : Quic?
}

///|
fn Conn::make(
  side : Side,
  rand : (Int32) -> Bytes,
  now : Int64,
  phase : Phase,
  quic? : Quic,
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
    client_random: b"",
    retried: false,
    retry_group: 0,
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
    ccs_sent: false,
    ccs_read: false,
    early: 0,
    quic,
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
  let conn = Conn::make(
    Client(config, host),
    rand,
    now,
    Expect(@hs.Client::new()),
  )
  conn.session = rand(32)
  conn.hello_first(config)
  conn
}

///|
fn Conn::hello_first(self : Conn, config : Client) -> Unit raise @alert.Alert {
  self.client_random = (self.rand)(32)
  let group = config.groups.get(0).unwrap_or(@ext.x25519)
  let (secret, public) = share(group, self.rand)
  self.shares = [(group, secret)]
  self.send_hello([(group, public)], None)
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
/// Middlebox compatibility mode (RFC 8446 §D.4): a dummy change_cipher_spec, sent once and always
/// in the clear — by a server after its first handshake message, by a client before its second
/// flight — when the ClientHello carried a legacy_session_id, so the exchange looks like a
/// resumed TLS 1.2 session to boxes that drop what they cannot parse.
fn Conn::send_change_cipher_spec(self : Conn) -> Unit {
  if self.ccs_sent || self.quic is Some(_) {
    return
  }
  self.ccs_sent = true
  self.outbox.write_bytes(
    @record.encode(ChangeCipherSpec, b"\x01"[:]) catch {
      _ => return
    },
  )
}

///|
/// Queue handshake messages: in the clear before keys, sealed after.
fn Conn::send_handshake(self : Conn, data : Bytes) -> Unit raise @alert.Alert {
  if self.quic is Some(q) {
    q.steps.push(Send(q.writing, data))
    return
  }
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
  while self.phase is (Expect(_) | Waiting | Finishing | Open) {
    let view = Bytes::from_array(self.inbox)
    guard @record.decode_encrypted(view[:]) is Some((rec, used)) else { break }
    // RFC 8446 §5.1: only a TLSCiphertext, always under application_data, may run past 2^14.
    if rec.kind != ApplicationData &&
      rec.fragment.length() > @record.max_fragment {
      raise @alert.fatal(RecordOverflow)
    }
    let raw = view[0:used].to_owned()
    self.inbox.drain(0, used) |> ignore
    match rec.kind {
      ChangeCipherSpec => self.on_change_cipher_spec(rec.fragment)
      ApplicationData if self.reader is None && self.skip_early(used) => ()
      _ =>
        match self.reader {
          None => self.dispatch(rec.kind, rec.fragment)
          // A peer that gives up mid-handshake may not have the keys to seal its alert yet.
          Some(_) if rec.kind is Alert && !(self.phase is Open) =>
            self.dispatch(Alert, rec.fragment)
          Some(r) => {
            if rec.kind != ApplicationData {
              raise @alert.fatal(UnexpectedMessage)
            }
            let (kind, content) = r.open(raw[:]) catch {
              @alert.Alert(kind=BadRecordMac, ..) if self.skip_early(used) =>
                continue
              e => raise e
            }
            self.early = 0
            self.dispatch(kind, content)
          }
        }
    }
  }
}

///|
/// RFC 8446 §5: a middlebox-compatibility change_cipher_spec, the single octet 1, may arrive
/// between the first ClientHello and the peer's Finished, and is dropped. One before the
/// ClientHello, after the Finished, with other content, inside a handshake message, or a second
/// one (§D.4 has a peer send one, and OpenSSL and BoringSSL take no more) is an
/// unexpected_message.
fn Conn::on_change_cipher_spec(
  self : Conn,
  fragment : Bytes,
) -> Unit raise @alert.Alert {
  let started = match self.side {
    Client(_, _) => true
    Server(_) => self.transcript is Some(_)
  }
  if fragment != b"\x01" ||
    !started ||
    self.ccs_read ||
    self.phase is Open ||
    self.messages.length() > 0 {
    raise @alert.fatal(UnexpectedMessage)
  }
  self.ccs_read = true
}

///|
/// RFC 8446 §4.2.10: a server that declines a client's 0-RTT data reads past it, up to its
/// `early_limit` — as records it has no key for after a HelloRetryRequest, as records that do
/// not open under the handshake key otherwise. Only application data counts against the limit
/// (§4.6.1), so a record of `size` octets counts less its header, the inner content type and
/// the AEAD tag. Whether it may still be dropped.
fn Conn::skip_early(self : Conn, size : Int32) -> Bool {
  let data = @cmp.maximum(0, size - @record.header - 1 - @record.tag_size)
  if self.early == 0 || data > self.early {
    return false
  }
  self.early = self.early - data
  true
}

///|
/// RFC 8446 §5.1: a message the keys change after must end its record, so nothing read under the
/// old keys is taken as if it came under the new ones.
fn Conn::aligned(self : Conn) -> Unit raise @alert.Alert {
  if self.messages.length() > 0 {
    raise @alert.fatal(UnexpectedMessage)
  }
}

///|
fn Conn::dispatch(
  self : Conn,
  kind : @record.Kind,
  content : Bytes,
) -> Unit raise @alert.Alert {
  // RFC 8446 §5.1: a handshake or alert fragment is never empty, sealed and padded or not.
  if content.length() == 0 && kind is (Handshake | Alert) {
    raise @alert.fatal(UnexpectedMessage)
  }
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
      guard self.phase is Open && self.messages.length() == 0 else {
        raise @alert.fatal(UnexpectedMessage)
      }
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
  // RFC 9001 §6: QUIC updates keys in its packets, and a KeyUpdate message is an error there.
  if self.quic is Some(_) {
    raise @alert.fatal(UnexpectedMessage)
  }
  self.aligned()
  let requested = match body.to_array() {
    [b'\x00'] => false
    [b'\x01'] => true
    [_] => raise @alert.fatal(IllegalParameter)
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
/// The peer's Finished (RFC 8446 §4.4.4): verify_data is exactly as long as the hash, so another
/// length is a decode_error rather than a MAC that fails.
fn Conn::check_finished(
  self : Conn,
  secret : Bytes,
  body : Bytes,
) -> Unit raise @alert.Alert {
  let d = self.digest()
  if body.length() != d.size() {
    raise @alert.fatal(DecodeError)
  }
  if !@keys.finished_ok(secret[:], self.th()[:], body[:], digest=d) {
    raise @alert.fatal(DecryptError)
  }
}

///|
fn next_secret(secret : Bytes, digest : @keys.Digest) -> Bytes {
  @keys.expand_label(secret[:], b"traffic upd", b"", len=digest.size(), digest~)
}
