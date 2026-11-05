// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One fragment of the flight this end is sending, and the epoch that carried
/// it, so a retransmission goes out under the same keys (RFC 6347 §4.2.4).
priv struct Seg12 {
  piece : Piece
  epoch : UInt64
}

///|
/// A DTLS 1.2 connection (RFC 6347), client or server, without I/O.
///
/// The shape of the API is [`Conn13`]'s — datagrams in through [`receive`],
/// datagrams out of [`take`], a caller-supplied clock — because a caller should
/// not have to care which DTLS it got. What differs is underneath, and it is
/// all of the record layer: DTLS 1.2 has its own header (an explicit epoch and
/// a 48-bit sequence number, no unified header), the sequence-number nonce
/// rather than 1.3's inner-content-type construction, and whole-flight
/// retransmission without ACKs.
///
/// The handshake messages, the TLS 1.2 suite table and the PRF are shared with
/// `@tls`; only the way they travel is here. `change_cipher_spec` is real in
/// this version: it is what moves a direction from epoch 0 to epoch 1.
pub struct Conn12 {
  priv mut handshake : @tls.Handshake
  priv mut inbound : Flight
  priv mut sending : Int32
  priv mut write : Cipher12?
  priv mut read : Cipher12?
  priv mut write_on : Bool
  priv mut read_on : Bool
  priv out : Array[Bytes]
  priv segs : Array[Seg12]
  priv plain : Buffer
  priv mut plain_seq : UInt64
  priv mut armed : Bool
  priv mut deadline : Int64?
  priv mut rto : Int64
  /// How this end answers a ClientHello it has not decided to keep state for.
  priv policy : Cookie
  /// The client's side of a HelloVerifyRequest: what to rebuild the handshake from, and where the
  /// peer's address is, which is what the cookie is an answer about.
  priv client : @tls.Client?
  priv host : String
  priv rand : (Int32) -> Bytes
  priv wall : Int64
  priv mut peer : Bytes
  priv mut verified : Bool
  priv mut retried : Bool
}

///|
fn Conn12::make(
  handshake : @tls.Handshake,
  policy~ : Cookie = Off,
  client? : @tls.Client,
  host~ : String = "",
  rand~ : (Int32) -> Bytes = fn(_) { b"" },
  wall~ : Int64 = 0L,
) -> Conn12 {
  {
    handshake,
    inbound: Flight::new(),
    sending: 0,
    write: None,
    read: None,
    write_on: false,
    read_on: false,
    out: [],
    segs: [],
    plain: Buffer(),
    plain_seq: 0UL,
    armed: false,
    deadline: None,
    rto: 1000L,
    policy,
    client,
    host,
    rand,
    wall,
    peer: b"",
    verified: false,
    retried: false,
  }
}

///|
/// A client connection to `host`. `wall` is the time, in seconds since the Unix
/// epoch, the server's certificate is judged at; `now` is the caller's
/// monotonic clock in milliseconds.
pub fn Conn12::client(
  config : @tls.Client,
  host : String,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
  wall~ : Int64,
) -> Conn12 raise @alert.Alert {
  let conn = Conn12::make(
    @tls.Handshake::client(only12(config), host, rand~, now=wall),
    client=only12(config),
    host~,
    rand~,
    wall~,
  )
  conn.handshake.opening(conn)
  conn.arm(now)
  conn
}

///|
/// A server connection awaiting a ClientHello. `now` is the caller's monotonic
/// clock in milliseconds; `wall` is the time a client certificate is judged at.
pub fn Conn12::server(
  config : @tls.Server,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
  wall? : Int64,
  cookie~ : Cookie = Off,
) -> Conn12 {
  // An empty key is the caller asking for one without having one to give: a key drawn here is
  // still a key that leaves with the server and is never written down.
  let policy = match cookie {
    Key(key) => if key.length() == 0 { Key(rand(32)) } else { cookie }
    Off => Off
  }
  let conn = Conn12::make(
    @tls.Handshake::server(only12_server(config), rand~, now=wall.unwrap_or(0L)),
    policy~,
    rand~,
    wall=wall.unwrap_or(0L),
  )
  conn.arm(now)
  conn
}

///|
/// DTLS 1.2 runs the AEAD suites `suites12` offers by default; CBC and CCM need
/// their own record framing and are refused rather than protected wrongly.
fn only12(config : @tls.Client) -> @tls.Client {
  { ..config, versions: [@tls.Tls12], }
}

///|
fn only12_server(config : @tls.Server) -> @tls.Server {
  { ..config, versions: [@tls.Tls12], }
}

// ------------------------------------------------------------------ receiving

///|
/// Take one datagram from the peer and process every record in it. `now` is the
/// caller's clock, in milliseconds.
pub fn Conn12::receive(
  self : Conn12,
  datagram : BytesView,
  now~ : Int64,
  peer~ : BytesView = b""[:],
) -> Unit raise @alert.Alert {
  if peer.length() > 0 {
    self.peer = peer.to_owned()
  }
  let mut at = 0
  while at < datagram.length() {
    let view = datagram[at:]
    guard view.length() >= header12 else { break }
    let epoch = @wire.read_u16(view, 3).to_uint64()
    if epoch == 0UL {
      guard decode12_record(view) is Some((kind, fragment, used)) else { break }
      at = at + used
      self.on_clear(kind, fragment)
    } else {
      guard self.read is Some(cipher) else { break }
      let opened = Some(cipher.open(view)) catch { _ => None }
      guard opened is Some((kind, content, _, used)) else { break }
      at = at + used
      self.on_protected(kind, content)
    }
  }
  self.arm(now)
}

///|
/// A DTLS 1.2 record header at epoch 0 is plaintext: type, version, epoch,
/// 48-bit sequence, length, then the fragment.
fn decode12_record(view : BytesView) -> (@record.Kind, Bytes, Int32)? {
  if view.length() < header12 {
    return None
  }
  guard @record.Kind::of(view[0].to_int()) is Some(kind) else { return None }
  let len = @wire.read_u16(view, 11)
  let end = header12 + len
  if len > @record.max_fragment || view.length() < end {
    return None
  }
  Some((kind, view[header12:end].to_owned(), end))
}

///|
fn Conn12::on_clear(
  self : Conn12,
  kind : @record.Kind,
  fragment : Bytes,
) -> Unit raise @alert.Alert {
  match kind {
    @record.Handshake => self.feed(fragment)
    @record.ChangeCipherSpec => {
      if fragment != b"\x01" {
        raise @alert.fatal(UnexpectedMessage)
      }
      // A retransmitted flight repeats its change_cipher_spec. It has no
      // message sequence number to deduplicate it, so the second one is
      // recognised by the direction already being in epoch 1 and dropped.
      if self.read_on {
        return
      }
      self.read_on = true
      self.handshake.change_cipher_spec()
    }
    @record.Alert => self.on_alert(fragment)
    _ => ()
  }
}

///|
fn Conn12::on_protected(
  self : Conn12,
  kind : @record.Kind,
  content : Bytes,
) -> Unit raise @alert.Alert {
  match kind {
    @record.Handshake => self.feed(content)
    @record.ApplicationData => self.plain.write_bytes(content)
    @record.Alert => self.on_alert(content)
    _ => ()
  }
}

///|
fn Conn12::on_alert(self : Conn12, body : Bytes) -> Unit raise @alert.Alert {
  let _ = self
  let alert = @alert.decode(body[:]) catch {
    @alert.Refused => raise @alert.fatal(DecodeError)
  }
  let @alert.Alert(level~, kind~) = alert
  match (level, kind) {
    (_, @alert.CloseNotify) => ()
    (_, @alert.UserCanceled) => ()
    _ => raise alert
  }
}

///|
fn Conn12::feed(self : Conn12, fragment : Bytes) -> Unit raise @alert.Alert {
  let mut at = 0
  while at < fragment.length() {
    guard read_piece(fragment[at:]) is Some((piece, used)) else { break }
    at = at + used
    // The cookie exchange is answered here, before the handshake sees anything: a ClientHello
    // that has not proved it can receive at its address must not move the state machine or make
    // it derive a key, or a forged source has bought exactly what the cookie is there to refuse.
    if whole_message(piece) {
      if piece.kind == @msg.Kind::HelloVerifyRequest.code() {
        if self.client is None {
          raise @alert.fatal(UnexpectedMessage)
        }
        self.answer_hello_verify(piece.body)
        continue
      }
      if !self.verified && piece.kind == @msg.Kind::ClientHello.code() {
        if !self.check_cookie(piece.body, piece.seq) {
          continue
        }
      }
    }
    let whole = self.inbound.take(piece)
    if whole.length() > 0 {
      // RFC 6347 §4.2.4: a flight is acknowledged by the answer to it, and
      // there is no ACK message in this version.
      self.segs.clear()
      self.armed = false
      self.deadline = None
    }
    for message in whole {
      self.handshake.receive(self, message[:])
    }
  }
}

// ------------------------------------------------------------- the cookie

///|
/// Whether a fragment is its whole message, which the cookie exchange requires: a HelloVerifyRequest
/// is one message and a ClientHello that has not been verified is not reassembled.
fn whole_message(piece : Piece) -> Bool {
  piece.at == 0 && piece.body.length() == piece.total
}

///|
/// Answer a ClientHello with a HelloVerifyRequest, or say that the cookie it carried is the one
/// this server would have given (RFC 6347 §4.2.1).
///
/// Nothing is kept between the two: the cookie is a MAC of the address the datagram came from,
/// under a key that never leaves the server, so the second ClientHello can be judged on its own.
/// `false` means the message was not for the handshake — it was answered, or it was not ours.
fn Conn12::check_cookie(
  self : Conn12,
  body : Bytes,
  seq : Int32,
) -> Bool raise @alert.Alert {
  guard self.policy is Key(key) else { return true }
  guard @msg.read_hello(body[:], cookie=true) is Some(hello) else {
    raise @alert.fatal(DecodeError)
  }
  if hello.cookie.length() > 0 && accepts(key[:], self.peer[:], hello.cookie[:]) {
    // §4.2.2: the ClientHello that answers a HelloVerifyRequest is message 1, and the server's
    // first message is numbered from there. Both counters start where this message is.
    self.inbound = Flight::new(from=seq)
    self.sending = seq
    self.verified = true
    return true
  }
  // No cookie, or one this server never gave. Answer the address that asked and keep nothing:
  // the request carries the same message sequence as the hello it answers (RFC 6347 §4.2.2), and
  // is not a flight of its own, so no segment is kept for retransmission.
  let message = @msg.hello_verify_request(
    legacy_version,
    seal(key[:], self.peer[:])[:],
  )
  for one in pieces(message, seq~, room=self.room()) {
    self.out.push(self.frame(0UL, @record.Handshake, piece(one)))
  }
  false
}

///|
/// Take a HelloVerifyRequest: keep its cookie and send the ClientHello again with it
/// (RFC 6347 §4.2.1), on a handshake that has seen nothing else.
///
/// The handshake is rebuilt rather than patched because the cookie is part of the message the
/// transcript is taken over: the First ClientHello and the request are not in it, and the second
/// ClientHello is.
fn Conn12::answer_hello_verify(
  self : Conn12,
  body : Bytes,
) -> Unit raise @alert.Alert {
  guard self.client is Some(config) else { return }
  guard @msg.read_hello_verify_request(body[:]) is Some(cookie) else {
    raise @alert.fatal(DecodeError)
  }
  // A second request for the same handshake is a server this client cannot satisfy; the first
  // cookie is the only one it will ever have.
  if self.retried {
    return
  }
  self.retried = true
  self.segs.clear()
  self.handshake = @tls.Handshake::client(
    config,
    self.host,
    rand=self.rand,
    now=self.wall,
    cookie=cookie[:],
  )
  self.inbound = Flight::new(from=1)
  self.handshake.opening(self)
}

// ------------------------------------------------------------------- sending

///|
fn Conn12::room(self : Conn12) -> Int32 {
  let _ = self
  1200 - header12 - @record.tag_size
}

///|
/// Frame one content unit at `epoch`, in the clear at epoch 0 and under the
/// epoch's cipher at epoch 1.
fn Conn12::frame(
  self : Conn12,
  epoch : UInt64,
  kind : @record.Kind,
  body : Bytes,
) -> Bytes raise @alert.Alert {
  if epoch == 0UL {
    let len = body.length()
    let out = Buffer()
    out.write_byte((kind.code() & 0xff).to_byte())
    @wire.u16(out, legacy_version)
    out.write_bytes(seq_octets(0UL, self.plain_seq))
    @wire.u16(out, len)
    out.write_bytes(body)
    self.plain_seq = self.plain_seq + 1UL
    out.to_bytes()
  } else {
    guard self.write is Some(cipher) else { raise @alert.fatal(InternalError) }
    cipher.seal(kind, body[:])
  }
}

///|
/// Apply one `Layer` operation.
fn Conn12::emit(
  self : Conn12,
  kind : @record.Kind,
  content : BytesView,
) -> Unit raise @alert.Alert {
  match kind {
    @record.Handshake => {
      let cut = pieces(content, seq=self.sending, room=self.room())
      self.sending = self.sending + 1
      let epoch = if self.write_on { 1UL } else { 0UL }
      for one in cut {
        let record = self.frame(epoch, Handshake, piece(one))
        self.out.push(record)
        self.segs.push({ piece: one, epoch, })
      }
    }
    _ => {
      let epoch = if self.write_on { 1UL } else { 0UL }
      let record = self.frame(epoch, kind, content.to_owned())
      self.out.push(record)
    }
  }
}

///|
/// One datagram for the peer, emptied by the call.
pub fn Conn12::take(self : Conn12) -> Bytes {
  if self.out.length() == 0 {
    return b""
  }
  let first = self.out[0]
  let _ = self.out.remove(0)
  first
}

///|
/// Queue application data, cut to fit the path's datagram size.
pub fn Conn12::write(
  self : Conn12,
  data : BytesView,
  now~ : Int64,
) -> Unit raise @alert.Alert {
  if !self.write_on {
    raise @alert.fatal(InternalError)
  }
  let room = self.room()
  let mut at = 0
  while at < data.length() {
    let take = if data.length() - at < room { data.length() - at } else { room }
    self.out.push(
      self.frame(1UL, ApplicationData, data[at:at + take].to_owned()),
    )
    at = at + take
  }
  self.arm(now)
}

///|
/// Application data received, emptied by the call.
pub fn Conn12::read(self : Conn12) -> Bytes {
  let out = self.plain.to_bytes()
  self.plain.reset()
  out
}

///|
/// Queue close_notify and stop accepting data.
pub fn Conn12::close(self : Conn12, now~ : Int64) -> Unit {
  self.handshake.close(self)
  self.arm(now)
}

// -------------------------------------------------------------------- timing

///|
fn Conn12::arm(self : Conn12, now : Int64) -> Unit {
  if !self.armed && self.segs.length() > 0 {
    self.armed = true
    self.deadline = Some(now + self.rto)
  }
}

///|
/// When [`tick`] is next due, in the same milliseconds `now` is given in, or
/// `None` when no flight is outstanding.
pub fn Conn12::deadline(self : Conn12) -> Int64? {
  self.deadline
}

///|
/// Report the clock and resend the whole unacknowledged flight when it is due
/// (RFC 6347 §4.2.4). DTLS 1.2 has no ACK message: a flight is acknowledged by
/// the answer to it, and nothing else.
pub fn Conn12::tick(self : Conn12, now~ : Int64) -> Unit raise @alert.Alert {
  if !self.armed {
    return
  }
  guard self.deadline is Some(due) && now >= due else { return }
  for seg in self.segs {
    let record = self.frame(seg.epoch, Handshake, piece(seg.piece))
    self.out.push(record)
  }
  self.rto = if self.rto * 2L > 60000L { 60000L } else { self.rto * 2L }
  self.deadline = Some(now + self.rto)
}

// ---------------------------------------------------------------------- layer

///|
impl @tls.Layer for Conn12 with fn send(self, kind, content) {
  self.emit(kind, content)
}

///|
impl @tls.Layer for Conn12 with fn install(self, direction, epoch, keys) {
  match keys {
    @tls.Block(suite, key, iv, mac, etm) => {
      let cipher = Cipher12::new(
        suite,
        key[:],
        iv[:],
        mac_key=mac[:],
        etm~,
        rand=self.rand,
        epoch~,
      )
      match direction {
        @tls.Write => self.write = Some(cipher)
        @tls.Read => self.read = Some(cipher)
      }
    }
    @tls.Traffic(_, _) => ()
  }
}

///|
impl @tls.Layer for Conn12 with fn change_cipher_spec(self) {
  let record = self.frame(0UL, ChangeCipherSpec, b"\x01") catch { _ => return }
  self.out.push(record)
  self.write_on = true
}

///|
impl @tls.Layer for Conn12 with fn open(self) {
  ignore(self)
}

///|
impl @tls.Layer for Conn12 with fn datagram(self) -> Bool {
  ignore(self)
  true
}

///|
impl @tls.Layer for Conn12 with fn keyed(self, direction) -> Bool {
  match direction {
    @tls.Write => self.write_on
    @tls.Read => self.read_on
  }
}

// ---------------------------------------------------------------- accessors

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
