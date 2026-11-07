// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One fragment of the flight this end is sending, and the record that carried
/// it (RFC 9147 §7.2). A record an ACK names retires the fragment; one that is
/// never named is retransmitted.
priv struct Seg {
  piece : Piece
  epoch : UInt64
  mut number : Number?
  mut acked : Bool
}

///|
/// A DTLS 1.3 connection (RFC 9147), client or server, without I/O.
///
/// Datagrams from the peer go in through [`receive`]; datagrams for the peer
/// come out of [`take`], one per call because that is what a socket sends.
/// Application data is read with [`read`] and written with [`write`].
///
/// The handshake is [`@tls.Handshake`] — DTLS 1.3 runs the TLS 1.3 handshake
/// unchanged. What this adds is everything a datagram forces: an epoch per
/// direction, record number encryption, the anti-replay window, and the ACK
/// and retransmission bookkeeping.
///
/// **There is no clock in here.** A datagram transport has to retransmit, and
/// when to do so is a policy. `now` is the caller's monotonic clock in
/// milliseconds; `wall` is the wall clock in seconds a certificate is judged
/// at. `deadline` says when the next `tick` is due.
pub struct Conn13 {
  priv handshake : @tls.Handshake
  priv mut inbound : Flight
  priv mut sending : Int32
  priv writes : Map[UInt64, Cipher]
  priv mut write_epoch : UInt64
  priv readers : Map[UInt64, Cipher]
  priv plain : Buffer
  priv out : Array[Bytes]
  priv segs : Array[Seg]
  priv ack : Array[Number]
  priv mut plain_seq : UInt64
  priv shell : Shell
  priv mut armed : Bool
  priv mut deadline : Int64?
  priv mut rto : Int64
  /// How this end answers a ClientHello it has not decided to keep state for.
  priv policy : Cookie
  /// The octets the transport gave for the peer's address, which a cookie is an answer about.
  priv mut peer : Bytes
}

///|
fn Conn13::make(handshake : @tls.Handshake, policy~ : Cookie = Off) -> Conn13 {
  {
    handshake,
    inbound: Flight::new(),
    sending: 0,
    writes: {},
    write_epoch: 0UL,
    readers: {},
    plain: Buffer(),
    out: [],
    segs: [],
    ack: [],
    plain_seq: 0UL,
    shell,
    armed: false,
    deadline: None,
    rto: 1000L,
    policy,
    peer: b"",
  }
}

///|
/// A client connection to `host`. `wall` is the time, in seconds since the Unix
/// epoch, the server's certificate is judged at; `now` is the caller's
/// monotonic clock in milliseconds.
pub fn Conn13::client(
  config : @tls.Client,
  host : String,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
  wall~ : Int64,
) -> Conn13 raise @alert.Alert {
  let conn = Conn13::make(
    @tls.Handshake::client(aes_only(config), host, rand~, now=wall),
  )
  conn.handshake.opening(conn)
  conn.arm(now)
  conn
}

///|
/// A server connection awaiting a ClientHello. `now` is the caller's monotonic
/// clock in milliseconds; `wall` is the time a client certificate is judged at.
///
/// `cookie` is how the server answers a ClientHello it has not decided to keep state for
/// (RFC 9147 §4.2): the HelloRetryRequest carries a value sealed over the address the datagram
/// came from, and the handshake goes on only for a hello that echoes it. `receive` therefore
/// takes the peer's address. `Off` answers every hello at once, which is what a server behind a
/// trusted path may want.
pub fn Conn13::server(
  config : @tls.Server,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
  wall? : Int64,
  cookie~ : Cookie = Off,
) -> Conn13 {
  // An empty key is the caller asking for one without having one to give: a key drawn here is
  // still a key that leaves with the server and is never written down.
  let policy = match cookie {
    Key(key) => if key.length() == 0 { Key(rand(32)) } else { cookie }
    Off => Off
  }
  let conn = Conn13::make(
    @tls.Handshake::server(
      aes_only_server(config),
      rand~,
      now=wall.unwrap_or(0L),
    ),
    policy~,
  )
  conn.arm(now)
  conn
}

///|
/// DTLS runs the AES-GCM suites by default: their record number mask is the AES
/// block the pion vectors pin, and every DTLS peer speaks them. ChaCha20 is
/// implemented but not offered unless a caller names it.
fn aes_only(config : @tls.Client) -> @tls.Client {
  {
    ..config,
    suites: config.suites.filter(fn(s) {
      s is (@record.Aes128Gcm | @record.Aes256Gcm)
    }),
  }
}

///|
fn aes_only_server(config : @tls.Server) -> @tls.Server {
  {
    ..config,
    suites: config.suites.filter(fn(s) {
      s is (@record.Aes128Gcm | @record.Aes256Gcm)
    }),
  }
}

// ------------------------------------------------------------------ receiving

///|
/// Take one datagram from the peer and process every record in it. `now` is the
/// caller's clock, in milliseconds. `peer` is whatever the transport calls the
/// remote address — octets it alone understands — and is what the cookie a
/// server asks for is sealed over (RFC 9147 §4.2).
///
/// A datagram that is not DTLS, or one whose records do not deprotect, is
/// dropped as RFC 9147 §4.1 and §4.5.2 require — the association survives, and
/// no state moves for a record that failed.
pub fn Conn13::receive(
  self : Conn13,
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
    match shape(datagram[at]) {
      Plain(_) => {
        let read = decode(view) catch { _ => None }
        guard read is Some((content, number, fragment, used)) else { break }
        at = at + used
        if content is @record.Handshake {
          self.note(number)
        }
        self.on_plain(content, fragment)
      }
      Sealed => {
        let epoch = (datagram[at].to_int() & 0x3).to_uint64()
        guard self.readers.get(epoch) is Some(cipher) else { break }
        // §4.5.2: a record that does not deprotect — a duplicate caught by the
        // replay window, or a forgery — is dropped and the association goes on.
        let opened = Some(cipher.open(view, cid=self.shell.cid.length())) catch {
          _ => None
        }
        guard opened is Some((content, body, number, used)) else { break }
        at = at + used
        if content is @record.Handshake {
          self.note(number)
        }
        self.on_sealed(content, body)
      }
      Foreign => break
    }
  }
  self.flush_ack()
  self.arm(now)
}

///|
fn Conn13::on_plain(
  self : Conn13,
  kind : @record.Kind,
  fragment : Bytes,
) -> Unit raise @alert.Alert {
  match kind {
    @record.Handshake => self.feed(fragment)
    @record.Ack =>
      match read_ack(fragment[:]) {
        Some(numbers) => self.retire(numbers[:])
        None => ()
      }
    @record.Alert => self.on_alert(fragment)
    _ => ()
  }
}

///|
fn Conn13::on_sealed(
  self : Conn13,
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
fn Conn13::on_alert(self : Conn13, body : Bytes) -> Unit raise @alert.Alert {
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
/// Take every whole handshake fragment in a record and feed each completed
/// message to the handshake.
fn Conn13::feed(self : Conn13, fragment : Bytes) -> Unit raise @alert.Alert {
  let mut at = 0
  while at < fragment.length() {
    guard read_piece(fragment[at:]) is Some((piece, used)) else { break }
    at = at + used
    // RFC 9147 §5.2: a side's first message is numbered zero and every message it generates after
    // that goes up by one. A server that kept nothing for the cookie exchange sees the second
    // ClientHello — message one — before it has seen message zero, so where the association is
    // has to be taken from the hello rather than assumed. This is the whole of statelessness: the
    // flight the peer reads starts at that number, and this end's own messages continue from it,
    // because the HelloRetryRequest that took the first number went out from another instance.
    if piece.at == 0 &&
      self.inbound.next() == 0 &&
      piece.seq > 0 &&
      piece.kind == @msg.Kind::ClientHello.code() {
      self.inbound = Flight::new(from=piece.seq)
      self.sending = piece.seq
    }
    for message in self.inbound.take(piece) {
      // RFC 9147 §5.1: a ClientHello is answered with a cookie before the handshake sees it, so a
      // hello that has not proved it can receive at its address moves nothing and derives nothing.
      if self.policy is Key(key) &&
        message[0].to_int() == @msg.Kind::ClientHello.code() &&
        self.handshake.version() is None {
        let address = self.peer
        self.handshake.demand_cookie(
          seal=fn(history, group) { seal13(key[:], address[:], history, group) },
          open=fn(cookie) { open13(key[:], address[:], cookie) },
        )
      }
      self.handshake.receive(self, message[:])
    }
  }
}

///|
fn Conn13::note(self : Conn13, number : Number) -> Unit {
  if !self.ack.contains(number) {
    self.ack.push(number)
  }
}

///|
/// Send an ACK for every handshake record just processed (RFC 9147 §7.1).
fn Conn13::flush_ack(self : Conn13) -> Unit raise @alert.Alert {
  if self.ack.length() == 0 {
    return
  }
  let numbers = self.ack.copy()
  self.ack.clear()
  let body = ack(numbers[:])
  let number = { epoch: 0UL, seq: self.plain_seq, }
  self.plain_seq = self.plain_seq + 1UL
  self.out.push(encode(Ack, number, body[:]))
}

// ------------------------------------------------------------------- sending

///|
fn Conn13::room(self : Conn13) -> Int32 {
  let _ = self
  1200 - plaintext_header - @record.tag_size
}

///|
/// Seal one content unit under `epoch`'s write keys, or in the clear at epoch 0.
fn Conn13::seal_at(
  self : Conn13,
  epoch : UInt64,
  kind : @record.Kind,
  body : Bytes,
) -> (Bytes, Number) raise @alert.Alert {
  match self.writes.get(epoch) {
    Some(cipher) => {
      let number = cipher.next()
      (cipher.seal(kind, body[:], shape=self.shell), number)
    }
    None => {
      let number = { epoch: 0UL, seq: self.plain_seq, }
      self.plain_seq = self.plain_seq + 1UL
      (encode(kind, number, body[:]), number)
    }
  }
}

///|
/// Apply one `Layer` operation. The handshake calls this, never a caller.
fn Conn13::emit(
  self : Conn13,
  kind : @record.Kind,
  content : BytesView,
) -> Unit raise @alert.Alert {
  match kind {
    @record.Handshake => {
      let cut = pieces(content, seq=self.sending, room=self.room())
      self.sending = self.sending + 1
      let epoch = self.write_epoch
      for one in cut {
        let (record, number) = self.seal_at(epoch, Handshake, piece(one))
        self.out.push(record)
        self.segs.push({
          piece: one,
          epoch,
          number: Some(number),
          acked: false,
        })
      }
    }
    _ => {
      let (record, _) = self.seal_at(self.write_epoch, kind, content.to_owned())
      self.out.push(record)
    }
  }
}

///|
/// One datagram for the peer, emptied by the call.
pub fn Conn13::take(self : Conn13) -> Bytes {
  if self.out.length() == 0 {
    return b""
  }
  let first = self.out[0]
  let _ = self.out.remove(0)
  first
}

///|
/// Queue application data, cut to fit the path's datagram size.
pub fn Conn13::write(
  self : Conn13,
  data : BytesView,
  now~ : Int64,
) -> Unit raise @alert.Alert {
  if self.write_epoch == 0UL {
    raise @alert.fatal(InternalError)
  }
  let room = self.room()
  let mut at = 0
  while at < data.length() {
    let take = if data.length() - at < room { data.length() - at } else { room }
    let (record, _) = self.seal_at(
      self.write_epoch,
      ApplicationData,
      data[at:at + take].to_owned(),
    )
    self.out.push(record)
    at = at + take
  }
  self.arm(now)
}

///|
/// Application data received, emptied by the call.
pub fn Conn13::read(self : Conn13) -> Bytes {
  let out = self.plain.to_bytes()
  self.plain.reset()
  out
}

///|
/// Queue close_notify and stop accepting data.
pub fn Conn13::close(self : Conn13, now~ : Int64) -> Unit {
  self.handshake.close(self)
  self.arm(now)
}

// -------------------------------------------------------------------- timing

///|
fn Conn13::arm(self : Conn13, now : Int64) -> Unit {
  if !self.armed && self.segs.iter().any(fn(s) { !s.acked }) {
    self.armed = true
    self.deadline = Some(now + self.rto)
  }
}

///|
/// When [`tick`] is next due, in the same milliseconds `now` is given in, or
/// `None` when nothing is outstanding.
pub fn Conn13::deadline(self : Conn13) -> Int64? {
  self.deadline
}

///|
/// Report the clock and retransmit what is overdue (RFC 9147 §5.8).
pub fn Conn13::tick(self : Conn13, now~ : Int64) -> Unit raise @alert.Alert {
  if !self.armed {
    return
  }
  guard self.deadline is Some(due) && now >= due else { return }
  for seg in self.segs {
    if !seg.acked {
      let (record, number) = self.seal_at(
        seg.epoch,
        Handshake,
        piece(seg.piece),
      )
      self.out.push(record)
      seg.number = Some(number)
    }
  }
  self.rto = if self.rto * 2L > 60000L { 60000L } else { self.rto * 2L }
  self.deadline = Some(now + self.rto)
}

///|
fn Conn13::retire(self : Conn13, numbers : ArrayView[Number]) -> Unit {
  for seg in self.segs {
    match seg.number {
      Some(number) if numbers.contains(number) => seg.acked = true
      _ => ()
    }
  }
  if !self.segs.iter().any(fn(s) { !s.acked }) {
    self.segs.clear()
    self.armed = false
    self.deadline = None
  }
}

// ---------------------------------------------------------------------- layer

///|
impl @tls.Layer for Conn13 with fn send(self, kind, content) {
  self.emit(kind, content)
}

///|
impl @tls.Layer for Conn13 with fn install(self, direction, epoch, keys) {
  match keys {
    @tls.Traffic(suite, secret) => {
      let cipher = Cipher::new(
        secret,
        epoch~,
        digest=suite.digest(),
        aead=aead_of(suite),
        mask=mask_of(suite),
        len=suite.key_size(),
      )
      match direction {
        @tls.Write => {
          self.writes[epoch] = cipher
          self.write_epoch = epoch
        }
        @tls.Read => self.readers[epoch] = cipher
      }
    }
    @tls.Block(_, _, _, _, _) => ()
  }
}

///|
impl @tls.Layer for Conn13 with fn change_cipher_spec(self) {
  ignore(self)
}

///|
impl @tls.Layer for Conn13 with fn open(self) {
  ignore(self)
}

///|
impl @tls.Layer for Conn13 with fn datagram(self) -> Bool {
  ignore(self)
  true
}

///|
impl @tls.Layer for Conn13 with fn keyed(self, direction) -> Bool {
  match direction {
    @tls.Write => self.write_epoch != 0UL
    @tls.Read => self.readers.length() > 0
  }
}

// ---------------------------------------------------------------- accessors

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
