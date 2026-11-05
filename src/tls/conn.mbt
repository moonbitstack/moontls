// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
priv enum Side {
  Client(Client, String)
  Server(Server)
}

///|
/// Which half of a client's proof is still awaited: its chain, or the
/// CertificateVerify that shows it holds the key.
priv enum Hold {
  Chain
  Proof
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
  /// Server: the client's certificate or its CertificateVerify awaited, after a
  /// CertificateRequest in the handshake (RFC 8446 A.2).
  Certifying(Hold)
  /// Server: the same two, after a CertificateRequest sent once the handshake was open
  /// (RFC 8446 §4.6.2).
  Renewing(Hold)
  /// A TLS 1.2 handshake, on either end.
  Legacy(Step12)
  Open
  Closed
}

///|
/// Whether the connection is still reading records: everything but a finished or a
/// broken one.
fn Phase::reading(self : Phase) -> Bool {
  match self {
    Expect(_)
    | Waiting
    | Finishing
    | Certifying(_)
    | Renewing(_)
    | Legacy(_)
    | Open => true
    Closed => false
  }
}

///|
/// A CertificateRequest this end sent or received, kept for the answer.
priv struct Asked {
  context : Bytes
  /// The signature schemes the asking side will verify, in its order.
  schemes : Array[Int32]
  /// TLS 1.2's `certificate_types`, which TLS 1.3 does not have.
  types : Array[Int32]
  /// Whether an empty answer ends the handshake.
  required : Bool
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
  priv mut group : Int32?
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
  priv mut ccs_sent : Bool
  priv mut ccs_read : Bool
  priv mut early : Int32
  priv quic : Quic?
  priv mut version : Version?
  priv mut server_random : Bytes
  priv mut master : Bytes
  priv mut extended : Bool
  priv mut indicated : Bool
  priv mut waiting : @record.Cipher?
  priv mut outgoing : @record.Cipher?
  priv mut suite12 : @record.Suite12?
  priv mut etm : Bool
  priv mut dh : (Bytes, Bytes, Bytes)?
  priv mut client_version : Int32
  priv mut asked : Asked?
  priv mut proved : Bool
  priv mut proof12 : Int32?
  priv mut psk : Bytes
  priv mut psk_suite : Int32
  priv mut ticket12 : Bytes
  priv mut psk12 : Bytes
  priv mut resume12 : Kind?
  priv mut resumed : Bool
  priv mut resumption : Bytes
  priv mut master13 : Bytes
  priv mut early_secret : Bytes
  priv mut early_reader : @record.Cipher?
  priv mut early_writer : @record.Cipher?
  priv mut early_sent : Bytes
  priv mut early_ok : Bool
  priv mut early_left : Int32
  priv mut offered_early : Bool
  priv mut hrr : Bytes
  priv mut client_finished : Bytes
  priv mut server_finished : Bytes
  priv mut wire : Int32
  priv mut ocsp : Bytes?
  priv mut peer_limit : Int32
  priv mut our_limit : Int32
  /// When the wire frames messages itself (QUIC's CRYPTO frames, DTLS's
  /// records), the handshake's output is queued here instead of framed into
  /// records. `None` is a TLS record stream.
  priv pipe : Pipe?
  /// Whether the key schedule uses RFC 9147 §5.9's `dtls13` label prefix.
  priv datagram : Bool
  /// The exporter master secret (RFC 8446 §7.1), empty until the server's
  /// Finished; what DTLS-SRTP exports from.
  priv mut exporter : Bytes
  /// The SRTP protection profile both ends agreed, if any (RFC 5764 §4.1).
  priv mut srtp_profile : @srtp.Profile?
}

///|
fn Conn::make(
  side : Side,
  rand : (Int32) -> Bytes,
  now : Int64,
  phase : Phase,
  quic? : Quic,
  pipe? : Pipe,
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
    group: None,
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
    ccs_sent: false,
    ccs_read: false,
    early: 0,
    quic,
    version: None,
    server_random: b"",
    master: b"",
    extended: false,
    indicated: false,
    waiting: None,
    outgoing: None,
    suite12: None,
    etm: false,
    dh: None,
    client_version: 0,
    asked: None,
    proved: false,
    proof12: None,
    psk: b"",
    psk_suite: 0,
    ticket12: b"",
    psk12: b"",
    resume12: None,
    resumed: false,
    resumption: b"",
    master13: b"",
    early_secret: b"",
    early_reader: None,
    early_writer: None,
    early_sent: b"",
    early_ok: false,
    early_left: 0,
    offered_early: false,
    hrr: b"",
    client_finished: b"",
    server_finished: b"",
    wire: @wire.legacy_version,
    ocsp: None,
    peer_limit: 0,
    our_limit: 0,
    pipe,
    datagram: pipe is Some(_),
    exporter: b"",
    srtp_profile: None,
  }
}

///|
/// A server connection awaiting a ClientHello.
///
/// `now` is the time, in seconds since the Unix epoch, a client certificate is judged at. A
/// server that asks for one and gives no clock cannot judge it, and the request is a local
/// misconfiguration rather than anything the peer did, so the handshake stops with an
/// `InternalError` where the CertificateRequest would have gone.
pub fn Conn::server(
  config : Server,
  rand~ : (Int32) -> Bytes,
  now? : Int64,
) -> Conn {
  Conn::make(Server(config), rand, now.unwrap_or(0L), Waiting)
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
  // A certificate with no key, or a key with no certificate, is a configuration that would only
  // surface as the server's alert in the middle of a handshake.
  if (config.cert.length() > 0) != (config.cert_key is Some(_)) {
    raise @alert.fatal(InternalError)
  }
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
/// A client handshake whose wire frames messages itself: its ClientHello is
/// queued in the pipe, unframed, for a `Handshake` to drain into a `Layer`.
fn Conn::pipe_client(
  config : Client,
  host : String,
  rand~ : (Int32) -> Bytes,
  now~ : Int64,
) -> Conn raise @alert.Alert {
  if (config.cert.length() > 0) != (config.cert_key is Some(_)) {
    raise @alert.fatal(InternalError)
  }
  let conn = Conn::make(
    Client(config, host),
    rand,
    now,
    Expect(@hs.Client::new()),
    pipe=Pipe::new(),
  )
  conn.session = rand(32)
  conn.hello_first(config)
  conn
}

///|
/// A server handshake whose wire frames messages itself.
fn Conn::pipe_server(
  config : Server,
  rand~ : (Int32) -> Bytes,
  now? : Int64,
) -> Conn {
  Conn::make(Server(config), rand, now.unwrap_or(0L), Waiting, pipe=Pipe::new())
}

///|
/// Feed one whole TLS handshake message — type, 24-bit length, body — with no
/// record or DTLSHandshake framing. A fatal alert is queued for the transport
/// before it is raised, so the peer is told why.
fn Conn::feed_message(
  self : Conn,
  message : BytesView,
) -> Unit raise @alert.Alert {
  if self.phase is Closed {
    return
  }
  for b in message {
    self.messages.push(b)
  }
  self.handshake() catch {
    @alert.Alert(level~, kind~) => {
      self.fail(kind)
      raise @alert.Alert(level~, kind~)
    }
  }
}

///|
/// What the handshake has asked of a message-framing transport since the last
/// call, in order, emptied by it.
fn Conn::take_pipe(self : Conn) -> Array[Out] {
  match self.pipe {
    Some(p) => {
      let out = p.out.copy()
      p.out.clear()
      out
    }
    None => []
  }
}

///|
/// Whether this end sent the ClientHello.
fn Conn::is_client(self : Conn) -> Bool {
  self.side is Client(_, _)
}

///|
/// The label prefix the key schedule runs under: `dtls13` over datagrams
/// (RFC 9147 §5.9), `tls13 ` over a stream.
fn Conn::prefix(self : Conn) -> BytesView {
  if self.datagram {
    @keys.datagram[:]
  } else {
    @keys.prefix[:]
  }
}

///|
fn Conn::hello_first(self : Conn, config : Client) -> Unit raise @alert.Alert {
  self.client_random = (self.rand)(32)
  self.send_hello(self.opening_shares(config), None)
}

///|
/// A key share for each of the first `shares` groups, the secrets kept for the answer.
fn Conn::opening_shares(
  self : Conn,
  config : Client,
) -> Array[(Int32, Bytes)] raise @alert.Alert {
  let groups = if config.groups.is_empty() {
    [@ext.x25519]
  } else {
    config.groups
  }
  let count = if config.shares < 1 {
    1
  } else if config.shares > groups.length() {
    groups.length()
  } else {
    config.shares
  }
  self.shares = []
  let sent = []
  // A group this build does not run can still be named in supported_groups; it gets no share.
  for group in groups {
    if sent.length() == count {
      break
    }
    if (Some(kx_of(group)) catch { _ => None }) is None {
      continue
    }
    let (secret, public) = share(group, self.rand)
    self.shares.push((group, secret))
    sent.push((group, public))
  }
  sent
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
  // RFC 8449 §4: what the peer said it would read caps every record written to it, its content
  // type counting against the limit.
  let room = if self.peer_limit > 1 {
    @cmp.minimum(self.peer_limit - 1, @record.max_fragment)
  } else {
    @record.max_fragment
  }
  let mut at = 0
  while at < data.length() {
    let end = @cmp.minimum(at + room, data.length())
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
/// Ask for new traffic keys in both directions (RFC 8446 §4.6.3). TLS 1.2 has no such message.
pub fn Conn::update(
  self : Conn,
  request~ : Bool = true,
) -> Unit raise @alert.Alert {
  guard self.phase is Open && !(self.version is Some(Tls10 | Tls11 | Tls12)) else {
    raise @alert.fatal(InternalError)
  }
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
/// The version negotiated, `None` before the hellos have settled it.
pub fn Conn::version(self : Conn) -> Version? {
  self.version
}

///|
/// The key-exchange group the handshake ran, one of the `@ext` code points; `None` before it is
/// settled, and for a TLS 1.2 exchange by RSA, which has none.
pub fn Conn::group(self : Conn) -> Int32? {
  self.group
}

///|
/// The TLS 1.3 suite negotiated.
pub fn Conn::suite(self : Conn) -> @record.Suite? {
  self.suite
}

///|
/// The TLS 1.2 suite negotiated.
pub fn Conn::suite12(self : Conn) -> @record.Suite12? {
  self.suite12
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
  match self.pipe {
    Some(p) => {
      p.push(Alert(body))
      return
    }
    None => ()
  }
  match self.writer {
    Some(w) =>
      self.outbox.write_bytes(w.seal(Alert, body[:]) catch { _ => return })
    None =>
      self.outbox.write_bytes(
        @record.encode(Alert, body[:], version=self.wire) catch {
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
  match self.pipe {
    Some(p) => {
      p.push(ChangeCipherSpec)
      return
    }
    None => ()
  }
  self.outbox.write_bytes(
    @record.encode(ChangeCipherSpec, b"\x01"[:], version=self.wire) catch {
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
  if self.pipe is Some(p) {
    for message in split_messages(data[:]) {
      p.push(Message(message))
    }
    return
  }
  let mut at = 0
  while at < data.length() {
    let end = @cmp.minimum(at + @record.max_fragment, data.length())
    let part = data[at:end]
    match self.writer {
      Some(w) => self.outbox.write_bytes(w.seal(Handshake, part))
      None =>
        self.outbox.write_bytes(
          @record.encode(Handshake, part, version=self.wire),
        )
    }
    at = end
  }
}

///|
fn Conn::digest(self : Conn) -> @keys.Digest {
  // RFC 2246 §5: 1.0 and 1.1 hash the handshake with MD5 and SHA-1 and run both in the PRF,
  // whatever the suite's own hash is.
  if self.version is Some(Tls10 | Tls11) {
    return Md5Sha1
  }
  match (self.suite12, self.suite) {
    (Some(s), _) => s.digest
    (_, Some(s)) => s.digest()
    _ => Sha256
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
  while self.phase.reading() {
    let view = Bytes::from_array(self.inbox)
    let legacy = match self.version {
      Some(v) => v.is_legacy()
      None => false
    }
    let read = if legacy {
      @record.decode12(view[:])
    } else {
      @record.decode_encrypted(view[:])
    }
    guard read is Some((rec, used)) else { break }
    // RFC 8446 §5.1: only a TLSCiphertext may run past 2^14, which in 1.3 is application_data and
    // in 1.2 is anything under a key.
    let keyed = if legacy {
      self.reader is Some(_)
    } else {
      rec.kind is ApplicationData
    }
    if !keyed && rec.fragment.length() > @record.max_fragment {
      raise @alert.fatal(RecordOverflow)
    }
    let raw = view[0:used].to_owned()
    self.inbox.drain(0, used) |> ignore
    match rec.kind {
      ChangeCipherSpec => self.on_change_cipher_spec(rec.fragment)
      // §4.2.10: 0-RTT records arrive under the early key, which only exists once the ClientHello
      // that offered them has been read. A record under the handshake key has the same outer
      // content type, so a miss falls through to the reader rather than failing the connection.
      ApplicationData if self.early_reader is Some(_) => {
        let early = self.early_reader.unwrap()
        let opened = Some(early.open(raw[:])) catch { _ => None }
        match opened {
          Some((kind, content)) => {
            if !(kind is ApplicationData) {
              raise @alert.fatal(UnexpectedMessage)
            }
            if content.length() > self.early_left {
              raise @alert.fatal(UnexpectedMessage)
            }
            self.early_left = self.early_left - content.length()
            self.plain.write_bytes(content)
          }
          None => {
            // Past the early data: from here the records are the handshake's.
            self.early_reader = None
            self.open_record(raw, used, rec)
          }
        }
      }
      ApplicationData if self.reader is None && self.skip_early(used) => ()
      _ => self.open_record(raw, used, rec)
    }
  }
}

///|
/// Read one record under whichever key is in force: none before the handshake has one, the TLS 1.2
/// cipher when the connection is that old, the handshake or application cipher otherwise.
fn Conn::open_record(
  self : Conn,
  raw : Bytes,
  used : Int32,
  rec : @record.Record,
) -> Unit raise @alert.Alert {
  match self.reader {
    None => self.dispatch(rec.kind, rec.fragment, keyed=false)
    Some(r) if r.is_tls12() => {
      let (kind, content) = r.open(raw[:])
      self.dispatch(kind, content, keyed=true)
    }
    // A peer that gives up mid-handshake may not have the keys to seal its alert yet.
    Some(_) if rec.kind is Alert && !(self.phase is Open) =>
      self.dispatch(Alert, rec.fragment, keyed=false)
    Some(r) => {
      if rec.kind != ApplicationData {
        raise @alert.fatal(UnexpectedMessage)
      }
      let (kind, content) = r.open(raw[:]) catch {
        @alert.Alert(kind=BadRecordMac, ..) if self.skip_early(used) => return
        e => raise e
      }
      self.early = 0
      self.dispatch(kind, content, keyed=true)
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
  if self.version is Some(Tls10 | Tls11 | Tls12) {
    return self.on_cipher12(fragment)
  }
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
  keyed~ : Bool,
) -> Unit raise @alert.Alert {
  // RFC 8446 §5.1: a handshake or alert fragment is never empty, sealed and padded or not.
  if content.length() == 0 && kind is (Handshake | Alert) {
    raise @alert.fatal(UnexpectedMessage)
  }
  // RFC 8449 §4: what this end said it would read is a promise the peer is held to, for the
  // records it protects; a ServerHello carrying a post-quantum share runs past most limits.
  if keyed && self.our_limit > 0 && content.length() + 1 > self.our_limit {
    raise @alert.fatal(RecordOverflow)
  }
  match kind {
    Handshake => {
      for b in content {
        self.messages.push(b)
      }
      self.handshake()
    }
    Alert => {
      let alert = @alert.decode(content[:]) catch {
        @alert.Refused => raise @alert.fatal(DecodeError)
      }
      let @alert.Alert(level~, kind~) = alert
      match (level, kind) {
        (_, CloseNotify) => self.phase = Closed
        // RFC 5746 §3.7: a warning that declines a renegotiation is not a failure, and the
        // connection it arrived on goes on.
        (Warning, NoRenegotiation) => ()
        (Warning, UserCanceled) => ()
        _ => {
          self.phase = Closed
          raise alert
        }
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
  // TLS 1.2 has no such message.
  if self.quic is Some(_) || self.version is Some(Tls10 | Tls11 | Tls12) {
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
  if !@keys.finished_ok(
      secret[:],
      self.th()[:],
      body[:],
      digest=d,
      prefix=self.prefix(),
    ) {
    raise @alert.fatal(DecryptError)
  }
}

///|
fn next_secret(secret : Bytes, digest : @keys.Digest) -> Bytes {
  @keys.expand_label(secret[:], b"traffic upd", b"", len=digest.size(), digest~)
}
