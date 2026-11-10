// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The datagrams that fit through the loopback: a DTLS record is bounded by the path's MTU, which
/// nothing here discovers, so this is what a jumbo frame allows and the library cuts its own
/// records well below it.
let datagram : Int32 = 65536

///|
/// What the pump needs of a datagram connection, so that one pump serves both versions. The two
/// are different types because their record layers are different record layers; everything above
/// the records is the same, and that is what this says.
pub(open) trait Datagram {
  fn is_closed(Self) -> Bool
  fn is_connected(Self) -> Bool
  fn receive(Self, BytesView, peer : BytesView) -> Unit raise @alert.Alert
  fn take(Self) -> Bytes
  fn read(Self) -> Bytes
  fn write(Self, BytesView) -> Unit raise @alert.Alert
  fn line(Self) -> String
}

///|
impl Datagram for @dtls.Conn13 with fn is_closed(self) {
  self.is_closed()
}

///|
impl Datagram for @dtls.Conn13 with fn is_connected(self) {
  self.is_connected()
}

///|
impl Datagram for @dtls.Conn13 with fn receive(self, bytes, peer) {
  self.receive(bytes, now=monotonic(), peer~)
}

///|
impl Datagram for @dtls.Conn13 with fn take(self) {
  self.take()
}

///|
impl Datagram for @dtls.Conn13 with fn read(self) {
  self.read()
}

///|
impl Datagram for @dtls.Conn13 with fn write(self, bytes) {
  self.write(bytes, now=monotonic())
}

///|
impl Datagram for @dtls.Conn13 with fn line(self) {
  summary13(self)
}

///|
impl Datagram for @dtls.Conn12 with fn is_closed(self) {
  self.is_closed()
}

///|
impl Datagram for @dtls.Conn12 with fn is_connected(self) {
  self.is_connected()
}

///|
impl Datagram for @dtls.Conn12 with fn receive(self, bytes, peer) {
  self.receive(bytes, now=monotonic(), peer~)
}

///|
impl Datagram for @dtls.Conn12 with fn take(self) {
  self.take()
}

///|
impl Datagram for @dtls.Conn12 with fn read(self) {
  self.read()
}

///|
impl Datagram for @dtls.Conn12 with fn write(self, bytes) {
  self.write(bytes, now=monotonic())
}

///|
impl Datagram for @dtls.Conn12 with fn line(self) {
  summary12(self)
}

///|
/// The one line a finished DTLS 1.3 handshake prints.
fn summary13(conn : @dtls.Conn13) -> String {
  let version = match conn.version() {
    Some(@tls.Tls13) => "1.3"
    Some(@tls.Tls12) => "1.2"
    Some(@tls.Tls11) => "1.1"
    Some(@tls.Tls10) => "1.0"
    None => "-"
  }
  let suite = match conn.suite() {
    Some(@record.Aes128Gcm) => "aes128"
    Some(@record.Aes256Gcm) => "aes256"
    Some(@record.ChaCha20Poly1305) => "chacha20"
    None => "-"
  }
  "ok version=\{version} suite=\{suite} group=\{conn.group().map(g => g.to_string()).unwrap_or("-")} " +
  "alpn=\{conn.alpn().unwrap_or("-")} sni=\{conn.server_name().unwrap_or("-")}"
}

///|
/// The one line a finished DTLS 1.2 handshake prints.
fn summary12(conn : @dtls.Conn12) -> String {
  let suite = match conn.suite() {
    Some(s) => s.code.to_string(radix=16)
    None => "-"
  }
  "ok version=1.2 suite=\{suite} " +
  "alpn=\{conn.alpn().unwrap_or("-")} sni=\{conn.server_name().unwrap_or("-")}"
}

///|
/// Send everything a connection has queued, one datagram per record.
async fn flush_udp(
  conn : &Datagram,
  sock : @socket.UdpServer,
  to : @socket.Addr,
) -> Unit {
  for ;; {
    let out = conn.take()
    if out.length() == 0 {
      break
    }
    sock.sendto(out, to)
  }
}

///|
/// Answer the plaintext a datagram connection has read, in the same two shapes the stream peer
/// uses.
fn answer_udp(
  conn : &Datagram,
  pending : Buffer,
  opts : Map[String, String],
) -> Unit raise {
  if opts.contains("http") {
    for ;; {
      let text = pending.to_bytes()
      guard text.find(b"\r\n\r\n") is Some(head) else { break }
      pending.reset()
      pending.write_bytes(text[head + 4:])
      let mut rows = 1
      for i = 0; i < head; i = i + 1 {
        if i + 1 < head && text[i] == b'\r' && text[i + 1] == b'\n' {
          rows = rows + 1
        }
      }
      let body = "x".repeat(rows)
      let reply = "HTTP/1.0 200 OK\r\ncontent-type: text/plain\r\ncontent-length=\{body.length()}\r\n\r\n" +
        body
      conn.write(@utf8.encode(reply)[:])
    }
  } else {
    for ;; {
      let text = pending.to_bytes()
      guard text.find(b"\n") is Some(end) else { break }
      pending.reset()
      pending.write_bytes(text[end + 1:])
      conn.write(text[0:end + 1].to_owned()[:])
    }
  }
}

///|
/// One association, and the plaintext it has read but not yet answered.
struct Peer {
  conn : &Datagram
  pending : Buffer
  mut announced : Bool
}

///|
/// A DTLS server: one association per peer address, since that is what a cookie is bound to and
/// what a caller multiplexing one socket has to key on.
///
/// With `cookie` every association demands one (RFC 9147 §5.1 for 1.3, RFC 6347 §4.2.1 for 1.2),
/// which is what the stateless exchange is tested by; without it the server answers the first
/// ClientHello at once.
pub async fn serve_udp(
  port : Int32,
  opts : Map[String, String],
  make13 : () -> @dtls.Conn13,
  make12 : () -> @dtls.Conn12,
) -> Unit {
  let sock = @socket.UdpServer::UdpServer(
    @socket.Addr::parse("127.0.0.1:\{port}"),
  )
  println("listening \{sock.addr.to_string()}")
  let peers : Map[String, Peer] = Map([])
  let buffer = FixedArray::make(datagram, b'\x00')
  let twelve = opts.contains("dtls12")
  for ;; {
    let (n, from) = sock.recvfrom(buffer, max_len=datagram) catch { _ => break }
    let key = from.to_string()
    let peer = match peers.get(key) {
      Some(peer) => peer
      None => {
        let peer = if twelve {
          { conn: make12(), pending: Buffer(), announced: false, }
        } else {
          { conn: make13(), pending: Buffer(), announced: false, }
        }
        peers[key] = peer
        peer
      }
    }
    let bytes = Bytes::makei(n, i => buffer[i])
    let failed = try {
      peer.conn.receive(bytes[:], @utf8.encode(key)[:])
      false
    } catch {
      _ => true
    }
    flush_udp(peer.conn, sock, from)
    if failed || peer.conn.is_closed() {
      let _ = peers.remove(key)
      continue
    }
    let plain = peer.conn.read()
    if plain.length() > 0 {
      peer.pending.write_bytes(plain)
      let answered = try {
        answer_udp(peer.conn, peer.pending, opts)
        true
      } catch {
        _ => false
      }
      flush_udp(peer.conn, sock, from)
      if answered && !peer.announced && peer.conn.is_connected() {
        peer.announced = true
        if !opts.contains("quiet") {
          println(peer.conn.line())
        }
      }
    }
  }
}

///|
/// One request over one datagram association, printing the same line the stream client prints.
pub async fn connect_udp(
  host : String,
  port : Int32,
  opts : Map[String, String],
  conn13 : @dtls.Conn13?,
  conn12 : @dtls.Conn12?,
) -> Unit {
  let conn : &Datagram = match (conn13, conn12) {
    (Some(conn), _) => as_datagram13(conn)
    (_, Some(conn)) => as_datagram12(conn)
    _ => {
      println("refused handshake")
      return
    }
  }
  let sock = @socket.UdpClient::UdpClient(
    @socket.Addr::parse("\{host}:\{port}"),
  )
  let name = opts.get("sni").unwrap_or(host)
  let pending = Buffer()
  let buffer = FixedArray::make(datagram, b'\x00')
  let (request, line_only) = request_of(opts, name)
  let mut sent = false
  let mut rounds = 0
  flush_client(conn, sock)
  while rounds < 400 && !conn.is_closed() {
    rounds = rounds + 1
    if !sent && conn.is_connected() {
      sent = true
      conn.write(@utf8.encode(request)[:]) catch {
        _ => ()
      }
      flush_client(conn, sock)
    }
    let next = @async.with_timeout_opt(2000, async fn() {
      sock.recv(buffer, max_len=datagram)
    })
    let n = match next {
      Some(n) => n
      None => break
    }
    if n <= 0 {
      break
    }
    let bytes = Bytes::makei(n, i => buffer[i])
    let failed = try {
      conn.receive(bytes[:], b""[:])
      false
    } catch {
      _ => true
    }
    if failed {
      break
    }
    flush_client(conn, sock)
    let plain = conn.read()
    if plain.length() > 0 {
      pending.write_bytes(plain)
    }
    if sent {
      let text = pending.to_bytes()
      if line_only && text.find(b"\n") is Some(_) {
        break
      }
    }
  }
  let answer = pending.to_bytes()
  let first = @utf8.decode_lossy(answer)
    .split("\n")
    .next()
    .unwrap_or("")
    .to_owned()
  if conn.is_connected() {
    println(conn.line() + " bytes=\{answer.length()} first=\{first}")
  } else {
    println("refused handshake")
  }
}

///|
/// A DTLS 1.3 connection seen as what the pump needs.
fn as_datagram13(conn : @dtls.Conn13) -> &Datagram {
  conn
}

///|
/// A DTLS 1.2 connection seen as what the pump needs.
fn as_datagram12(conn : @dtls.Conn12) -> &Datagram {
  conn
}

///|
/// Send everything a datagram client has queued.
async fn flush_client(conn : &Datagram, sock : @socket.UdpClient) -> Unit {
  for ;; {
    let out = conn.take()
    if out.length() == 0 {
      break
    }
    sock.send(out)
  }
}
