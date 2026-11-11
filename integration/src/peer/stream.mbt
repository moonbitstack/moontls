// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How much one read takes from the socket. One TLS record is 2^14 plus its header and tag, and a
/// flight is often several of them, so a chunk that size keeps the pump from being the slow part
/// of an interop run.
let chunk : Int32 = 65536

///|
/// Move everything the handshake wants sent onto the socket.
async fn flush_tcp(conn : @tls.Conn, sock : @socket.Tcp) -> Unit {
  for ;; {
    let out = conn.take()
    if out.length() == 0 {
      break
    }
    sock.write(out)
  }
}

///|
/// Hand an alert — or anything else the connection queued before giving up — to the peer, so it
/// sees a reason rather than a closed socket.
async fn last_words(conn : @tls.Conn, sock : @socket.Tcp) -> Unit {
  flush_tcp(conn, sock) catch {
    _ => ()
  }
}

///|
/// The first line of an answer, cut short: a transfer case would otherwise put a megabyte on the
/// line the harness reads.
fn head_of(answer : String) -> String {
  let line = answer.split("\n").next().unwrap_or("").to_owned()
  if line.length() > 48 {
    line[0:48].to_owned() + "..."
  } else {
    line
  }
}

///|
/// What a peer says once a handshake is up, on one line: what the run is judged by.
pub fn summary(
  conn : @tls.Conn,
  bytes : Int32,
  resumed : Bool,
  early : Bool,
  first : String,
) -> String {
  let version = match conn.version() {
    Some(v) =>
      match v {
        @tls.Tls10 => "1.0"
        @tls.Tls11 => "1.1"
        @tls.Tls12 => "1.2"
        @tls.Tls13 => "1.3"
      }
    None => "-"
  }
  let suite = match (conn.suite12(), conn.suite()) {
    (Some(s), _) => s.code.to_string(radix=16)
    (_, Some(@record.Aes128Gcm)) => "aes128"
    (_, Some(@record.Aes256Gcm)) => "aes256"
    (_, Some(@record.ChaCha20Poly1305)) => "chacha20"
    _ => "-"
  }
  let group = match conn.group() {
    Some(g) => g.to_string()
    None => "-"
  }
  "ok version=\{version} suite=\{suite} group=\{group} alpn=\{conn.alpn().unwrap_or("-")} " +
  "sni=\{conn.server_name().unwrap_or("-")} resumed=\{if resumed { 1 } else { 0 }} " +
  "early=\{if early { 1 } else { 0 }} bytes=\{bytes} first=\{first}"
}

///|
/// Echo what arrives, line by line, or answer HTTP requests when `http` was asked for.
///
/// The two shapes are what the interop tools expect: `openssl s_client` types a line and reads the
/// same line back, and tlsfuzzer sends one request and reads one response.
fn answer_tcp(
  conn : @tls.Conn,
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
      let line = text[0:end + 1].to_owned()
      if @utf8.decode_lossy(line).trim_end(chars="\r\n") == "update" {
        conn.update(request=true)
      }
      conn.write(line[:])
    }
  }
}

///|
/// Serve one TCP connection: read ciphertext off the socket, hand it to the connection, hand back
/// whatever it wants written, and echo what it read.
async fn serve_tcp_conn(
  sock : @socket.Tcp,
  config : @tls.Server,
  opts : Map[String, String],
) -> Unit {
  let conn = @tls.Conn::server(config, rand=entropy, now=wall_clock())
  defer sock.close()
  let pending = Buffer()
  let mut announced = false
  let mut failed = false
  let mut asked = false
  for ;; {
    flush_tcp(conn, sock) catch {
      _ => ()
    }
    if !announced && conn.is_connected() {
      announced = true
      say(opts, summary(conn, 0, conn.is_resumed(), conn.early_accepted(), "-"))
    }
    // `renegotiate` on a server: once the first answer is out, ask the client for a second
    // handshake (RFC 5746 §4). A client cannot start one in this library — `Conn::renegotiate` is
    // the server's HelloRequest — so this is the direction the option exists for.
    if !asked &&
      announced &&
      conn.is_connected() &&
      opts.contains("renegotiate") {
      asked = true
      conn.renegotiate() catch {
        _ => ()
      }
    }
    let plain = conn.read()
    if plain.length() > 0 {
      pending.write_bytes(plain)
    }
    answer_tcp(conn, pending, opts) catch {
      _ => failed = true
    }
    // What the answer queued leaves before this end waits again: the peer is waiting for it, not
    // for another read.
    flush_tcp(conn, sock) catch {
      _ => ()
    }
    if failed || conn.is_closed() {
      break
    }
    let next = sock.read_some(max_len=chunk) catch { _ => None }
    match next {
      Some(bytes) => {
        if bytes.length() == 0 {
          flush_tcp(conn, sock) catch {
            _ => ()
          }
          break
        }
        conn.receive(bytes[:]) catch {
          _ => {
            last_words(conn, sock)
            failed = true
          }
        }
      }
      None => {
        flush_tcp(conn, sock) catch {
          _ => ()
        }
        break
      }
    }
  }
}

///|
/// One request over one TCP connection, answered by whatever the peer wrote back.
async fn connect_tcp(
  host : String,
  port : Int32,
  roots : String,
  opts : Map[String, String],
) -> Unit {
  let rounds = if opts.contains("resume") { 2 } else { 1 }
  let sessions = @tls.Sessions::new()
  let config = client_config(roots, opts, Some(sessions))
  let name = opts.get("sni").unwrap_or(host)
  let mut last = ""
  for round in 0..<rounds {
    let sock = @socket.Tcp::connect(@socket.Addr::parse("\{host}:\{port}")) catch {
      e => {
        say(opts, "refused connect \{e}")
        return
      }
    }
    let conn = @tls.Conn::client(config, name, rand=entropy, now=wall_clock())
    let (request, line_only) = request_of(opts, name)
    // 0-RTT is data the client owes before it has heard from the server, so it goes out with the
    // first flight rather than after the handshake. The request is what a real client has to say
    // before the handshake, and sending it early is the whole point of the case; a server that
    // declines it gets it again from the connection, which is why nothing below sends it twice.
    let mut early = false
    if opts.contains("early") && round > 0 {
      conn.write_early(@utf8.encode(request)[:]) catch {
        e => say(opts, "early failed \{e}")
      }
      flush_tcp(conn, sock) catch {
        _ => ()
      }
      early = true
    }
    let pending = Buffer()
    let mut sent = false
    let mut failed = false
    let mut why = ""
    for ;; {
      flush_tcp(conn, sock) catch {
        _ => failed = true
      }
      if opts.contains("debug") {
        say(
          opts,
          "step: connected=\{conn.is_connected()} closed=\{conn.is_closed()} sent=\{sent}",
        )
      }
      if failed {
        break
      }
      if !sent && conn.is_connected() {
        sent = true
        if opts.contains("update") {
          conn.update(request=true) catch {
            _ => failed = true
          }
        }
        // Early data the server declined is on the connection already, waiting to be written
        // again; a request that was never early is written here for the first time.
        if !early {
          conn.write(@utf8.encode(request)[:]) catch {
            _ => failed = true
          }
        }
        continue
      }
      let plain = conn.read()
      if plain.length() > 0 {
        pending.write_bytes(plain)
      }
      if sent {
        let text = pending.to_bytes()
        // `head` is for a server that answers and then keeps the connection open — `s_server
        // -www` does — where the answer's first line is all a case needs to see.
        if (line_only && text.find(b"\n") is Some(_)) ||
          (opts.contains("head") && text.find(b"\r\n") is Some(_)) ||
          (!line_only && conn.is_closed()) {
          break
        }
      }
      if conn.is_closed() {
        break
      }
      let next = sock.read_some(max_len=chunk) catch { _ => None }
      if opts.contains("debug") {
        let n = match next {
          Some(b) => b.length()
          None => -1
        }
        say(opts, "read \{n}")
      }
      match next {
        Some(bytes) => {
          if bytes.length() == 0 {
            break
          }
          conn.receive(bytes[:]) catch {
            @alert.Alert(kind~, ..) => {
              why = alert_name(kind)
              failed = true
            }
          }
        }
        None => break
      }
    }
    sock.close()
    let answer = pending.to_bytes()
    // An answer that arrived is the handshake completed, whatever the connection looks like now: a
    // server that closes as soon as it has replied — a Go handler that returns, `s_server` without
    // `-rev` — leaves nothing to be connected to, and that is not a refusal.
    if !conn.is_connected() && answer.length() == 0 {
      match conn.refused() {
        Some(refused) => say(opts, "refused chain \{refused}")
        None =>
          // A round number only means something when a run has more than one.
          say(
            opts,
            "refused " +
            (if why == "" { "handshake" } else { why }) +
            (if rounds > 1 { " in round \{round}" } else { "" }),
          )
      }
      return
    }
    let first = head_of(@utf8.decode_lossy(answer))
    last = summary(
      conn,
      answer.length(),
      conn.is_resumed(),
      conn.early_accepted(),
      first,
    )
    if round + 1 == rounds {
      say(opts, last)
    } else {
      // What the first round was for: the second one either resumes from it or does not.
      say(opts, "first " + last)
    }
  }
}
