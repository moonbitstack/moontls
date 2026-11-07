// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A TLS and DTLS peer for interop runs.
///
///     tls-peer server <port> <chain.pem> <key.pem> [options]
///     tls-peer client <host> <port> <roots.pem> [options]
///     tls-peer dtls-server <port> <chain.pem> <key.pem> [options]
///     tls-peer dtls-client <host> <port> <roots.pem> [options]
///
/// Both ends speak the same protocol on top of TLS: a server echoes each line it reads, or answers
/// each HTTP request with one response in one write when `http` is given; a client sends one
/// request and prints one line about what came back. A client line that starts `ok ` lists the
/// version, the suite, the group, ALPN, SNI, whether the handshake resumed, whether 0-RTT was
/// accepted, how many octets came back and the first line of them; `refused <why>` is the other
/// outcome. A server prints the same line when its handshake finishes.
///
/// Options, all `key=value` or bare: `versions=10,11,12,13`, `suites=aes128,aes256,chacha20`,
/// `suites12=<codes in hex>|all`, `schemes12`, `groups=x25519,p256,p384,p521,x448,ffdhe2048,...,
/// x25519mlkem768,mlkem768,...`, `alpn=h2,http/1.1`, `sni=<name>`, `cert=<pem>`, `key=<pem>`
/// (a client certificate), `ask=1|2` and `roots=<pem>` (a server asking for one), `renegotiate`,
/// `ocsp=<der>` (a server stapling it) or `ocsp` (a client asking), `compress`, `early`,
/// `record_limit=<n>`, `tickets=<n>`, `srtp`, `update`, `get=</path>`, `send=<text>`, `resume`
/// (two handshakes on one session store), `http`, `cookie` (a DTLS 1.3 server demanding one),
/// `quiet`.
///
/// A certificate and key decide the signature scheme, so ML-DSA is `cert=` a file with an ML-DSA
/// key and nothing else.
fn usage() -> Unit {
  println(
    "usage: tls-peer server <port> <chain.pem> <key.pem> [options]\n" +
    "       tls-peer client <host> <port> <roots.pem> [options]\n" +
    "       tls-peer dtls-server <port> <chain.pem> <key.pem> [options]\n" +
    "       tls-peer dtls-client <host> <port> <roots.pem> [options]",
  )
}

///|
/// A port argument.
fn port_of(text : String) -> Int32 {
  @string.parse_int(text) catch {
    _ => abort("not a port: " + text)
  }
}

///|
async fn main {
  match @env.args() {
    [_, "server", port, chain, key, .. rest] => {
      let opts = options(rest)
      let config = server_config(chain, key, opts) catch {
        e => {
          println("bad server configuration \{e}")
          return
        }
      }
      let listener = @socket.TcpServer::TcpServer(
        @socket.Addr::parse("127.0.0.1:\{port_of(port)}"),
      )
      println("listening 127.0.0.1:\{port_of(port)}")
      listener.run_forever(
        (sock, _) => serve_tcp_conn(sock, config, opts),
        allow_failure=true,
      )
    }
    [_, "client", host, port, roots, .. rest] => {
      let opts = options(rest)
      connect_tcp(host, port_of(port), roots, opts) catch {
        e => println("refused \{e}")
      }
    }
    [_, "dtls-server", port, chain, key, .. rest] => {
      let opts = options(rest)
      let config = server_config(chain, key, opts) catch {
        e => {
          println("bad server configuration \{e}")
          return
        }
      }
      let cookie = if opts.contains("cookie") {
        @dtls.Cookie::Key(entropy(32))
      } else {
        @dtls.Cookie::Off
      }
      serve_udp(
        port_of(port),
        opts,
        () => {
          @dtls.Conn13::server(
            config,
            rand=entropy,
            now=monotonic(),
            wall=wall_clock(),
            cookie~,
          )
        },
        () => {
          @dtls.Conn12::server(
            config,
            rand=entropy,
            now=monotonic(),
            wall=wall_clock(),
            cookie~,
          )
        },
      )
    }
    [_, "dtls-client", host, port, roots, .. rest] => {
      let opts = options(rest)
      let config = client_config(roots, opts, None) catch {
        e => {
          println("bad client configuration \{e}")
          return
        }
      }
      let name = opts.get("sni").unwrap_or(host)
      let twelve = opts.contains("dtls12")
      let conn13 = if twelve {
        None
      } else {
        Some(
          @dtls.Conn13::client(
            config,
            name,
            rand=entropy,
            now=monotonic(),
            wall=wall_clock(),
          ) catch {
            _ => {
              println("refused handshake")
              return
            }
          },
        )
      }
      let conn12 = if twelve {
        Some(
          @dtls.Conn12::client(
            config,
            name,
            rand=entropy,
            now=monotonic(),
            wall=wall_clock(),
          ) catch {
            _ => {
              println("refused handshake")
              return
            }
          },
        )
      } else {
        None
      }
      connect_udp(host, port_of(port), opts, conn13, conn12) catch {
        e => println("refused \{e}")
      }
    }
    _ => usage()
  }
}
