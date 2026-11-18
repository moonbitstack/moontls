// A peer for the interop matrix, written against rustls.
//
//     rustls-peer client <host> <port> <ca.pem> [sni=NAME] [alpn=a,b] [resume] [cert=PATH key=PATH]
//     rustls-peer server <port> <chain.pem> <key.pem> [alpn=a,b] [clientca=PATH]
//
// Both sides speak lines: the server answers every line it reads with the same line, and the
// client sends one, reads it back, and prints where the connection landed. The line is what the
// matrix compares, so it names the version, the suite, ALPN, and whether the session was resumed.
//
// rustls has no TLS 1.0 or 1.1 and no TLS 1.2 CBC suites, which is the point of having it in the
// matrix: what it accepts is what a strict modern peer accepts.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, Stream};

/// Everything the two modes take off the command line.
struct Opts {
    sni: String,
    alpn: Vec<Vec<u8>>,
    resume: bool,
    cert: Option<String>,
    key: Option<String>,
    client_ca: Option<String>,
}

fn parse_opts(args: &[String]) -> Opts {
    let mut opts = Opts {
        sni: "localhost".to_string(),
        alpn: Vec::new(),
        resume: false,
        cert: None,
        key: None,
        client_ca: None,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "resume" {
            opts.resume = true;
        } else if let Some(value) = arg.strip_prefix("sni=") {
            opts.sni = value.to_string();
        } else if let Some(value) = arg.strip_prefix("alpn=") {
            opts.alpn = value
                .split(',')
                .filter(|one| !one.is_empty())
                .map(|one| one.as_bytes().to_vec())
                .collect();
        } else if let Some(value) = arg.strip_prefix("cert=") {
            opts.cert = Some(value.to_string());
        } else if let Some(value) = arg.strip_prefix("key=") {
            opts.key = Some(value.to_string());
        } else if let Some(value) = arg.strip_prefix("clientca=") {
            opts.client_ca = Some(value.to_string());
        } else {
            eprintln!("unknown option: {arg}");
            exit(2);
        }
        i += 1;
    }
    opts
}

fn read_certs(path: &str) -> Vec<CertificateDer<'static>> {
    let file = File::open(path).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| fail(&format!("{path}: {e}")))
}

fn read_key(path: &str) -> PrivateKeyDer<'static> {
    let file = File::open(path).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .unwrap_or_else(|e| fail(&format!("{path}: {e}")))
        .unwrap_or_else(|| fail(&format!("{path}: no private key")))
}

fn fail(message: &str) -> ! {
    eprintln!("rustls-peer: {message}");
    exit(1)
}

fn roots(path: &str) -> RootCertStore {
    let mut store = RootCertStore::empty();
    for cert in read_certs(path) {
        store
            .add(cert)
            .unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    }
    store
}

fn socket(host: &str, port: u16) -> TcpStream {
    let stream = TcpStream::connect((host, port)).unwrap_or_else(|e| fail(&format!("connect: {e}")));
    // A case that stalls is a failure of the peer as much as of the library, and a test that waits
    // for the runner's own clock says nothing.
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(20)))
        .expect("write timeout");
    stream
}

fn client(args: &[String]) -> ! {
    if args.len() < 3 {
        fail("client <host> <port> <ca.pem> [options]");
    }
    let host = args[0].clone();
    let port: u16 = args[1].parse().unwrap_or_else(|_| fail("port"));
    let opts = parse_opts(&args[3..]);

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots(&args[2]))
        .with_no_client_auth();
    config.alpn_protocols = opts.alpn.clone();
    // One store for both connections, which is what makes the second one a resumption.
    // 32, not 8: the cache divides what it is given by eight to bound the servers it holds, and a
    // bound of one server is a cache that evicts each ticket as it inserts it.
    config.resumption = rustls::client::Resumption::in_memory_sessions(32);
    if let (Some(cert), Some(key)) = (&opts.cert, &opts.key) {
        config = ClientConfig::builder()
            .with_root_certificates(roots(&args[2]))
            .with_client_auth_cert(read_certs(cert), read_key(key))
            .unwrap_or_else(|e| fail(&format!("client certificate: {e}")));
        config.alpn_protocols = opts.alpn.clone();
        config.resumption = rustls::client::Resumption::in_memory_sessions(32);
    }
    let config = Arc::new(config);

    if opts.resume {
        // The first connection is what collects the ticket; only the second one is reported.
        let _ = one(&config, &host, port, &opts.sni);
    }
    let (version, suite, alpn, resumed, first) = one(&config, &host, port, &opts.sni);
    println!(
        "ok version={version} suite={suite} alpn={alpn} resumed={} bytes={} first={first}",
        if resumed { 1 } else { 0 },
        first.len()
    );
    exit(0)
}

/// One connection: send a line, read the answer, and report what the handshake settled on.
fn one(
    config: &Arc<ClientConfig>,
    host: &str,
    port: u16,
    sni: &str,
) -> (String, String, String, bool, String) {
    let name = ServerName::try_from(sni.to_string()).unwrap_or_else(|e| fail(&format!("sni: {e}")));
    let mut conn = ClientConnection::new(config.clone(), name).unwrap_or_else(|e| fail(&format!("{e}")));
    let mut sock = socket(host, port);
    // The handshake first: `Stream` buffers application data until it has run one, and a case
    // that only ever writes once would leave the line in the buffer.
    conn.complete_io(&mut sock)
        .unwrap_or_else(|e| fail(&format!("handshake: {e}")));
    {
        let mut tls = Stream::new(&mut conn, &mut sock);
        tls.write_all(b"ping\n")
            .unwrap_or_else(|e| fail(&format!("write: {e}")));
        if let Err(e) = tls.flush() {
            fail(&format!("flush: {e}"));
        }
    }
    let mut line = String::new();
    {
        let mut tls = Stream::new(&mut conn, &mut sock);
        let mut reader = BufReader::new(&mut tls);
        reader
            .read_line(&mut line)
            .unwrap_or_else(|e| fail(&format!("read: {e}")));
    }
    // A ticket is a separate flight, and a server is free to put it after its first application
    // data — OpenSSL does. The socket is drained for a moment so the ticket reaches the store the
    // next connection resumes from; a run that did not wait would report every resumption as a
    // full handshake and say nothing about the library under test.
    drain(&mut conn, &mut sock);
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "1.2",
        Some(other) => fail(&format!("unexpected version {other:?}")),
        None => fail("no version"),
    };
    let suite = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "-".to_string());
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_else(|| "-".to_string());
    let resumed = matches!(
        conn.handshake_kind(),
        Some(rustls::HandshakeKind::Resumed)
    );
    let first = line.trim_end().to_string();
    (version.to_string(), suite, alpn, resumed, first)
}

/// Read whatever arrives for a moment without waiting for a close: the ticket flight of a server
/// that puts it after its first application data is the case this exists for.
fn drain(conn: &mut ClientConnection, sock: &mut TcpStream) {
    sock.set_read_timeout(Some(Duration::from_millis(400))).ok();
    let mut seen = 0;
    while seen < 65536 {
        match conn.read_tls(sock) {
            Ok(0) => break,
            Ok(n) => {
                seen += n;
                if conn.process_new_packets().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    sock.set_read_timeout(Some(Duration::from_secs(20))).ok();
}

fn server(args: &[String]) -> ! {
    if args.len() < 3 {
        fail("server <port> <chain.pem> <key.pem> [options]");
    }
    let port: u16 = args[0].parse().unwrap_or_else(|_| fail("port"));
    let opts = parse_opts(&args[3..]);
    let chain = read_certs(&args[1]);
    let key = read_key(&args[2]);
    let builder = if let Some(ca) = &opts.client_ca {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(ca)))
            .build()
            .unwrap_or_else(|e| fail(&format!("client verifier: {e}")));
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder().with_no_client_auth()
    };
    let mut config = builder
        .with_single_cert(chain, key)
        .unwrap_or_else(|e| fail(&format!("certificate: {e}")));
    config.alpn_protocols = opts.alpn.clone();
    let config = Arc::new(config);

    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| fail(&format!("bind: {e}")));
    eprintln!("listening on {port}");
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let config = config.clone();
        std::thread::spawn(move || {
            let _ = serve(config, stream);
        });
    }
    exit(0)
}

fn serve(config: Arc<ServerConfig>, mut sock: TcpStream) -> std::io::Result<()> {
    sock.set_read_timeout(Some(Duration::from_secs(20)))?;
    sock.set_write_timeout(Some(Duration::from_secs(20)))?;
    let mut conn = ServerConnection::new(config).map_err(|e| std::io::Error::other(e.to_string()))?;
    conn.complete_io(&mut sock)?;
    let mut tls = Stream::new(&mut conn, &mut sock);
    let mut reader = BufReader::new(&mut tls);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        reader.get_mut().write_all(line.as_bytes())?;
        reader.get_mut().flush()?;
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        fail("client|server");
    }
    match args[0].as_str() {
        "client" => client(&args[1..]),
        "server" => server(&args[1..]),
        other => fail(&format!("unknown mode {other}")),
    }
}
