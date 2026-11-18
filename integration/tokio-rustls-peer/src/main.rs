// A peer for the interop matrix, written against tokio-rustls.
//
//     tokio-rustls-peer client <host> <port> <ca.pem> [sni=NAME] [alpn=a,b] [versions=12|13]
//                              [resume] [cert=PATH key=PATH]
//     tokio-rustls-peer server <port> <chain.pem> <key.pem> [alpn=a,b] [clientca=PATH]
//
// Both sides speak lines: the server answers every line it reads with the same line, and the
// client sends one, reads it back, and prints where the connection landed.
//
// The engine is the same rustls the synchronous peer drives; what this peer adds is the other
// shape a consumer puts around it — tokio's reactor rather than a blocking socket per thread, and
// one `AsyncWrite`/`AsyncRead` stream rather than a handshake that has to be pumped by hand. A
// defect in how this library's records interleave with an async runtime shows up here and nowhere
// else, which is the reason it is a peer of its own rather than a flag on the other one.

use std::fs::File;
use std::io::{BufReader, Write};
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct Opts {
    sni: String,
    alpn: Vec<Vec<u8>>,
    resume: bool,
    versions: Option<&'static rustls::SupportedProtocolVersion>,
    cert: Option<String>,
    key: Option<String>,
    client_ca: Option<String>,
}

fn parse_opts(args: &[String]) -> Opts {
    let mut opts = Opts {
        sni: "localhost".to_string(),
        alpn: Vec::new(),
        resume: false,
        versions: None,
        cert: None,
        key: None,
        client_ca: None,
    };
    for arg in args {
        if arg == "resume" {
            opts.resume = true;
        } else if arg == "early" {
            // This peer reports resumption only; the early-data cases live where the client can
            // say what it sent before the handshake finished.
        } else if let Some(value) = arg.strip_prefix("sni=") {
            opts.sni = value.to_string();
        } else if let Some(value) = arg.strip_prefix("alpn=") {
            opts.alpn = value
                .split(',')
                .filter(|one| !one.is_empty())
                .map(|one| one.as_bytes().to_vec())
                .collect();
        } else if let Some(value) = arg.strip_prefix("versions=") {
            opts.versions = match value {
                "12" => Some(&rustls::version::TLS12),
                "13" => Some(&rustls::version::TLS13),
                other => fail(&format!("unknown versions={other}")),
            };
        } else if let Some(value) = arg.strip_prefix("cert=") {
            opts.cert = Some(value.to_string());
        } else if let Some(value) = arg.strip_prefix("key=") {
            opts.key = Some(value.to_string());
        } else if let Some(value) = arg.strip_prefix("clientca=") {
            opts.client_ca = Some(value.to_string());
        } else {
            fail(&format!("unknown option: {arg}"));
        }
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
    eprintln!("tokio-rustls-peer: {message}");
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

fn builder(versions: Option<&'static rustls::SupportedProtocolVersion>) -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    match versions {
        Some(one) => ClientConfig::builder_with_protocol_versions(&[one]),
        None => ClientConfig::builder(),
    }
}

fn client_config(opts: &Opts, ca: &str) -> Arc<ClientConfig> {
    let mut config = if let (Some(cert), Some(key)) = (&opts.cert, &opts.key) {
        builder(opts.versions)
            .with_root_certificates(roots(ca))
            .with_client_auth_cert(read_certs(cert), read_key(key))
            .unwrap_or_else(|e| fail(&format!("client certificate: {e}")))
    } else {
        builder(opts.versions)
            .with_root_certificates(roots(ca))
            .with_no_client_auth()
    };
    config.alpn_protocols = opts.alpn.clone();
    // 32, not 8: the cache divides what it is given by eight to bound the servers it holds, and a
    // bound of one server is a cache that evicts each ticket as it inserts it.
    config.resumption = rustls::client::Resumption::in_memory_sessions(32);
    Arc::new(config)
}

async fn one(
    config: &Arc<ClientConfig>,
    host: &str,
    port: u16,
    sni: &str,
) -> (String, String, String, bool, String) {
    let name = ServerName::try_from(sni.to_string()).unwrap_or_else(|e| fail(&format!("sni: {e}")));
    let stream = TcpStream::connect((host, port))
        .await
        .unwrap_or_else(|e| fail(&format!("connect: {e}")));
    let mut tls = TlsConnector::from(config.clone())
        .connect(name, stream)
        .await
        .unwrap_or_else(|e| fail(&format!("handshake: {e}")));
    tls.write_all(b"ping\n")
        .await
        .unwrap_or_else(|e| fail(&format!("write: {e}")));
    tls.flush().await.unwrap_or_else(|e| fail(&format!("flush: {e}")));

    let mut line = String::new();
    {
        let mut reader = AsyncBufReader::new(&mut tls);
        reader
            .read_line(&mut line)
            .await
            .unwrap_or_else(|e| fail(&format!("read: {e}")));
    }

    // A ticket is a separate flight and a server may put it after its first application data, so
    // the stream is drained for a moment before the connection closes: a run that did not wait
    // would report every resumption as a full handshake.
    let _ = tokio::time::timeout(Duration::from_millis(400), async {
        let mut sink = [0u8; 4096];
        loop {
            match tokio::io::AsyncReadExt::read(&mut tls, &mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    })
    .await;

    let (_, session) = tls.get_ref();
    let version = match session.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "1.2",
        Some(other) => fail(&format!("unexpected version {other:?}")),
        None => fail("no version"),
    };
    let suite = session
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "-".to_string());
    let alpn = session
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_else(|| "-".to_string());
    let resumed = matches!(
        session.handshake_kind(),
        Some(rustls::HandshakeKind::Resumed)
    );
    let first = line.trim_end().to_string();
    (version.to_string(), suite, alpn, resumed, first)
}

async fn run_client(host: String, port: u16, ca: String, opts: Opts) {
    let config = client_config(&opts, &ca);
    if opts.resume {
        let _ = one(&config, &host, port, &opts.sni).await;
    }
    let (version, suite, alpn, resumed, first) = one(&config, &host, port, &opts.sni).await;
    println!(
        "ok version={version} suite={suite} alpn={alpn} sni={} resumed={} early=0 bytes={} first={first}",
        opts.sni,
        if resumed { 1 } else { 0 },
        first.len() + 1
    );
    exit(0)
}

async fn run_server(port: u16, chain: String, key: String, opts: Opts) {
    let builder = if let Some(ca) = &opts.client_ca {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(ca)))
            .build()
            .unwrap_or_else(|e| fail(&format!("client verifier: {e}")));
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder().with_no_client_auth()
    };
    let mut config = builder
        .with_single_cert(read_certs(&chain), read_key(&key))
        .unwrap_or_else(|e| fail(&format!("certificate: {e}")));
    config.alpn_protocols = opts.alpn.clone();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| fail(&format!("bind: {e}")));
    eprintln!("listening on {port}");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _ = serve(acceptor, stream).await;
        });
    }
}

async fn serve(acceptor: TlsAcceptor, stream: TcpStream) -> std::io::Result<()> {
    let mut tls = acceptor.accept(stream).await?;
    let mut reader = AsyncBufReader::new(&mut tls);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        reader.get_mut().write_all(line.as_bytes()).await?;
        reader.get_mut().flush().await?;
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        fail("client|server");
    }
    match args[0].as_str() {
        "client" => {
            if args.len() < 4 {
                fail("client <host> <port> <ca.pem> [options]");
            }
            let port: u16 = args[2].parse().unwrap_or_else(|_| fail("port"));
            let opts = parse_opts(&args[4..]);
            run_client(args[1].clone(), port, args[3].clone(), opts).await
        }
        "server" => {
            if args.len() < 4 {
                fail("server <port> <chain.pem> <key.pem> [options]");
            }
            let port: u16 = args[1].parse().unwrap_or_else(|_| fail("port"));
            let opts = parse_opts(&args[4..]);
            run_server(port, args[2].clone(), args[3].clone(), opts).await
        }
        other => fail(&format!("unknown mode {other}")),
    }
}
