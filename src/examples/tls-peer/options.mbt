// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// `key=value` arguments after the fixed ones, and bare words as keys with an empty value.
pub fn options(args : ArrayView[String]) -> Map[String, String] {
  let out : Map[String, String] = Map([])
  for arg in args {
    match arg.find("=") {
      Some(i) => out[arg[:i].to_owned()] = arg[i + 1:].to_owned()
      None => out[arg] = ""
    }
  }
  out
}

///|
/// Print one status line, and write it to `report=<path>` as well when a run gave one.
///
/// A server's stdout is a pipe the harness reads, which C block buffers: a line written to it is
/// still in the buffer when the run ends and the peer is killed, so a server that says nothing is
/// indistinguishable from one that said everything. The file is opened, appended and closed for
/// each line, which is what makes it visible at once.
pub async fn say(opts : Map[String, String], line : String) -> Unit {
  println(line)
  match opts.get("report") {
    Some(path) =>
      @fs.write_file(path, line + "\n", append=true) catch {
        _ => ()
      }
    None => ()
  }
}

///|
/// The name RFC 8446 §6.2 gives an alert, so that a run's expectations read like the specification
/// rather than like this file.
pub fn alert_name(kind : @alert.Kind) -> String {
  match kind {
    CloseNotify => "close_notify"
    UnexpectedMessage => "unexpected_message"
    BadRecordMac => "bad_record_mac"
    RecordOverflow => "record_overflow"
    HandshakeFailure => "handshake_failure"
    BadCertificate => "bad_certificate"
    UnsupportedCertificate => "unsupported_certificate"
    CertificateRevoked => "certificate_revoked"
    CertificateExpired => "certificate_expired"
    CertificateUnknown => "certificate_unknown"
    IllegalParameter => "illegal_parameter"
    UnknownCa => "unknown_ca"
    AccessDenied => "access_denied"
    DecodeError => "decode_error"
    DecryptError => "decrypt_error"
    ProtocolVersion => "protocol_version"
    InsufficientSecurity => "insufficient_security"
    InternalError => "internal_error"
    InappropriateFallback => "inappropriate_fallback"
    UserCanceled => "user_canceled"
    MissingExtension => "missing_extension"
    UnsupportedExtension => "unsupported_extension"
    UnrecognizedName => "unrecognized_name"
    BadCertificateStatusResponse => "bad_certificate_status_response"
    UnknownPskIdentity => "unknown_psk_identity"
    CertificateRequired => "certificate_required"
    NoApplicationProtocol => "no_application_protocol"
    NoRenegotiation => "no_renegotiation"
    Other(code) => "alert_\{code}"
  }
}

///|
fn split(list : String?) -> Array[String]? {
  list.map(text => text.split(",").map(s => s.to_owned()).collect())
}

///|
fn number(text : String, what : String) -> Int32 {
  @string.parse_int(text) catch {
    _ => abort("not a \{what}: " + text)
  }
}

///|
fn suites_of(names : Array[String]?) -> Array[@record.Suite]? {
  names.map(ns => {
    ns.map(name => {
      match name {
        "aes128" => @record.Aes128Gcm
        "aes256" => @record.Aes256Gcm
        "chacha20" => @record.ChaCha20Poly1305
        other => abort("no such suite: " + other)
      }
    })
  })
}

///|
fn suites12_of(names : Array[String]?) -> Array[@record.Suite12]? {
  names.map(list => {
    match list {
      ["all"] => @record.all12
      codes =>
        codes.map(text => {
          let code = @string.parse_int(text, base=16) catch {
            _ => abort("not a suite code: " + text)
          }
          match @record.Suite12::of(code) {
            Some(suite) => suite
            None => abort("no such suite: " + text)
          }
        })
    }
  })
}

///|
fn versions_of(names : Array[String]?) -> Array[@tls.Version]? {
  names.map(list => {
    list.map(name => {
      match name {
        "10" => @tls.Tls10
        "11" => @tls.Tls11
        "12" => @tls.Tls12
        "13" => @tls.Tls13
        other => abort("no such version: " + other)
      }
    })
  })
}

///|
/// The groups an option names. The TLS 1.3 hybrids and ML-KEM alone come first because they are
/// what this library offers by default and what a peer that speaks them is being tested against.
fn groups_of(names : Array[String]?) -> Array[Int32]? {
  names.map(list => {
    list.map(name => {
      match name {
        "x25519" => @ext.x25519
        "x448" => @ext.x448
        "p256" => @ext.secp256r1
        "p384" => @ext.secp384r1
        "p521" => @ext.secp521r1
        "brainpool256" => @ext.brainpool_p256
        "brainpool384" => @ext.brainpool_p384
        "brainpool512" => @ext.brainpool_p512
        "x25519mlkem768" => @ext.x25519mlkem768
        "p256mlkem768" => @ext.secp256r1mlkem768
        "p384mlkem1024" => @ext.secp384r1mlkem1024
        "mlkem768" => @ext.mlkem768
        "mlkem1024" => @ext.mlkem1024
        "ffdhe2048" => @ext.ffdhe2048
        "ffdhe3072" => @ext.ffdhe3072
        "ffdhe4096" => @ext.ffdhe4096
        "ffdhe6144" => @ext.ffdhe6144
        "ffdhe8192" => @ext.ffdhe8192
        other => abort("no such group: " + other)
      }
    })
  })
}

///|
/// This process's randomness: the platform's own, since a peer that could be predicted would make
/// an interop run say nothing.
pub fn entropy(n : Int32) -> Bytes {
  guard @env.rand(n) is Some(bytes) else { abort("no system entropy") }
  bytes
}

///|
/// The wall clock in seconds, which is what a certificate is judged at.
pub fn wall_clock() -> Int64 {
  (@env.now() / 1000UL).reinterpret_as_int64()
}

///|
/// A clock in milliseconds for the retransmission timers.
pub fn monotonic() -> Int64 {
  @env.now().reinterpret_as_int64()
}

///|
async fn text_of(path : String) -> String {
  @fs.read_file(path).text() catch {
    e => abort("cannot read \{path}: \{e}")
  }
}

///|
async fn bytes_of(path : String) -> Bytes {
  @fs.read_file(path).binary() catch {
    e => abort("cannot read \{path}: \{e}")
  }
}

///|
/// A server's configuration from the command line.
pub async fn server_config(
  chain : String,
  key : String,
  opts : Map[String, String],
) -> @tls.Server {
  let request = match opts.get("ask") {
    Some("1") => @tls.Ask::Requested
    Some("2") => @tls.Ask::Required
    _ => @tls.Ask::Off
  }
  let anchors = match opts.get("roots") {
    Some(path) => Some(@x509.Roots::pem(text_of(path)))
    None => None
  }
  let client_auth = @tls.ClientAuth::new(mode=request, roots?=anchors)
  let staple = match opts.get("ocsp") {
    Some(path) => Some(bytes_of(path))
    None => None
  }
  let tickets = match opts.get("tickets") {
    Some(n) => @tls.Tickets::new([entropy(32)], count=number(n, "ticket count"))
    None => @tls.tickets
  }
  @tls.Server::new(
    @x509.pems(text_of(chain)),
    @x509.PrivateKey::pem(text_of(key)),
    alpn?=split(opts.get("alpn")),
    suites?=suites_of(split(opts.get("suites"))),
    suites12?=suites12_of(split(opts.get("suites12"))),
    schemes12?=if opts.contains("schemes12") {
      Some(@tls.all_schemes12)
    } else {
      None
    },
    groups?=groups_of(split(opts.get("groups"))),
    versions?=versions_of(split(opts.get("versions"))),
    client_auth~,
    renegotiation=opts.contains("renegotiate"),
    ocsp?=staple,
    compress=opts.contains("compress"),
    record_limit=opts
      .get("record_limit")
      .map(n => number(n, "record limit"))
      .unwrap_or(0),
    tickets~,
    srtp=if opts.contains("srtp") { @srtp.supported } else { [] },
  )
}

///|
/// A client's configuration from the command line. `sessions` is passed in rather than built here,
/// because a run that resumes keeps it across two handshakes.
pub async fn client_config(
  roots : String,
  opts : Map[String, String],
  sessions : @tls.Sessions?,
) -> @tls.Client {
  let chain = match opts.get("cert") {
    Some(path) => Some(@x509.pems(text_of(path)))
    None => None
  }
  let key = match opts.get("key") {
    Some(path) => Some(@x509.PrivateKey::pem(text_of(path)))
    None => None
  }
  @tls.Client::new(
    @x509.Roots::pem(text_of(roots)),
    alpn?=split(opts.get("alpn")),
    suites?=suites_of(split(opts.get("suites"))),
    suites12?=suites12_of(split(opts.get("suites12"))),
    schemes12?=if opts.contains("schemes12") {
      Some(@tls.all_schemes12)
    } else {
      None
    },
    groups?=groups_of(split(opts.get("groups"))),
    versions?=versions_of(split(opts.get("versions"))),
    cert?=chain,
    cert_key?=key,
    sessions?,
    early=opts.contains("early"),
    renegotiation=opts.contains("renegotiate"),
    ocsp=opts.contains("ocsp"),
    compress=opts.contains("compress"),
    record_limit=opts
      .get("record_limit")
      .map(n => number(n, "record limit"))
      .unwrap_or(0),
    srtp=if opts.contains("srtp") { @srtp.supported } else { [] },
  )
}

///|
/// What a client asks for, and whether a complete line is the end of the answer.
pub fn request_of(opts : Map[String, String], name : String) -> (String, Bool) {
  match (opts.get("get"), opts.get("send"), opts.get("big")) {
    (Some(path), _, _) =>
      ("GET \{path} HTTP/1.0\r\nHost: \{name}\r\n\r\n", false)
    (_, Some(text), _) => (text + "\n", true)
    // A line long enough to be cut into many records both ways, which is what a transfer case is
    // for: one line, so the peer still knows when the answer is complete.
    (_, None, Some(size)) => ("x".repeat(number(size, "size")) + "\n", true)
    (_, None, None) => ("ping\n", true)
  }
}
