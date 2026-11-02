// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How a client judges the server's certificate chain. There is no switch that turns checking
/// off: a self-signed server is trusted by putting its certificate in the roots, or by a `Custom`
/// judge that raises to refuse.
pub(all) enum Verify {
  /// RFC 5280 path validation to the roots, and the leaf naming the host.
  Chain
  /// The caller's judgement over the chain (DER, leaf first) and the host.
  Custom((Array[Bytes], String) -> Unit raise)
}

///|
/// The suites offered or accepted, in preference order: all three of TLS 1.3's, ChaCha20-Poly1305
/// first. The AES here is software, several times slower than ChaCha20 and with table lookups a
/// cache can time; BoringSSL puts ChaCha20 first on hardware without AES instructions for the
/// same two reasons.
pub let suites : Array[@record.Suite] = [ChaCha20Poly1305, Aes128Gcm, Aes256Gcm]

///|
/// The TLS 1.2 suites offered or accepted, in preference order: ECDHE with an AEAD. The rest of what
/// this library speaks, `@record.all12`, is there for a peer that has nothing better, and asking for
/// it is a decision: RSA key exchange has no forward secrecy and CBC has a history.
pub let suites12 : Array[@record.Suite12] = @record.suites12

///|
/// The signature schemes TLS 1.2 may use, offered or accepted: SHA-2, PSS and Ed25519.
pub let schemes12 : Array[Int32] = offered

///|
/// Every scheme this library speaks in TLS 1.2. The two SHA-1 ones are what a client that sends no
/// signature_algorithms is taken to mean (RFC 5246 §7.4.1.4.1), and a collision in SHA-1 has been
/// computed, so RFC 9155 forbids them in new work. Asking for them is for old peers.
pub let all_schemes12 : Array[Int32] = [
  ..offered, @ext.rsa_pkcs1_sha224, @ext.ecdsa_sha224, @ext.rsa_pkcs1_sha1, @ext.ecdsa_sha1,
]

///|
/// The smallest finite-field prime a client takes from a server, in bits: what OpenSSL's security
/// level 2 asks for. A TLS 1.2 server names its own group, and Logjam was servers naming small ones.
pub let dh_bits : Int32 = 2048

///|
/// The key-exchange groups, in preference order: X25519, the NIST curves, then X448. The
/// finite-field groups of RFC 7919 are implemented and left out: a peer that picks ffdhe8192
/// costs a server thousands of times what X25519 does, and Go, BoringSSL and rustls leave them
/// out by default too. Pass them in `groups` to accept them.
pub let groups : Array[Int32] = [
  @ext.x25519, @ext.secp256r1, @ext.secp384r1, @ext.secp521r1, @ext.x448,
]

///|
/// How much 0-RTT data a server reads past when it declines it: OpenSSL's default for
/// `SSL_CTX_set_recv_max_early_data`, one full record.
pub let early_limit : Int32 = 16384

///|
/// How much the server asks of the client's certificate (RFC 8446 §4.4.2).
pub(all) enum Ask {
  /// No CertificateRequest is sent, and one that arrives is an unexpected_message.
  Off
  /// One is sent; a client with nothing to show answers with an empty Certificate.
  Requested
  /// One is sent; a client with nothing to show is given certificate_required.
  Required
  /// None in the handshake; one whenever the application asks, with `Conn::request_certificate`
  /// (RFC 8446 §4.6.2). TLS 1.2 has no such request and never asks.
  Deferred
} derive(Eq, Debug)

///|
pub extend Ask with Eq::{equal, not_equal}

///|
pub extend Ask with Debug::{to_repr}

///|
/// A server's side of client authentication: whether it asks, and how it judges
/// the chain it is shown.
///
/// A client chain is verified to `roots` with the `Client` usage, which is what
/// makes a certificate issued for a server fail here (RFC 5280 §4.2.1.12). A
/// server that asks for a certificate must name its anchors: `Server::new`
/// refuses one that does not, because the alternative is accepting whatever
/// arrives.
pub(all) struct ClientAuth {
  mode : Ask
  roots : @x509.Roots?
  policy : @x509.Policy
}

///|
pub fn ClientAuth::new(
  mode~ : Ask = Off,
  roots? : @x509.Roots,
  policy~ : @x509.Policy = client_policy,
) -> ClientAuth {
  { mode, roots, policy, }
}

///|
/// The path-validation policy for a client chain: RFC 5280 with the client
/// usage, so an end-entity certificate issued for a server is refused.
pub let client_policy : @x509.Policy = @x509.Policy::new(usage=Client)

///|
/// The default: no certificate is asked for, as every server did before.
pub let client_auth : ClientAuth = {
  mode: Off,
  roots: None,
  policy: client_policy,
}

///|
/// A server's configuration: its chain (DER, leaf first) and the leaf's private key, the
/// application protocols it speaks in preference order, the suites of each version and the groups
/// it accepts, and `early_limit`, the most declined 0-RTT data it skips before treating what follows
/// as an attack (RFC 8446 §4.2.10).
///
/// The scheme a CertificateVerify is signed under follows from the key: an ECDSA key signs with its
/// curve's own hash, an RSA key with RSASSA-PSS.
pub(all) struct Server {
  chain : Array[Bytes]
  key : @x509.PrivateKey
  alpn : Array[String]
  suites : Array[@record.Suite]
  suites12 : Array[@record.Suite12]
  schemes12 : Array[Int32]
  groups : Array[Int32]
  early_limit : Int32
  versions : Array[Version]
  client_auth : ClientAuth
  renegotiation : Bool
  /// Whether a Certificate is compressed when the client offered an algorithm for it
  /// (RFC 8879 §4), and one is configured here.
  compress : Bool
  /// The OCSP response stapled to the leaf certificate, when a client asks for one (RFC 6066 §8).
  ocsp : Bytes?
  /// The largest record this server will read, or zero for the 2^14 every TLS has
  /// (RFC 8449 §4).
  record_limit : Int32
  tickets : Tickets
  sessions : Sessions?
}

///|
/// Refuses an empty chain and a key that is not the leaf's: either would only show up later, as a
/// client's alert in the middle of a handshake. A server that asks for a client certificate must
/// also say which anchors it takes.
pub fn Server::new(
  chain : Array[Bytes],
  key : @x509.PrivateKey,
  alpn? : Array[String],
  suites~ : Array[@record.Suite] = suites,
  suites12~ : Array[@record.Suite12] = suites12,
  schemes12~ : Array[Int32] = schemes12,
  groups~ : Array[Int32] = groups,
  early_limit~ : Int32 = early_limit,
  versions~ : Array[Version] = versions,
  client_auth~ : ClientAuth = client_auth,
  renegotiation~ : Bool = false,
  ocsp? : Bytes,
  compress~ : Bool = false,
  record_limit~ : Int32 = 0,
  tickets~ : Tickets = tickets,
  sessions? : Sessions,
) -> Server raise @asn1.Refused {
  guard chain is [leaf, ..] else {
    raise @asn1.Malformed("empty certificate chain")
  }
  if @x509.parse(leaf[:]).spki.key() != key.public() {
    raise @asn1.Malformed("private key is not the leaf certificate's")
  }
  if client_auth.mode is (Requested | Required | Deferred) &&
    client_auth.roots is None {
    raise @asn1.Malformed("client certificates need trust anchors")
  }
  {
    chain,
    key,
    alpn: alpn.unwrap_or([]),
    suites,
    suites12,
    schemes12,
    groups,
    early_limit,
    versions,
    client_auth,
    renegotiation,
    ocsp,
    compress,
    record_limit,
    tickets,
    sessions,
  }
}

///|
/// A client's configuration: the trust anchors, the application protocols it offers, the suites of
/// each version and the groups it offers, how it judges the chain, the path-validation policy, and
/// `dh_bits`, the smallest prime it takes from a server.
///
/// `cert` and `cert_key` are the certificate chain (DER, leaf first) and key a server's
/// CertificateRequest is answered with; empty means the client has none to show. A client with one
/// also offers post_handshake_auth, so a server may ask for it after the handshake (RFC 8446 §4.6.2).
pub(all) struct Client {
  roots : @x509.Roots
  alpn : Array[String]
  suites : Array[@record.Suite]
  suites12 : Array[@record.Suite12]
  schemes12 : Array[Int32]
  groups : Array[Int32]
  verify : Verify
  policy : @x509.Policy
  versions : Array[Version]
  dh_bits : Int32
  cert : Array[Bytes]
  cert_key : @x509.PrivateKey?
  sessions : Sessions?
  early : Bool
  renegotiation : Bool
  /// Whether the ClientHello asks for the leaf's OCSP status (RFC 6066 §8).
  ocsp : Bool
  /// Whether the ClientHello says it will take a compressed Certificate (RFC 8879 §3).
  compress : Bool
  /// The largest record this client will read, or zero for 2^14 (RFC 8449 §4).
  record_limit : Int32
}

///|
pub fn Client::new(
  roots : @x509.Roots,
  alpn? : Array[String],
  suites~ : Array[@record.Suite] = suites,
  suites12~ : Array[@record.Suite12] = suites12,
  schemes12~ : Array[Int32] = schemes12,
  groups~ : Array[Int32] = groups,
  verify~ : Verify = Chain,
  policy~ : @x509.Policy = @x509.policy,
  versions~ : Array[Version] = versions,
  dh_bits~ : Int32 = dh_bits,
  cert? : Array[Bytes],
  cert_key? : @x509.PrivateKey,
  sessions? : Sessions,
  early~ : Bool = false,
  renegotiation~ : Bool = false,
  ocsp~ : Bool = false,
  compress~ : Bool = false,
  record_limit~ : Int32 = 0,
) -> Client {
  {
    roots,
    alpn: alpn.unwrap_or([]),
    suites,
    suites12,
    schemes12,
    groups,
    verify,
    policy,
    versions,
    dh_bits,
    cert: cert.unwrap_or([]),
    cert_key,
    sessions,
    early,
    renegotiation,
    ocsp,
    compress,
    record_limit,
  }
}
