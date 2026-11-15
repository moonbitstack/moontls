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
/// The signature schemes TLS 1.2 may use, offered or accepted: SHA-2 with ECDSA, RSASSA-PSS,
/// Ed25519 and the PKCS#1 pairs a chain is signed with.
///
/// RFC 8446 §4.2.3 gives the names TLS 1.3 added — RFC 8734's three brainpool schemes and the
/// ML-DSA ones — and TLS 1.2 cannot express them: there a scheme is a hash and a signature
/// algorithm, and the curve comes from the key. So they are left out, both from the offer and from
/// a CertificateRequest this library sends, which would otherwise ask a TLS 1.2 peer for something
/// that version has no way to answer.
pub let schemes12 : Array[Int32] = [
  @ext.ecdsa_secp256r1_sha256, @ext.ecdsa_secp384r1_sha384, @ext.ecdsa_secp521r1_sha512,
  @ext.ed25519, @ext.rsa_pss_rsae_sha256, @ext.rsa_pss_rsae_sha384, @ext.rsa_pss_rsae_sha512,
  @ext.rsa_pss_pss_sha256, @ext.rsa_pss_pss_sha384, @ext.rsa_pss_pss_sha512, @ext.rsa_pkcs1_sha256,
  @ext.rsa_pkcs1_sha384, @ext.rsa_pkcs1_sha512,
]

///|
/// Every scheme this library speaks in TLS 1.2. The four SHA-1 and SHA-224 ones are what a peer
/// that sends no signature_algorithms is taken to mean (RFC 5246 §7.4.1.4.1), and a collision in
/// SHA-1 has been computed, so RFC 9155 forbids them in new work. Asking for them is for old peers.
pub let all_schemes12 : Array[Int32] = [
  ..schemes12, @ext.rsa_pkcs1_sha224, @ext.ecdsa_sha224, @ext.rsa_pkcs1_sha1, @ext.ecdsa_sha1,
]

///|
/// The smallest finite-field prime a client takes from a server, in bits: what OpenSSL's security
/// level 2 asks for. A TLS 1.2 server names its own group, and Logjam was servers naming small ones.
pub let dh_bits : Int32 = 2048

///|
/// The key-exchange groups, in preference order: X25519MLKEM768, X25519, the NIST curves, then
/// X448 — the hybrid first, as Chrome, Firefox, Go, OpenSSL 3.5 and rustls now put it. The other
/// two hybrids and ML-KEM alone are implemented and left out, as they are by those five. The
/// finite-field groups of RFC 7919 are left out too: a peer that picks ffdhe8192 costs a server
/// thousands of times what X25519 does. Pass any of them in `groups` to accept them.
pub let groups : Array[Int32] = [
  @ext.x25519mlkem768, @ext.x25519, @ext.secp256r1, @ext.secp384r1, @ext.secp521r1,
  @ext.x448,
]

///|
/// RFC 7027's three brainpool groups, for a TLS 1.2 peer that asks for them.
/// They are not in `groups`: a client offers them by naming them.
pub let brainpool : Array[Int32] = [
  @ext.brainpool_p256, @ext.brainpool_p384, @ext.brainpool_p512,
]

///|
/// How many of `groups`, from the front, a first ClientHello carries a key share for. Two is what
/// Go and OpenSSL 3.5 send — X25519MLKEM768 and X25519 — so a server that has no hybrid answers
/// at once instead of with a HelloRetryRequest.
pub let shares : Int32 = 2

///|
/// How much 0-RTT data a server reads past when it declines it: OpenSSL's default for
/// `SSL_CTX_set_recv_max_early_data`, one full record.
pub let early_limit : Int32 = 16384

///|
/// A pre-shared key and the identity that names it (RFC 8446 §4.2.11).
///
/// The key never goes on the wire; the identity does, and it is what a server matches to find the
/// key. `digest` is the hash the PSK is bound to, and it fixes the suite: a PSK under SHA-256 can
/// only be used with a suite whose hash is SHA-256, because the binder and the early secret are
/// derived over that hash.
///
/// This is the configuration side of an out-of-band secret — a value two ends already share, from
/// a file, a provisioning system, or an earlier connection. A ticket is the same mechanism with
/// the secret derived from a handshake instead.
pub(all) struct Psk {
  identity : Bytes
  key : Bytes
  digest : @keys.Digest
}

///|
/// `key` should be at least as long as the hash it is bound to — 32 octets for SHA-256 — which is
/// what RFC 8446 §4.2.11 says of a PSK's entropy. A shorter one is accepted: what a peer does with
/// a key it was given is the caller's decision, not this library's.
pub fn Psk::new(
  identity : BytesView,
  key : BytesView,
  digest~ : @keys.Digest = @keys.digest,
) -> Psk {
  { identity: identity.to_owned(), key: key.to_owned(), digest, }
}

///|
/// The certificate compression algorithms this library speaks, in preference order (RFC 8879 §4.2):
/// zlib, brotli, zstd. A client advertises them in this order; a server takes the first it is
/// offered that also makes the message shorter.
pub let compressions : Array[Int32] = [
  @ext.zlib_compression, @ext.brotli_compression, @ext.zstd_compression,
]

///|
/// The key-exchange modes a PSK may be used with, default: `psk_dhe_ke` alone.
///
/// The key exchange is what makes a recorded handshake useless to whoever replays it later, so a
/// PSK alone — `psk_ke` — is off until a caller asks for it.
pub let psk_modes : Array[Int32] = [@ext.psk_dhe_ke]

///|
/// How much the server asks of the client's certificate (RFC 8446 §4.4.2).
#derive(Eq, Debug)
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
}

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
///
/// `alternatives` are further credentials, tried in order after `chain` and `key` (RFC 8446
/// §4.4.2.2): the first whose key the client's signature algorithms allow, whose suites and curve a
/// TLS 1.2 client accepts, and whose leaf is for the host the client named by SNI goes out. With
/// none fitting, `chain` does, and the handshake ends as it would without alternatives.
pub(all) struct Server {
  chain : Array[Bytes]
  key : @x509.PrivateKey
  alternatives : Array[Credential]
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
  /// The algorithms this server may compress with, in preference order; the client's offer
  /// decides which of them is actually used.
  compressions : Array[Int32]
  /// The OCSP response stapled to the leaf certificate, when a client asks for one (RFC 6066 §8).
  ocsp : Bytes?
  /// The largest record this server will read, or zero for the 2^14 every TLS has
  /// (RFC 8449 §4).
  record_limit : Int32
  tickets : Tickets
  sessions : Sessions?
  /// The SRTP protection profiles this server will answer `use_srtp` with
  /// (RFC 5764 §4.1). Empty means it does not speak DTLS-SRTP.
  srtp : Array[@srtp.Profile]
  /// The pre-shared keys this server accepts, by identity (RFC 8446 §4.2.11). Empty leaves the
  /// tickets it issues as its only PSKs.
  psk : Array[Psk]
  /// The modes a PSK may be used in, by preference. `psk_dhe_ke` alone by default: `psk_ke` keys
  /// the handshake from the secret alone, with no forward secrecy.
  psk_modes : Array[Int32]
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
  compressions~ : Array[Int32] = compressions,
  record_limit~ : Int32 = 0,
  tickets~ : Tickets = tickets,
  sessions? : Sessions,
  srtp~ : Array[@srtp.Profile] = [],
  psk~ : Array[Psk] = [],
  psk_modes~ : Array[Int32] = psk_modes,
  alternatives~ : Array[Credential] = [],
) -> Server raise @asn1.Refused {
  owned(chain, key)
  for c in alternatives {
    owned(c.chain, c.key)
  }
  if client_auth.mode is (Requested | Required | Deferred) &&
    client_auth.roots is None {
    raise @asn1.Malformed("client certificates need trust anchors")
  }
  {
    chain,
    key,
    alternatives,
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
    compressions,
    record_limit,
    tickets,
    sessions,
    srtp,
    psk,
    psk_modes,
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
  shares : Int32
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
  /// The algorithms the ClientHello says it will take, best first (RFC 8879 §3).
  compressions : Array[Int32]
  /// The largest record this client will read, or zero for 2^14 (RFC 8449 §4).
  record_limit : Int32
  /// The SRTP protection profiles this client offers (RFC 5764 §4.1). Empty
  /// means it does not ask for DTLS-SRTP.
  srtp : Array[@srtp.Profile]
  /// The pre-shared keys this client offers, in order (RFC 8446 §4.2.11). A ticket
  /// the session store holds is offered after them.
  psk : Array[Psk]
  /// The modes these PSKs may be used in, which is what the ClientHello declares.
  psk_modes : Array[Int32]
}

///|
pub fn Client::new(
  roots : @x509.Roots,
  alpn? : Array[String],
  suites~ : Array[@record.Suite] = suites,
  suites12~ : Array[@record.Suite12] = suites12,
  schemes12~ : Array[Int32] = schemes12,
  groups~ : Array[Int32] = groups,
  shares~ : Int32 = shares,
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
  compressions~ : Array[Int32] = compressions,
  record_limit~ : Int32 = 0,
  srtp~ : Array[@srtp.Profile] = [],
  psk~ : Array[Psk] = [],
  psk_modes~ : Array[Int32] = psk_modes,
) -> Client {
  {
    roots,
    alpn: alpn.unwrap_or([]),
    suites,
    suites12,
    schemes12,
    groups,
    shares,
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
    compressions,
    record_limit,
    srtp,
    psk,
    psk_modes,
  }
}
