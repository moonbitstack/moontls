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
}

///|
/// Refuses an empty chain and a key that is not the leaf's: either would only show up later, as a
/// client's alert in the middle of a handshake.
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
) -> Server raise @asn1.Refused {
  guard chain is [leaf, ..] else {
    raise @asn1.Malformed("empty certificate chain")
  }
  if @x509.parse(leaf[:]).spki.key() != key.public() {
    raise @asn1.Malformed("private key is not the leaf certificate's")
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
  }
}

///|
/// A client's configuration: the trust anchors, the application protocols it offers, the suites of
/// each version and the groups it offers, how it judges the chain, the path-validation policy, and
/// `dh_bits`, the smallest prime it takes from a server.
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
  }
}
