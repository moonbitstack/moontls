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
/// application protocols it speaks in preference order, the suites and groups it accepts, and
/// `early_limit`, the most declined 0-RTT data it skips before treating what follows as an attack
/// (RFC 8446 §4.2.10).
///
/// The scheme a CertificateVerify is signed under follows from the key: an ECDSA key signs with its
/// curve's own hash, an RSA key with RSASSA-PSS.
pub(all) struct Server {
  chain : Array[Bytes]
  key : @x509.PrivateKey
  alpn : Array[String]
  suites : Array[@record.Suite]
  groups : Array[Int32]
  early_limit : Int32
}

///|
/// Refuses an empty chain and a key that is not the leaf's: either would only show up later, as a
/// client's alert in the middle of a handshake.
pub fn Server::new(
  chain : Array[Bytes],
  key : @x509.PrivateKey,
  alpn? : Array[String],
  suites~ : Array[@record.Suite] = suites,
  groups~ : Array[Int32] = groups,
  early_limit~ : Int32 = early_limit,
) -> Server raise @asn1.Refused {
  guard chain is [leaf, ..] else {
    raise @asn1.Malformed("empty certificate chain")
  }
  if @x509.parse(leaf[:]).spki.key() != key.public() {
    raise @asn1.Malformed("private key is not the leaf certificate's")
  }
  { chain, key, alpn: alpn.unwrap_or([]), suites, groups, early_limit, }
}

///|
/// A client's configuration: the trust anchors, the application protocols it offers, the suites
/// and groups it offers, how it judges the chain, and the path-validation policy.
pub(all) struct Client {
  roots : @x509.Roots
  alpn : Array[String]
  suites : Array[@record.Suite]
  groups : Array[Int32]
  verify : Verify
  policy : @x509.Policy
}

///|
pub fn Client::new(
  roots : @x509.Roots,
  alpn? : Array[String],
  suites~ : Array[@record.Suite] = suites,
  groups~ : Array[Int32] = groups,
  verify~ : Verify = Chain,
  policy~ : @x509.Policy = @x509.policy,
) -> Client {
  { roots, alpn: alpn.unwrap_or([]), suites, groups, verify, policy, }
}
