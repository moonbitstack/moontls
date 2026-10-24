// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A server's signing key. The scheme it signs under follows from the key: an ECDSA key signs with
/// its curve's own hash, an RSA key with RSASSA-PSS.
pub(all) enum Key {
  Ecdsa(@ecdsa.PrivateKey)
  Rsa(@rsa.PrivateKey)
  Ed25519(@ed25519.PrivateKey)
}

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
/// The suites offered or accepted, in preference order: all three of TLS 1.3's.
pub let suites : Array[@record.Suite] = [Aes128Gcm, Aes256Gcm, ChaCha20Poly1305]

///|
/// The key-exchange groups, in preference order: X25519, then the two NIST curves.
pub let groups : Array[Int32] = [@ext.x25519, @ext.secp256r1, @ext.secp384r1]

///|
/// A server's configuration: its chain (DER, leaf first) and key, the application protocols it
/// speaks in preference order, and the suites and groups it accepts.
pub(all) struct Server {
  chain : Array[Bytes]
  key : Key
  alpn : Array[String]
  suites : Array[@record.Suite]
  groups : Array[Int32]
}

///|
pub fn Server::new(
  chain : Array[Bytes],
  key : Key,
  alpn? : Array[String],
  suites~ : Array[@record.Suite] = suites,
  groups~ : Array[Int32] = groups,
) -> Server {
  { chain, key, alpn: alpn.unwrap_or([]), suites, groups, }
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
