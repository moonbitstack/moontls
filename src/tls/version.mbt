// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A protocol version. TLS 1.0 and 1.1 are not here: RFC 8996 forbids negotiating them.
pub(all) enum Version {
  Tls12
  Tls13
} derive(Eq, Debug)

///|
pub extend Version with Eq::{equal, not_equal}

///|
pub extend Version with Debug::{to_repr}

///|
/// The version's code on the wire.
pub fn Version::code(self : Version) -> Int32 {
  match self {
    Tls12 => 0x0303
    Tls13 => 0x0304
  }
}

///|
/// The version a code names, `None` for one this library does not speak.
pub fn Version::of(code : Int32) -> Version? {
  match code {
    0x0303 => Some(Tls12)
    0x0304 => Some(Tls13)
    _ => None
  }
}

///|
/// The versions spoken, best first: both, as Go, rustls and OpenSSL enable by default. Much of the
/// web still answers only to 1.2.
pub let versions : Array[Version] = [Tls13, Tls12]

///|
/// The last eight octets of a ServerHello's random from a 1.3 server that picked 1.2
/// (RFC 8446 §4.1.3). A 1.3 client that sees them knows something in between took 1.3 away.
let downgrade : Bytes = b"DOWNGRD\x01"

///|
/// TLS_FALLBACK_SCSV (RFC 7507): a client saying this is a retry at a lower version.
let fallback_scsv : Int32 = 0x5600

///|
/// TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746 §3.3), the suite-list form of renegotiation_info.
let renegotiation_scsv : Int32 = 0x00ff

///|
/// Where a TLS 1.2 handshake has got to: what each end waits for next (RFC 5246 §7.3).
priv enum Step12 {
  /// Client: the server's Certificate.
  Chain
  /// Client: its ServerKeyExchange.
  Exchange
  /// Client: a CertificateRequest or its ServerHelloDone.
  Done
  /// Server: the ClientKeyExchange.
  ClientKey
  /// Either end: the peer's change_cipher_spec, which turns on what it sends next.
  Cipher
  /// Either end: the peer's Finished.
  Closing
}

///|
/// A hash for ECDSA as TLS 1.2 uses it, where the scheme's name does not tie it to a curve.
fn ecdsa_digest(scheme : Int32) -> @keys.Digest? {
  match scheme {
    s if s == @ext.ecdsa_secp256r1_sha256 => Some(Sha256)
    s if s == @ext.ecdsa_secp384r1_sha384 => Some(Sha384)
    _ => None
  }
}

///|
/// Whether `sig` over `content` verifies under the leaf's key with `scheme`, by TLS 1.2's rules:
/// PKCS#1 is allowed, and an ECDSA scheme names a hash rather than a curve (RFC 5246 §7.4.1.4.1).
fn verified12(
  leaf : @x509.Cert,
  scheme : Int32,
  content : Bytes,
  sig : Bytes,
) -> Bool {
  let key = leaf.spki.key() catch { _ => return false }
  match key {
    Ed25519(k) => scheme == @ext.ed25519 && k.verify(content[:], sig[:])
    Rsa(k) => {
      if pss_digest(scheme) is Some(d) {
        return k
          .with_scheme(digest=d, scheme=Pss(salt=pss_salt(d)))
          .verify(content[:], sig[:])
      }
      guard pkcs1_digest(scheme) is Some(d) else { return false }
      k.with_scheme(digest=d, scheme=Pkcs1).verify(content[:], sig[:])
    }
    Ec(k) => {
      guard ecdsa_raw(sig, k.curve().size()) is Some(raw) else { return false }
      match ecdsa_digest(scheme) {
        Some(d) => {
          let hashed = @ecdsa.PublicKey::with_hash(
            k.bytes()[:],
            d.hasher(),
            curve=k.curve(),
          ) catch {
            _ => return false
          }
          hashed.verify(content[:], raw[:])
        }
        None =>
          scheme == @ext.ecdsa_secp521r1_sha512 &&
          k.curve() is P521 &&
          k.verify(content[:], raw[:])
      }
    }
  }
}

///|
/// The schemes a key can sign a ServerKeyExchange under, best first: PSS for RSA where the client
/// takes it, and PKCS#1, which is all a TLS 1.2 client is sure to.
fn schemes12(key : @x509.PrivateKey) -> Array[Int32] {
  let out = schemes(key)
  if key is Rsa(_) {
    out.push(@ext.rsa_pkcs1_sha256)
    out.push(@ext.rsa_pkcs1_sha384)
    out.push(@ext.rsa_pkcs1_sha512)
  }
  out
}

///|
/// Cut the key block into the two directions' ciphers (RFC 5246 §6.3): the client's write key, the
/// server's, then the two IVs.
fn Conn::ciphers12(self : Conn) -> (@record.Cipher, @record.Cipher) {
  let suite = self.suite.unwrap()
  let (k, v) = (suite.key_size(), suite.iv12())
  let block = @keys.key_block(
    self.master[:],
    self.client_random[:],
    self.server_random[:],
    len=2 * (k + v),
    digest=self.digest(),
  )
  (
    @record.Cipher::tls12(block[0:k], block[2 * k:2 * k + v], suite~),
    @record.Cipher::tls12(block[k:2 * k], block[2 * k + v:], suite~),
  )
}

///|
/// The master secret from the ECDHE's shared secret. With extended_master_secret it is bound to
/// the transcript as it stands, which is through the ClientKeyExchange (RFC 7627 §3).
fn Conn::master_from(self : Conn, shared : Bytes) -> Unit {
  let session = if self.extended { Some(self.th()) } else { None }
  self.master = @keys.master12(
    shared[:],
    self.client_random[:],
    self.server_random[:],
    session?=session.map(hash => hash[:]),
    digest=self.digest(),
  )
}

///|
/// Check the peer's Finished against the transcript as it stands.
fn Conn::check_finished12(
  self : Conn,
  body : Bytes,
  client~ : Bool,
) -> Unit raise @alert.Alert {
  if body.length() != 12 {
    raise @alert.fatal(DecodeError)
  }
  if !@keys.finished12_ok(
      self.master[:],
      self.th()[:],
      body[:],
      client~,
      digest=self.digest(),
    ) {
    raise @alert.fatal(DecryptError)
  }
}

///|
/// This end's Finished, folded into the transcript.
fn Conn::send_finished12(
  self : Conn,
  client~ : Bool,
) -> Unit raise @alert.Alert {
  let verify = @keys.finished12(
    self.master[:],
    self.th()[:],
    client~,
    digest=self.digest(),
  )
  let message = @msg.frame(Finished, verify[:])
  self.record(message[:])
  self.send_handshake(message)
}

///|
/// A change_cipher_spec in a TLS 1.2 handshake: it is a real message there, and turns on the reader
/// for what follows. Anywhere else, or with a handshake message half read, it is an error.
fn Conn::on_cipher12(self : Conn, fragment : Bytes) -> Unit raise @alert.Alert {
  guard self.phase is Legacy(Cipher) &&
    fragment == b"\x01" &&
    self.messages.length() == 0 &&
    self.waiting is Some(cipher) else {
    raise @alert.fatal(UnexpectedMessage)
  }
  self.reader = Some(cipher)
  self.waiting = None
  self.phase = Legacy(Closing)
}

///|
/// A peer asking for a new handshake on a TLS 1.2 connection. This library does not renegotiate,
/// and says so with the warning RFC 5746 leaves for that, on a connection that otherwise goes on.
fn Conn::decline_renegotiation(self : Conn) -> Unit {
  self.send_alert(@alert.warning(NoRenegotiation))
}
