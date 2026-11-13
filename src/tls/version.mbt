// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A protocol version. TLS 1.0 and 1.1 are here but not on offer by default: RFC 8996 forbids
/// negotiating them, and every one of their records is an attack surface RFC 5246 spent a decade
/// closing. A caller that needs them says so.
#derive(Eq, Debug)
pub(all) enum Version {
  Tls10
  Tls11
  Tls12
  Tls13
}

///|
pub extend Version with Eq::{equal, not_equal}

///|
pub extend Version with Debug::{to_repr}

///|
/// The version's code on the wire.
pub fn Version::code(self : Version) -> Int32 {
  match self {
    Tls10 => 0x0301
    Tls11 => 0x0302
    Tls12 => 0x0303
    Tls13 => 0x0304
  }
}

///|
/// The version a code names, `None` for one this library does not speak.
pub fn Version::of(code : Int32) -> Version? {
  match code {
    0x0301 => Some(Tls10)
    0x0302 => Some(Tls11)
    0x0303 => Some(Tls12)
    0x0304 => Some(Tls13)
    // RFC 9147 §5.3: DTLS's own numbers, 0xfefd down to 0xfeff, in `supported_versions` alone.
    0xfefc => Some(Tls13)
    // RFC 9147 §4 and RFC 6347 §4.1: a DTLS record and the first ClientHello
    // carry DTLS 1.2's own number, which names the same protocol.
    0xfefd => Some(Tls12)
    0xfefe => Some(Tls11)
    0xfeff => Some(Tls10)
    _ => None
  }
}

///|
/// The version a datagram transport writes where a stream writes 0x0303: DTLS
/// 1.2's own number, which every DTLS record and the first ClientHello carry.
pub let datagram_version : Int32 = 0xfefd

///|
/// The code `supported_versions` names this version by, on the carrier it travels on: 0x0304 for
/// TLS 1.3 and 0xfefc for DTLS 1.3, 0x0303 for TLS 1.2 and 0xfefd for DTLS 1.2 (RFC 9147 §5.3).
/// DTLS has its own number for every version it shares with TLS, and a datagram hello that lists
/// the TLS one is not offering a DTLS version at all.
pub fn supported(version : Version, datagram~ : Bool = false) -> Int32 {
  if datagram {
    // RFC 9147 §5.3: DTLS numbers its versions 0xfefd down to 0xfeff, and a datagram hello that
    // names 0x0303 in `supported_versions` is offering TLS 1.2, which is not a DTLS version at all.
    match version {
      Tls13 => @ext.version_13_datagram
      Tls12 => 0xfefd
      Tls11 => 0xfefe
      Tls10 => 0xfeff
    }
  } else {
    version.code()
  }
}

///|
/// Whether this version is one of the three whose records, PRF and signatures TLS 1.2 shares.
pub fn Version::is_legacy(self : Version) -> Bool {
  self is (Tls10 | Tls11 | Tls12)
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
  /// Server: the client's CertificateVerify, when it showed a certificate (RFC 5246 §7.4.8).
  Proof
  /// Either end: the peer's change_cipher_spec, which turns on what it sends next.
  Cipher
  /// Either end: the peer's Finished.
  Closing
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
    MlDsa(_) => false
    Rsa(k) => {
      if pss_digest(scheme) is Some(d) {
        return k
          .with_scheme(digest=d, scheme=Pss(salt=Exact(pss_salt(d))))
          .verify(content[:], sig[:])
      }
      guard pkcs1_digest(scheme) is Some(d) else { return false }
      k.with_scheme(digest=d, scheme=Pkcs1).verify(content[:], sig[:])
    }
    Ec(k) => {
      guard ecdsa_raw(sig, k.curve().size()) is Some(raw) &&
        ecdsa_hash(scheme) is Some(hash) else {
        return false
      }
      let hashed = @ecdsa.PublicKey::with_hash(
        k.bytes()[:],
        hash,
        curve=k.curve(),
      ) catch {
        _ => return false
      }
      hashed.verify(content[:], raw[:])
    }
  }
}

///|
/// The schemes a key can sign a ServerKeyExchange under, best first: PSS for RSA where the client
/// takes it, then PKCS#1, which is all a TLS 1.2 client is sure to; for ECDSA any of the hashes,
/// since a scheme there names one and does not tie it to the key's curve.
fn key_schemes12(key : @x509.PrivateKey) -> Array[Int32] {
  match key {
    Ec(_) =>
      [
        @ext.ecdsa_secp256r1_sha256, @ext.ecdsa_secp384r1_sha384, @ext.ecdsa_secp521r1_sha512,
        @ext.ecdsa_sha224, @ext.ecdsa_sha1,
      ]
    Rsa(_) =>
      [
        ..schemes(key),
        @ext.rsa_pkcs1_sha256,
        @ext.rsa_pkcs1_sha384,
        @ext.rsa_pkcs1_sha512,
        @ext.rsa_pkcs1_sha224,
        @ext.rsa_pkcs1_sha1,
      ]
    Ed25519(_) => schemes(key)
    MlDsa(_) => []
  }
}

///|
/// Sign under a TLS 1.2 scheme, where an ECDSA key signs with whichever hash the scheme names.
fn sign12(
  key : @x509.PrivateKey,
  scheme : Int32,
  content : Bytes,
) -> Bytes raise @alert.Alert {
  guard key is Ec(k) else { return sign(key, scheme, content) }
  guard ecdsa_hash(scheme) is Some(hash) else {
    raise @alert.fatal(InternalError)
  }
  let hashed = @ecdsa.PrivateKey::with_hash(k.bytes()[:], hash, curve=k.curve()) catch {
    _ => raise @alert.fatal(InternalError)
  }
  ecdsa_der(hashed.sign(content[:]))
}

///|
/// Cut the key block into the two directions' ciphers (RFC 5246 §6.3): both MAC keys, both write
/// keys, both IVs, the client's first each time.
fn Conn::ciphers12(self : Conn) -> (@record.Cipher, @record.Cipher) {
  let suite = self.suite12.unwrap()
  let (m, k) = (suite.mac_size(), suite.key_size())
  // RFC 2246 §6.3: TLS 1.0's key block carries a sixteen-octet IV per direction for CBC, used as
  // the first record's IV and then chained; 1.1 and 1.2 write an IV with every record instead.
  let implicit = suite.is_cbc() && self.version is Some(Tls10)
  let v = if implicit { 16 } else { suite.iv_size() }
  let block = @keys.key_block(
    self.master[:],
    self.client_random[:],
    self.server_random[:],
    len=2 * (m + k + v),
    digest=self.digest(),
  )
  let keys = 2 * m
  let ivs = keys + 2 * k
  match self.pipe {
    Some(p) =>
      p.push(
        Keys12(
          suite,
          block[keys:keys + k].to_owned(),
          block[ivs:ivs + v].to_owned(),
          block[0:m].to_owned(),
          block[keys + k:keys + 2 * k].to_owned(),
          block[ivs + v:ivs + 2 * v].to_owned(),
          block[m:2 * m].to_owned(),
          self.etm,
        ),
      )
    None => ()
  }
  let half = (side : Int32) => {
    @record.Cipher::of12(
      suite,
      block[keys + side * k:keys + (side + 1) * k],
      block[ivs + side * v:ivs + (side + 1) * v],
      mac_key=block[side * m:(side + 1) * m],
      etm=self.etm,
      rand=self.rand,
      implicit~,
      wire=self.wire,
    )
  }
  (half(0), half(1))
}

///|
/// A finite-field secret without its leading zeros, which TLS 1.2 drops (RFC 5246 §8.1.2) and 1.3
/// keeps.
fn strip_zeros(secret : Bytes) -> Bytes {
  let mut at = 0
  while at < secret.length() - 1 && secret[at] == b'\x00' {
    at = at + 1
  }
  secret[at:].to_owned()
}

///|
/// The master secret from the premaster secret. With extended_master_secret it is bound to
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
  // RFC 5746 §3.4: kept for a renegotiation, which must name this handshake.
  if client {
    self.client_finished = body
  } else {
    self.server_finished = body
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
  // RFC 5746 §3.4: our own verify_data is half of what a renegotiation must name.
  if client {
    self.client_finished = verify
  } else {
    self.server_finished = verify
  }
  let message = @msg.frame(Finished, verify[:])
  self.record_sent(message[:])
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
