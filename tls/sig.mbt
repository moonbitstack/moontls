// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The signature schemes a key can sign a CertificateVerify under (RFC 8446 §4.2.3). TLS 1.3 ties
/// an ECDSA scheme to one curve and one hash, so an ECDSA key has exactly one.
fn Key::schemes(self : Key) -> Array[Int32] {
  match self {
    Ecdsa(k) =>
      match k.curve() {
        P256 => [@ext.ecdsa_secp256r1_sha256]
        P384 => [@ext.ecdsa_secp384r1_sha384]
        P521 => [@ext.ecdsa_secp521r1_sha512]
        Secp256k1 => []
      }
    Rsa(_) =>
      [
        @ext.rsa_pss_rsae_sha256, @ext.rsa_pss_rsae_sha384, @ext.rsa_pss_rsae_sha512,
      ]
    Ed25519(_) => [@ext.ed25519]
  }
}

///|
/// The schemes a client offers: every one this library can check.
let offered : Array[Int32] = [
  @ext.ecdsa_secp256r1_sha256, @ext.ecdsa_secp384r1_sha384, @ext.ecdsa_secp521r1_sha512,
  @ext.ed25519, @ext.rsa_pss_rsae_sha256, @ext.rsa_pss_rsae_sha384, @ext.rsa_pss_rsae_sha512,
]

///|
fn pss_digest(scheme : Int32) -> @rsa.Digest? {
  match scheme {
    s if s == @ext.rsa_pss_rsae_sha256 => Some(Sha256)
    s if s == @ext.rsa_pss_rsae_sha384 => Some(Sha384)
    s if s == @ext.rsa_pss_rsae_sha512 => Some(Sha512)
    _ => None
  }
}

///|
fn pss_salt(d : @rsa.Digest) -> Int32 {
  match d {
    Sha384 => 48
    Sha512 => 64
    _ => 32
  }
}

///|
/// Sign `content` under `scheme`. An ECDSA signature goes on the wire DER-encoded (RFC 8446
/// §4.2.3), where the library signs the fixed-width `r || s`.
fn Key::sign(
  self : Key,
  scheme : Int32,
  content : Bytes,
) -> Bytes raise @alert.Alert {
  match self {
    Ecdsa(k) => {
      let raw = k.sign(content[:])
      let half = raw.length() / 2
      @asn1.sequence([
        @asn1.integer(raw[0:half].to_owned()),
        @asn1.integer(raw[half:].to_owned()),
      ])
    }
    Ed25519(k) => k.sign(content[:])
    Rsa(k) => {
      guard pss_digest(scheme) is Some(d) else {
        raise @alert.fatal(InternalError)
      }
      k.with_scheme(digest=d, scheme=Pss(salt=pss_salt(d))).sign(content[:])
    }
  }
}

///|
/// Whether `sig` over `content` verifies under the leaf certificate's key with `scheme`.
fn verified(
  leaf : @x509.Cert,
  scheme : Int32,
  content : Bytes,
  sig : Bytes,
) -> Bool {
  let key = leaf.spki.key() catch { _ => return false }
  match key {
    Ec(k) => {
      let curve : @curve.Curve? = match scheme {
        s if s == @ext.ecdsa_secp256r1_sha256 => Some(P256)
        s if s == @ext.ecdsa_secp384r1_sha384 => Some(P384)
        s if s == @ext.ecdsa_secp521r1_sha512 => Some(P521)
        _ => None
      }
      guard curve is Some(c) && c == k.curve() else { return false }
      guard ecdsa_raw(sig, c.size()) is Some(raw) else { return false }
      k.verify(content[:], raw[:])
    }
    Ed25519(k) => scheme == @ext.ed25519 && k.verify(content[:], sig[:])
    Rsa(k) => {
      guard pss_digest(scheme) is Some(d) else { return false }
      k
      .with_scheme(digest=d, scheme=Pss(salt=pss_salt(d)))
      .verify(content[:], sig[:])
    }
  }
}

///|
/// A DER ECDSA-Sig-Value as the fixed-width `r || s`, or `None` when it is malformed or does not
/// fit the curve.
fn ecdsa_raw(sig : Bytes, size : Int32) -> Bytes? {
  let seq = @asn1.only(sig[:]) catch { _ => return None }
  let rs = seq.items() catch { _ => return None }
  guard seq.tag == 0x30 && rs.length() == 2 else { return None }
  let r = rs[0].int() catch { _ => return None }
  let s = rs[1].int() catch { _ => return None }
  if r <= 0N ||
    s <= 0N ||
    r.to_octets().length() > size ||
    s.to_octets().length() > size {
    return None
  }
  let out = Buffer()
  out.write_bytes(r.to_octets(length=size))
  out.write_bytes(s.to_octets(length=size))
  Some(out.to_bytes())
}
