// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The signature schemes a key can sign a CertificateVerify under (RFC 8446 §4.2.3). TLS 1.3 ties
/// an ECDSA scheme to one curve and one hash, so an ECDSA key has exactly one.
fn schemes(key : @x509.PrivateKey) -> Array[Int32] {
  match key {
    Ec(k) =>
      match k.curve() {
        P256 => [@ext.ecdsa_secp256r1_sha256]
        P384 => [@ext.ecdsa_secp384r1_sha384]
        P521 => [@ext.ecdsa_secp521r1_sha512]
        BrainpoolP256r1 => [@ext.ecdsa_brainpool_p256]
        BrainpoolP384r1 => [@ext.ecdsa_brainpool_p384]
        BrainpoolP512r1 => [@ext.ecdsa_brainpool_p512]
        _ => []
      }
    Rsa(_) =>
      [
        @ext.rsa_pss_rsae_sha256, @ext.rsa_pss_rsae_sha384, @ext.rsa_pss_rsae_sha512,
      ]
    Ed25519(_) => [@ext.ed25519]
  }
}

///|
/// The schemes a CertificateVerify may be signed under in TLS 1.3 (RFC 8446 §4.2.3): PKCS#1 is
/// left out because §4.4.3 forbids it there, though a certificate chain is still signed with it and
/// `offered` speaks for those too.
let verifiable : Array[Int32] = [
  @ext.ecdsa_secp256r1_sha256, @ext.ecdsa_secp384r1_sha384, @ext.ecdsa_secp521r1_sha512,
  @ext.ecdsa_brainpool_p256, @ext.ecdsa_brainpool_p384, @ext.ecdsa_brainpool_p512,
  @ext.ed25519, @ext.rsa_pss_rsae_sha256, @ext.rsa_pss_rsae_sha384, @ext.rsa_pss_rsae_sha512,
]

///|
/// The schemes a client offers: every one this library can check. Without
/// signature_algorithms_cert the list also speaks for the certificate chain (RFC 8446 §4.2.3),
/// so it ends with the PKCS#1 schemes most chains are signed with, as rustls and OpenSSL send
/// them; a server that finds no chain it may present otherwise closes the connection. A
/// CertificateVerify under PKCS#1 is still refused.
let offered : Array[Int32] = [
  @ext.ecdsa_secp256r1_sha256, @ext.ecdsa_secp384r1_sha384, @ext.ecdsa_secp521r1_sha512,
  @ext.ecdsa_brainpool_p256, @ext.ecdsa_brainpool_p384, @ext.ecdsa_brainpool_p512,
  @ext.ed25519, @ext.rsa_pss_rsae_sha256, @ext.rsa_pss_rsae_sha384, @ext.rsa_pss_rsae_sha512,
  @ext.rsa_pkcs1_sha256, @ext.rsa_pkcs1_sha384, @ext.rsa_pkcs1_sha512,
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
fn pkcs1_digest(scheme : Int32) -> @rsa.Digest? {
  match scheme {
    s if s == @ext.rsa_pkcs1_sha256 => Some(Sha256)
    s if s == @ext.rsa_pkcs1_sha384 => Some(Sha384)
    s if s == @ext.rsa_pkcs1_sha512 => Some(Sha512)
    s if s == @ext.rsa_pkcs1_sha224 => Some(Sha224)
    s if s == @ext.rsa_pkcs1_sha1 => Some(Sha1)
    _ => None
  }
}

///|
/// The hash an ECDSA scheme names, which in TLS 1.2 is all it names (RFC 5246 §7.4.1.4.1).
fn ecdsa_hash(scheme : Int32) -> (() -> &@spec.Hash)? {
  let sha2 = (kind : @sha2.Kind) => {
    () => {
      let h : &@spec.Hash = @sha2.Hasher::new(kind~)
      h
    }
  }
  match scheme {
    s if s == @ext.ecdsa_sha1 =>
      Some(() => {
        let h : &@spec.Hash = @sha1.Hasher::new()
        h
      })
    s if s == @ext.ecdsa_sha224 => Some(sha2(Sha224))
    s if s == @ext.ecdsa_secp256r1_sha256 => Some(sha2(Sha256))
    s if s == @ext.ecdsa_secp384r1_sha384 => Some(sha2(Sha384))
    s if s == @ext.ecdsa_secp521r1_sha512 => Some(sha2(Sha512))
    s if s == @ext.ecdsa_brainpool_p256 => Some(sha2(Sha256))
    s if s == @ext.ecdsa_brainpool_p384 => Some(sha2(Sha384))
    s if s == @ext.ecdsa_brainpool_p512 => Some(sha2(Sha512))
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
/// A fixed-width `r || s` as the ECDSA-Sig-Value that goes on the wire.
fn ecdsa_der(raw : Bytes) -> Bytes {
  let half = raw.length() / 2
  @asn1.sequence([
    @asn1.integer(raw[0:half].to_owned()),
    @asn1.integer(raw[half:].to_owned()),
  ])
}

///|
/// Sign `content` under `scheme`. An ECDSA signature goes on the wire DER-encoded (RFC 8446
/// §4.2.3), where the library signs the fixed-width `r || s`.
fn sign(
  key : @x509.PrivateKey,
  scheme : Int32,
  content : Bytes,
) -> Bytes raise @alert.Alert {
  match key {
    Ec(k) => ecdsa_der(k.sign(content[:]))
    Ed25519(k) => k.sign(content[:])
    Rsa(k) => {
      if pkcs1_digest(scheme) is Some(d) {
        return k.with_scheme(digest=d, scheme=Pkcs1).sign(content[:])
      }
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
        s if s == @ext.ecdsa_brainpool_p256 => Some(BrainpoolP256r1)
        s if s == @ext.ecdsa_brainpool_p384 => Some(BrainpoolP384r1)
        s if s == @ext.ecdsa_brainpool_p512 => Some(BrainpoolP512r1)
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
