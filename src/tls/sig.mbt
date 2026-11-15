// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The signature schemes a key can sign a CertificateVerify under (RFC 8446 §4.2.3). TLS 1.3 ties
/// an ECDSA scheme to one curve and one hash, so an ECDSA key has exactly one; `rsa` is what the
/// certificate makes of an RSA key.
fn schemes(key : @x509.PrivateKey, rsa~ : RsaKind = Rsae) -> Array[Int32] {
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
        @ext.rsa_pss_pss_sha256, @ext.rsa_pss_pss_sha384, @ext.rsa_pss_pss_sha512,
      ].filter(s => rsa.digest(s) is Some(_))
    Ed25519(_) => [@ext.ed25519]
    MlDsa(k) => [mldsa_scheme(k.kind())]
  }
}

///|
/// What a certificate makes of an RSA key (RFC 8446 §4.2.3): an rsaEncryption key signs under the
/// `rsa_pss_rsae_*` schemes and, in TLS 1.2, PKCS#1; an RSASSA-PSS key (RFC 4055) under the
/// `rsa_pss_pss_*` schemes alone, and only the one of the digest its parameters hold it to.
priv enum RsaKind {
  Rsae
  Pss(@rsa.Digest?)
}

///|
/// The kind of a certificate's key. mooncred reads RSASSA-PSS parameters down to the digest they
/// name, by its OID.
fn RsaKind::of(spki : @x509.Spki) -> RsaKind {
  guard spki.alg == "1.2.840.113549.1.1.10" else { return Rsae }
  Pss(
    match spki.params {
      Some("2.16.840.1.101.3.4.2.2") => Some(Sha384)
      Some("2.16.840.1.101.3.4.2.3") => Some(Sha512)
      Some(_) => Some(Sha256)
      None => None
    },
  )
}

///|
/// The kind of the key a chain's leaf holds. A chain that does not parse is taken as
/// rsaEncryption; the handshake that presents it fails on its own account.
fn RsaKind::of_chain(chain : Array[Bytes]) -> RsaKind {
  guard chain is [leaf, ..] else { return Rsae }
  let cert = @x509.parse(leaf[:]) catch { _ => return Rsae }
  RsaKind::of(cert.spki)
}

///|
/// The digest of a PSS scheme a key of this kind may sign under, `None` for one it may not.
fn RsaKind::digest(self : RsaKind, scheme : Int32) -> @rsa.Digest? {
  match (self, pss_pss_digest(scheme)) {
    (Rsae, _) => rsae_digest(scheme)
    (Pss(Some(held)), Some(d)) => if d == held { Some(d) } else { None }
    (Pss(_), d) => d
  }
}

///|
/// The one scheme an ML-DSA key signs under: like Ed25519, a key's parameter set names it.
fn mldsa_scheme(kind : @mldsa.Kind) -> Int32 {
  match kind {
    D44 => @ext.mldsa44
    D65 => @ext.mldsa65
    D87 => @ext.mldsa87
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
  @ext.rsa_pss_pss_sha256, @ext.rsa_pss_pss_sha384, @ext.rsa_pss_pss_sha512, @ext.mldsa44,
  @ext.mldsa65, @ext.mldsa87,
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
  @ext.rsa_pss_pss_sha256, @ext.rsa_pss_pss_sha384, @ext.rsa_pss_pss_sha512, @ext.mldsa44,
  @ext.mldsa65, @ext.mldsa87, @ext.rsa_pkcs1_sha256, @ext.rsa_pkcs1_sha384, @ext.rsa_pkcs1_sha512,
]

///|
/// The digest of an `rsa_pss_rsae_*` scheme, the ones an rsaEncryption key signs under.
fn rsae_digest(scheme : Int32) -> @rsa.Digest? {
  match scheme {
    s if s == @ext.rsa_pss_rsae_sha256 => Some(Sha256)
    s if s == @ext.rsa_pss_rsae_sha384 => Some(Sha384)
    s if s == @ext.rsa_pss_rsae_sha512 => Some(Sha512)
    _ => None
  }
}

///|
/// The digest of an `rsa_pss_pss_*` scheme, the ones an RSASSA-PSS key signs under.
fn pss_pss_digest(scheme : Int32) -> @rsa.Digest? {
  match scheme {
    s if s == @ext.rsa_pss_pss_sha256 => Some(Sha256)
    s if s == @ext.rsa_pss_pss_sha384 => Some(Sha384)
    s if s == @ext.rsa_pss_pss_sha512 => Some(Sha512)
    _ => None
  }
}

///|
/// The digest of either kind of PSS scheme: the two sign alike, MGF1 over the same hash and a salt
/// as long as it, and differ only in the key they are allowed to.
fn pss_digest(scheme : Int32) -> @rsa.Digest? {
  match rsae_digest(scheme) {
    Some(d) => Some(d)
    None => pss_pss_digest(scheme)
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
    MlDsa(k) => k.sign(content[:])
    Rsa(k) => {
      if pkcs1_digest(scheme) is Some(d) {
        return k.with_scheme(digest=d, scheme=Pkcs1).sign(content[:])
      }
      guard pss_digest(scheme) is Some(d) else {
        raise @alert.fatal(InternalError)
      }
      k
      .with_scheme(digest=d, scheme=Pss(salt=Exact(pss_salt(d))))
      .sign(content[:])
    }
  }
}

///|
/// Whether `scheme` is one this key could sign or verify under at all (RFC 8446 §4.4.3): TLS 1.3
/// ties an ECDSA scheme to one curve, and Ed25519 and ML-DSA have a single scheme each. A scheme
/// that does not fit the key is a contradiction between the message and the certificate, which
/// §4.4.3 answers with illegal_parameter — where a signature that is merely wrong is a
/// decrypt_error, and the difference is whether the peer named a scheme its own key cannot use.
fn fits(key : @x509.Key, scheme : Int32, rsa~ : RsaKind = Rsae) -> Bool {
  match key {
    Ec(k) =>
      match scheme {
        s if s == @ext.ecdsa_secp256r1_sha256 => k.curve() == P256
        s if s == @ext.ecdsa_secp384r1_sha384 => k.curve() == P384
        s if s == @ext.ecdsa_secp521r1_sha512 => k.curve() == P521
        s if s == @ext.ecdsa_brainpool_p256 => k.curve() == BrainpoolP256r1
        s if s == @ext.ecdsa_brainpool_p384 => k.curve() == BrainpoolP384r1
        s if s == @ext.ecdsa_brainpool_p512 => k.curve() == BrainpoolP512r1
        _ => false
      }
    Ed25519(_) => scheme == @ext.ed25519
    MlDsa(k) => scheme == mldsa_scheme(k.kind())
    Rsa(_) => rsa.digest(scheme) is Some(_)
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
    MlDsa(k) => scheme == mldsa_scheme(k.kind()) && k.verify(content[:], sig[:])
    Rsa(k) => {
      guard RsaKind::of(leaf.spki).digest(scheme) is Some(d) else {
        return false
      }
      k
      .with_scheme(digest=d, scheme=Pss(salt=Exact(pss_salt(d))))
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
