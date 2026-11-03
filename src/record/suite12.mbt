// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2's cipher suites, as a table: in 1.2 a suite names the key exchange, the certificate and
// the record protection all at once, so another suite is another row and nothing else.

///|
/// How the two ends agree on a premaster secret.
#derive(Eq, Debug)
pub(all) enum Exchange {
  Ecdhe
  Dhe
  /// The client encrypts it to the server's RSA key. No forward secrecy.
  Rsa
}

///|
pub extend Exchange with Eq::{equal, not_equal}

///|
pub extend Exchange with Debug::{to_repr}

///|
/// The kind of certificate a suite is for. EdDSA certificates go with `Ecdsa`, as RFC 8422 §5.1 has.
#derive(Eq, Debug)
pub(all) enum Auth {
  Rsa
  Ecdsa
}

///|
pub extend Auth with Eq::{equal, not_equal}

///|
pub extend Auth with Debug::{to_repr}

///|
/// The MAC of a CBC suite.
#derive(Eq, Debug)
pub(all) enum Mac {
  Sha1
  Sha256
  Sha384
}

///|
pub extend Mac with Eq::{equal, not_equal}

///|
pub extend Mac with Debug::{to_repr}

///|
/// The hash a MAC is keyed over.
pub fn Mac::hasher(self : Mac) -> () -> &@spec.Hash {
  match self {
    Sha1 =>
      () => {
        let h : &@spec.Hash = @sha1.Hasher::new()
        h
      }
    Sha256 => @keys.Digest::Sha256.hasher()
    Sha384 => @keys.Digest::Sha384.hasher()
  }
}

///|
/// The MAC's length, which is also its key's.
pub fn Mac::size(self : Mac) -> Int32 {
  match self {
    Sha1 => 20
    Sha256 => 32
    Sha384 => 48
  }
}

///|
/// How a suite protects its records.
#derive(Eq, Debug)
pub(all) enum Bulk {
  Aead(Suite)
  /// AES in CCM mode, with a tag of 16 octets or 8 (RFC 6655).
  Ccm(key~ : Int32, tag~ : Int32)
  /// AES in CBC mode with HMAC (RFC 5246 §6.2.3.2).
  Cbc(key~ : Int32, mac~ : Mac)
}

///|
pub extend Bulk with Eq::{equal, not_equal}

///|
pub extend Bulk with Debug::{to_repr}

///|
/// A row of the table.
#derive(Eq, Debug)
pub(all) struct Suite12 {
  code : Int32
  exchange : Exchange
  auth : Auth
  bulk : Bulk
  /// The hash of the PRF and the transcript.
  digest : @keys.Digest
}

///|
pub extend Suite12 with Eq::{equal, not_equal}

///|
pub extend Suite12 with Debug::{to_repr}

///|
/// The ECDHE suites with an AEAD, which is what is on by default: forward secrecy, and no MAC to
/// time.
pub let suites12 : Array[Suite12] = [
  row(0xcca9, Ecdhe, Ecdsa, Aead(ChaCha20Poly1305), Sha256),
  row(0xcca8, Ecdhe, Rsa, Aead(ChaCha20Poly1305), Sha256),
  row(0xc02b, Ecdhe, Ecdsa, Aead(Aes128Gcm), Sha256),
  row(0xc02f, Ecdhe, Rsa, Aead(Aes128Gcm), Sha256),
  row(0xc02c, Ecdhe, Ecdsa, Aead(Aes256Gcm), Sha384),
  row(0xc030, Ecdhe, Rsa, Aead(Aes256Gcm), Sha384),
]

///|
/// Every suite this library speaks, strongest first. Asking for these is asking to talk to whatever
/// is out there; `suites12` is the default for good reason.
pub let all12 : Array[Suite12] = [
  ..suites12,
  row(0xc0ac, Ecdhe, Ecdsa, Ccm(key=16, tag=16), Sha256),
  row(0xc0ad, Ecdhe, Ecdsa, Ccm(key=32, tag=16), Sha256),
  row(0xc0ae, Ecdhe, Ecdsa, Ccm(key=16, tag=8), Sha256),
  row(0xc0af, Ecdhe, Ecdsa, Ccm(key=32, tag=8), Sha256),
  row(0xccaa, Dhe, Rsa, Aead(ChaCha20Poly1305), Sha256),
  row(0x009e, Dhe, Rsa, Aead(Aes128Gcm), Sha256),
  row(0x009f, Dhe, Rsa, Aead(Aes256Gcm), Sha384),
  row(0xc09e, Dhe, Rsa, Ccm(key=16, tag=16), Sha256),
  row(0xc09f, Dhe, Rsa, Ccm(key=32, tag=16), Sha256),
  row(0xc0a2, Dhe, Rsa, Ccm(key=16, tag=8), Sha256),
  row(0xc0a3, Dhe, Rsa, Ccm(key=32, tag=8), Sha256),
  row(0xc023, Ecdhe, Ecdsa, Cbc(key=16, mac=Sha256), Sha256),
  row(0xc027, Ecdhe, Rsa, Cbc(key=16, mac=Sha256), Sha256),
  row(0xc024, Ecdhe, Ecdsa, Cbc(key=32, mac=Sha384), Sha384),
  row(0xc028, Ecdhe, Rsa, Cbc(key=32, mac=Sha384), Sha384),
  row(0xc009, Ecdhe, Ecdsa, Cbc(key=16, mac=Sha1), Sha256),
  row(0xc013, Ecdhe, Rsa, Cbc(key=16, mac=Sha1), Sha256),
  row(0xc00a, Ecdhe, Ecdsa, Cbc(key=32, mac=Sha1), Sha256),
  row(0xc014, Ecdhe, Rsa, Cbc(key=32, mac=Sha1), Sha256),
  row(0x0067, Dhe, Rsa, Cbc(key=16, mac=Sha256), Sha256),
  row(0x006b, Dhe, Rsa, Cbc(key=32, mac=Sha256), Sha256),
  row(0x0033, Dhe, Rsa, Cbc(key=16, mac=Sha1), Sha256),
  row(0x0039, Dhe, Rsa, Cbc(key=32, mac=Sha1), Sha256),
  row(0x009c, Rsa, Rsa, Aead(Aes128Gcm), Sha256),
  row(0x009d, Rsa, Rsa, Aead(Aes256Gcm), Sha384),
  row(0xc09c, Rsa, Rsa, Ccm(key=16, tag=16), Sha256),
  row(0xc09d, Rsa, Rsa, Ccm(key=32, tag=16), Sha256),
  row(0xc0a0, Rsa, Rsa, Ccm(key=16, tag=8), Sha256),
  row(0xc0a1, Rsa, Rsa, Ccm(key=32, tag=8), Sha256),
  row(0x003c, Rsa, Rsa, Cbc(key=16, mac=Sha256), Sha256),
  row(0x003d, Rsa, Rsa, Cbc(key=32, mac=Sha256), Sha256),
  row(0x002f, Rsa, Rsa, Cbc(key=16, mac=Sha1), Sha256),
  row(0x0035, Rsa, Rsa, Cbc(key=32, mac=Sha1), Sha256),
]

///|
fn row(
  code : Int32,
  exchange : Exchange,
  auth : Auth,
  bulk : Bulk,
  digest : @keys.Digest,
) -> Suite12 {
  { code, exchange, auth, bulk, digest, }
}

///|
/// The suite's name in the IANA registry, which is what `openssl ciphers -stdname` prints.
pub fn Suite12::name(self : Suite12) -> String {
  let exchange = match (self.exchange, self.auth) {
    (Ecdhe, Ecdsa) => "ECDHE_ECDSA"
    (Ecdhe, Rsa) => "ECDHE_RSA"
    (Dhe, _) => "DHE_RSA"
    (Rsa, _) => "RSA"
  }
  let bulk = match self.bulk {
    Aead(Aes128Gcm) => "AES_128_GCM_SHA256"
    Aead(Aes256Gcm) => "AES_256_GCM_SHA384"
    Aead(ChaCha20Poly1305) => "CHACHA20_POLY1305_SHA256"
    Ccm(key~, tag~) => {
      let short = if tag == 8 { "_8" } else { "" }
      "AES_\{key * 8}_CCM\{short}"
    }
    Cbc(key~, mac~) => {
      let hash = match mac {
        Sha1 => "SHA"
        Sha256 => "SHA256"
        Sha384 => "SHA384"
      }
      "AES_\{key * 8}_CBC_\{hash}"
    }
  }
  "TLS_\{exchange}_WITH_\{bulk}"
}

///|
/// The suite a code names, `None` for one this library does not speak.
pub fn Suite12::of(code : Int32) -> Suite12? {
  all12.iter().find_first(s => s.code == code)
}

///|
/// The key length.
pub fn Suite12::key_size(self : Suite12) -> Int32 {
  match self.bulk {
    Aead(suite) => suite.key_size()
    Ccm(key~, ..) | Cbc(key~, ..) => key
  }
}

///|
/// The MAC key length: nothing for an AEAD.
pub fn Suite12::mac_size(self : Suite12) -> Int32 {
  match self.bulk {
    Cbc(mac~, ..) => mac.size()
    _ => 0
  }
}

///|
/// The fixed part of the nonce the key block gives each direction: GCM's and CCM's four-octet salt,
/// ChaCha20-Poly1305's twelve, and nothing for CBC, whose IV goes out with each record.
pub fn Suite12::iv_size(self : Suite12) -> Int32 {
  match self.bulk {
    Aead(ChaCha20Poly1305) => 12
    Aead(_) | Ccm(..) => 4
    Cbc(..) => 0
  }
}

///|
/// Whether records under this suite are CBC, which is what encrypt-then-MAC applies to.
pub fn Suite12::is_cbc(self : Suite12) -> Bool {
  self.bulk is Cbc(..)
}
