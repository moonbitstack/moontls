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
  /// A key both ends hold already, named by its identity (RFC 4279 §2). No forward secrecy.
  Psk
  /// A finite-field exchange keyed together with a pre-shared key (RFC 4279 §3).
  DhePsk
  /// An elliptic-curve exchange keyed together with a pre-shared key (RFC 5489).
  EcdhePsk
  /// A premaster encrypted to the server's RSA key, keyed together with a pre-shared key
  /// (RFC 4279 §4). No forward secrecy.
  RsaPsk
  /// SRP-6a over a user name and password, the server holding only a verifier (RFC 5054).
  Srp
  /// The Diffie-Hellman key in the server's certificate and an ephemeral one from the client
  /// (RFC 5246 §7.4.2). No forward secrecy. `auth` names the suite and no longer restricts the
  /// certificate's issuer in TLS 1.2.
  Dh
}

///|
/// Whether a pre-shared key goes into the premaster.
pub fn Exchange::takes_psk(self : Exchange) -> Bool {
  self is (Psk | DhePsk | EcdhePsk | RsaPsk)
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
  /// No certificate: the secret both ends hold is what authenticates.
  Shared
  /// A DSA certificate, which only TLS 1.2's DHE_DSS and SRP_SHA_DSS suites show.
  Dss
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
/// A block cipher a TLS 1.2 suite runs, with its key length.
#derive(Eq, Debug)
pub(all) enum BlockCipher {
  Aes128
  Aes256
  Camellia128
  Camellia256
  Aria128
  Aria256
  Seed
  Idea
  TripleDes
}

///|
pub extend BlockCipher with Eq::{equal, not_equal}

///|
pub extend BlockCipher with Debug::{to_repr}

///|
/// The key length in octets.
pub fn BlockCipher::key_size(self : BlockCipher) -> Int32 {
  match self {
    Aes256 | Camellia256 | Aria256 => 32
    TripleDes => 24
    Aes128 | Camellia128 | Aria128 | Seed | Idea => 16
  }
}

///|
/// The block length in octets, which is also a CBC record's IV length.
pub fn BlockCipher::block_size(self : BlockCipher) -> Int32 {
  match self {
    Idea | TripleDes => 8
    _ => 16
  }
}

///|
/// The cipher's part of a suite's registry name.
pub fn BlockCipher::name(self : BlockCipher) -> String {
  match self {
    Aes128 => "AES_128"
    Aes256 => "AES_256"
    Camellia128 => "CAMELLIA_128"
    Camellia256 => "CAMELLIA_256"
    Aria128 => "ARIA_128"
    Aria256 => "ARIA_256"
    Seed => "SEED"
    Idea => "IDEA"
    TripleDes => "3DES_EDE"
  }
}

///|
/// The cipher keyed with `key`. Aborts on a key of the wrong length: every key reaching it came out
/// of the key block at `key_size`.
pub fn BlockCipher::block(self : BlockCipher, key : BytesView) -> &@spec.Block {
  let made : Result[&@spec.Block, @spec.Broken] = try {
    match self {
      Aes128 | Aes256 => Ok(@aes.Cipher::new(key))
      Camellia128 | Camellia256 => Ok(@camellia.Cipher::new(key))
      Aria128 | Aria256 => Ok(@aria.Cipher::new(key))
      Seed => Ok(@seed.Cipher::new(key))
      Idea => Ok(@idea.Cipher::new(key))
      TripleDes => Ok(@des.TripleDes::new(key))
    }
  } catch {
    e => Err(e)
  }
  match made {
    Ok(block) => block
    Err(_) => abort("moontls: \{self.name()} refused a key of its length")
  }
}

///|
/// How a suite protects its records.
#derive(Eq, Debug)
pub(all) enum Bulk {
  /// GCM over a 128-bit block cipher (RFC 5288, RFC 6367, RFC 6209).
  Gcm(BlockCipher)
  /// CCM, with a tag of 16 octets or 8 (RFC 6655).
  Ccm(BlockCipher, tag~ : Int32)
  /// ChaCha20-Poly1305 (RFC 7905).
  ChaCha20Poly1305
  /// CBC with HMAC (RFC 5246 §6.2.3.2).
  Cbc(BlockCipher, mac~ : Mac)
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
  row(0xcca9, Ecdhe, Ecdsa, ChaCha20Poly1305, Sha256),
  row(0xcca8, Ecdhe, Rsa, ChaCha20Poly1305, Sha256),
  row(0xc02b, Ecdhe, Ecdsa, Gcm(Aes128), Sha256),
  row(0xc02f, Ecdhe, Rsa, Gcm(Aes128), Sha256),
  row(0xc02c, Ecdhe, Ecdsa, Gcm(Aes256), Sha384),
  row(0xc030, Ecdhe, Rsa, Gcm(Aes256), Sha384),
]

///|
/// Every suite this library speaks, strongest first. Asking for these is asking to talk to whatever
/// is out there; `suites12` is the default for good reason.
pub let all12 : Array[Suite12] = [
  ..suites12,
  row(0xc0ac, Ecdhe, Ecdsa, Ccm(Aes128, tag=16), Sha256),
  row(0xc0ad, Ecdhe, Ecdsa, Ccm(Aes256, tag=16), Sha256),
  row(0xc0ae, Ecdhe, Ecdsa, Ccm(Aes128, tag=8), Sha256),
  row(0xc0af, Ecdhe, Ecdsa, Ccm(Aes256, tag=8), Sha256),
  row(0xccaa, Dhe, Rsa, ChaCha20Poly1305, Sha256),
  row(0x009e, Dhe, Rsa, Gcm(Aes128), Sha256),
  row(0x009f, Dhe, Rsa, Gcm(Aes256), Sha384),
  row(0xc09e, Dhe, Rsa, Ccm(Aes128, tag=16), Sha256),
  row(0xc09f, Dhe, Rsa, Ccm(Aes256, tag=16), Sha256),
  row(0xc0a2, Dhe, Rsa, Ccm(Aes128, tag=8), Sha256),
  row(0xc0a3, Dhe, Rsa, Ccm(Aes256, tag=8), Sha256),
  row(0xc023, Ecdhe, Ecdsa, Cbc(Aes128, mac=Sha256), Sha256),
  row(0xc027, Ecdhe, Rsa, Cbc(Aes128, mac=Sha256), Sha256),
  row(0xc024, Ecdhe, Ecdsa, Cbc(Aes256, mac=Sha384), Sha384),
  row(0xc028, Ecdhe, Rsa, Cbc(Aes256, mac=Sha384), Sha384),
  row(0xc009, Ecdhe, Ecdsa, Cbc(Aes128, mac=Sha1), Sha256),
  row(0xc013, Ecdhe, Rsa, Cbc(Aes128, mac=Sha1), Sha256),
  row(0xc00a, Ecdhe, Ecdsa, Cbc(Aes256, mac=Sha1), Sha256),
  row(0xc014, Ecdhe, Rsa, Cbc(Aes256, mac=Sha1), Sha256),
  row(0x0067, Dhe, Rsa, Cbc(Aes128, mac=Sha256), Sha256),
  row(0x006b, Dhe, Rsa, Cbc(Aes256, mac=Sha256), Sha256),
  row(0x0033, Dhe, Rsa, Cbc(Aes128, mac=Sha1), Sha256),
  row(0x0039, Dhe, Rsa, Cbc(Aes256, mac=Sha1), Sha256),
  row(0x009c, Rsa, Rsa, Gcm(Aes128), Sha256),
  row(0x009d, Rsa, Rsa, Gcm(Aes256), Sha384),
  row(0xc09c, Rsa, Rsa, Ccm(Aes128, tag=16), Sha256),
  row(0xc09d, Rsa, Rsa, Ccm(Aes256, tag=16), Sha256),
  row(0xc0a0, Rsa, Rsa, Ccm(Aes128, tag=8), Sha256),
  row(0xc0a1, Rsa, Rsa, Ccm(Aes256, tag=8), Sha256),
  row(0x003c, Rsa, Rsa, Cbc(Aes128, mac=Sha256), Sha256),
  row(0x003d, Rsa, Rsa, Cbc(Aes256, mac=Sha256), Sha256),
  row(0x002f, Rsa, Rsa, Cbc(Aes128, mac=Sha1), Sha256),
  row(0x0035, Rsa, Rsa, Cbc(Aes256, mac=Sha1), Sha256),
  ..registry12,
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
    (Ecdhe, _) => "ECDHE_RSA"
    (Dh, Dss) => "DH_DSS"
    (Dh, _) => "DH_RSA"
    (Dhe, Dss) => "DHE_DSS"
    (Dhe, _) => "DHE_RSA"
    (Rsa, _) => "RSA"
    (Psk, _) => "PSK"
    (DhePsk, _) => "DHE_PSK"
    (EcdhePsk, _) => "ECDHE_PSK"
    (RsaPsk, _) => "RSA_PSK"
    (Srp, Rsa) => "SRP_SHA_RSA"
    (Srp, Dss) => "SRP_SHA_DSS"
    (Srp, _) => "SRP_SHA"
  }
  let bulk = match self.bulk {
    Gcm(cipher) => {
      let prf = if self.digest is Sha384 { "SHA384" } else { "SHA256" }
      "\{cipher.name()}_GCM_\{prf}"
    }
    Ccm(cipher, tag~) => {
      let short = if tag == 8 { "_8" } else { "" }
      "\{cipher.name()}_CCM\{short}"
    }
    ChaCha20Poly1305 => "CHACHA20_POLY1305_SHA256"
    Cbc(cipher, mac~) => {
      let hash = match mac {
        Sha1 => "SHA"
        Sha256 => "SHA256"
        Sha384 => "SHA384"
      }
      "\{cipher.name()}_CBC_\{hash}"
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
    Gcm(cipher) | Ccm(cipher, ..) | Cbc(cipher, ..) => cipher.key_size()
    ChaCha20Poly1305 => 32
  }
}

///|
/// The MAC key length: nothing for an AEAD.
pub fn Suite12::mac_size(self : Suite12) -> Int32 {
  match self.bulk {
    Cbc(_, mac~) => mac.size()
    _ => 0
  }
}

///|
/// The fixed part of the nonce the key block gives each direction: GCM's and CCM's four-octet salt,
/// ChaCha20-Poly1305's twelve, and nothing for CBC, whose IV goes out with each record.
pub fn Suite12::iv_size(self : Suite12) -> Int32 {
  match self.bulk {
    ChaCha20Poly1305 => 12
    Gcm(_) | Ccm(_, ..) => 4
    Cbc(_, ..) => 0
  }
}

///|
/// Whether records under this suite are CBC, which is what encrypt-then-MAC applies to.
pub fn Suite12::is_cbc(self : Suite12) -> Bool {
  self.bulk is Cbc(_, ..)
}
