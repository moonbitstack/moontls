// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2's key derivation (RFC 5246 §5, §6.3, §8.1, RFC 7627): a PRF instead of HKDF, run over the
// hash of the negotiated suite.

///|
/// `P_hash(secret, seed)` (RFC 5246 §5): HMAC the seed again and again, each round folded back into
/// the next, out to `len` octets.
fn p_hash(
  secret : BytesView,
  start : BytesView,
  len : Int32,
  hasher : () -> &@spec.Hash,
) -> Bytes {
  let out = Buffer()
  let mut a = start.to_owned()
  while out.length() < len {
    a = @hmac.mac(secret, a[:], hasher)
    let block = Buffer()
    block.write_bytes(a)
    block.write_bytesview(start)
    out.write_bytes(@hmac.mac(secret, block.to_bytes()[:], hasher))
  }
  out.to_bytes()[0:len].to_owned()
}

///|
/// `PRF(secret, label, seed)` (RFC 5246 §5): `P_hash` over `label + seed`, out to `len` octets.
///
/// With `Md5Sha1` it is TLS 1.0's and 1.1's PRF instead (RFC 2246 §5): the secret is split in two
/// halves that overlap by an octet when its length is odd, `P_MD5` runs over the first and
/// `P_SHA1` over the second, and the two are XORed. That is a different construction, not a
/// different hash, which is why it is here and not in `Digest`.
pub fn prf(
  secret : BytesView,
  label : BytesView,
  seed : BytesView,
  len~ : Int32,
  digest~ : Digest = digest,
) -> Bytes {
  let tagged = Buffer()
  tagged.write_bytesview(label)
  tagged.write_bytesview(seed)
  let start = tagged.to_bytes()
  match digest {
    Md5Sha1 => {
      let half = (secret.length() + 1) / 2
      let first = p_hash(secret[0:half], start[:], len, fn() -> &@spec.Hash {
        @md5.Hasher::new()
      })
      let second = p_hash(secret[secret.length() - half:], start[:], len, fn() -> &@spec.Hash {
        @sha1.Hasher::new()
      })
      Bytes::makei(len, i => (first[i].to_int() ^ second[i].to_int()).to_byte())
    }
    _ => p_hash(secret, start[:], len, digest.hasher())
  }
}

///|
/// The master secret. `session` is the hash of the handshake through ClientKeyExchange when both
/// ends agreed extended_master_secret (RFC 7627 §4), which binds it to this handshake; `None`
/// falls back to the two hellos' randoms (RFC 5246 §8.1).
pub fn master12(
  premaster : BytesView,
  client_random : BytesView,
  server_random : BytesView,
  session? : BytesView,
  digest~ : Digest = digest,
) -> Bytes {
  match session {
    Some(hash) =>
      prf(premaster, b"extended master secret"[:], hash, len=48, digest~)
    None => {
      let seed = Buffer()
      seed.write_bytesview(client_random)
      seed.write_bytesview(server_random)
      prf(premaster, b"master secret"[:], seed.to_bytes()[:], len=48, digest~)
    }
  }
}

///|
/// The key block (RFC 5246 §6.3), which the suite cuts into keys and IVs. Note the seed's order:
/// the server's random first here, the client's first in the master secret.
pub fn key_block(
  master : BytesView,
  client_random : BytesView,
  server_random : BytesView,
  len~ : Int32,
  digest~ : Digest = digest,
) -> Bytes {
  let seed = Buffer()
  seed.write_bytesview(server_random)
  seed.write_bytesview(client_random)
  prf(master, b"key expansion"[:], seed.to_bytes()[:], len~, digest~)
}

///|
/// A TLS 1.2 exporter (RFC 5705 §4): `PRF(master_secret, label,
/// client_random + server_random + context)`. DTLS-SRTP over 1.2 exports its
/// keying material this way, under the same label the 1.3 path uses.
pub fn exporter12(
  master : BytesView,
  label : BytesView,
  client_random : BytesView,
  server_random : BytesView,
  context : BytesView,
  len~ : Int32,
  digest~ : Digest = digest,
) -> Bytes {
  let seed = Buffer()
  seed.write_bytesview(client_random)
  seed.write_bytesview(server_random)
  seed.write_bytesview(context)
  prf(master, label, seed.to_bytes()[:], len~, digest~)
}

///|
/// A Finished message's `verify_data` (RFC 5246 §7.4.9): twelve octets over the transcript hash,
/// `client` saying whose.
pub fn finished12(
  master : BytesView,
  transcript : BytesView,
  client~ : Bool,
  digest~ : Digest = digest,
) -> Bytes {
  let label = if client { b"client finished" } else { b"server finished" }
  prf(master, label[:], transcript, len=12, digest~)
}

///|
/// Whether a received Finished carries the `verify_data` expected, compared in constant time for
/// the reason `finished_ok` gives.
pub fn finished12_ok(
  master : BytesView,
  transcript : BytesView,
  verify_data : BytesView,
  client~ : Bool,
  digest~ : Digest = digest,
) -> Bool {
  @spec.eq(finished12(master, transcript, client~, digest~)[:], verify_data)
}
