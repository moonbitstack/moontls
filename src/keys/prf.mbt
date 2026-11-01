// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2's key derivation (RFC 5246 §5, §6.3, §8.1, RFC 7627): a PRF instead of HKDF, run over the
// hash of the negotiated suite.

///|
/// `PRF(secret, label, seed)` (RFC 5246 §5): `P_hash` over `label + seed`, out to `len` octets.
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
  let out = Buffer()
  let mut a = start
  while out.length() < len {
    a = @hmac.mac(secret, a[:], digest.hasher())
    let block = Buffer()
    block.write_bytes(a)
    block.write_bytes(start)
    out.write_bytes(@hmac.mac(secret, block.to_bytes()[:], digest.hasher()))
  }
  out.to_bytes()[0:len].to_owned()
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
