// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2's RSA key exchange: the premaster secret in RSAES-PKCS1-v1_5 (RFC 5246 §7.4.7.1).

///|
/// How long a premaster secret is, the two version octets included.
pub let premaster_size : Int32 = 48

///|
/// Wrap a premaster secret for `key`'s owner (RFC 8017 §7.2.1). `Size` when the key is too short to
/// hold it with the eight octets of filler the padding demands.
pub fn wrap_premaster(
  key : @rsa.PublicKey,
  premaster : BytesView,
  rand~ : (Int32) -> Bytes,
) -> Bytes raise @spec.Broken {
  let fill = key.size() - premaster.length() - 3
  if fill < 8 {
    raise @spec.Size(want=premaster.length() + 11, got=key.size())
  }
  let filler : Array[Byte] = []
  while filler.length() < fill {
    for b in rand(fill - filler.length()) {
      if b != b'\x00' {
        filler.push(b)
      }
    }
  }
  let block = Buffer()
  block.write_byte(b'\x00')
  block.write_byte(b'\x02')
  block.write_bytes(Bytes::from_array(filler))
  block.write_byte(b'\x00')
  block.write_bytesview(premaster)
  key.rsaep(block.to_bytes()[:])
}

///|
/// Unwrap a premaster secret, whose first two octets must be `version`. A block that is wrong in any
/// way gives a random secret instead of an error: the handshake goes on and fails at Finished like
/// any other mismatch, since telling the sender which blocks were well formed is Bleichenbacher's
/// oracle. The block is walked whole and the choice is made by masking, so nothing branches on what
/// was decrypted.
pub fn unwrap_premaster(
  key : @rsa.PrivateKey,
  wrapped : BytesView,
  version~ : Int32,
  rand~ : (Int32) -> Bytes,
) -> Bytes {
  let stand_in = rand(premaster_size)
  let block = key.rsadp(wrapped) catch { _ => return stand_in }
  let start = block.length() - premaster_size
  if start < 11 {
    return stand_in
  }
  let mut bad = block[0].to_int() | (block[1].to_int() ^ 2)
  for i in 2..<(start - 1) {
    bad = bad | (((block[i].to_int() - 1) >> 31) & 1)
  }
  bad = bad |
    block[start - 1].to_int() |
    (block[start].to_int() ^ (version >> 8)) |
    (block[start + 1].to_int() ^ (version & 0xff))
  let keep = (bad - 1) >> 31
  Bytes::makei(premaster_size, i => {
    let chosen = (block[start + i].to_int() & keep) |
      (stand_in[i].to_int() & keep.lnot())
    chosen.to_byte()
  })
}
