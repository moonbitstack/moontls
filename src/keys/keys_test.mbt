// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The key schedule against an independent computation.
//
// The secrets below were produced by RFC 8446 §7.1 written out over Python's
// own HMAC, so they share no code with this package. The Early Secret for a
// zero PSK is also the one RFC 8448 publishes —
// `33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a` — which
// anchors the ladder to the RFC's own trace rather than only to our arithmetic.

///|
/// A fixed ECDHE secret: the octets 0..31. Nothing here is secret, and a
/// reproducible input is the point.
let ecdhe : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

///|
let hello : Bytes = b"client hello .. server hello"

///|
let finished_msgs : Bytes = b"client hello .. server finished"

///|
test "the Early Secret for a zero PSK is RFC 8448's" {
  assert_eq(
    @base16.encode(@keys.early()),
    "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
  )
  // An all-zero PSK given explicitly is the same thing said out loud.
  assert_eq(
    @base16.encode(@keys.early(psk=Bytes::make(32, b'\x00')[:])),
    "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
  )
}

///|
test "the ladder matches an independent implementation" {
  let early = @keys.early()
  let handshake = @keys.handshake(early[:], ecdhe[:])
  assert_eq(
    @base16.encode(handshake),
    "ddbe37614d014a8c19db0a47955ee6930b3ee727c408386ba274344962b0e015",
  )
  let master = @keys.master(handshake[:])
  assert_eq(
    @base16.encode(master),
    "055796c9a2f048dd920b01351ba00d131ba528efa37749efb03e31b643c615b2",
  )
  let hello_hash = @keys.digest.hash(hello[:])
  let finished_hash = @keys.digest.hash(finished_msgs[:])
  assert_eq(
    @base16.encode(@keys.client_handshake(handshake[:], hello_hash[:])),
    "13dbfa58529f5e6768f79cb0791aff419bb0863d639b45286d668d148def4829",
  )
  assert_eq(
    @base16.encode(@keys.server_handshake(handshake[:], hello_hash[:])),
    "d9046931f6b18fed48b5dab4a317587bf2845e5f9e574c43ee608933a5ba6a3b",
  )
  assert_eq(
    @base16.encode(@keys.client_application(master[:], finished_hash[:])),
    "33666a5edc79b8d8d46d288a24b09218f72265ce35e37f841035484b570f5fe8",
  )
  assert_eq(
    @base16.encode(@keys.server_application(master[:], finished_hash[:])),
    "2818c34fc5073bcb8cd0c7f8d2620d94120bb4f96719d389b09f394629519d17",
  )
}

///|
/// The digest is a knob, and turning it changes every secret: a SHA-384 suite
/// runs the same ladder 48 octets wide.
test "the digest is a knob at every step" {
  let early = @keys.early(digest=Sha384)
  assert_eq(early.length(), 48)
  assert_eq(
    @base16.encode(early),
    "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5",
  )
  let handshake = @keys.handshake(early[:], ecdhe[:], digest=Sha384)
  assert_eq(
    @base16.encode(handshake),
    "03e67b8797b8868b32c737ad09d2454266b47b828fe83999484501c1d0f12bfefdecf2341ab055c50f8f81a4d91610dd",
  )
  let hello_hash = @keys.Digest::Sha384.hash(hello[:])
  assert_eq(
    @base16.encode(
      @keys.client_handshake(handshake[:], hello_hash[:], digest=Sha384),
    ),
    "1c216b9b535df3958f0280f602f7be339331dcc2ab4d9c44143de60477f678f65fc6ef962f87ad21824ec9de1fb1327b",
  )
  // And SHA-256 is what it is without being asked for.
  assert_eq(@keys.digest, @keys.Digest::Sha256)
  assert_eq(@keys.Digest::Sha256.size(), 32)
  assert_eq(@keys.Digest::Sha384.size(), 48)
}

///|
test "a transcript accumulates to the hash of the concatenation" {
  let t = @keys.Transcript::new()
  t.add(b"client hello "[:])
  t.add(b".. server hello"[:])
  assert_eq(
    @base16.encode(t.hash()),
    @base16.encode(@keys.digest.hash(hello[:])),
  )
  // An empty transcript is the hash of the empty string, which the "derived"
  // steps of the ladder run over.
  assert_eq(
    @base16.encode(@keys.Transcript::new().hash()),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
}

///|
test "a Finished carries the verify_data its key MACs" {
  let handshake = @keys.handshake(@keys.early()[:], ecdhe[:])
  let base = @keys.client_handshake(
    handshake[:],
    @keys.digest.hash(hello[:])[:],
  )
  assert_eq(
    @base16.encode(@keys.finished_key(base[:])),
    "a00d1bfb22999d2c5d7df57745ce6974f7342b988ccc697ac55de41372fd493a",
  )
  let transcript = @keys.digest.hash(finished_msgs[:])
  assert_eq(
    @base16.encode(@keys.finished(base[:], transcript[:])),
    "0acf0aed245447c607eeb982350f4336705545ca2c1e8d54b428b6b44afdbf19",
  )
  assert_eq(
    @keys.finished_ok(
      base[:],
      transcript[:],
      @base16.decode(
        "0acf0aed245447c607eeb982350f4336705545ca2c1e8d54b428b6b44afdbf19",
      )[:],
    ),
    true,
  )
}

///|
/// A wrong verify_data is refused, and one octet is enough.
test "a Finished with the wrong verify_data is refused" {
  let handshake = @keys.handshake(@keys.early()[:], ecdhe[:])
  let base = @keys.client_handshake(
    handshake[:],
    @keys.digest.hash(hello[:])[:],
  )
  let transcript = @keys.digest.hash(finished_msgs[:])
  let good = @keys.finished(base[:], transcript[:]).to_array()
  good[31] = (good[31].to_int() ^ 1).to_byte()
  assert_eq(
    @keys.finished_ok(base[:], transcript[:], Bytes::from_array(good)[:]),
    false,
  )
  // A truncated one too: a prefix that matches is still not the whole thing.
  assert_eq(@keys.finished_ok(base[:], transcript[:], b"\x0a\xcf"[:]), false)
}

///|
/// HKDF-Expand-Label's framing is the protocol's, so it is worth pinning on its
/// own: the label carries the `tls13 ` prefix and the length appears twice.
test "expand_label frames the HkdfLabel RFC 8446 defines" {
  let out = @keys.expand_label(
    b"\x00\x01\x02\x03"[:],
    b"key"[:],
    b""[:],
    len=16,
  )
  assert_eq(out.length(), 16)
  // The same expansion reached through `expand` with the label built by hand.
  let info = Bytes::from_array([
    b'\x00', b'\x10', b'\x09', b't', b'l', b's', b'1', b'3', b' ', b'k', b'e', b'y',
    b'\x00',
  ])
  assert_eq(
    @base16.encode(out),
    @base16.encode(@keys.expand(b"\x00\x01\x02\x03"[:], info[:], len=16)),
  )
}

///|
/// The two secrets that outlive the handshake, against the same independent
/// computation as the ladder above.
test "the exporter and resumption secrets match an independent implementation" {
  let master = @keys.master(@keys.handshake(@keys.early()[:], ecdhe[:])[:])
  let finished_hash = @keys.digest.hash(finished_msgs[:])
  assert_eq(
    @base16.encode(@keys.exporter_master(master[:], finished_hash[:])),
    "9db395597c5fcb912ae4417219b3410cbbae91bc0f05e346ed0af4880d4920ca",
  )
  assert_eq(
    @base16.encode(@keys.resumption_master(master[:], finished_hash[:])),
    "26d6e09552f187a49d6104c37aba1baa8903657624aecd7fa06c05bd09f041b2",
  )
}

///|
/// RFC 8446 §7.5 hashes the context whether or not there is one, so an empty
/// context is a real input and not an absent one — two exports under the same
/// label differ as soon as the context does.
test "an export is fixed by its label, its context and its length" {
  let master = @keys.master(@keys.handshake(@keys.early()[:], ecdhe[:])[:])
  let secret = @keys.exporter_master(
    master[:],
    @keys.digest.hash(finished_msgs[:])[:],
  )
  assert_eq(
    @base16.encode(@keys.exporter(secret[:], b"EXPERIMENTAL", b"", len=32)),
    "aec38ee33c68b20ee2b04f68a913355ed7ef199d8295af3779dc70209bf2a18d",
  )
  assert_eq(
    @base16.encode(@keys.exporter(secret[:], b"EXPERIMENTAL", b"ctx", len=32)),
    "a14d4b96758a8beaafabaf391d83e469508d3b7afed3d3594e01ed98010c8fbc",
  )
  // The requested length goes into the HkdfLabel, so a shorter export is not
  // the longer one's prefix — it shares no octet with it.
  let short = @keys.exporter(secret[:], b"EXPERIMENTAL", b"", len=16)
  assert_eq(@base16.encode(short), "948c263700215d28d087ad6a317af35e")
}
