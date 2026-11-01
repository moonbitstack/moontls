// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// `known` is the SHA-256 PRF vector published on the IETF TLS list; the rest are Python's hashlib
// and hmac writing RFC 5246 §5 and RFC 7627 §4 out, which share no code with this package.

///|
fn octets(hex : String) -> Bytes {
  let out = Buffer()
  let nibble = (c : Int32) => {
    if c >= 'a'.to_int() {
      c - 'a'.to_int() + 10
    } else {
      c - '0'.to_int()
    }
  }
  for i = 0; i < hex.length(); i = i + 2 {
    out.write_byte(
      ((nibble(hex[i].to_int()) << 4) | nibble(hex[i + 1].to_int())).to_byte(),
    )
  }
  out.to_bytes()
}

///|
fn run(start : Int32, size : Int32) -> Bytes {
  Bytes::makei(size, i => (start + i).to_byte())
}

///|
test "the PRF matches the published SHA-256 vector" {
  assert_eq(
    @keys.prf(
      octets("9bbe436ba940f017b17652849a71db35")[:],
      b"test label"[:],
      octets("a0ba9f936cda311827a6f796ffd5198c")[:],
      len=100,
      digest=Sha256,
    ),
    octets(
      "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66",
    ),
  )
}

///|
test "the PRF matches Python's over both hashes" {
  let seed = run(100, 32)
  assert_eq(
    @keys.prf(run(0, 16)[:], b"test label"[:], seed[:], len=100, digest=Sha256),
    octets(
      "e7042c810b49f2073dafe4c8f18c630d5ee8493db1c890dbf330ec1c925ff2774a638729d9020f36966b3e47cd2b9765bf1299c23f1f88924b518711afd66845cdf34a28ba124e9e2423417fddfe5c043c01a8d4fe4294e9c02ed04ce03119ac70367a1d",
    ),
  )
  assert_eq(
    @keys.prf(run(0, 16)[:], b"test label"[:], seed[:], len=148, digest=Sha384),
    octets(
      "8179bc9d28c2ebca46a0868b70abfabba256f51693178caac6ed78ff52c067f908e76c77b58e9bbc1217b02f157243e6d73ee3465f571ef9554841801d3d9b12786afe38d20cc0d0349f17f167f277162f3e0be7acaead452cd356eb4db7ba25eaaca40a9f2250b9a106113aa204f91d5fe7cbfba9a02c2c0c1b237e52add0a55105156bb833c160b36db779e210f9494e066a58",
    ),
  )
}

///|
test "the master secret, the key block and Finished match Python's" {
  let (premaster, client, server, hash) = (
    run(0, 32),
    run(32, 32),
    run(64, 32),
    run(96, 32),
  )
  let master = @keys.master12(premaster[:], client[:], server[:], digest=Sha256)
  assert_eq(
    master,
    octets(
      "518bc65fd30dabe86349152f98435c94d907b50c92a931c5a2f9e3a4d90f3439f2726c763fb1a40aec90b8bc60173f7c",
    ),
  )
  assert_eq(
    @keys.master12(
      premaster[:],
      client[:],
      server[:],
      session=hash[:],
      digest=Sha256,
    ),
    octets(
      "8cdbae5b0bf6a6020c5ec3c46534625817ab9100f71ac2cdf7e32146052853dad37661bc893e6220930227e0f7009053",
    ),
  )
  assert_eq(
    @keys.key_block(master[:], client[:], server[:], len=40, digest=Sha256),
    octets(
      "9052d2e0e4485b2e323effcbc8a47e0839454ba1588ffbc35dccffd8fe8f67f36aee3d733b5a6abc",
    ),
  )
  assert_eq(
    @keys.finished12(master[:], hash[:], client=true, digest=Sha256),
    octets("7dec70c0f70d2c1ad8e52dd0"),
  )
  assert_eq(
    @keys.finished12(master[:], hash[:], client=false, digest=Sha256),
    octets("2d4806a12e979726e9c0ba1b"),
  )
  assert_true(
    @keys.finished12_ok(
      master[:],
      hash[:],
      octets("2d4806a12e979726e9c0ba1b")[:],
      client=false,
      digest=Sha256,
    ),
  )
  assert_false(
    @keys.finished12_ok(
      master[:],
      hash[:],
      octets("7dec70c0f70d2c1ad8e52dd0")[:],
      client=false,
      digest=Sha256,
    ),
  )
}
