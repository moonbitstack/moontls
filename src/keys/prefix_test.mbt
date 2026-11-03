// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 9147 §5.9: a DTLS association derives everything under `dtls13`, and a TLS one under
// `tls13 `. A round trip against this library alone cannot tell the two apart, because either
// prefix agrees with itself; only comparing the two, and refusing to cross-verify a Finished,
// catches a ladder with the wrong prefix.

///|
test "keys: the dtls13 prefix reaches every label-bearing step" {
  let early = @keys.early()
  let ecdhe : Bytes = b"\x9f\x2c\x11\x04\x01\x02\x03\x04\x05\x06\x07\x08"
  let tls_handshake = @keys.handshake(early[:], ecdhe[:])
  let datagram_handshake = @keys.handshake(
    early[:],
    ecdhe[:],
    prefix=@keys.datagram[:],
  )
  assert_true(tls_handshake != datagram_handshake)
  assert_true(
    @keys.master(tls_handshake[:]) !=
    @keys.master(datagram_handshake[:], prefix=@keys.datagram[:]),
  )
  let transcript = @keys.digest.hash(b"a transcript")
  let pairs : Array[(Bytes, Bytes)] = [
    (
      @keys.client_handshake(tls_handshake[:], transcript[:]),
      @keys.client_handshake(
        datagram_handshake[:],
        transcript[:],
        prefix=@keys.datagram[:],
      ),
    ),
    (
      @keys.server_handshake(tls_handshake[:], transcript[:]),
      @keys.server_handshake(
        datagram_handshake[:],
        transcript[:],
        prefix=@keys.datagram[:],
      ),
    ),
    (
      @keys.client_application(tls_handshake[:], transcript[:]),
      @keys.client_application(
        datagram_handshake[:],
        transcript[:],
        prefix=@keys.datagram[:],
      ),
    ),
    (
      @keys.server_application(tls_handshake[:], transcript[:]),
      @keys.server_application(
        datagram_handshake[:],
        transcript[:],
        prefix=@keys.datagram[:],
      ),
    ),
    (
      @keys.client_early(early[:], transcript[:]),
      @keys.client_early(early[:], transcript[:], prefix=@keys.datagram[:]),
    ),
    (
      @keys.exporter_master(tls_handshake[:], transcript[:]),
      @keys.exporter_master(
        datagram_handshake[:],
        transcript[:],
        prefix=@keys.datagram[:],
      ),
    ),
    (
      @keys.resumption_master(tls_handshake[:], transcript[:]),
      @keys.resumption_master(
        datagram_handshake[:],
        transcript[:],
        prefix=@keys.datagram[:],
      ),
    ),
    (
      @keys.binder_key(early[:]),
      @keys.binder_key(early[:], prefix=@keys.datagram[:]),
    ),
    (
      @keys.resumption(tls_handshake[:], b"\x00"),
      @keys.resumption(datagram_handshake[:], b"\x00", prefix=@keys.datagram[:]),
    ),
  ]
  for pair in pairs {
    let (tls, datagram) = pair
    assert_true(tls != datagram)
    assert_eq(tls.length(), datagram.length())
  }
}

///|
test "keys: a Finished verifies only under the prefix that made it" {
  let base : Bytes = Bytes::make(32, b'\x2a')
  let transcript = @keys.digest.hash(b"through the server Finished")
  let datagram = @keys.finished(
    base[:],
    transcript[:],
    prefix=@keys.datagram[:],
  )
  assert_true(
    @keys.finished_ok(
      base[:],
      transcript[:],
      datagram[:],
      prefix=@keys.datagram[:],
    ),
  )
  assert_false(@keys.finished_ok(base[:], transcript[:], datagram[:]))
  let tls = @keys.finished(base[:], transcript[:])
  assert_true(tls != datagram)
  assert_false(
    @keys.finished_ok(base[:], transcript[:], tls[:], prefix=@keys.datagram[:]),
  )
}
