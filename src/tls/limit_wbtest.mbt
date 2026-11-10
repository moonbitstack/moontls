// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 8449 §4: the size a peer says it will read is a promise, and one it only makes when it names
// an extension of its own. A peer that names none is not held to a limit it never agreed to, and
// OpenSSL's server is one: it sends 16 KiB records under a ClientHello that asked for 512.

///|
let idle_rand : (Int32) -> Bytes = _ => Bytes::make(32, b'\x01')

///|
/// A client that has not been sent a byte: enough to ask what it would do with one.
fn idle_client() -> Conn raise {
  let config = Client::new(@x509.Roots::new(), groups=[@ext.x25519], shares=1)
  Conn::client(config, "a.example", rand=idle_rand, now=1767225600L)
}

///|
test "tls: a record_size_limit binds only a peer that named one" {
  let c = idle_client()
  c.our_limit = 512
  // Nothing came back, so the peer never said it knew the extension.
  assert_false(c.past_limit(true, 4097))
  assert_false(c.past_limit(true, 512))
  // Once it names one, its own records are held to 512 — the content type counting inside.
  c.peer_limit = 1000
  assert_false(c.past_limit(true, 511))
  assert_true(c.past_limit(true, 512))
  assert_true(c.past_limit(true, 4097))
  // An unprotected record — a ServerHello carrying a post-quantum share — is outside the limit.
  assert_false(c.past_limit(false, 4097))
}

///|
test "tls: a bounded record is measured against the version's own count" {
  let c = idle_client()
  c.our_limit = 512
  c.peer_limit = 1000
  c.version = Some(Tls12)
  // RFC 8449 §4: in 1.2 the content type is in the header, so only the data is counted.
  assert_false(c.past_limit(true, 512))
  assert_true(c.past_limit(true, 513))
}
