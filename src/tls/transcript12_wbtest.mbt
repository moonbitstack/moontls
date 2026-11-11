// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 6347 §4.2.2: a DTLS handshake message travels under a twelve-octet header that numbers it,
// and the transcript — EMS's session hash, the certificate verify, every Finished — is taken over
// the message as it went on the wire. TLS hashes the body under a four-octet header and DTLS 1.3
// does the same, so this is a property of DTLS 1.2 alone, and one no two ends of this library can
// disagree about: both would hash their own reading and complete the handshake either way.

///|
let fixed_rand : (Int32) -> Bytes = n => Bytes::make(n, b'\x2a')

///|
fn hello_conn() -> Handshake raise {
  let config = Client::new(@x509.Roots::new(), groups=[@ext.x25519], shares=1)
  {
    conn: Conn::pipe_client(
      config,
      "a.example",
      rand=fixed_rand,
      now=1767225600L,
    ),
  }
}

///|
/// The eight octets a DTLS 1.2 transcript adds to a message: the number, the fragment offset and
/// the fragment length.
fn dtls_header(messages : Bytes, hello : Bytes, seq : Int32) -> Unit raise {
  assert_eq(messages.length(), hello.length() + 8)
  assert_eq(messages[0].to_int(), hello[0].to_int())
  assert_true(messages[1:4] == hello[1:4])
  let want = Buffer()
  @wire.u16(want, seq)
  @wire.u24(want, 0)
  @wire.u24(want, hello.length() - 4)
  assert_true(messages[4:12] == want.to_bytes()[:])
  assert_true(messages[12:] == hello[4:])
}

///|
test "dtls 1.2: the transcript carries the handshake header" {
  let handshake = hello_conn()
  handshake.number12()
  handshake.conn.begin_transcript(None)
  let hello = handshake.conn.first_hello
  handshake.conn.record_sent(hello[:])
  guard handshake.conn.transcript is Some(t) else { fail("no transcript") }
  // The first message each way is numbered zero.
  dtls_header(t.messages(), hello, 0)
}

///|
/// After a HelloVerifyRequest both directions start at one: the request and the first
/// ClientHello it answered took number zero (RFC 6347 §4.2.1).
test "dtls 1.2: a transcript that starts after a cookie numbers from one" {
  let handshake = hello_conn()
  handshake.number12(from=1)
  handshake.conn.begin_transcript(None)
  let hello = handshake.conn.first_hello
  handshake.conn.record_sent(hello[:])
  guard handshake.conn.transcript is Some(t) else { fail("no transcript") }
  dtls_header(t.messages(), hello, 1)
}

///|
test "tls: a transcript without the datagram framing is the message itself" {
  let handshake = hello_conn()
  handshake.conn.begin_transcript(None)
  let hello = handshake.conn.first_hello
  handshake.conn.record_sent(hello[:])
  guard handshake.conn.transcript is Some(t) else { fail("no transcript") }
  assert_eq(t.messages(), hello)
}
