// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Records out of turn.
//
// A handshake is a sequence, and the interesting failures are the ones where the sequence is
// broken: a record that belongs after the handshake arriving before it, a change of cipher state
// announced twice, a message the state machine is not waiting for. Each of these has one right
// answer in RFC 8446 — a named fatal alert — and the answers are pinned here one by one.
//
// This is the other half of `decode_matrix_test.mbt`: that file says a wrong message must not
// crash, this one says what a wrong message must be told.

///|
fn sequence_expect(
  name : String,
  want : @alert.Kind,
  run : () -> Unit raise,
) -> Unit raise {
  try {
    run()
    abort("\{name}: no alert, want \{want.to_repr()}")
  } catch {
    @alert.Alert(kind~, ..) => {
      if kind != want {
        abort("\{name}: got \{kind.to_repr()}, want \{want.to_repr()}")
      }
      assert_true(kind.is_fatal())
    }
    e => abort("\{name}: not an alert: \{e}")
  }
}

///|
test "sequence: records that belong after the handshake are refused before it" {
  // §5.1: a TLSPlaintext record in the clear is a handshake, an alert, or a change_cipher_spec.
  // Application data in the clear is none of those.
  sequence_expect("plaintext application data", UnexpectedMessage, () => {
    let server = server_with(p256_leaf, p256())
    server.receive(@record.encode(@record.Kind::ApplicationData, b"early"))
  })
  sequence_expect("an undefined content type", UnexpectedMessage, () => {
    let server = server_with(p256_leaf, p256())
    server.receive(b"\x55\x03\x03\x00\x01\x00")
  })
  sequence_expect("an empty handshake record", UnexpectedMessage, () => {
    let server = server_with(p256_leaf, p256())
    server.receive(b"\x16\x03\x01\x00\x00")
  })
}

///|
/// RFC 8446 §5: a change_cipher_spec is tolerated once in each direction, in the middlebox
/// compatibility mode, and never before the ClientHello that starts the handshake. A second one is
/// a message the state machine did not ask for.
test "sequence: change_cipher_spec out of turn is unexpected_message" {
  let ccs = b"\x14\x03\x03\x00\x01\x01"
  sequence_expect("a change_cipher_spec before the hello", UnexpectedMessage, () => {
    let server = server_with(p256_leaf, p256())
    server.receive(ccs)
  })
  sequence_expect("a second change_cipher_spec", UnexpectedMessage, () => {
    let server = server_with(p256_leaf, p256())
    server.receive(ccs)
    server.receive(ccs)
  })
}

///|
/// After the handshake every record is encrypted (RFC 8446 §5.2). A record that is not is a record
/// whose authentication tag does not verify, which is `bad_record_mac` — the answer an attacker
/// gets for guessing at the keys.
test "sequence: a plaintext record after the handshake does not authenticate" {
  sequence_expect("plaintext after the handshake", BadRecordMac, () => {
    let server = server_with(p256_leaf, p256())
    let client = client_with()
    shuttle(client, server)
    assert_true(server.is_connected())
    server.receive(@record.encode(@record.Kind::ApplicationData, b"late"))
  })
}

///|
/// A handshake message the state machine has finished with. The ServerHello is the one with a
/// fixed shape, so a framed one with an empty body reaches the dispatcher rather than the parser.
test "sequence: a second ServerHello is unexpected_message" {
  sequence_expect("a handshake after the handshake", UnexpectedMessage, () => {
    let server = server_with(p256_leaf, p256())
    let client = client_with()
    shuttle(client, server)
    assert_true(client.is_connected())
    client.receive(b"\x16\x03\x03\x00\x04\x02\x00\x00\x00")
  })
}

///|
/// An alert in the clear before the handshake. RFC 8446 §6 allows an alert at any time — it is how
/// a server says it will not speak to this client at all — and `close_notify` ends the connection
/// without an answer.
test "sequence: a close_notify before the handshake ends the connection" {
  let server = server_with(p256_leaf, p256())
  server.receive(b"\x15\x03\x03\x00\x02\x01\x00")
  assert_true(server.is_closed())
}
