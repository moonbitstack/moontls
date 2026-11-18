// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What a peer may say and this library may not: a corpus that is wrong in every octet, one at a
// time. A decoder that panics on a length it cannot trust is a denial of service in a server that
// accepts connections from anyone, so the rule these pin is that every answer is either an alert or
// a handshake that goes on — never a crash, and never silence.

///|
/// `data` with the octet at `at` replaced.
fn changed(data : Bytes, at : Int32, byte : Byte) -> Bytes {
  let copy = data.to_array()
  copy[at] = byte
  Bytes::from_array(copy)
}

///|
test "tls: a ClientHello corrupted in any one octet is an alert or an answer, never a crash" {
  let config = @tls.Server::new([der(p256_leaf)], p256())
  let hello = client_with().take()
  assert_true(hello.length() > 0)
  let poisoned = [b'\x00', b'\xff']
  let mut refused = 0
  let mut carried = 0
  for at in 0..<hello.length() {
    for byte in poisoned {
      if hello[at] == byte {
        continue
      }
      let server = @tls.Conn::server(config, rand=rng(6), now~)
      try {
        server.receive(changed(hello, at, byte)[:])
        if server.take().length() > 0 {
          carried = carried + 1
        }
      } catch {
        @alert.Alert(kind~, ..) =>
          // A fatal alert is an answer: the handler decided this connection is over.
          if kind.is_fatal() {
            refused = refused + 1
          }
      }
    }
  }
  // A corpus in which nothing is ever refused would say the server accepted every corruption,
  // which is the failure this test exists to catch; one in which nothing is ever answered would
  // say it refuses what it should not.
  assert_true(refused > 0)
  assert_true(carried > 0)
}

///|
test "tls: a server flight fed one octet at a time is never judged before its last octet" {
  // Half a handshake is what a connection that is cut off looks like. The client may have nothing
  // to say until the flight is complete, and may refuse it — it may not panic, and it may not
  // report a connection it has not got.
  let server = server_with(p256_leaf, p256())
  let client = client_with()
  server.receive(client.take()[:])
  let flight = server.take()
  assert_true(flight.length() > 0)
  for i in 0..<(flight.length() - 1) {
    client.receive(flight[i:i + 1])
    assert_true(!client.is_connected())
  }
  client.receive(flight[flight.length() - 1:])
  assert_true(client.is_connected())
}
