// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A connection whose wire is not a record stream.
//
// TLS over a stream frames messages into records itself; QUIC carries them in
// CRYPTO frames; DTLS carries them in its own records with message sequence
// numbers, fragments and ACKs. In every one of those the *handshake* is the
// same, so this pipe is the handshake's output with the framing removed: whole
// messages, alerts, key installs and the moment the handshake opens, in the
// order they must reach the wire.
//
// It is private on purpose. The public seam is `Layer`; `Handshake` drains this
// pipe into a `Layer`, and the datagram connections implement the layer.

///|
/// One thing the handshake wants its transport to do, in order.
priv enum Out {
  /// A whole TLS handshake message: type, 24-bit length, body.
  Message(Bytes)
  /// An encoded alert: a level and a description.
  Alert(Bytes)
  /// A change_cipher_spec, which DTLS 1.2 sends and DTLS 1.3 does not.
  ChangeCipherSpec
  /// The traffic secrets of a TLS 1.3 level, client first.
  Keys13(Level, Bytes, Bytes)
  /// One TLS 1.2 key block, cut into both directions' key, IV and MAC.
  Keys12(@record.Suite12, Bytes, Bytes, Bytes, Bytes, Bytes, Bytes, Bool)
}

///|
/// The handshake's outgoing queue for a transport that frames messages itself.
priv struct Pipe {
  out : Array[Out]
}

///|
fn Pipe::new() -> Pipe {
  { out: [], }
}

///|
fn Pipe::push(self : Pipe, one : Out) -> Unit {
  self.out.push(one)
}

///|
/// Cut a flight — one or more TLS handshake messages concatenated — into the
/// messages it is made of. A DTLS transport numbers and fragments each message
/// on its own, so it cannot take the flight as one unit the way CRYPTO frames
/// can.
fn split_messages(data : BytesView) -> Array[Bytes] {
  let out : Array[Bytes] = []
  let mut at = 0
  while at + 4 <= data.length() {
    let len = (data[at + 1].to_int() << 16) |
      (data[at + 2].to_int() << 8) |
      data[at + 3].to_int()
    let end = at + 4 + len
    if end > data.length() {
      break
    }
    out.push(data[at:end].to_owned())
    at = end
  }
  out
}
