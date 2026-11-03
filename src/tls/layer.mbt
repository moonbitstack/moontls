// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The seam between a handshake and the wire it runs over.
//
// A TLS handshake and a DTLS handshake are the same handshake: the same
// messages, the same key schedule, the same negotiation. What differs is how
// the octets travel — a byte stream with records that may split or join a
// message, or a series of datagrams with message sequence numbers, fragments
// and ACKs. So the handshake is written once, against this contract, and each
// wire plugs in its own implementation:
//
//   * `tls::Conn`     a TLS record layer over a stream
//   * `dtls::Conn13`  a DTLS 1.3 record layer over datagrams
//   * `dtls::Conn12`  a DTLS 1.2 record layer over datagrams
//
// A layer is passive. It never reads a clock and never decides when to resend:
// the handshake calls `send` and `install`, and the caller drives the clock
// through the connection that owns the layer.

///|
/// Which direction of a connection a key protects (RFC 8446 §7.3).
///
/// `Read` is what the peer writes and this end decrypts; `Write` is the other
/// way. The two never share a key, and a layer installs them independently.
#derive(Eq, Debug)
pub(all) enum Direction {
  Read
  Write
}

///|
pub extend Direction with Eq::{equal, not_equal}

///|
pub extend Direction with Debug::{to_repr}

///|
/// The key material a handshake hands a record layer when one direction changes
/// keys.
///
/// TLS 1.3 and DTLS 1.3 exchange a traffic secret and let the layer expand it
/// (RFC 8446 §7.3): the expansion is where the two differ, because the label
/// prefix is `tls13 ` over a stream and `dtls13` over datagrams (RFC 9147
/// §5.9). TLS 1.2 and DTLS 1.2 exchange a key block instead (RFC 5246 §6.3),
/// already cut to one direction, because their PRF and their record protection
/// have no such seam.
pub(all) enum Keys {
  /// A traffic secret and the suite whose hash and lengths it is expanded with.
  Traffic(@record.Suite, Bytes)
  /// One direction's slice of a 1.2 key block: the suite, the write key, the
  /// IV or nonce salt, the MAC key (empty under an AEAD), and whether
  /// encrypt-then-MAC was agreed.
  Block(@record.Suite12, Bytes, Bytes, Bytes, Bool)
}

///|
/// The record layer a handshake drives.
///
/// The handshake never sees a record, an epoch, a sequence number or a
/// datagram. It asks for content to be sent and for keys to be installed, and
/// the layer decides how that becomes octets — including how many records a
/// flight takes, and how a message is fragmented.
pub(open) trait Layer {
  /// Queue one content unit for the peer, protected under whatever the layer
  /// has installed for the write direction. Before keys this is a plaintext
  /// record; after, a protected one.
  fn send(Self, @record.Kind, BytesView) -> Unit raise @alert.Alert

  /// Install a direction's keys. The layer advances its own epoch, if it has
  /// one, and derives whatever traffic keys the wire needs from `keys`.
  fn install(Self, Direction, Keys) -> Unit raise @alert.Alert

  /// Queue a dummy change_cipher_spec (RFC 8446 §D.4). A TLS 1.3 stream sends
  /// one for middlebox compatibility; a datagram layer sends nothing.
  fn change_cipher_spec(Self) -> Unit

  /// The handshake has completed: the write direction's application keys are in
  /// place and application data may flow.
  fn open(Self) -> Unit

  /// Whether this layer carries datagrams. A datagram layer numbers and
  /// acknowledges handshake messages; a stream layer does neither.
  fn datagram(Self) -> Bool

  /// Whether a direction has keys yet, which decides whether a content unit may
  /// be sent at all.
  fn keyed(Self, Direction) -> Bool
}
