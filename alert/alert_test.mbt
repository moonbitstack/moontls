// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The §6.1 and §6.2 registry, the codec, and which descriptions end a
// connection. Every assertion is on the wire value RFC 8446 assigns, so the
// numbers here are the RFC's and not this package's spelling of them.

///|
test "every description carries the code RFC 8446 assigns" {
  let assigned = [
    (@alert.Kind::CloseNotify, 0),
    (@alert.Kind::UnexpectedMessage, 10),
    (@alert.Kind::BadRecordMac, 20),
    (@alert.Kind::RecordOverflow, 22),
    (@alert.Kind::HandshakeFailure, 40),
    (@alert.Kind::BadCertificate, 42),
    (@alert.Kind::UnsupportedCertificate, 43),
    (@alert.Kind::CertificateRevoked, 44),
    (@alert.Kind::CertificateExpired, 45),
    (@alert.Kind::CertificateUnknown, 46),
    (@alert.Kind::IllegalParameter, 47),
    (@alert.Kind::UnknownCa, 48),
    (@alert.Kind::AccessDenied, 49),
    (@alert.Kind::DecodeError, 50),
    (@alert.Kind::DecryptError, 51),
    (@alert.Kind::ProtocolVersion, 70),
    (@alert.Kind::InsufficientSecurity, 71),
    (@alert.Kind::InternalError, 80),
    (@alert.Kind::InappropriateFallback, 86),
    (@alert.Kind::UserCanceled, 90),
    (@alert.Kind::MissingExtension, 109),
    (@alert.Kind::UnsupportedExtension, 110),
    (@alert.Kind::UnrecognizedName, 112),
    (@alert.Kind::BadCertificateStatusResponse, 113),
    (@alert.Kind::UnknownPskIdentity, 115),
    (@alert.Kind::CertificateRequired, 116),
    (@alert.Kind::NoApplicationProtocol, 120),
  ]
  for pair in assigned {
    assert_eq(pair.0.code(), pair.1)
    // And the code reads back as the description it came from.
    assert_eq(@alert.Kind::of(pair.1), pair.0)
  }
  assert_eq(assigned.length(), 27)
}

///|
/// A code the RFC does not assign is carried through, not dropped: the
/// description is the only diagnostic the peer gets.
test "an unassigned description keeps its number" {
  assert_eq(@alert.Kind::of(200), @alert.Kind::Other(200))
  assert_eq(@alert.Kind::Other(200).code(), 200)
  assert_eq(@alert.Kind::of(1), @alert.Kind::Other(1))
}

///|
test "the levels are 1 and 2, and nothing else is a level" {
  assert_eq(@alert.Level::Warning.code(), 1)
  assert_eq(@alert.Level::Fatal.code(), 2)
  assert_eq(@alert.Level::of(1), Some(@alert.Level::Warning))
  assert_eq(@alert.Level::of(2), Some(@alert.Level::Fatal))
  assert_eq(@alert.Level::of(0), None)
  assert_eq(@alert.Level::of(3), None)
}

///|
/// RFC 8446 §6.1: every alert is fatal except close_notify and user_canceled,
/// whatever level the sender put on it.
test "only close_notify and user_canceled leave a connection usable" {
  assert_eq(@alert.Kind::CloseNotify.is_fatal(), false)
  assert_eq(@alert.Kind::UserCanceled.is_fatal(), false)
  assert_eq(@alert.Kind::DecodeError.is_fatal(), true)
  assert_eq(@alert.Kind::HandshakeFailure.is_fatal(), true)
  assert_eq(@alert.Kind::Other(200).is_fatal(), true)
  // The level does not change the answer.
  let Alert(kind=warned, ..) = @alert.warning(@alert.Kind::DecodeError)
  assert_eq(warned.is_fatal(), true)
  let Alert(kind=closed, ..) = @alert.fatal(@alert.Kind::CloseNotify)
  assert_eq(closed.is_fatal(), false)
}

///|
test "an alert round-trips through its two octets" {
  let a = @alert.fatal(@alert.Kind::DecodeError)
  assert_eq(@alert.encode(a), b"\x02\x32")
  assert_eq(@alert.decode(b"\x02\x32"[:]), Some(a))
  let w = @alert.warning(@alert.Kind::CloseNotify)
  assert_eq(@alert.encode(w), b"\x01\x00")
  assert_eq(@alert.decode(b"\x01\x00"[:]), Some(w))
}

///|
test "decode refuses a truncated alert and an unassigned level" {
  assert_eq(@alert.decode(b""[:]), None)
  assert_eq(@alert.decode(b"\x02"[:]), None)
  // A level the RFC does not assign is refused rather than guessed at.
  assert_eq(@alert.decode(b"\x00\x32"[:]), None)
  assert_eq(@alert.decode(b"\x03\x32"[:]), None)
  // Trailing octets past the two are not the alert's business.
  assert_eq(
    @alert.decode(b"\x02\x32\xff"[:]),
    Some(@alert.fatal(@alert.Kind::DecodeError)),
  )
}

///|
/// The alert is the error a handshake raises, so it is caught by kind.
test "an alert is raisable and caught by kind" {
  fn refuse() -> Unit raise @alert.Alert {
    raise @alert.fatal(@alert.Kind::MissingExtension)
  }

  let mut seen = @alert.Kind::CloseNotify
  refuse() catch {
    Alert(kind~, ..) => seen = kind
  }
  assert_eq(seen, @alert.Kind::MissingExtension)
  assert_eq(seen.code(), 109)
}
