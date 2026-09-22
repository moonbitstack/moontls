// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An alert's level (RFC 8446 §6).
///
/// TLS 1.3 acts on the description rather than the level: only `CloseNotify`
/// and `UserCanceled` leave a connection usable, whichever level carries them.
/// The level is still on the wire, so it is still read and written.
pub(all) enum Level {
  Warning
  Fatal
} derive(Eq, Debug)

///|
pub extend Level with Eq::{equal, not_equal}

///|
pub extend Level with Debug::{to_repr}

///|
/// The octet this level goes on the wire as.
pub fn Level::code(self : Level) -> Int {
  match self {
    Warning => 1
    Fatal => 2
  }
}

///|
/// The level an octet names, or `None` for one RFC 8446 does not assign.
pub fn Level::of(code : Int) -> Level? {
  match code {
    1 => Some(Warning)
    2 => Some(Fatal)
    _ => None
  }
}

///|
/// What an endpoint says went wrong (RFC 8446 §6.1, §6.2).
///
/// The description is the only diagnostic a peer ever receives, so it is what
/// makes a failed handshake readable from the other end — a connection that
/// simply goes away tells the client nothing.
///
/// `Other` carries a code the RFC does not assign. An unrecognised description
/// still arrives, and dropping the number would lose the only thing it said.
pub(all) enum Kind {
  /// The sender is done writing — a clean shutdown, not a failure.
  CloseNotify
  /// A message arrived that the state machine was not waiting for, or out of order.
  UnexpectedMessage
  /// A record failed to decrypt or to authenticate.
  BadRecordMac
  /// A record's plaintext ran past the 2^14-octet limit.
  RecordOverflow
  /// No parameters both endpoints support — no shared group, suite or signature scheme.
  HandshakeFailure
  /// A certificate was corrupt, or carried a signature that did not verify.
  BadCertificate
  /// The certificate was of a type the receiver does not support.
  UnsupportedCertificate
  /// The signer revoked the certificate.
  CertificateRevoked
  /// The certificate has expired, or is not yet valid.
  CertificateExpired
  /// Some other problem with the certificate, with no more precise description.
  CertificateUnknown
  /// A field was well-formed on its own but contradicts the rest of the message.
  IllegalParameter
  /// The chain verified but ended at no trusted anchor.
  UnknownCa
  /// The certificate verified, but the receiver declines to proceed with this peer.
  AccessDenied
  /// A message could not be parsed: a length overran, or a field was out of range.
  DecodeError
  /// A handshake signature or a Finished MAC failed to verify.
  DecryptError
  /// The peer offered no protocol version this endpoint supports.
  ProtocolVersion
  /// handshake_failure, narrowed: the peer's parameters are weaker than accepted.
  InsufficientSecurity
  /// A local failure, unrelated to the peer or to the protocol.
  InternalError
  /// The peer fell back to an older version for an unacceptable reason.
  InappropriateFallback
  /// The handshake is being abandoned for a reason outside the protocol.
  UserCanceled
  /// A message lacked an extension RFC 8446 §9.2 makes mandatory for it.
  MissingExtension
  /// A server sent back an extension the ClientHello never offered.
  UnsupportedExtension
  /// No server exists for the name `server_name` asked for.
  UnrecognizedName
  /// The stapled OCSP response was invalid.
  BadCertificateStatusResponse
  /// The PSK identity offered is unknown and no full handshake will be run.
  UnknownPskIdentity
  /// The client sent no certificate where the server requires one.
  CertificateRequired
  /// None of the ALPN protocols offered is one this server speaks (RFC 7301 §3.2).
  NoApplicationProtocol
  /// A description RFC 8446 does not assign, carried through as its number.
  Other(Int)
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The octet this description goes on the wire as.
pub fn Kind::code(self : Kind) -> Int {
  match self {
    CloseNotify => 0
    UnexpectedMessage => 10
    BadRecordMac => 20
    RecordOverflow => 22
    HandshakeFailure => 40
    BadCertificate => 42
    UnsupportedCertificate => 43
    CertificateRevoked => 44
    CertificateExpired => 45
    CertificateUnknown => 46
    IllegalParameter => 47
    UnknownCa => 48
    AccessDenied => 49
    DecodeError => 50
    DecryptError => 51
    ProtocolVersion => 70
    InsufficientSecurity => 71
    InternalError => 80
    InappropriateFallback => 86
    UserCanceled => 90
    MissingExtension => 109
    UnsupportedExtension => 110
    UnrecognizedName => 112
    BadCertificateStatusResponse => 113
    UnknownPskIdentity => 115
    CertificateRequired => 116
    NoApplicationProtocol => 120
    Other(code) => code
  }
}

///|
/// The description an octet names. Never fails: one the RFC does not assign
/// becomes `Other`.
pub fn Kind::of(code : Int) -> Kind {
  match code {
    0 => CloseNotify
    10 => UnexpectedMessage
    20 => BadRecordMac
    22 => RecordOverflow
    40 => HandshakeFailure
    42 => BadCertificate
    43 => UnsupportedCertificate
    44 => CertificateRevoked
    45 => CertificateExpired
    46 => CertificateUnknown
    47 => IllegalParameter
    48 => UnknownCa
    49 => AccessDenied
    50 => DecodeError
    51 => DecryptError
    70 => ProtocolVersion
    71 => InsufficientSecurity
    80 => InternalError
    86 => InappropriateFallback
    90 => UserCanceled
    109 => MissingExtension
    110 => UnsupportedExtension
    112 => UnrecognizedName
    113 => BadCertificateStatusResponse
    115 => UnknownPskIdentity
    116 => CertificateRequired
    120 => NoApplicationProtocol
    other => Other(other)
  }
}

///|
/// Whether this description ends the connection (RFC 8446 §6.1).
///
/// Everything but `CloseNotify` and `UserCanceled`, whatever level the sender
/// put on it — the level is advisory and the description is not.
pub fn Kind::is_fatal(self : Kind) -> Bool {
  self != CloseNotify && self != UserCanceled
}

///|
/// An alert (RFC 8446 §6).
///
/// It is also the error a handshake raises, so one value carries both the
/// reason a caller branches on and the two octets to put on the wire.
pub(all) suberror Alert {
  Alert(level~ : Level, kind~ : Kind)
} derive(Eq, Debug)

///|
pub extend Alert with Eq::{equal, not_equal}

///|
pub extend Alert with Debug::{to_repr}

///|
/// A fatal alert carrying `kind` — every way a TLS 1.3 handshake can fail.
pub fn fatal(kind : Kind) -> Alert {
  Alert(level=Fatal, kind~)
}

///|
/// A warning alert carrying `kind`: `CloseNotify` and `UserCanceled`, the two a
/// peer may act on without tearing the connection down.
pub fn warning(kind : Kind) -> Alert {
  Alert(level=Warning, kind~)
}

///|
/// The two octets an alert goes on the wire as (RFC 8446 §6).
pub fn encode(alert : Alert) -> Bytes {
  let Alert(level~, kind~) = alert
  let out = Buffer()
  out.write_byte((level.code() & 0xff).to_byte())
  out.write_byte((kind.code() & 0xff).to_byte())
  out.to_bytes()
}

///|
/// Read an alert back off the wire, or `None` if fewer than two octets are
/// there.
///
/// A level the RFC does not assign is refused rather than guessed at; an
/// unassigned description is carried through as [`Kind::Other`], because the
/// description is the diagnostic and losing it loses the message.
pub fn decode(view : BytesView) -> Alert? {
  if view.length() < 2 {
    return None
  }
  match Level::of(view[0].to_int()) {
    Some(level) => Some(Alert(level~, kind=Kind::of(view[1].to_int())))
    None => None
  }
}
