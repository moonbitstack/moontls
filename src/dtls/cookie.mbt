// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How a DTLS server answers a ClientHello before it has decided to keep any
/// state for it (RFC 9147 §4.2, RFC 6347 §4.2.1).
///
/// A datagram server is exposed to source-address spoofing: an attacker can
/// name a victim's address and make the server send a whole flight there. A
/// cookie is the answer — the server puts a stateless, keyed value in its first
/// answer, and only continues for a ClientHello that echoes it back, which a
/// spoofer cannot do because it never sees the reply.
///
/// `Off` is what a caller behind a trusted path may choose; `Key` is the safe
/// default and keeps nothing between the two ClientHellos.
#derive(Eq, Debug)
pub(all) enum Cookie {
  /// No cookie exchange: every ClientHello is answered at once.
  Off
  /// A cookie sealed under this key, which the server derives nothing else
  /// from. The key never leaves the server.
  Key(Bytes)
}

///|
pub extend Cookie with Eq::{equal, not_equal}

///|
pub extend Cookie with Debug::{to_repr}
