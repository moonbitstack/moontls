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

///|
/// The cookie a server answers `address` with: an HMAC-SHA-256 under the cookie key over the
/// octets the transport gave for the peer's address.
///
/// A MAC rather than a ciphertext, because the question the server asks of the second ClientHello
/// is not "what does this say" but "is this the address I answered". Nothing is kept between the
/// two — the key is the only state, and it is the same for every client.
///
/// RFC 6347 §4.2.1 gives the shape and leaves the content to the implementation; binding the
/// address is what makes the exchange worth anything against a spoofed source, and binding only
/// the address is what lets it work without a table.
fn seal(key : BytesView, address : BytesView) -> Bytes {
  @hmac.mac(key, address, fn() { @sha2.Hasher::new() })
}

///|
/// Whether `value` is the cookie this key answers `address` with.
///
/// The octets are compared in full whatever they are: a cookie is public, but a comparison that
/// stopped at the first difference would tell an attacker how much of a forged one is right.
fn accepts(key : BytesView, address : BytesView, value : BytesView) -> Bool {
  let want = seal(key, address)
  if want.length() != value.length() {
    return false
  }
  let mut diff = 0
  for i, b in want {
    diff = diff | (b.to_int() ^ value[i].to_int())
  }
  diff == 0
}
