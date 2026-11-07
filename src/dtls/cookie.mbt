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

// ------------------------------------------------------------ DTLS 1.3's cookie

///|
/// The octets a MAC occupies in a DTLS 1.3 cookie: half a SHA-256 digest, which leaves the rest of
/// the cookie for what the server has to remember without keeping it.
let mac_size : Int32 = 16

///|
/// What a DTLS 1.3 cookie has to carry so that the server can keep nothing (RFC 9147 §5.1).
///
/// The retry's transcript is `message_hash(first ClientHello)` followed by the retry itself
/// (RFC 8446 §4.4.1). An instance that never saw the first ClientHello cannot compute that hash,
/// so the cookie carries it, and carries the group the retry asked for so the retry can be written
/// again octet for octet — the transcript covers it too.
///
/// ```text
///   +------------------+------------------------+-------------+
///   | MAC over the two | hash(first ClientHello) | group, or 0 |
///   +------------------+------------------------+-------------+
/// ```
///
/// The hash is as long as the suite's digest, which the cookie's own length tells a reader.
///
/// The MAC is over the address *and* what follows it, so neither can be swapped for something the
/// server did not say.
pub fn seal13(
  key : BytesView,
  address : BytesView,
  history : BytesView,
  group : Int32?,
) -> Bytes {
  let tail = Buffer()
  tail.write_bytes(history)
  @wire.u16(tail, group.unwrap_or(0))
  let tail = tail.to_bytes()
  let body = Buffer()
  body.write_bytes(address)
  body.write_bytes(tail)
  let mac = @hmac.mac(key, body.to_bytes()[:], fn() { @sha2.Hasher::new() })
  let out = Buffer()
  out.write_bytes(mac[0:mac_size])
  out.write_bytes(tail)
  out.to_bytes()
}

///|
/// What a ClientHello's cookie stands for — the hash of the first ClientHello, and the group the
/// retry asked for — or `None` when this server did not give it, or gave it to another address.
pub fn open13(
  key : BytesView,
  address : BytesView,
  cookie : BytesView,
) -> (Bytes, Int32?)? {
  if cookie.length() < mac_size + 2 + 32 {
    return None
  }
  let body = Buffer()
  body.write_bytes(address)
  body.write_bytesview(cookie[mac_size:])
  let want = @hmac.mac(key, body.to_bytes()[:], fn() { @sha2.Hasher::new() })
  let mut diff = 0
  for i = 0; i < mac_size; i = i + 1 {
    diff = diff | (want[i].to_int() ^ cookie[i].to_int())
  }
  if diff != 0 {
    return None
  }
  let end = cookie.length() - 2
  let history = cookie[mac_size:end].to_owned()
  let code = @wire.read_u16(cookie, end)
  Some((history, if code == 0 { None } else { Some(code) }))
}
