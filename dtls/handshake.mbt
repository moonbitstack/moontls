// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The DTLSHandshake header (RFC 9147 §5.2): type, a 24-bit length, a 16-bit
/// message sequence, and the 24-bit offset and length of this fragment.
pub let handshake_header : Int = 12

///|
/// The TLS 1.3 Handshake header the transcript is taken over: type and a
/// 24-bit length (RFC 8446 §4).
pub let tls_header : Int = 4

///|
/// One fragment of a handshake message as it travels (RFC 9147 §5.2).
///
/// `body` is this fragment's octets, not the whole message; `total` is how long
/// the whole message is. A message small enough to fit one record still travels
/// as a fragment — offset zero, fragment length equal to total — which is why
/// there is no separate unfragmented shape.
pub(all) struct Piece {
  kind : Int
  total : Int
  seq : Int
  at : Int
  body : Bytes
} derive(Eq, Debug)

///|
pub extend Piece with Eq::{equal, not_equal}

///|
pub extend Piece with Debug::{to_repr}

///|
/// Write one fragment with its DTLSHandshake header (RFC 9147 §5.2).
pub fn piece(fragment : Piece) -> Bytes raise @alert.Alert {
  if fragment.at + fragment.body.length() > fragment.total {
    raise @alert.fatal(InternalError)
  }
  let out = Buffer()
  out.write_byte((fragment.kind & 0xff).to_byte())
  @wire.u24(out, fragment.total)
  @wire.u16(out, fragment.seq)
  @wire.u24(out, fragment.at)
  @wire.u24(out, fragment.body.length())
  out.write_bytes(fragment.body)
  out.to_bytes()
}

///|
/// Read one fragment and how many octets it took, or `None` while the view is
/// short of a whole one.
pub fn read_piece(view : BytesView) -> (Piece, Int)? raise @alert.Alert {
  if view.length() < handshake_header {
    return None
  }
  let total = @wire.read_u24(view, 1)
  let at = @wire.read_u24(view, 6)
  let len = @wire.read_u24(view, 9)
  if at + len > total {
    raise @alert.fatal(DecodeError)
  }
  let end = handshake_header + len
  if view.length() < end {
    return None
  }
  Some(
    (
      {
        kind: view[0].to_int(),
        total,
        seq: @wire.read_u16(view, 4),
        at,
        body: view[handshake_header:end].to_owned(),
      },
      end,
    ),
  )
}

///|
/// Cut a whole TLS-style handshake message into fragments that each fit `room`
/// octets of record payload (RFC 9147 §5.5).
///
/// `message` is the message as TLS 1.3 writes it — type, 24-bit length, body —
/// because that is the form the transcript is taken over and the form the rest
/// of this library produces. `room` is what is left of the datagram after the
/// record header and the AEAD tag; the caller knows the path MTU, this does
/// not.
///
/// A message is never cut into a fragment with no body: a zero-length fragment
/// of a non-empty message tells a receiver nothing and RFC 9147 §5.5 has no use
/// for one. An empty message — a Finished with no verify_data cannot happen,
/// but an EndOfEarlyData can — still produces exactly one fragment.
pub fn pieces(
  message : BytesView,
  seq~ : Int,
  room~ : Int,
) -> Array[Piece] raise @alert.Alert {
  if message.length() < tls_header {
    raise @alert.fatal(InternalError)
  }
  let kind = message[0].to_int()
  let total = @wire.read_u24(message, 1)
  if total != message.length() - tls_header {
    raise @alert.fatal(InternalError)
  }
  let body = message[tls_header:]
  let each = room - handshake_header
  if each < 1 {
    raise @alert.fatal(InternalError)
  }
  let out = []
  if total == 0 {
    out.push({ kind, total, seq, at: 0, body: b"", })
    return out
  }
  let mut at = 0
  while at < total {
    let take = if total - at < each { total - at } else { each }
    out.push({ kind, total, seq, at, body: body[at:at + take].to_owned(), })
    at = at + take
  }
  out
}

///|
/// A message being put back together from fragments (RFC 9147 §5.5).
///
/// Fragments may arrive out of order, more than once, and overlapping — a
/// retransmission is free to cut the message differently from the first
/// attempt. So this keeps the octets and a map of which are filled rather than
/// a count.
struct Partial {
  kind : Int
  total : Int
  body : FixedArray[Byte]
  filled : FixedArray[Bool]
  mut have : Int
}

///|
/// Fragments reassembled into whole messages, in message-sequence order
/// (RFC 9147 §5.5).
///
/// A flight arrives in pieces, out of order, with duplicates. This takes
/// fragments as they come and hands back messages only when they are complete
/// and only when every message before them is complete — a handshake cannot
/// process message 3 before message 2, and the transcript would be wrong if it
/// tried.
pub struct Flight {
  parts : Map[Int, Partial]
  done : Map[Int, Bytes]
  mut next : Int
}

///|
/// An empty flight expecting message sequence `from` next.
///
/// `from` is not always zero: a post-handshake message continues the sequence
/// the handshake left off at, because RFC 9147 §5.2 never resets it.
pub fn Flight::new(from? : Int = 0) -> Flight {
  { parts: {}, done: {}, next: from, }
}

///|
/// The message sequence this flight is waiting for.
pub fn Flight::next(self : Flight) -> Int {
  self.next
}

///|
/// Take one fragment (RFC 9147 §5.5).
///
/// The return is every message that this fragment completed, in sequence order
/// — usually none or one, but a late fragment can release a run of messages
/// that were waiting behind it. Each is a whole TLS 1.3 handshake message, type
/// and 24-bit length included, ready for the transcript.
///
/// A fragment of a message already delivered is dropped rather than refused: a
/// retransmission that crossed with the ACK is ordinary, not an error.
pub fn Flight::take(
  self : Flight,
  fragment : Piece,
) -> Array[Bytes] raise @alert.Alert {
  let out = []
  if fragment.seq < self.next {
    return out
  }
  if self.done.contains(fragment.seq) {
    return out
  }
  if fragment.at + fragment.body.length() > fragment.total {
    raise @alert.fatal(DecodeError)
  }
  let part = match self.parts.get(fragment.seq) {
    Some(part) => {
      // §5.5: the two halves of one message must agree about what it is. They
      // disagree only if a fragment was forged or the peer is confused, and
      // either way the message cannot be reassembled.
      if part.kind != fragment.kind || part.total != fragment.total {
        raise @alert.fatal(DecodeError)
      }
      part
    }
    None => {
      let part = {
        kind: fragment.kind,
        total: fragment.total,
        body: FixedArray::make(fragment.total, b'\x00'),
        filled: FixedArray::make(fragment.total, false),
        have: 0,
      }
      self.parts[fragment.seq] = part
      part
    }
  }
  for i = 0; i < fragment.body.length(); i = i + 1 {
    let at = fragment.at + i
    if !part.filled[at] {
      part.filled[at] = true
      part.body[at] = fragment.body[i]
      part.have = part.have + 1
    }
  }
  if part.have == part.total {
    let whole = Buffer()
    whole.write_byte((part.kind & 0xff).to_byte())
    @wire.u24(whole, part.total)
    for i = 0; i < part.total; i = i + 1 {
      whole.write_byte(part.body[i])
    }
    self.done[fragment.seq] = whole.to_bytes()
    self.parts.remove(fragment.seq)
  }
  while self.done.get(self.next) is Some(message) {
    out.push(message)
    self.done.remove(self.next)
    self.next = self.next + 1
  }
  out
}

///|
/// Whether anything is half-reassembled — which is what RFC 9147 §7.1 calls a
/// disruption in the incoming flight, and the moment to send an ACK.
pub fn Flight::partial(self : Flight) -> Bool {
  self.parts.length() > 0
}

///|
/// Whether a message is whole but cannot be delivered yet because one before it
/// has not arrived — the other shape of RFC 9147 §7.1's disruption.
pub fn Flight::waiting(self : Flight) -> Bool {
  self.done.length() > 0
}
