// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A TLS 1.3 handshake message: type, 24-bit length, body.
fn message(kind : Int, body : Bytes) -> Bytes {
  let out = Buffer()
  out.write_byte(kind.to_byte())
  out.write_byte(((body.length() >> 16) & 0xff).to_byte())
  out.write_byte(((body.length() >> 8) & 0xff).to_byte())
  out.write_byte((body.length() & 0xff).to_byte())
  out.write_bytes(body)
  out.to_bytes()
}

///|
/// `n` octets counting up, so a fragment's offset is visible in its content.
fn ramp(n : Int) -> Bytes {
  let out = Buffer()
  for i = 0; i < n; i = i + 1 {
    out.write_byte((i & 0xff).to_byte())
  }
  out.to_bytes()
}

///|
/// RFC 9147 §5.2: the DTLSHandshake header is the TLS one plus a message
/// sequence and this fragment's range — twelve octets against TLS's four.
test "a fragment's header is the twelve octets RFC 9147 §5.2 describes" {
  let wire = @dtls.piece({
    kind: 1,
    total: 0x010203,
    seq: 0x0405,
    at: 0x000708,
    body: b"\xaa\xbb",
  })
  assert_eq(@base16.encode(wire), "010102030405000708000002aabb")
  guard @dtls.read_piece(wire[:]) is Some((back, used)) else {
    fail("a whole fragment did not read back")
  }
  assert_eq(used, wire.length())
  assert_eq(back.kind, 1)
  assert_eq(back.total, 0x010203)
  assert_eq(back.seq, 0x0405)
  assert_eq(back.at, 0x000708)
  assert_eq(back.body, b"\xaa\xbb")
}

///|
test "a message that fits travels as one fragment" {
  let msg = message(20, b"verify data")
  let cut = @dtls.pieces(msg[:], seq=0, room=200)
  assert_eq(cut.length(), 1)
  assert_eq(cut[0].at, 0)
  assert_eq(cut[0].total, 11)
  assert_eq(cut[0].body, b"verify data")
}

///|
test "a message too big for one record is cut to fit" {
  let msg = message(11, ramp(300))
  // 12 octets of header leave 88 of each 100-octet record for the body.
  let cut = @dtls.pieces(msg[:], seq=3, room=100)
  assert_eq(cut.length(), 4)
  let mut at = 0
  for piece in cut {
    assert_eq(piece.kind, 11)
    assert_eq(piece.total, 300)
    assert_eq(piece.seq, 3)
    assert_eq(piece.at, at)
    assert_true(piece.body.length() <= 88)
    at = at + piece.body.length()
  }
  assert_eq(at, 300)
}

///|
/// An EndOfEarlyData has no body, and a message with no body still has to be
/// sent — as one fragment of nothing.
test "an empty message is one empty fragment" {
  let cut = @dtls.pieces(message(5, b"")[:], seq=1, room=100)
  assert_eq(cut.length(), 1)
  assert_eq(cut[0].total, 0)
  assert_eq(cut[0].body, b"")
}

///|
test "fragments reassemble into the message they were cut from" {
  let msg = message(11, ramp(300))
  let flight = @dtls.Flight::new()
  let cut = @dtls.pieces(msg[:], seq=0, room=100)
  let out = []
  for piece in cut {
    for whole in flight.take(piece) {
      out.push(whole)
    }
  }
  assert_eq(out.length(), 1)
  assert_eq(out[0], msg)
  assert_false(flight.partial())
  assert_eq(flight.next(), 1)
}

///|
/// Datagrams reorder, so fragments do. The message comes out whole and in one
/// piece whatever order its parts arrive in.
test "fragments arriving backwards still reassemble" {
  let msg = message(11, ramp(300))
  let flight = @dtls.Flight::new()
  let cut = @dtls.pieces(msg[:], seq=0, room=100)
  let backwards = cut.rev()
  let out = []
  for piece in backwards {
    for whole in flight.take(piece) {
      out.push(whole)
    }
  }
  assert_eq(out.length(), 1)
  assert_eq(out[0], msg)
}

///|
/// A retransmission may cut the message differently from the first attempt
/// (RFC 9147 §5.5), so the pieces overlap. Overlap is not a duplicate and not
/// an error.
test "overlapping fragments from a recut retransmission reassemble" {
  let msg = message(11, ramp(300))
  let flight = @dtls.Flight::new()
  let first = @dtls.pieces(msg[:], seq=0, room=100)
  let again = @dtls.pieces(msg[:], seq=0, room=60)
  let out = []
  // The first attempt loses everything but its opening fragment; the recut
  // retransmission fills the rest, overlapping what arrived.
  for whole in flight.take(first[0]) {
    out.push(whole)
  }
  for piece in again {
    for whole in flight.take(piece) {
      out.push(whole)
    }
  }
  assert_eq(out.length(), 1)
  assert_eq(out[0], msg)
}

///|
/// A handshake cannot process message 3 before message 2: the transcript is
/// ordered even though the transport is not.
test "a message is held until every message before it is whole" {
  let flight = @dtls.Flight::new()
  let second = message(8, b"encrypted extensions")
  let third = message(11, b"certificate")
  // Messages 1 and 2 arrive; message 0 has not.
  assert_eq(flight.take(@dtls.pieces(second[:], seq=1, room=99)[0]).length(), 0)
  assert_eq(flight.take(@dtls.pieces(third[:], seq=2, room=99)[0]).length(), 0)
  assert_eq(flight.next(), 0)
  // Message 0 arrives and releases all three, in order.
  let first = message(2, b"server hello")
  let out = flight.take(@dtls.pieces(first[:], seq=0, room=99)[0])
  assert_eq(out.length(), 3)
  assert_eq(out[0], first)
  assert_eq(out[1], second)
  assert_eq(out[2], third)
  assert_eq(flight.next(), 3)
}

///|
/// A retransmission that crossed with the ACK is ordinary: the fragment is
/// dropped, not refused, and the message is not delivered twice.
test "a fragment of an already delivered message is dropped" {
  let flight = @dtls.Flight::new()
  let msg = message(2, b"server hello")
  let piece = @dtls.pieces(msg[:], seq=0, room=99)[0]
  assert_eq(flight.take(piece).length(), 1)
  assert_eq(flight.take(piece).length(), 0)
  assert_eq(flight.take(piece).length(), 0)
}

///|
/// Two fragments claiming different things about the same message cannot both
/// be right, and reassembling them would produce a message neither peer sent.
test "fragments that disagree about their message are refused" {
  let flight = @dtls.Flight::new()
  let a : @dtls.Piece = {
    kind: 11,
    total: 40,
    seq: 0,
    at: 0,
    body: b"\x01\x02",
  }
  let b : @dtls.Piece = {
    kind: 11,
    total: 90,
    seq: 0,
    at: 0,
    body: b"\x01\x02",
  }
  let c : @dtls.Piece = {
    kind: 13,
    total: 40,
    seq: 0,
    at: 0,
    body: b"\x01\x02",
  }
  flight.take(a) |> ignore
  assert_true(refused(() => flight.take(b) |> ignore))
  assert_true(refused(() => flight.take(c) |> ignore))
}

///|
/// A fragment claiming to run past the end of its own message is malformed,
/// and RFC 9147 §5.5 has nothing to do with it.
test "a fragment past the end of its message is refused" {
  let over : @dtls.Piece = {
    kind: 11,
    total: 4,
    seq: 0,
    at: 3,
    body: b"\x01\x02\x03",
  }
  assert_true(refused(() => @dtls.piece(over) |> ignore))
  let flight = @dtls.Flight::new()
  assert_true(refused(() => flight.take(over) |> ignore))
}

///|
/// A half-reassembled message is what RFC 9147 §7.1 calls a disruption, and the
/// moment to tell the far side what did arrive.
test "a partly arrived message shows as a disruption" {
  let flight = @dtls.Flight::new()
  let cut = @dtls.pieces(message(11, ramp(300))[:], seq=0, room=100)
  assert_false(flight.partial())
  flight.take(cut[0]) |> ignore
  assert_true(flight.partial())
  for i = 1; i < cut.length(); i = i + 1 {
    flight.take(cut[i]) |> ignore
  }
  assert_false(flight.partial())
}

///|
/// Post-handshake messages continue the sequence rather than restarting it
/// (RFC 9147 §5.2), so a flight can be started part-way through.
test "a flight can start part-way through the sequence" {
  let flight = @dtls.Flight::new(from=7)
  assert_eq(flight.next(), 7)
  let msg = message(24, b"key update")
  assert_eq(flight.take(@dtls.pieces(msg[:], seq=7, room=99)[0]).length(), 1)
  assert_eq(flight.next(), 8)
}

///|
test "an ACK round-trips and sorts its record numbers" {
  let numbers : Array[@dtls.Number] = [
    { epoch: 3UL, seq: 1UL, },
    { epoch: 2UL, seq: 9UL, },
    { epoch: 3UL, seq: 0UL, },
  ]
  let wire = @dtls.ack(numbers[:])
  assert_eq(wire.length(), 2 + 3 * 16)
  guard @dtls.read_ack(wire[:]) is Some(back) else {
    fail("a whole ACK did not read back")
  }
  assert_eq(back.length(), 3)
  assert_eq(back[0], { epoch: 2UL, seq: 9UL, })
  assert_eq(back[1], { epoch: 3UL, seq: 0UL, })
  assert_eq(back[2], { epoch: 3UL, seq: 1UL, })
}

///|
test "an empty ACK is a list of nothing, not a malformed one" {
  let wire = @dtls.ack([][:])
  assert_eq(@base16.encode(wire), "0000")
  guard @dtls.read_ack(wire[:]) is Some(back) else {
    fail("a whole ACK did not read back")
  }
  assert_eq(back.length(), 0)
}

///|
/// A record number is sixteen octets, so a payload that does not divide into
/// sixteen is not a list of them.
test "a truncated or ragged ACK is refused" {
  assert_eq(@dtls.read_ack(b""[:]), None)
  assert_eq(@dtls.read_ack(b"\x00"[:]), None)
  assert_eq(@dtls.read_ack(b"\x00\x10"[:]), None)
  assert_eq(
    @dtls.read_ack(b"\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01"[:]),
    None,
  )
}
