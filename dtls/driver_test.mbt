// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A record number, short enough to write inline.
fn at(epoch : UInt64, seq : UInt64) -> @dtls.Number {
  { epoch, seq, }
}

///|
/// `n` octets counting up, so a fragment's offset is visible in its content.
fn filler(n : Int) -> Bytes {
  let out = Buffer()
  for i = 0; i < n; i = i + 1 {
    out.write_byte((i & 0xff).to_byte())
  }
  out.to_bytes()
}

///|
/// Hand every fragment of `message` from one driver to the other, in order,
/// each in its own record. Answers what the far side made of them.
fn deliver(
  from : @dtls.Driver,
  to : @dtls.Driver,
  message : Bytes,
  room~ : Int,
  epoch~ : UInt64,
  first~ : UInt64,
) -> Array[@msg.Kind] raise {
  let kinds = []
  let cut = from.send(message[:], room~)
  for i, piece in cut {
    let number = at(epoch, first + i.to_uint64())
    from.sent(piece, number)
    for kind in to.take(piece, number) {
      kinds.push(kind)
    }
  }
  kinds
}

///|
/// RFC 9147 §5.2: the message sequence counts messages, not fragments, and is
/// not reset once the handshake is over.
test "the message sequence counts messages and not fragments" {
  let client = @dtls.Driver::new(Client)
  assert_eq(client.sending(), 0)
  let hello = @msg.frame(ClientHello, filler(300)[:])
  let cut = client.send(hello[:], room=100)
  assert_eq(cut.length(), 4)
  for piece in cut {
    assert_eq(piece.seq, 0)
  }
  assert_eq(client.sending(), 1)
  client.send(@msg.frame(Finished, filler(4)[:])[:], room=100) |> ignore
  assert_eq(client.sending(), 2)
}

///|
/// The whole main handshake, both ends driven, every message fragmented — the
/// transcripts have to come out equal or the key schedules diverge.
test "a full handshake runs both ends to Connected" {
  let client = @dtls.Driver::new(Client)
  let server = @dtls.Driver::new(Server)
  let room = 60
  // Flight 1: the client's Hello.
  let hello = @msg.frame(ClientHello, filler(192)[:])
  assert_eq(deliver(client, server, hello, room~, epoch=0UL, first=0UL), [
    ClientHello,
  ])
  assert_eq(server.state(), Answering(RecvdClientHello))
  // Flight 2: the server's, in the order RFC 8446 §4 sends them.
  let sh = @msg.frame(ServerHello, filler(90)[:])
  assert_eq(deliver(server, client, sh, room~, epoch=0UL, first=0UL), [
    ServerHello,
  ])
  let ee = @msg.frame(EncryptedExtensions, filler(20)[:])
  assert_eq(deliver(server, client, ee, room~, epoch=2UL, first=0UL), [
    EncryptedExtensions,
  ])
  let cert = @msg.frame(Certificate, filler(400)[:])
  assert_eq(deliver(server, client, cert, room~, epoch=2UL, first=1UL), [
    Certificate,
  ])
  let cv = @msg.frame(CertificateVerify, filler(70)[:])
  assert_eq(deliver(server, client, cv, room~, epoch=2UL, first=10UL), [
    CertificateVerify,
  ])
  let sfin = @msg.frame(Finished, filler(32)[:])
  assert_eq(deliver(server, client, sfin, room~, epoch=2UL, first=11UL), [
    Finished,
  ])
  assert_true(client.connected())
  server.sent_flight()
  assert_eq(server.state(), Answering(WaitFinished))
  // Flight 3: the client's Finished.
  let cfin = @msg.frame(Finished, filler(32)[:])
  assert_eq(deliver(client, server, cfin, room~, epoch=2UL, first=1UL), [
    Finished,
  ])
  assert_true(server.connected())
  // Both ends hashed the same messages in the same order.
  assert_eq(client.transcript(), server.transcript())
}

///|
/// RFC 9147 §7.2: the receipt of any record responding to a flight is an
/// acknowledgement of the whole flight.
test "the peer's answer retires our flight" {
  let client = @dtls.Driver::new(Client)
  let server = @dtls.Driver::new(Server)
  let hello = @msg.frame(ClientHello, filler(192)[:])
  deliver(client, server, hello, room=60, epoch=0UL, first=0UL) |> ignore
  // Nothing has acknowledged it yet, so all of it would be retransmitted.
  assert_eq(client.outstanding().length(), 4)
  let sh = @msg.frame(ServerHello, filler(20)[:])
  deliver(server, client, sh, room=200, epoch=0UL, first=0UL) |> ignore
  // The answer arrived, so there is nothing left to retransmit.
  assert_eq(client.outstanding().length(), 0)
}

///|
/// §7.2 again: an ACK retires the fragments it names and leaves the rest to be
/// retransmitted.
test "an ACK retires the fragments it names" {
  let client = @dtls.Driver::new(Client)
  let hello = @msg.frame(ClientHello, filler(192)[:])
  let cut = client.send(hello[:], room=60)
  assert_eq(cut.length(), 4)
  for i, piece in cut {
    client.sent(piece, at(0UL, i.to_uint64()))
  }
  assert_eq(client.outstanding().length(), 4)
  // The first and third records arrived.
  client.acked([at(0UL, 0UL), at(0UL, 2UL)][:])
  let left = client.outstanding()
  assert_eq(left.length(), 2)
  assert_eq(left[0].at, cut[1].at)
  assert_eq(left[1].at, cut[3].at)
  // §7.2: a record counts as acknowledged if it appears in any ACK, so a later
  // ACK that elides it does not bring it back.
  client.acked([at(0UL, 1UL)][:])
  assert_eq(client.outstanding().length(), 1)
  client.acked([at(0UL, 3UL)][:])
  assert_eq(client.outstanding().length(), 0)
}

///|
/// A fragment whose record was never named cannot be retired by an ACK, and
/// stays outstanding — the safe direction.
test "a fragment with no record number is never acknowledged" {
  let client = @dtls.Driver::new(Client)
  let cut = client.send(@msg.frame(ClientHello, filler(192)[:])[:], room=60)
  client.sent(cut[0], at(0UL, 0UL))
  client.acked([at(0UL, 0UL), at(0UL, 1UL), at(0UL, 2UL), at(0UL, 3UL)][:])
  assert_eq(client.outstanding().length(), 3)
}

///|
/// RFC 9147 §7.1: a fragment that is not the next thing expected is a sign of
/// disruption, and the moment to send an ACK naming what did arrive.
test "an out-of-order fragment is a disruption worth acknowledging" {
  let server = @dtls.Driver::new(Server)
  let client = @dtls.Driver::new(Client)
  let hello = @msg.frame(ClientHello, filler(192)[:])
  let cut = client.send(hello[:], room=60)
  assert_false(server.stalled())
  // The second fragment arrives first.
  server.take(cut[1], at(0UL, 1UL)) |> ignore
  assert_true(server.stalled())
  assert_eq(server.ack(), [at(0UL, 1UL)])
  // The rest fill in; once the message is whole there is nothing outstanding.
  server.take(cut[0], at(0UL, 0UL)) |> ignore
  server.take(cut[2], at(0UL, 2UL)) |> ignore
  let done = server.take(cut[3], at(0UL, 3UL))
  assert_eq(done, [ClientHello])
  assert_false(server.stalled())
  assert_eq(server.ack().length(), 4)
}

///|
/// §7.1: ACKs cover records received *and processed*, so a duplicate — which is
/// processed by being dropped — does not enter the list twice.
test "a duplicate fragment is not acknowledged twice" {
  let server = @dtls.Driver::new(Server)
  let client = @dtls.Driver::new(Client)
  let cut = client.send(@msg.frame(ClientHello, filler(40)[:])[:], room=200)
  assert_eq(cut.length(), 1)
  assert_eq(server.take(cut[0], at(0UL, 0UL)), [ClientHello])
  assert_eq(server.ack(), [at(0UL, 0UL)])
  // The same fragment again, in a different record: nothing new was processed.
  assert_eq(server.take(cut[0], at(0UL, 7UL)), [])
  assert_eq(server.ack(), [at(0UL, 0UL)])
}

///|
/// §7.1: sending a flight of our own implicitly acknowledges the one it
/// answers, so the list starts again.
test "sending a flight clears what there was to acknowledge" {
  let server = @dtls.Driver::new(Server)
  let client = @dtls.Driver::new(Client)
  let cut = client.send(@msg.frame(ClientHello, filler(40)[:])[:], room=200)
  server.take(cut[0], at(0UL, 0UL)) |> ignore
  assert_eq(server.ack().length(), 1)
  server.send(@msg.frame(ServerHello, filler(20)[:])[:], room=200) |> ignore
  assert_eq(server.ack().length(), 0)
}

///|
/// §7.1: an ACK naming nothing is worth sending — a client holding
/// EncryptedExtensions it cannot decrypt says "I have nothing from you" rather
/// than letting the server wait out a retransmission timer.
test "an empty acknowledgement is a legitimate answer" {
  let driver = @dtls.Driver::new(Client)
  assert_eq(driver.ack(), [])
  assert_eq(@dtls.ack(driver.ack()[:]).length(), 2)
}

///|
/// A message that arrives before the one in front of it is held, and the state
/// machine is not advanced out of order.
test "a message is held until the one before it arrives" {
  let client = @dtls.Driver::new(Client)
  let server = @dtls.Driver::new(Server)
  let sh = server.send(@msg.frame(ServerHello, filler(20)[:])[:], room=200)
  let ee = server.send(
    @msg.frame(EncryptedExtensions, filler(20)[:])[:],
    room=200,
  )
  // EncryptedExtensions first: whole, but not deliverable.
  assert_eq(client.take(ee[0], at(2UL, 0UL)), [])
  assert_true(client.stalled())
  assert_eq(client.state(), Asking(WaitServerHello))
  // The ServerHello releases both, in order.
  assert_eq(client.take(sh[0], at(0UL, 0UL)), [ServerHello, EncryptedExtensions])
  assert_eq(client.state(), Asking(WaitCertOrRequest))
  assert_false(client.stalled())
}

///|
/// A message out of the order Appendix A allows is `UnexpectedMessage`, over
/// datagrams as over a stream.
test "a message that does not belong is refused" {
  let client = @dtls.Driver::new(Client)
  let server = @dtls.Driver::new(Server)
  let fin = server.send(@msg.frame(Finished, filler(32)[:])[:], room=200)
  assert_true(refused(() => client.take(fin[0], at(2UL, 0UL)) |> ignore))
}

///|
/// `sent_flight` is the server's move. A client has no flight to be waiting
/// past: Appendix A.1 leaves it Connected on the server's Finished.
test "only a server advances past its own flight" {
  let client = @dtls.Driver::new(Client)
  assert_true(refused(() => client.sent_flight()))
  let server = @dtls.Driver::new(Server)
  assert_eq(server.role(), Server)
  assert_eq(client.role(), Client)
}

///|
/// RFC 9147 §6.1 numbers the epochs, and they are numbers rather than an
/// enumeration because every KeyUpdate takes the next one.
test "the epochs are the numbers §6.1 gives them" {
  assert_eq(@dtls.plain, 0UL)
  assert_eq(@dtls.early, 1UL)
  assert_eq(@dtls.handshake, 2UL)
  assert_eq(@dtls.application, 3UL)
}

///|
/// §5.2: the transcript is taken over the TLS messages without the sequence and
/// fragment range, so how a message was cut cannot change the keys.
test "the transcript does not depend on how the messages were cut" {
  let whole = @dtls.Driver::new(Client)
  let cut = @dtls.Driver::new(Client)
  let hello = @msg.frame(ClientHello, filler(300)[:])
  whole.send(hello[:], room=4096) |> ignore
  cut.send(hello[:], room=30) |> ignore
  assert_eq(whole.transcript(), cut.transcript())
}
