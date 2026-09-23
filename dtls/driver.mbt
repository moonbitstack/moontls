// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The epoch a record belongs to (RFC 9147 §6.1).
///
/// Epoch 0 is unprotected: the two Hellos and the alerts that can be sent
/// before there are keys. Epoch 1 protects 0-RTT data, 2 the rest of the
/// handshake, 3 the application data — and every KeyUpdate after that takes the
/// next number, which is why the epoch is a counter and not an enumeration.
pub let plain : UInt64 = 0UL

///|
/// The epoch 0-RTT data travels in (RFC 9147 §6.1).
pub let early : UInt64 = 1UL

///|
/// The epoch the handshake is protected under, from EncryptedExtensions
/// onwards (RFC 9147 §6.1).
pub let handshake : UInt64 = 2UL

///|
/// The first application-data epoch (RFC 9147 §6.1). Each KeyUpdate moves to
/// the next.
pub let application : UInt64 = 3UL

///|
/// Which end of the handshake this is (RFC 9147 §5.7).
///
/// The two ends run different state machines and send different flights, and
/// over datagrams either end of a WebRTC connection may be the client, so both
/// are here rather than only the one a server needs.
pub(all) enum Role {
  Client
  Server
} derive(Eq, Debug)

///|
pub extend Role with Eq::{equal, not_equal}

///|
pub extend Role with Debug::{to_repr}

///|
/// Where the handshake has got to — RFC 8446 Appendix A's state machine for
/// whichever end this is.
///
/// DTLS changes how the messages travel, not which may follow which, so these
/// are `hs`'s states unchanged.
pub(all) enum State {
  Asking(@hs.Client)
  Answering(@hs.Server)
} derive(Eq, Debug)

///|
pub extend State with Eq::{equal, not_equal}

///|
pub extend State with Debug::{to_repr}

///|
/// Whether the handshake has completed.
pub fn State::connected(self : State) -> Bool {
  match self {
    Asking(state) => state == Connected
    Answering(state) => state == Connected
  }
}

///|
/// One fragment we sent, and the record that carried it (RFC 9147 §7.2).
///
/// §7.2 asks an implementation to "track which messages appear in which
/// records", because an ACK names records and what has to be retransmitted is
/// fragments. This is that mapping.
struct Carried {
  piece : Piece
  mut number : Number?
  mut acked : Bool
}

///|
/// A handshake running over datagrams (RFC 9147 §5).
///
/// It owns the three things a datagram transport forces on a handshake and
/// nothing else: message sequence numbers and fragmentation on the way out
/// (§5.2, §5.5), reassembly and ordering on the way in (§5.5), and the
/// bookkeeping that says what still has to be retransmitted and what has to be
/// acknowledged (§5.8, §7).
///
/// **There is no clock here.** §5.8's timers are a policy, and a library that
/// started one would be choosing a retransmission strategy for its caller. This
/// reports what is outstanding and what arrived; when to resend is the
/// caller's.
///
/// It owns no keys and no records either: which epoch to send in, and which
/// [`Cipher`] to seal with, belong to whoever has the connection.
pub struct Driver {
  role : Role
  mut state : State
  transcript : @keys.Transcript
  incoming : Flight
  mut sending : Int
  out : Array[Carried]
  seen : Array[Number]
  mut stalled : Bool
}

///|
/// A fresh handshake for this end.
///
/// A client starts having not yet sent its ClientHello, which is the state
/// RFC 8446 Appendix A.1 calls START and which `hs` does not name — so
/// `Asking(WaitServerHello)` is where it begins, and the ClientHello goes
/// through [`Driver::send`] like any other message.
pub fn Driver::new(
  role : Role,
  digest? : @keys.Digest = @keys.digest,
) -> Driver {
  {
    role,
    state: match role {
      Client => Asking(@hs.Client::new())
      Server => Answering(@hs.Server::new())
    },
    transcript: @keys.Transcript::new(digest~),
    incoming: Flight::new(),
    sending: 0,
    out: [],
    seen: [],
    stalled: false,
  }
}

///|
/// Which end this is.
pub fn Driver::role(self : Driver) -> Role {
  self.role
}

///|
/// Where the handshake has got to.
pub fn Driver::state(self : Driver) -> State {
  self.state
}

///|
/// Whether the handshake has completed.
pub fn Driver::connected(self : Driver) -> Bool {
  self.state.connected()
}

///|
/// The transcript hash over every message sent and received, in message order
/// (RFC 9147 §5.2).
///
/// The transcript is taken over the TLS 1.3 messages, without the message
/// sequence and fragment range DTLS wraps them in — so a handshake that was
/// fragmented and one that was not produce the same hash, which is what lets
/// the key schedule be shared with TLS unchanged.
pub fn Driver::transcript(self : Driver) -> Bytes {
  self.transcript.hash()
}

///|
/// The message sequence the next message sent will carry (RFC 9147 §5.2).
pub fn Driver::sending(self : Driver) -> Int {
  self.sending
}

// --------------------------------------------------------------- sending

///|
/// Cut a message into the fragments that will carry it, assigning its message
/// sequence and folding it into the transcript (RFC 9147 §5.2, §5.5).
///
/// `message` is the TLS 1.3 message — type, 24-bit length, body — as `msg`
/// writes one. `room` is how many octets of record payload a fragment may
/// occupy, which the caller knows from the path MTU and this does not.
///
/// The fragments are remembered until they are acknowledged, so
/// [`Driver::outstanding`] can answer a retransmission timer. Starting a new
/// flight clears what there is to acknowledge: RFC 9147 §7.1 makes a responding
/// flight an implicit acknowledgement of the one it answers.
pub fn Driver::send(
  self : Driver,
  message : BytesView,
  room~ : Int,
) -> Array[Piece] raise @alert.Alert {
  if self.out.length() == 0 {
    self.seen.clear()
    self.stalled = false
  }
  let cut = pieces(message, seq=self.sending, room~)
  self.sending = self.sending + 1
  self.transcript.add(message)
  for one in cut {
    self.out.push({ piece: one, number: None, acked: false, })
  }
  cut
}

///|
/// Say which record carried a fragment, so an ACK naming that record can retire
/// it (RFC 9147 §7.2).
///
/// A fragment whose record is never named is never retired by an ACK and will
/// be retransmitted — the safe direction, and the reason this is a separate
/// call rather than something [`Driver::send`] could guess.
pub fn Driver::sent(self : Driver, piece : Piece, number : Number) -> Unit {
  for carried in self.out {
    if carried.number is None && carried.piece == piece {
      carried.number = Some(number)
      break
    }
  }
}

///|
/// The fragments of the current flight that have not been acknowledged
/// (RFC 9147 §5.8, §7.2).
///
/// Empty means there is nothing to retransmit — either the flight was
/// acknowledged, or the peer answered it, which §7.2 makes the same thing.
pub fn Driver::outstanding(self : Driver) -> Array[Piece] {
  let out = []
  for carried in self.out {
    if !carried.acked {
      out.push(carried.piece)
    }
  }
  out
}

// -------------------------------------------------------------- receiving

///|
/// Take a fragment that arrived in record `number` (RFC 9147 §5.5, §7.1).
///
/// The return is every message this fragment completed, as a message type per
/// message — usually none or one, but a late fragment can release a run that
/// was waiting behind it. Each completed message advances the state machine and
/// goes into the transcript, in order.
///
/// Taking a fragment that is part of an answer retires our own flight:
/// RFC 9147 §7.2 makes the receipt of any record responding to a flight an
/// acknowledgement of the whole of it.
pub fn Driver::take(
  self : Driver,
  piece : Piece,
  number : Number,
) -> Array[@msg.Kind] raise @alert.Alert {
  // §7.1: a fragment that is not the next thing expected is a sign of
  // disruption, and the moment to tell the far side what did arrive.
  if piece.seq != self.incoming.next() {
    self.stalled = true
  }
  let whole = self.incoming.take(piece)
  // §7.1: ACKs cover records that were received and processed, so a fragment
  // that was dropped as a duplicate is not one of them.
  if whole.length() > 0 || self.incoming.partial() {
    if !self.seen.contains(number) {
      self.seen.push(number)
    }
  }
  if self.incoming.partial() || self.incoming.waiting() {
    self.stalled = true
  }
  let kinds = []
  for message in whole {
    guard @msg.unframe(message[:]) is Some((kind, _)) else {
      raise @alert.fatal(DecodeError)
    }
    self.transcript.add(message[:])
    self.state = match self.state {
      Asking(state) => Asking(state.recv(kind))
      Answering(state) => Answering(state.recv(kind))
    }
    kinds.push(kind)
  }
  if whole.length() > 0 {
    // §7.2: any record responding to our flight acknowledges all of it.
    self.out.clear()
    self.stalled = self.incoming.partial() || self.incoming.waiting()
  }
  kinds
}

///|
/// Take an ACK (RFC 9147 §7.2).
///
/// A fragment whose record appears in any ACK is acknowledged and will not be
/// retransmitted; the rest of the flight still will be. §7.2 is explicit that a
/// record counts as acknowledged if it appears in *any* ACK, so an ACK that
/// elides a record already named does not un-acknowledge it.
pub fn Driver::acked(self : Driver, numbers : ArrayView[Number]) -> Unit {
  for carried in self.out {
    if carried.number is Some(number) && numbers.contains(number) {
      carried.acked = true
    }
  }
}

///|
/// Whether something arrived out of order or a flight is half here — which
/// RFC 9147 §7.1 calls a disruption and makes the moment to send an ACK.
pub fn Driver::stalled(self : Driver) -> Bool {
  self.stalled
}

///|
/// The record numbers to acknowledge: the handshake records received and
/// processed from the flight arriving now (RFC 9147 §7.1).
///
/// It may be empty, and an empty ACK is worth sending: §7.1 gives the case of a
/// client that has EncryptedExtensions it cannot yet decrypt, where saying "I
/// have nothing from you" is what stops the server waiting out a full
/// retransmission timer.
pub fn Driver::ack(self : Driver) -> Array[Number] {
  let out = self.seen.copy()
  out.sort()
  out
}

// ------------------------------------------------------------- sent flight

///|
/// Advance a server past its own flight, waiting for a client certificate when
/// one was asked for (RFC 8446 Appendix A.2).
///
/// A client has no equivalent: its flight ends the handshake, and Appendix A.1
/// leaves it in `Connected` on the server's Finished.
pub fn Driver::sent_flight(
  self : Driver,
  client_cert? : Bool = false,
) -> Unit raise @alert.Alert {
  self.state = match self.state {
    Answering(state) => Answering(state.sent_flight(client_cert~))
    Asking(_) => raise @alert.fatal(InternalError)
  }
}
