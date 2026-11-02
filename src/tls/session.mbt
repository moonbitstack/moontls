// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Session resumption's bookkeeping: what a client keeps to come back with, what a server keeps to
// recognise it, and the ticket keys a server seals its own state under.
//
// A ticket is the server's state encrypted under a key only the server has, so a resumption needs
// no storage on the server at all — the client carries the state back. A session id is the older
// arrangement, where the server keeps the state and hands out a name for it; TLS 1.2 needs both,
// TLS 1.3 has only tickets.

///|
/// How a stored session comes back: as a TLS 1.3 PSK, as a TLS 1.2 session id the server looks up,
/// or as a TLS 1.2 ticket the server reads itself (RFC 5077).
pub(all) enum Kind {
  Psk
  Id
  Ticket
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// A connection worth resuming: the client's memory of one, or the server's record of a session id
/// it issued.
///
/// `ticket` is what goes back on the wire — a TLS 1.3 ticket, a TLS 1.2 session id or ticket — and
/// `secret` is what makes it worth anything: the PSK a TLS 1.3 ticket stands for, or a TLS 1.2
/// master secret.
pub(all) struct Session {
  host : String
  version : Version
  kind : Kind
  /// The suite's code on the wire.
  suite : Int32
  ticket : Bytes
  secret : Bytes
  /// How long it may be used for, in seconds from `born`.
  lifetime : Int64
  /// When it was issued, in seconds since the Unix epoch.
  born : Int64
  /// The most 0-RTT data a TLS 1.3 server will take under it; zero for none.
  early : Int32
  /// The ticket's `ticket_age_add` (RFC 8446 §4.6.1), which keeps a client's clock its own.
  age_add : Int32
} derive(Eq, Debug)

///|
pub extend Session with Eq::{equal, not_equal}

///|
pub extend Session with Debug::{to_repr}

///|
/// How many sessions one store keeps for one host: enough for a client that reconnects a few times
/// while a server rotates its keys, and few enough that a store cannot grow without bound.
pub let session_limit : Int32 = 8

///|
/// The sessions a client may resume, or a server's cache of the session ids it issued.
///
/// One store is meant to outlive a connection: hand the same one to every `Conn::client` and every
/// `Conn::server`, and a second connection finds what the first left. `now` is the clock a session
/// is judged against, since a store has none of its own.
pub struct Sessions {
  limit : Int32
  entries : Array[Session]
}

///|
/// An empty store.
pub fn Sessions::new(limit~ : Int32 = session_limit) -> Sessions {
  { limit, entries: [], }
}

///|
/// Remember a session, newest first, dropping the ones for the same ticket and the ones that have
/// run out, and keeping at most `limit` for each host.
pub fn Sessions::put(self : Sessions, session : Session) -> Unit {
  let kept : Array[Session] = []
  for one in self.entries {
    if one.host != session.host || one.ticket != session.ticket {
      kept.push(one)
    }
  }
  kept.push(session)
  let ordered = kept.rev()
  let out : Array[Session] = []
  let counts : Map[String, Int32] = Map([])
  for one in ordered {
    let seen = counts.get(one.host).unwrap_or(0)
    if seen < self.limit {
      out.push(one)
      counts[one.host] = seen + 1
    }
  }
  self.entries.clear()
  for one in out {
    self.entries.push(one)
  }
}

///|
/// The newest session for `host` of `version` that has not run out, if there is one.
pub fn Sessions::get(
  self : Sessions,
  host~ : String,
  version~ : Version,
  now~ : Int64,
) -> Session? {
  self.entries
  .iter()
  .find_first(s => {
    s.host == host &&
    s.version == version &&
    now - s.born <= s.lifetime &&
    now >= s.born
  })
}

///|
/// The session a ticket or session id names, whatever host it was filed under: what a server looks
/// a name up by, and what a client uses to find the state behind an identity it kept.
pub fn Sessions::find(self : Sessions, ticket~ : BytesView) -> Session? {
  let wanted = ticket.to_owned()
  self.entries.iter().find_first(s => s.ticket == wanted)
}

///|
/// How many sessions the store holds, of every host.
pub fn Sessions::length(self : Sessions) -> Int32 {
  self.entries.length()
}

///|
/// Forget everything.
pub fn Sessions::clear(self : Sessions) -> Unit {
  self.entries.clear()
}

// -------------------------------------------------------------------- tickets

///|
/// A server's ticket keys and policy: `keys` newest first, of which the first seals and all of them
/// open, so a key can be retired by dropping it from the end of the list.
///
/// `count` is how many tickets a handshake hands out — several, because a client may use each only
/// once — `lifetime` how long they last, and `early` the most 0-RTT data a ticket allows. Empty
/// `keys` turns tickets off, which is the default.
pub(all) struct Tickets {
  keys : Array[Bytes]
  count : Int32
  lifetime : Int64
  early : Int32
} derive(Eq, Debug)

///|
pub extend Tickets with Eq::{equal, not_equal}

///|
pub extend Tickets with Debug::{to_repr}

///|
/// How long a ticket lasts unless the server says otherwise: 2 hours, which is what nginx and
/// Go's `crypto/tls` use.
pub let ticket_lifetime : Int64 = 7200

///|
/// No tickets at all, which is what a server did before TLS 1.3 had them.
pub let tickets : Tickets = {
  keys: [],
  count: 0,
  lifetime: ticket_lifetime,
  early: 0,
}

///|
/// Ticket policy with a key. The keys are AES-256 keys, which is what seals the ticket; `count` of
/// zero leaves resumption off whatever the keys say.
pub fn Tickets::new(
  keys : ArrayView[Bytes],
  count~ : Int32 = 2,
  lifetime~ : Int64 = ticket_lifetime,
  early~ : Int32 = 0,
) -> Tickets {
  { keys: keys.to_owned(), count, lifetime, early, }
}

///|
/// The same policy with `key` as the newest key: what a server does when it rotates.
pub fn Tickets::rotate(self : Tickets, key : Bytes) -> Tickets {
  { ..self, keys: [key, ..self.keys], }
}

///|
/// Whether this policy hands out tickets at all.
pub fn Tickets::is_on(self : Tickets) -> Bool {
  self.keys.length() > 0 && self.count > 0
}

///|
/// What a ticket carries inside it: the server's whole memory of the connection.
priv struct TicketState {
  suite : Int32
  born : Int64
  lifetime : Int64
  early : Int32
  age_add : Int32
  psk : Bytes
}

///|
/// The ticket a client gets back, sealing `state` under the newest key: a key index, a nonce and
/// the ciphertext (RFC 8446 §4.6.1 leaves the ticket's contents to the server).
///
/// The key index is the additional data, so a ticket sealed under one key cannot be read as if it
/// had been sealed under another.
fn seal_ticket(
  policy : Tickets,
  state : TicketState,
  rand : (Int32) -> Bytes,
) -> Bytes raise @alert.Alert {
  let index = 0
  guard policy.keys.get(index) is Some(key) else {
    raise @alert.fatal(InternalError)
  }
  let body = Buffer()
  @wire.u16(body, state.suite)
  for value in [state.born, state.lifetime] {
    for shift = 56; shift >= 0; shift = shift - 8 {
      body.write_byte(((value >> shift) & 0xffL).to_byte())
    }
  }
  body.write_byte(((state.early >> 24) & 0xff).to_byte())
  body.write_byte(((state.early >> 16) & 0xff).to_byte())
  body.write_byte(((state.early >> 8) & 0xff).to_byte())
  body.write_byte((state.early & 0xff).to_byte())
  body.write_byte(((state.age_add >> 24) & 0xff).to_byte())
  body.write_byte(((state.age_add >> 16) & 0xff).to_byte())
  body.write_byte(((state.age_add >> 8) & 0xff).to_byte())
  body.write_byte((state.age_add & 0xff).to_byte())
  body.write_byte((state.psk.length() & 0xff).to_byte())
  body.write_bytes(state.psk)
  let plain = body.to_bytes()
  let nonce = rand(12)
  let aad = b"moontls ticket"
  let cipher = @record.Suite::Aes256Gcm
    .aead(key)
    .seal(nonce=nonce[:], plain=plain[:], aad=aad[:])
  let out = Buffer()
  @wire.u16(out, index)
  out.write_bytes(nonce)
  out.write_bytes(cipher)
  out.to_bytes()
}

///|
/// Read a ticket back, or `None` when no key opens it — which is what a ticket from a retired key
/// looks like, and what a forged one does too.
fn open_ticket(policy : Tickets, ticket : Bytes) -> TicketState? {
  if ticket.length() < 2 + 12 + 16 {
    return None
  }
  let index = @wire.read_u16(ticket, 0)
  let nonce = ticket[2:14]
  let cipher = ticket[14:]
  let aad = b"moontls ticket"
  // The index says which key sealed it; a rotation moves it, so a miss falls back to trying them
  // all. The AEAD is what decides, and a wrong key cannot be mistaken for a right one.
  let mut plain : Bytes? = None
  for key in policy.keys {
    let opened = @record.Suite::Aes256Gcm
      .aead(key)
      .open(nonce~, cipher~, aad=aad[:]) catch {
        _ => continue
      }
    plain = Some(opened)
    break
  }
  let plain = match plain {
    Some(plain) => plain
    None => return None
  }
  ignore(index)
  @wire.decode(plain[:], r => {
    let suite = r.u16()
    let mut born = 0L
    for _ in 0..<8 {
      born = (born << 8) | r.u8().to_int64()
    }
    let mut lifetime = 0L
    for _ in 0..<8 {
      lifetime = (lifetime << 8) | r.u8().to_int64()
    }
    let mut early = 0
    for _ in 0..<4 {
      early = (early << 8) | r.u8()
    }
    let mut age_add = 0
    for _ in 0..<4 {
      age_add = (age_add << 8) | r.u8()
    }
    let psk = r.vec(1).rest().to_owned()
    { suite, born, lifetime, early, age_add, psk, }
  })
}
