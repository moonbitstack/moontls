// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.3 resumption (RFC 8446 §4.6.1, §4.2.11, §4.5): a ticket a server hands out, a
// pre_shared_key a client offers back, the binder that ties the two to this handshake, and the
// 0-RTT data a resumption may carry before the handshake completes.

///|
/// The session this client would offer for `host`, out of the store its configuration names.
fn Conn::pick_session(
  self : Conn,
  config : Client,
  host : String,
  version : Version,
) -> Session? {
  match config.sessions {
    Some(store) => store.get(host~, version~, now=self.now)
    None => None
  }
}

///|
/// The ClientHello with a `pre_shared_key` offer appended and its binder computed
/// (RFC 8446 §4.2.11.2).
///
/// The binder is a Finished-style MAC over the ClientHello truncated at the binders, so the
/// message has to exist twice: once with a binder-shaped hole, which is what is hashed, and once
/// with the answer in it, which is what goes out. After a HelloRetryRequest both earlier messages
/// come before the truncated ClientHello in the same hash, which is why `hrr` is read here.
fn Conn::hello_with_psk(
  self : Conn,
  base : @msg.Hello,
  session : Session,
) -> Bytes raise @alert.Alert {
  guard @record.Suite::of(session.suite) is Some(suite) else {
    raise @alert.fatal(InternalError)
  }
  let d = suite.digest()
  // §4.2.11.1: the age is the ticket's own age plus its age_add, both taken modulo 2^32, so the
  // server learns how long a client held a ticket without learning when it connected.
  let age = (((self.now - session.born) * 1000L) & 0xffff_ffffL).to_int() +
    session.age_add
  let identity : @ext.Identity = { identity: session.ticket, age, }
  let hole = @ext.pre_shared_key(
    [identity][:],
    [Bytes::make(d.size(), b'\x00')][:],
  )
  let probe = @msg.hello(
    {
      ..base,
      extensions: base.extensions + [{ kind: PreSharedKey, data: hole, }],
    },
    cookie=self.legacy_datagram,
  )
  let offset = match @ext.binder_offset(probe[:], d.size()) {
    Some(at) => at
    None => raise @alert.fatal(InternalError)
  }
  let binder_key = @keys.binder_key(
    @keys.early(psk=session.secret[:], digest=d),
    digest=d,
  )
  let hash = if self.hrr.length() > 0 {
    let joined = Buffer()
    joined.write_bytes(self.first_hello)
    joined.write_bytes(self.hrr)
    joined.write_bytesview(probe[0:offset])
    d.hash(joined.to_bytes()[:])
  } else {
    d.hash(probe[0:offset])
  }
  let binder = @keys.finished(binder_key[:], hash[:], digest=d)
  self.psk = session.secret
  self.psk_suite = session.suite
  // §4.2.10: the ticket said how much 0-RTT data it allows, which is what the client is held to.
  self.early_left = if session.early < 0 { 0x7fffffff } else { session.early }
  self.offered_early = base.extensions.iter().any(e => e.kind is EarlyData)
  let body = @ext.pre_shared_key([identity][:], [binder][:])
  @msg.hello(
    {
      ..base,
      extensions: base.extensions + [{ kind: PreSharedKey, data: body, }],
    },
    cookie=self.legacy_datagram,
  )
}

///|
/// Whether a server's ServerHello accepted the PSK this client offered (RFC 8446 §4.2.11): the
/// extension carries the index of the identity it chose, which for one offer is zero.
fn Conn::accept_resumption(
  self : Conn,
  sh : @msg.Server,
) -> Unit raise @alert.Alert {
  match @ext.find(sh.extensions[:], PreSharedKey) {
    Some(e) => {
      if self.psk.length() == 0 {
        // Nothing was offered, so nothing could have been chosen.
        raise @alert.fatal(UnsupportedExtension)
      }
      if e.data.length() != 2 || @wire.read_u16(e.data, 0) != 0 {
        raise @alert.fatal(IllegalParameter)
      }
      self.resumed = true
    }
    None => self.resumed = false
  }
}

// ------------------------------------------------------------------ the client

///|
/// Remember a ticket a server sent (RFC 8446 §4.6.1).
///
/// The PSK is `Derive-Secret(Resumption Master Secret, "resumption", ticket_nonce)`, so the ticket
/// itself needs no key of its own on the client side — the nonce is what tells two tickets from one
/// connection apart. A ticket whose lifetime has run out, or one for a host this connection is not
/// to, is dropped rather than stored.
fn Conn::on_ticket(
  self : Conn,
  config : Client,
  host : String,
  body : Bytes,
) -> Unit raise @alert.Alert {
  guard @msg.read_new_session_ticket(body[:]) is Some(t) else {
    raise @alert.fatal(DecodeError)
  }
  guard self.suite is Some(suite) else { return }
  // §4.6.1: a lifetime past 604800 seconds is to be read as exactly that.
  let lifetime = if t.lifetime > 604800 {
    604800L
  } else {
    t.lifetime.to_int64()
  }
  if lifetime == 0L || self.resumption.length() == 0 {
    return
  }
  let early = match @ext.find(t.extensions[:], EarlyData) {
    Some(e) => {
      let size = @ext.read_max_early_data(e.data[:]).unwrap_or(0)
      // RFC 9001 §4.6.1: over QUIC anything but 0xffffffff is a protocol violation.
      if self.quic is Some(_) && size != -1 {
        raise @alert.fatal(IllegalParameter)
      }
      size
    }
    None => 0
  }
  let psk = @keys.resumption(
    self.resumption[:],
    t.nonce[:],
    digest=suite.digest(),
  )
  match config.sessions {
    Some(store) =>
      store.put({
        host,
        version: Tls13,
        kind: Psk,
        suite: suite.code(),
        ticket: t.ticket,
        secret: psk,
        lifetime,
        born: self.now,
        early,
        age_add: t.age_add,
      })
    None => ()
  }
}

///|
/// The resumption master secret, which every ticket this connection hands out stands for
/// (RFC 8446 §7.1): `Derive-Secret(Master Secret, "res master", ClientHello..client Finished)`.
fn Conn::close_transcript(self : Conn) -> Unit {
  if self.master13.length() == 0 {
    return
  }
  let d = self.digest()
  self.resumption = @keys.resumption_master(
    self.master13[:],
    self.th()[:],
    digest=d,
  )
}

///|
/// Queue 0-RTT data under the client's early traffic secret (RFC 8446 §4.2.10, §7.1).
///
/// Only a client that offered early_data in its ClientHello may, and only before the server has
/// answered: once the handshake has a key schedule of its own, 0-RTT is over. Whether the server
/// took it is `early_accepted`; data it declined is sent again, as ordinary data, when the
/// handshake opens — so a caller that writes early and then writes normally sees its bytes arrive
/// once, in order, either way.
pub fn Conn::write_early(
  self : Conn,
  data : BytesView,
) -> Unit raise @alert.Alert {
  guard self.phase is Expect(@hs.Client::WaitServerHello) else {
    raise @alert.fatal(InternalError)
  }
  guard self.early_writer is Some(w) else { raise @alert.fatal(InternalError) }
  if self.early_sent.length() + data.length() > self.early_left {
    raise @alert.fatal(InternalError)
  }
  let mut at = 0
  while at < data.length() {
    let end = @cmp.minimum(at + @record.max_fragment, data.length())
    self.outbox.write_bytes(w.seal(ApplicationData, data[at:end]))
    at = end
  }
  let joined = Buffer()
  joined.write_bytes(self.early_sent)
  joined.write_bytesview(data)
  self.early_sent = joined.to_bytes()
}

///|
/// Whether the server accepted the 0-RTT data this client sent.
pub fn Conn::early_accepted(self : Conn) -> Bool {
  self.early_ok
}

///|
/// Whether this handshake resumed a session instead of authenticating a certificate (RFC 8446
/// §4.6.1). A resumed handshake is authenticated by the ticket, so `peer` is empty on both ends
/// unless a client certificate was asked for again.
pub fn Conn::is_resumed(self : Conn) -> Bool {
  self.resumed
}

// ------------------------------------------------------------------ the server

///|
/// Whether a ClientHello says it can resume with (EC)DHE (RFC 8446 §4.2.9).
///
/// A client that offers `pre_shared_key` without this extension is one a server must abort for
/// (same section); one that offers it with only `psk_ke` is asking for a mode this library does
/// not implement, and both ends are better off without a ticket that cannot be used.
fn declares_psk_dhe(hello : @msg.Hello) -> Bool {
  match @ext.find(hello.extensions[:], PskKeyExchangeModes) {
    Some(e) =>
      match @ext.read_psk_modes(e.data[:]) {
        Some(modes) => modes.contains(@ext.psk_dhe_ke)
        None => false
      }
    None => false
  }
}

///|
/// Look through a ClientHello's PSK offers for one this server issued, and verify the binder that
/// comes with it (RFC 8446 §4.2.11).
///
/// The first identity that opens and whose binder verifies is the one taken; anything else leaves
/// the handshake to run in full, which is what a client that offered an unknown ticket expects
/// (§4.2.11: a server that does not accept one continues without it).
fn Conn::accept_psk(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  // With no clock (`now` left out) a ticket's lifetime cannot be judged, so none is taken.
  guard config.tickets.is_on() && self.now != 0L else { return }
  // §4.2.9: a client that only offers psk_ke wants a handshake this library will not run.
  if !self.modes_dhe {
    return
  }
  guard @ext.find(hello.extensions[:], PreSharedKey) is Some(e) else { return }
  // §4.2.11: pre_shared_key has to be the last extension, and the binder is found by measuring
  // back from the end of the message.
  match hello.extensions.rev().get(0) {
    Some(last) =>
      if !(last.kind is PreSharedKey) {
        raise @alert.fatal(IllegalParameter)
      }
    None => ()
  }
  guard @ext.read_pre_shared_key(e.data[:]) is Some((identities, binders)) else {
    raise @alert.fatal(DecodeError)
  }
  for i, identity in identities {
    if self.resumed {
      break
    }
    guard open_ticket(config.tickets, identity.identity) is Some(state) else {
      continue
    }
    guard @record.Suite::of(state.suite) is Some(suite) else { continue }
    if !hello.suites.contains(suite.code()) {
      continue
    }
    // §4.2.11.1 and §8.3: the reported age is the real one plus age_add, in milliseconds. The two
    // ends read different clocks at different moments, so a difference is no reason to refuse the
    // ticket; it only says this hello may be a replay, which is what 0-RTT cannot survive.
    let reported = (identity.age - state.age_add).to_int64() & 0xffff_ffffL
    let drift = (self.now - state.born) * 1000L - reported
    let fresh = drift.abs() <= config.tickets.drift
    if self.now - state.born > state.lifetime || self.now < state.born {
      continue
    }
    let d = suite.digest()
    let binder_key = @keys.binder_key(
      @keys.early(psk=state.psk[:], digest=d),
      digest=d,
    )
    guard @ext.binder_offset(raw[:], d.size(), n=identities.length())
      is Some(at) else {
      raise @alert.fatal(DecodeError)
    }
    if !@keys.finished_ok(
        binder_key[:],
        d.hash(raw[0:at]),
        binders[i][:],
        digest=d,
      ) {
      continue
    }
    self.psk = state.psk
    self.resumed = true
    self.suite = Some(suite)
    // §4.2.10: 0-RTT only under a ticket that allows it, and only when the application said so.
    if fresh &&
      hello.extensions.iter().any(x => x.kind is EarlyData) &&
      state.early > 0 &&
      config.tickets.early > 0 {
      self.early_ok = true
      self.early_left = @cmp.minimum(state.early, config.tickets.early)
    }
    return
  }
}

///|
/// Start the client's early read keys and window once the ClientHello has settled which PSK this
/// handshake uses (RFC 8446 §7.1).
fn Conn::open_early(self : Conn, first_hello : Bytes) -> Unit {
  if !self.early_ok {
    return
  }
  guard self.suite is Some(suite) else { return }
  let d = suite.digest()
  self.early_secret = @keys.early(psk=self.psk[:], digest=d)
  let secret = @keys.client_early(
    self.early_secret[:],
    d.hash(first_hello),
    digest=d,
  )
  self.early_reader = Some(@record.Cipher::new(secret[:], suite~))
  if self.quic is Some(q) {
    q.steps.push(Early(secret~, suite~))
  }
}

///|
/// Hand out `count` tickets once the handshake is over (RFC 8446 §4.6.1): each carries the server's
/// state, sealed under the newest ticket key, and a nonce of its own so that no two tickets stand
/// for the same PSK.
fn Conn::issue_tickets(self : Conn, config : Server) -> Unit raise @alert.Alert {
  guard config.tickets.is_on() && self.resumption.length() > 0 && self.now != 0L else {
    return
  }
  // §4.2.9: "Servers SHOULD NOT send NewSessionTicket with tickets that are not compatible with
  // the advertised modes". Every ticket this library issues stands for a PSK with (EC)DHE — the
  // only mode it selects — so a client that did not advertise `psk_dhe_ke` gets none, and is
  // spared tickets whose resumption it would never be offered.
  if !self.modes_dhe {
    return
  }
  guard self.suite is Some(suite) else { return }
  let mut i = 0
  while i < config.tickets.count {
    let nonce = Bytes::from_array([
      ((i >> 8) & 0xff).to_byte(),
      (i & 0xff).to_byte(),
    ])
    let psk = @keys.resumption(
      self.resumption[:],
      nonce[:],
      digest=suite.digest(),
    )
    let raw_age = (self.rand)(4)
    let age_add = (raw_age[0].to_int() << 24) |
      (raw_age[1].to_int() << 16) |
      (raw_age[2].to_int() << 8) |
      raw_age[3].to_int()
    let ticket_bytes = seal_ticket(
      config.tickets,
      {
        suite: suite.code(),
        born: self.now,
        lifetime: config.tickets.lifetime,
        early: config.tickets.early,
        age_add,
        psk,
      },
      self.rand,
    )
    let extensions : Array[@ext.Ext] = if config.tickets.early > 0 {
      // RFC 9001 §4.6.1: QUIC has its own flow control, and the field is fixed at 0xffffffff.
      let size = if self.quic is Some(_) { -1 } else { config.tickets.early }
      [{ kind: EarlyData, data: @ext.max_early_data(size), }]
    } else {
      []
    }
    let message = @msg.new_session_ticket({
      lifetime: config.tickets.lifetime.to_int(),
      age_add,
      nonce,
      ticket: ticket_bytes,
      extensions,
    })
    self.send_handshake(message)
    i = i + 1
  }
}
