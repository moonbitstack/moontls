// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.2 resumption (RFC 5246 §7.3, RFC 5077): the abbreviated handshake, which skips the
// certificate and the key exchange and starts from a master secret both ends already have.
//
// Two ways to name that secret. A session id is a name the server looks up in its own cache; a
// ticket is the server's cache entry sealed under a ticket key, handed to the client to carry
// back. The handshake is the same either way — the difference is who remembers.

///|
/// The TLS 1.2 session this client would offer, if its store has one: the session id replaces the
/// random one in the ClientHello, a ticket travels in an extension, and either way the stored
/// master secret is what the handshake would start from.
fn Conn::offer_session12(self : Conn, config : Client, host : String) -> Unit {
  guard config.sessions is Some(store) else { return }
  guard store.get(host~, version=Tls12, now=self.now) is Some(s) else { return }
  match s.kind {
    Id => self.session = s.ticket
    Ticket => self.ticket12 = s.ticket
    Psk => return
  }
  self.psk12 = s.secret
  self.psk_suite = s.suite
  self.resume12 = Some(s.kind)
}

///|
/// The TLS 1.2 session id a server puts in its ServerHello when it hands one out: a name of its own
/// choosing, which the client brings back.
fn Conn::issue_id12(self : Conn) -> Bytes {
  (self.rand)(32)
}

///|
/// Whether a ServerHello answered a TLS 1.2 offer of ours, by whichever of the two names we used.
fn Conn::resumes12(self : Conn, sh : @msg.Server) -> Bool {
  guard self.resume12 is Some(kind) && self.psk12.length() > 0 else {
    return false
  }
  match kind {
    Id => sh.session_id == self.session && sh.session_id.length() > 0
    // RFC 5077 §3.4: a server taking a ticket says so with an empty extension of its own.
    Ticket =>
      match @ext.find(sh.extensions[:], SessionTicket) {
        Some(e) => @ext.read_session_ticket(e.data[:]) is Some(_)
        None => false
      }
    Psk => false
  }
}

///|
/// The client's side of an abbreviated handshake: the stored master secret, the stored suite's
/// ciphers, its change_cipher_spec and Finished, and then the server's Finished to wait for
/// (RFC 5246 §7.3).
fn Conn::resume_client12(
  self : Conn,
  suite : @record.Suite12,
  sh : @msg.Server,
  raw : Bytes,
) -> Unit {
  self.version = Some(Tls12)
  self.wire = Tls12.code()
  self.suite12 = Some(suite)
  self.server_random = sh.random
  self.master = self.psk12
  self.begin_transcript(None)
  self.record_sent(self.first_hello[:])
  self.record(raw[:])
  // RFC 5246 §7.3: in an abbreviated handshake the server sends its Finished first, so the
  // client's covers it too — which is why this half waits for it before writing anything.
  let (mine, theirs) = self.ciphers12()
  self.outgoing = Some(mine)
  self.waiting = Some(theirs)
  self.resumed = true
  self.phase = Legacy(Cipher)
}

///|
/// The server's side: it answers a ClientHello that named a session it still has, with the same
/// suite, then its own change_cipher_spec and Finished, and waits for the client's (RFC 5246 §7.3).
fn Conn::resume_server12(
  self : Conn,
  hello : @msg.Hello,
  raw : Bytes,
  session : Session,
  ticket~ : Bool,
) -> Unit raise @alert.Alert {
  guard @record.Suite12::of(session.suite) is Some(suite) else {
    raise @alert.fatal(IllegalParameter)
  }
  self.version = Some(Tls12)
  self.wire = Tls12.code()
  self.suite12 = Some(suite)
  self.client_random = hello.random
  self.client_version = hello.version
  self.server_random = (self.rand)(32)
  // RFC 5246 §7.3: the session id the client named comes back untouched — that echo is how it
  // knows the handshake was abbreviated rather than a new one that happens to agree.
  self.session = hello.session_id
  self.master = session.secret
  self.resumed = true
  self.begin_transcript(None)
  self.record(raw[:])
  let extensions : Array[@ext.Ext] = []
  // RFC 5746 §3.6 and RFC 7627 §5.3: the answers a full handshake gives to the same offers.
  if @ext.find(hello.extensions[:], RenegotiationInfo) is Some(_) ||
    hello.suites.contains(renegotiation_scsv) {
    extensions.push({ kind: RenegotiationInfo, data: @ext.no_renegotiation(), })
  }
  if @ext.find(hello.extensions[:], ExtendedMasterSecret) is Some(_) {
    self.extended = true
    extensions.push({ kind: ExtendedMasterSecret, data: b"", })
  }
  if ticket {
    extensions.push({ kind: SessionTicket, data: @ext.session_ticket(b""[:]), })
  }
  let sh = @msg.server_hello({
    version: supported(Tls12, datagram=self.datagram),
    random: self.server_random,
    session_id: self.session,
    suite: suite.code,
    compression: 0,
    extensions,
  })
  self.record_sent(sh[:])
  // The key block puts the client's keys first, so a server reads its own second.
  let (theirs, mine) = self.ciphers12()
  let flight = Buffer()
  flight.write_bytes(sh)
  self.send_handshake(flight.to_bytes())
  self.send_change_cipher_spec()
  self.writer = Some(mine)
  self.send_finished12(client=false)
  // The server's half is out, so what it awaits is the client's change_cipher_spec and then its
  // Finished: the same two steps a full handshake leaves, from the other side.
  self.waiting = Some(theirs)
  self.phase = Legacy(Cipher)
}

///|
/// A TLS 1.2 ClientHello that names a session this server can resume: by session id in its cache,
/// or by a ticket it sealed itself (RFC 5077 §3.4).
fn Conn::prior_session12(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
) -> (Session, Bool)? {
  // A ticket first: it needs no storage, and a client that has one also sends a session id.
  if config.tickets.is_on() {
    match @ext.find(hello.extensions[:], SessionTicket) {
      Some(e) =>
        match @ext.read_session_ticket(e.data[:]) {
          Some(ticket) if ticket.length() > 0 =>
            match open_ticket(config.tickets, ticket) {
              Some(state) =>
                if self.now - state.born <= state.lifetime {
                  return Some(
                    (
                      {
                        host: "",
                        version: Tls12,
                        kind: Ticket,
                        suite: state.suite,
                        ticket,
                        secret: state.psk,
                        lifetime: state.lifetime,
                        born: state.born,
                        early: 0,
                        age_add: 0,
                      },
                      true,
                    ),
                  )
                }
              None => ()
            }
          _ => ()
        }
      None => ()
    }
  }
  guard config.sessions is Some(store) else { return None }
  guard hello.session_id.length() > 0 else { return None }
  match store.find(ticket=hello.session_id[:]) {
    Some(session) =>
      if session.version is Tls12 && self.now - session.born <= session.lifetime {
        Some((session, false))
      } else {
        None
      }
    None => None
  }
}

///|
/// Remember a TLS 1.2 handshake that has just finished, for the next one: as a session id in the
/// server's cache, or as a ticket, or as both when both are configured.
fn Conn::remember12(
  self : Conn,
  config : Server,
  host : String,
) -> Unit raise @alert.Alert {
  if self.master.length() == 0 {
    return
  }
  guard self.suite12 is Some(suite) else { return }
  let lifetime = config.tickets.lifetime
  match config.sessions {
    Some(store) => {
      if self.session.length() == 0 {
        self.session = self.issue_id12()
      }
      store.put({
        host,
        version: Tls12,
        kind: Id,
        suite: suite.code,
        ticket: self.session,
        secret: self.master,
        lifetime,
        born: self.now,
        early: 0,
        age_add: 0,
      })
    }
    None => ()
  }
  if config.tickets.is_on() {
    let ticket = seal_ticket(
      config.tickets,
      {
        suite: suite.code,
        born: self.now,
        lifetime,
        early: 0,
        age_add: 0,
        psk: self.master,
      },
      self.rand,
    )
    let message = @msg.new_session_ticket12(lifetime.to_int(), ticket[:])
    self.send_handshake(message)
  }
}

///|
/// Remember a TLS 1.2 handshake on the client side: the session id the server named is the name to
/// bring back, and the master secret is what makes it worth resuming.
fn Conn::remember_client12(self : Conn, config : Client, host : String) -> Unit {
  guard config.sessions is Some(store) else { return }
  guard self.suite12 is Some(suite) &&
    self.master.length() > 0 &&
    self.session.length() > 0 else {
    return
  }
  store.put({
    host,
    version: Tls12,
    kind: Id,
    suite: suite.code,
    ticket: self.session,
    secret: self.master,
    lifetime: ticket_lifetime,
    born: self.now,
    early: 0,
    age_add: 0,
  })
}

///|
/// Keep a TLS 1.2 ticket the server sent (RFC 5077 §3.3), with the master secret that is what it
/// stands for.
fn Conn::on_ticket12(
  self : Conn,
  config : Client,
  host : String,
  body : Bytes,
) -> Unit raise @alert.Alert {
  guard @msg.read_new_session_ticket12(body[:]) is Some((lifetime, ticket)) else {
    raise @alert.fatal(DecodeError)
  }
  guard config.sessions is Some(store) else { return }
  guard self.suite12 is Some(suite) else { return }
  let lifetime = if lifetime <= 0 { 0L } else { lifetime.to_int64() }
  if lifetime == 0L {
    return
  }
  store.put({
    host,
    version: Tls12,
    kind: Ticket,
    suite: suite.code,
    ticket,
    secret: self.master,
    lifetime,
    born: self.now,
    early: 0,
    age_add: 0,
  })
}
