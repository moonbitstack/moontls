// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn ticketed(host : String, ticket : Bytes) -> Session {
  {
    host,
    version: Tls13,
    kind: Ticket,
    suite: 0x1301,
    ticket,
    secret: b"",
    lifetime: 3600L,
    born: 0L,
    early: 0,
    age_add: 0,
  }
}

///|
test "a store keeps the id a ticket was issued under, and forgets it with the ticket" {
  let store = Sessions::new(limit=1)
  store.put(ticketed("a", b"t1"))
  store.remember(b"t1", b"id-one"[:])
  assert_eq(store.issued_under(b"t1"[:]), b"id-one")
  store.remember(b"t1", b"id-two"[:])
  assert_eq(store.issued_under(b"t1"[:]), b"id-two")
  assert_eq(store.issued_under(b"t9"[:]), b"")
  // A datagram's hello carries no id, and there is nothing to keep.
  store.put(ticketed("b", b"t2"))
  store.remember(b"t2", b""[:])
  assert_eq(store.issued_under(b"t2"[:]), b"")
  // The limit is per host: a second ticket for `a` pushes the first out, and its id goes too.
  store.put(ticketed("a", b"t3"))
  assert_eq(store.find(ticket=b"t1"[:]), None)
  assert_eq(store.issued_under(b"t1"[:]), b"")
  store.remember(b"t3", b"id-three"[:])
  store.clear()
  assert_eq(store.length(), 0)
  assert_eq(store.issued_under(b"t3"[:]), b"")
}
