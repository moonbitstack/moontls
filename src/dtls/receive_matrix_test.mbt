// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What arrives on a datagram socket, from anyone.
//
// `Conn13::receive` and `Conn12::receive` are the only entry points an attacker reaches without
// first being trusted with anything, and a datagram is the easiest octet stream in TLS to get
// wrong: its length is in the datagram itself, its epoch and sequence number are attacker-chosen,
// and its handshake messages may be fragmented, reordered or duplicated. The rule here is the same
// as for the stream decoders: an alert is an answer, an abort is a bug.
//
// A fresh connection per datagram, because a state machine's answer to the tenth bad datagram is
// not the answer to the first, and it is the first that a stranger sends.

///|
fn datagram_corpus13() -> Array[Bytes] raise {
  let out : Array[Bytes] = []
  let client = client13()
  for datagram in collect(client) {
    out.push(datagram)
  }
  out
}

///|
fn datagram_corpus12() -> Array[Bytes] raise {
  let out : Array[Bytes] = []
  let client = client12()
  for datagram in collect12(client) {
    out.push(datagram)
  }
  out
}

///|
/// A server's answer to one datagram, with any alert treated as an answer.
fn feed13(datagram : BytesView) -> Unit raise {
  let server = server13()
  server.receive(datagram, now=0L)
}

///|
fn feed12(datagram : BytesView) -> Unit raise {
  let server = server12()
  server.receive(datagram, now=0L)
}

///|
test "dtls 1.3: every prefix of a real datagram is answered, never a crash" {
  let corpus = datagram_corpus13()
  assert_true(corpus.length() > 0)
  for datagram in corpus {
    for cut in 0..<(datagram.length() + 1) {
      feed13(datagram[0:cut]) catch {
        _ => ()
      }
    }
  }
}

///|
test "dtls 1.2: every prefix of a real datagram is answered, never a crash" {
  let corpus = datagram_corpus12()
  assert_true(corpus.length() > 0)
  for datagram in corpus {
    for cut in 0..<(datagram.length() + 1) {
      feed12(datagram[0:cut]) catch {
        _ => ()
      }
    }
  }
}

///|
/// The octets a datagram is most likely to be wrong in are its header: content type, version,
/// epoch, sequence number, length. Those are the first sixteen, and every one of them is flipped
/// here in both directions.
test "dtls: a datagram wrong in any header octet is answered, never a crash" {
  for datagram in datagram_corpus13() {
    let header = if datagram.length() < 20 { datagram.length() } else { 20 }
    for at in 0..<header {
      for byte in [b'\x00', b'\x17', b'\xff'] {
        if datagram[at] == byte {
          continue
        }
        let copy = datagram.to_array()
        copy[at] = byte
        feed13(Bytes::from_array(copy)[:]) catch {
          _ => ()
        }
      }
    }
  }
  for datagram in datagram_corpus12() {
    let header = if datagram.length() < 20 { datagram.length() } else { 20 }
    for at in 0..<header {
      for byte in [b'\x00', b'\x16', b'\xff'] {
        if datagram[at] == byte {
          continue
        }
        let copy = datagram.to_array()
        copy[at] = byte
        feed12(Bytes::from_array(copy)[:]) catch {
          _ => ()
        }
      }
    }
  }
}

///|
/// Random datagrams, including the lengths a record header can claim and a few past any real
/// maximum. A length field is the first thing a fuzzer finds, so it is worth sending on purpose.
test "dtls: random datagrams are answered, never a crash" {
  let source = rng(31337)
  for n in 0..<300 {
    let len = n * 41 % 1400
    feed13(source(len)) catch {
      _ => ()
    }
    feed12(source(len)) catch {
      _ => ()
    }
  }
}
