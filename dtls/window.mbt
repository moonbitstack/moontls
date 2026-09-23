// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How far out of order a datagram may arrive and still be accepted
/// (RFC 9147 §4.5.1).
///
/// The RFC leaves the size to the receiver and says only to pick one large
/// enough for plausible reordering. 64 is what the sliding window of
/// RFC 4303 §3.4.3 — the one §4.5.1 borrows — gives as its own default, and
/// what every DTLS stack ships.
pub let window : Int = 64

///|
/// The record numbers of one epoch already seen (RFC 9147 §4.5.1).
///
/// A right edge and a bitmap behind it: a number to the right of the edge is
/// new and moves the edge, a number within the bitmap is new only if its bit is
/// clear, and a number to the left of the bitmap is too old to judge and is
/// refused. One of these per epoch, because each epoch restarts at zero.
pub struct Window {
  size : Int
  mut edge : UInt64
  mut bits : Array[Bool]
  mut started : Bool
}

///|
/// An empty window of `size` record numbers.
pub fn Window::new(size? : Int = window) -> Window {
  let size = if size < 1 { 1 } else { size }
  { size, edge: 0UL, bits: Array::make(size, false), started: false, }
}

///|
/// Whether `seq` has already been seen — a question with no side effect, for a
/// caller that wants to look before deprotecting.
pub fn Window::seen(self : Window, seq : UInt64) -> Bool {
  if !self.started {
    return false
  }
  if seq > self.edge {
    return false
  }
  let back = self.edge - seq
  if back >= self.size.to_uint64() {
    return true
  }
  self.bits[back.to_int()]
}

///|
/// Record `seq` as seen, or refuse it as a replay (RFC 9147 §4.5.1).
///
/// `false` means the number is a duplicate or has fallen off the left edge.
/// This is called only after the record deprotects — §4.5.1 is explicit that
/// the window must not move for a record that failed, or an attacker could
/// knock a live sequence number out of the window with forgeries.
pub fn Window::accept(self : Window, seq : UInt64) -> Bool {
  if !self.started {
    self.started = true
    self.edge = seq
    self.bits[0] = true
    return true
  }
  if seq > self.edge {
    let ahead = seq - self.edge
    if ahead >= self.size.to_uint64() {
      self.bits = Array::make(self.size, false)
    } else {
      let shift = ahead.to_int()
      let moved = Array::make(self.size, false)
      for i = 0; i + shift < self.size; i = i + 1 {
        moved[i + shift] = self.bits[i]
      }
      self.bits = moved
    }
    self.edge = seq
    self.bits[0] = true
    return true
  }
  let back = self.edge - seq
  if back >= self.size.to_uint64() {
    return false
  }
  let at = back.to_int()
  if self.bits[at] {
    return false
  }
  self.bits[at] = true
  true
}

///|
/// The highest sequence number accepted so far, or `None` before the first one.
pub fn Window::high(self : Window) -> UInt64? {
  if self.started {
    Some(self.edge)
  } else {
    None
  }
}

///|
/// Reconstruct a full sequence number from the low `bits` of one
/// (RFC 9147 §4.2.2).
///
/// §4.2.2 recommends the candidate numerically closest to one past the highest
/// record already deprotected, which is what this computes: take the high part
/// of that expectation, and try the neighbouring windows when the low part says
/// the counter has wrapped.
pub fn Window::expand(self : Window, truncated : UInt64, bits : Int) -> UInt64 {
  let span = 1UL << bits
  let mask = span - 1UL
  let expected = match self.high() {
    Some(edge) => edge + 1UL
    None => 0UL
  }
  let base = expected & mask.lnot()
  let mut best = base | (truncated & mask)
  if best + span / 2UL < expected {
    best = best + span
  } else if best >= span && best > expected + span / 2UL {
    best = best - span
  }
  best
}
