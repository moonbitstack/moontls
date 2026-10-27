// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
test "a new window has seen nothing" {
  let w = @dtls.Window::new()
  assert_eq(w.high(), None)
  assert_false(w.seen(0UL))
  assert_false(w.seen(1000UL))
}

///|
test "each number is accepted once" {
  let w = @dtls.Window::new()
  assert_true(w.accept(0UL))
  assert_false(w.accept(0UL))
  assert_true(w.accept(1UL))
  assert_false(w.accept(1UL))
  assert_eq(w.high(), Some(1UL))
}

///|
/// RFC 9147 §4.5.1: records within the window are checked against what has been
/// received, so reordering is fine and repetition is not.
test "reordering inside the window is accepted, repetition is not" {
  let w = @dtls.Window::new(size=8)
  assert_true(w.accept(5UL))
  assert_true(w.accept(2UL))
  assert_true(w.accept(4UL))
  assert_false(w.accept(2UL))
  assert_false(w.accept(5UL))
  assert_true(w.accept(0UL))
  assert_eq(w.high(), Some(5UL))
  assert_true(w.seen(0UL))
  assert_true(w.seen(2UL))
  assert_false(w.seen(1UL))
  assert_true(w.accept(1UL))
}

///|
/// The left edge is where the window stops being able to tell a replay from a
/// very late record; §4.5.1 says to reject what falls off it.
test "a number past the left edge is refused" {
  let w = @dtls.Window::new(size=4)
  assert_true(w.accept(10UL))
  // 7, 8 and 9 are inside a four-wide window whose right edge is 10.
  assert_true(w.accept(7UL))
  // 6 is not.
  assert_false(w.accept(6UL))
  assert_false(w.accept(0UL))
}

///|
/// A jump further than the window is wide leaves nothing behind to compare
/// against, so the bitmap starts over rather than keeping stale bits that would
/// refuse live records.
test "a jump past the window clears it" {
  let w = @dtls.Window::new(size=8)
  assert_true(w.accept(1UL))
  assert_true(w.accept(2UL))
  assert_true(w.accept(100UL))
  assert_eq(w.high(), Some(100UL))
  assert_true(w.accept(99UL))
  assert_false(w.accept(100UL))
  // 2 is long past the left edge now.
  assert_false(w.accept(2UL))
}

///|
/// RFC 9147 §4.2.2: the candidate nearest one past the highest record already
/// deprotected. An 8-bit sequence number wraps every 256 records, and the
/// window is what says which side of the wrap a truncated number is on.
test "a truncated sequence number expands to the nearest candidate" {
  let w = @dtls.Window::new()
  // Nothing seen yet: the expectation is zero, so the number reads as itself.
  assert_eq(w.expand(0x05UL, 8), 5UL)
  assert_eq(w.expand(0xffUL, 8), 255UL)
  w.accept(250UL) |> ignore
  // Expecting 251. A low number has wrapped forward, not gone backwards.
  assert_eq(w.expand(0xfcUL, 8), 252UL)
  assert_eq(w.expand(0x02UL, 8), 258UL)
  // A 16-bit number has the room not to wrap here at all.
  assert_eq(w.expand(0x0002UL, 16), 2UL)
  w.accept(70000UL) |> ignore
  assert_eq(w.expand(0x1171UL, 16), 70001UL)
}

///|
/// The size is a knob, and a window of one accepts only what moves forward.
test "the window size is a knob" {
  let w = @dtls.Window::new(size=1)
  assert_true(w.accept(4UL))
  assert_false(w.accept(4UL))
  assert_false(w.accept(3UL))
  assert_true(w.accept(5UL))
}
