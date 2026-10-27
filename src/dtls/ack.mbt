// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Write an ACK (RFC 9147 §7): the record numbers received and either processed
/// or buffered, in increasing order.
///
/// The sort is not a courtesy — §7 says "in numerically increasing order", and
/// a receiver is entitled to stop reading at the first number that goes
/// backwards. Sorting here means a caller can collect numbers as they arrive.
///
/// An ACK is not a handshake message: it has its own content type so that it
/// never enters the transcript.
pub fn ack(numbers : ArrayView[Number]) -> Bytes raise @alert.Alert {
  let sorted = numbers.to_owned()
  sorted.sort()
  let body = Buffer()
  for n in sorted {
    @wire.u64(body, n.epoch)
    @wire.u64(body, n.seq)
  }
  let inner = body.to_bytes()
  if inner.length() > 0xffff {
    raise @alert.fatal(InternalError)
  }
  let out = Buffer()
  @wire.u16(out, inner.length())
  out.write_bytes(inner)
  out.to_bytes()
}

///|
/// The record numbers an ACK acknowledges, or `None` if the payload is
/// truncated or its length does not divide into whole record numbers.
pub fn read_ack(view : BytesView) -> Array[Number]? {
  if view.length() < 2 {
    return None
  }
  let len = @wire.read_u16(view, 0)
  if len % 16 != 0 || view.length() < 2 + len {
    return None
  }
  let out = []
  for at = 2; at < 2 + len; at = at + 16 {
    out.push({
      epoch: @wire.read_u64(view, at),
      seq: @wire.read_u64(view, at + 8),
    })
  }
  Some(out)
}
