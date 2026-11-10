// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The peer opens sockets, which this backend has none of. `moon check --target all` still has to
/// see a program here.
#coverage.skip
fn main {
  println("tls-peer opens sockets: run it on the native or wasm backend")
}
