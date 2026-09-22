name = "moonbitstack/moontls"

version = "0.6.1"

readme = "README.md"

repository = "https://github.com/moonbitstack/moontls"

license = "Apache-2.0"

keywords = [ "tls", "tls13", "rfc8446", "handshake", "moonbit" ]

description = "moontls — the TLS 1.3 protocol state machine for MoonBit (RFC 8446): record layer, handshake and key schedule, bytes in and events out. No sockets, no cryptography of its own: the algorithms are mooncrypt's and certificate reading is mooncred's."

preferred_target = "wasm-gc"

import {
  "moonbitstack/mooncrypt@0.3.1",
  "moonbitstack/moonbase@0.4.0",
  "moonbitstack/moonvar@0.2.0",
}
