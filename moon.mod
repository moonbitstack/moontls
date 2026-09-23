name = "moonbitstack/moontls"

version = "0.8.0"

readme = "README.md"

repository = "https://github.com/moonbitstack/moontls"

license = "Apache-2.0"

keywords = [ "tls", "tls13", "dtls", "rfc8446", "rfc9147", "moonbit" ]

description = "moontls — the TLS 1.3 protocol state machine for MoonBit (RFC 8446) and DTLS 1.3 over datagrams (RFC 9147): record layers, handshake, key schedule and DTLS-SRTP keying, bytes in and events out. No sockets, no cryptography of its own."

preferred_target = "wasm-gc"

import {
  "moonbitstack/mooncrypt@0.3.1",
  "moonbitstack/moonbase@0.4.0",
  "moonbitstack/moonvar@0.2.0",
}
