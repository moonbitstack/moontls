name = "moonbitstack/moontls"

version = "0.9.13"

readme = "README.md"

repository = "https://github.com/moonbitstack/moontls"

license = "Apache-2.0"

keywords = [
  "tls",
  "ssl",
  "tls13",
  "tls12",
  "tls11",
  "tls10",
  "dtls",
  "dtls13",
  "dtls12",
  "https",
  "x509",
  "alpn",
  "sni",
  "psk",
  "session-resumption",
  "ocsp",
  "post-quantum",
  "ml-kem",
  "x25519mlkem768",
  "hybrid-key-exchange",
  "srtp",
  "rfc8446",
  "rfc5246",
  "rfc9147",
  "rfc6347",
  "encryption",
  "moonbit",
]

description = "TLS 1.3 and DTLS 1.3 for MoonBit."

import {
  "moonbitstack/mooncrypt@0.4.8",
  "moonbitstack/mooncred@0.6.7",
  "moonbitstack/moonbase@0.4.2",
  "moonbitstack/moonvar@0.2.0",
  "moonbitstack/moonzip@0.3.4",
}

source = "src"
