name = "moonbitstack/moontls"

version = "0.9.15"

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
  "dtls-srtp",
  "hello-retry-request",
  "stateless-cookie",
  "record-size-limit",
  "certificate-compression",
  "brainpool",
  "rfc7027",
  "rfc8734",
  "rfc8446",
  "rfc5246",
  "rfc9147",
  "rfc6347",
  "encryption",
  "moonbit",
]

description = "TLS 1.3 and DTLS 1.3 for MoonBit."

import {
  "moonbitstack/mooncrypt@0.4.12",
  "moonbitstack/mooncred@0.6.11",
  "moonbitstack/moonbase@0.4.3",
  "moonbitstack/moonvar@0.2.1",
  "moonbitstack/moonzip@0.3.7",
  "moonbitlang/async@0.22.5",
}

source = "src"
