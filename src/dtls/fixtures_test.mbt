// Test fixtures shared by the DTLS connections: the same root and P-256 leaf
// the TLS tests use, so a datagram handshake is judged by the same chain.

///|
let now : Int64 = 1767225600

///|
fn rng(seed : Int32) -> (Int32) -> Bytes {
  let counter = Ref(seed)
  n => {
    let out = Buffer()
    while out.length() < n {
      counter.val = counter.val + 1
      out.write_bytes(@sha2.hash(@utf8.encode(counter.val.to_string())[:]))
    }
    out.to_bytes()[0:n].to_owned()
  }
}

///|
fn der(text : String) -> Bytes raise {
  @x509.pem(text)
}

///|
fn key(text : String) -> @x509.PrivateKey raise {
  @x509.PrivateKey::pem(text)
}

///|
let root : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBOTCB4aADAgECAhRBoRNE2qUhDT7gsQZp87k7rG4hgDAKBggqhkjOPQQDAjAT
  #|MREwDwYDVQQDDAh0bHMgcm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00MDAxMDEwMDAw
  #|MDBaMBMxETAPBgNVBAMMCHRscyByb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
  #|QgAE5Tl/MQGIDlEsYL0ooTHgwuwyddUOWA6mFhw0nIvogBVN7hCiqZpjzIe/+gTL
  #|2jmlCKKRFhyE8qTPTVCgAZCxh6MTMBEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO
  #|PQQDAgNHADBEAiAgWUh++JxjgLIuoat2eRS1EqNd+a7uozNrXSBWIQ9zZQIgGLI6
  #|Ec2yYljzZQ8wjbUjJnL/NRzS5dZ4+HZsSF/DXKY=
  #|-----END CERTIFICATE-----

///|
let p256_leaf : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBUDCB96ADAgECAhRjYY5dHAd3VQ3tyPL7/3le5Fvm+TAKBggqhkjOPQQDAjAT
  #|MREwDwYDVQQDDAh0bHMgcm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00MDAxMDEwMDAw
  #|MDBaMA8xDTALBgNVBAMMBHAyNTYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ6
  #|y11wYOg06UWDk0waEosabR4QPHrtYFiqwUcCXo2B1LS7Eq9399CS6M4iIqK1mo03
  #|iNp/ZYu76deRCF96VH1Xoy0wKzAUBgNVHREEDTALgglhLmV4YW1wbGUwEwYDVR0l
  #|BAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAwRQIgZKc+Qk2H/NenjER8IGYl
  #|3XUX4v2Og5H2y8s3QfRMMu4CIQDL4Z0K1TBRZRCDpjeXoaACuBWI9dC/U7xDzPLo
  #|O7ftvA==
  #|-----END CERTIFICATE-----

///|
let p256_key : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkd9OIQmt6ZJz2WUh
  #|D/+AZp/or4McQbJfSAhmjgVReCKhRANCAAQ6y11wYOg06UWDk0waEosabR4QPHrt
  #|YFiqwUcCXo2B1LS7Eq9399CS6M4iIqK1mo03iNp/ZYu76deRCF96VH1X
  #|-----END PRIVATE KEY-----
