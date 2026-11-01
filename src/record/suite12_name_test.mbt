///|
test "a suite's name is the registry's" {
  let name = (code : Int32) => {
    guard @record.Suite12::of(code) is Some(suite) else {
      fail("unknown \{code}")
    }
    suite.name()
  }
  assert_eq(name(0xc02f), "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
  assert_eq(name(0xc02c), "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
  assert_eq(name(0xcca8), "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
  assert_eq(name(0xc0ac), "TLS_ECDHE_ECDSA_WITH_AES_128_CCM")
  assert_eq(name(0xc0af), "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8")
  assert_eq(name(0x0033), "TLS_DHE_RSA_WITH_AES_128_CBC_SHA")
  assert_eq(name(0x006b), "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256")
  assert_eq(name(0xc024), "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384")
  assert_eq(name(0x009c), "TLS_RSA_WITH_AES_128_GCM_SHA256")
  assert_eq(name(0xc0a1), "TLS_RSA_WITH_AES_256_CCM_8")
  assert_eq(name(0x002f), "TLS_RSA_WITH_AES_128_CBC_SHA")
}

///|
test "no two suites share a name" {
  let names : Map[String, Int32] = Map([])
  for suite in @record.all12 {
    assert_true(names.get(suite.name()) is None)
    names[suite.name()] = suite.code
  }
  assert_eq(names.length(), @record.all12.length())
}
