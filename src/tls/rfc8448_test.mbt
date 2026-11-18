// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 8448, "Example Handshake Traces for TLS 1.3": the octets the RFC publishes, fed through this
// library's key schedule and record layer.
//
// A trace is a different kind of test from a round trip. Two ends of this library that share a
// mistake agree with each other and disagree with everyone else; a published trace cannot be
// agreed with, only matched. Every secret below is quoted from the RFC, and every record is
// sealed here and compared octet for octet with the record the RFC prints.
//
// https://www.rfc-editor.org/rfc/rfc8448
//
// The dumps are extracted from the RFC's own text rather than typed in, so what is checked here is
// the RFC's arithmetic and not a transcription of it.

///|
/// One of the RFC's hex dumps.
fn rfc8(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// The octets of `data`, as a string the assertion can show.
fn rfc8_hex(data : BytesView) -> String {
  @base16.encode(data)
}

///|
let rfc8_ch3 : String = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"

///|
let rfc8_sh3 : String = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"

///|
let rfc8_flight3 : String = "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"

///|
let rfc8_flight3_sealed : String = "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b"

///|
let rfc8_fin_c3 : String = "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"

///|
let rfc8_fin_c3_sealed : String = "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546"

///|
let rfc8_nst3 : String = "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d3570008002a000400000400"

///|
let rfc8_app_c3_sealed : String = "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4"

///|
let rfc8_app_s3_sealed : String = "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d"

///|
let rfc8_alert_c3_sealed : String = "1703030013c9872760655666b74d7ff1153efd6db6d0b0e3"

///|
let rfc8_ch5 : String = "010000b00303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee9258a346677b6f000006130113031302010000810000000b0009000006736572766572ff01000100000a00080006001d00170018003300260024001d0020e8e8e3f3b93a25ed97a14a7dcacb8a272c6288e585c6484d05262fcad062ad1f002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"

///|
let rfc8_hrr5 : String = "020000ac0303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c001301000084003300020017002c0074007271dcd04bb88bc3189119398a00000000eefafc76c146b823b096f8aacad365dd0030953f4edf625636e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b0c8be778257d16aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934b0002b00020304"

///|
let rfc8_ch5b : String = "010001fc0303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee9258a346677b6f000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00080006001d001700180033004700450017004104a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002c0074007271dcd04bb88bc3189119398a00000000eefafc76c146b823b096f8aacad365dd0030953f4edf625636e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b0c8be778257d16aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934b0002d00020101001c00024001001500af00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

///|
let rfc8_sh5b : String = "020000770303bb341d847fd789c47c387172dc0c9bf147fccacb5043d86ca4c598d3ff571b9800130100004f003300450017004104583e054b7a66672ae020ad9d2686fcc85b5ad41a134a0f03ee72b893052bd85b4c8de6776f5b04ac07d83540eab3e3d9c547bc6528c4317d294686093a6cad7d002b00020304"

// The two ephemeral X25519 shares of §3, and the secret they agree on — which is the IKM the RFC
// feeds to HKDF-Extract for the handshake secret.

///|
let rfc8_x25519_client_private : String = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"

///|
let rfc8_x25519_client_public : String = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"

///|
let rfc8_x25519_server_private : String = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"

///|
let rfc8_x25519_server_public : String = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"

///|
let rfc8_x25519_shared : String = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"

// The P-256 shares of §5, where the server answers the X25519 share with a HelloRetryRequest.

///|
let rfc8_p256_client_private : String = "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39"

///|
let rfc8_p256_client_public : String = "04a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780"

///|
let rfc8_p256_server_private : String = "8c510601f9765bfb8ed693449a48989859b5cfa879cb9f5443c41c5ff10634ed"

///|
let rfc8_p256_server_public : String = "04583e054b7a66672ae020ad9d2686fcc85b5ad41a134a0f03ee72b893052bd85b4c8de6776f5b04ac07d83540eab3e3d9c547bc6528c4317d294686093a6cad7d"

///|
let rfc8_p256_shared : String = "c142ce13ca11b5c2233652e63ad3d97844f1621fbfb9de69d547dc8fedeabeb4"

// §3's secrets, in the order the ladder makes them.

///|
let rfc8_early : String = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"

///|
let rfc8_derived : String = "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"

///|
let rfc8_handshake : String = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"

///|
let rfc8_c_hs : String = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"

///|
let rfc8_s_hs : String = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"

///|
let rfc8_master : String = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"

///|
let rfc8_c_ap : String = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"

///|
let rfc8_s_ap : String = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"

///|
let rfc8_exp_master : String = "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"

///|
let rfc8_res_master : String = "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"

///|
let rfc8_resumption : String = "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"

// The transcript hashes the RFC quotes at three points: after ServerHello, after the server's
// Finished, and after the client's.

///|
let rfc8_hash_sh : String = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"

///|
let rfc8_hash_sfin : String = "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"

///|
let rfc8_hash_cfin : String = "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"

// The traffic keys and IVs, as the RFC expands them.

///|
let rfc8_s_hs_key : String = "3fce516009c21727d0f2e4e86ee403bc"

///|
let rfc8_s_hs_iv : String = "5d313eb2671276ee13000b30"

///|
let rfc8_c_hs_key : String = "dbfaa693d1762c5b666af5d950258d01"

///|
let rfc8_c_hs_iv : String = "5bd3c71b836e0b76bb73265f"

///|
let rfc8_s_ap_key : String = "9f02283b6c9c07efc26bb9f2ac92e356"

///|
let rfc8_s_ap_iv : String = "cf782b88dd83549aadf1e984"

///|
let rfc8_c_ap_key : String = "17422dda596ed5d9acd890e3c63f5051"

///|
let rfc8_c_ap_iv : String = "5b78923dee08579033e523d9"

// The two verify_data values, and the finished keys they are MACs under.

///|
let rfc8_s_finished : String = "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"

///|
let rfc8_s_finished_key : String = "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"

///|
let rfc8_c_finished : String = "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"

///|
let rfc8_c_finished_key : String = "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"

// §5's ladder, which is the one that runs behind a HelloRetryRequest.

///|
let rfc8_hrr_handshake : String = "ce022e5e6e81e50736d773f2d3adfce8220d049bf510f0dbfac927ef4243b148"

///|
let rfc8_hrr_master : String = "1131545d0baf79ddce9b87f06945781a57dd18ef378dcd2060f8f9a569027ed8"

///|
let rfc8_hrr_c_hs : String = "158aa7ab8855073582b41d674b4055cabcc534728f659314861b4e08e2011566"

///|
let rfc8_hrr_s_hs : String = "3403e781e2af7b6508da28574f6e95a1abf162de83a97927c37672a4a0cef8a1"

///|
let rfc8_hrr_hash : String = "8aa8e828ec2f8a884fec95a3139de01c15a3daa7ff5bfc3f4bfcc21b438d7bf8"

///|
/// §3 of RFC 8448: the shares, and the secret the two ends agree on.
test "rfc8448: the ephemeral shares and the secret they agree on" {
  assert_eq(
    rfc8_hex(@x25519.public(rfc8(rfc8_x25519_client_private))),
    rfc8_x25519_client_public,
  )
  assert_eq(
    rfc8_hex(@x25519.public(rfc8(rfc8_x25519_server_private))),
    rfc8_x25519_server_public,
  )
  // The agreement is the one HKDF-Extract is later salted with, which ties the curve to the
  // schedule: a share right and a secret wrong would be a handshake that fails only with a peer.
  assert_eq(
    rfc8_hex(
      @x25519.shared(
        rfc8(rfc8_x25519_client_private),
        rfc8(rfc8_x25519_server_public),
      ),
    ),
    rfc8_x25519_shared,
  )
  assert_eq(
    rfc8_hex(
      @x25519.shared(
        rfc8(rfc8_x25519_server_private),
        rfc8(rfc8_x25519_client_public),
      ),
    ),
    rfc8_x25519_shared,
  )
}

///|
/// §5 of RFC 8448: the same, on the curve a HelloRetryRequest moves the handshake to.
test "rfc8448: the retried share is P-256, and its secret is the one the trace uses" {
  assert_eq(
    rfc8_hex(@ecdh.public(rfc8(rfc8_p256_client_private))),
    rfc8_p256_client_public,
  )
  assert_eq(
    rfc8_hex(@ecdh.public(rfc8(rfc8_p256_server_private))),
    rfc8_p256_server_public,
  )
  assert_eq(
    rfc8_hex(
      @ecdh.shared(
        rfc8(rfc8_p256_client_private),
        rfc8(rfc8_p256_server_public),
      ),
    ),
    rfc8_p256_shared,
  )
  assert_eq(
    rfc8_hex(
      @ecdh.shared(
        rfc8(rfc8_p256_server_private),
        rfc8(rfc8_p256_client_public),
      ),
    ),
    rfc8_p256_shared,
  )
}

///|
/// The ladder of §3, one rung at a time. Each assertion is a step of RFC 8446 §7.1 with the RFC's
/// own answer, so a mistake is named at the step that made it.
test "rfc8448: the simple handshake's key schedule is the trace's" {
  // The hello the trace records really is the hello this library's parser reads.
  let hello = @msg.read_hello(rfc8(rfc8_ch3)[4:])
  assert_true(hello is Some(_))
  let server = @msg.read_server_hello(rfc8(rfc8_sh3)[4:])
  assert_true(server is Some(_))

  let t = @keys.Transcript::new()
  t.add(rfc8(rfc8_ch3))
  t.add(rfc8(rfc8_sh3))
  assert_eq(rfc8_hex(t.hash()), rfc8_hash_sh)

  let early = @keys.early()
  assert_eq(rfc8_hex(early), rfc8_early)
  assert_eq(
    rfc8_hex(@keys.derive_secret(early, b"derived", @keys.digest.hash(b""))),
    rfc8_derived,
  )
  let hs = @keys.handshake(early, rfc8(rfc8_x25519_shared))
  assert_eq(rfc8_hex(hs), rfc8_handshake)
  assert_eq(rfc8_hex(@keys.client_handshake(hs, t.hash())), rfc8_c_hs)
  assert_eq(rfc8_hex(@keys.server_handshake(hs, t.hash())), rfc8_s_hs)
  let master = @keys.master(hs)
  assert_eq(rfc8_hex(master), rfc8_master)
}

///|
/// The rest of the ladder, after the server's flight enters the transcript: the application
/// secrets, the exporter, and the resumption master secret.
test "rfc8448: the application secrets, the exporter and the resumption master" {
  let flight = rfc8(rfc8_flight3)
  let t = @keys.Transcript::new()
  t.add(rfc8(rfc8_ch3))
  t.add(rfc8(rfc8_sh3))
  t.add(flight)
  assert_eq(rfc8_hex(t.hash()), rfc8_hash_sfin)

  let master = rfc8(rfc8_master)
  assert_eq(rfc8_hex(@keys.client_application(master, t.hash())), rfc8_c_ap)
  assert_eq(rfc8_hex(@keys.server_application(master, t.hash())), rfc8_s_ap)
  assert_eq(rfc8_hex(@keys.exporter_master(master, t.hash())), rfc8_exp_master)

  // The client's Finished is the last thing the resumption master secret covers.
  t.add(rfc8(rfc8_fin_c3))
  assert_eq(rfc8_hex(t.hash()), rfc8_hash_cfin)
  let res = @keys.resumption_master(master, t.hash())
  assert_eq(rfc8_hex(res), rfc8_res_master)
  assert_eq(rfc8_hex(@keys.resumption(res, b"\x00\x00")), rfc8_resumption)
}

///|
/// The two Finished messages: each verify_data is the MAC the RFC prints, under the key the RFC
/// expands, over the hash the RFC quotes.
test "rfc8448: both Finished messages are the trace's" {
  let flight = rfc8(rfc8_flight3)
  let t = @keys.Transcript::new()
  t.add(rfc8(rfc8_ch3))
  t.add(rfc8(rfc8_sh3))
  // Up to but not including the server's Finished: that is the transcript a server Finished
  // covers (RFC 8446 §4.4.4), and the hash of it is not one the RFC prints.
  t.add(flight[0:flight.length() - 36])

  let s_hs = rfc8(rfc8_s_hs)
  assert_eq(rfc8_hex(@keys.finished_key(s_hs)), rfc8_s_finished_key)
  assert_eq(rfc8_hex(@keys.finished(s_hs, t.hash())), rfc8_s_finished)
  assert_true(@keys.finished_ok(s_hs, t.hash(), rfc8(rfc8_s_finished)))
  assert_false(@keys.finished_ok(s_hs, t.hash(), rfc8(rfc8_c_finished)))

  t.add(flight[flight.length() - 36:])
  let c_hs = rfc8(rfc8_c_hs)
  assert_eq(rfc8_hex(@keys.finished_key(c_hs)), rfc8_c_finished_key)
  assert_eq(rfc8_hex(@keys.finished(c_hs, t.hash())), rfc8_c_finished)
  assert_true(@keys.finished_ok(c_hs, t.hash(), rfc8(rfc8_c_finished)))
}

///|
/// The record layer: the server's whole handshake flight, the client's Finished, a ticket, and
/// application data, each sealed here and compared with the record the RFC prints.
test "rfc8448: the records seal to the trace's octets" {
  // The handshake traffic keys are the ones the RFC expands from the two traffic secrets.
  assert_eq(rfc8_hex(@record.traffic(rfc8(rfc8_s_hs)).key), rfc8_s_hs_key)
  assert_eq(rfc8_hex(@record.traffic(rfc8(rfc8_s_hs)).iv), rfc8_s_hs_iv)
  assert_eq(rfc8_hex(@record.traffic(rfc8(rfc8_c_hs)).key), rfc8_c_hs_key)
  assert_eq(rfc8_hex(@record.traffic(rfc8(rfc8_c_hs)).iv), rfc8_c_hs_iv)
  assert_eq(rfc8_hex(@record.traffic(rfc8(rfc8_s_ap)).key), rfc8_s_ap_key)
  assert_eq(rfc8_hex(@record.traffic(rfc8(rfc8_s_ap)).iv), rfc8_s_ap_iv)
  assert_eq(rfc8_hex(@record.traffic(rfc8(rfc8_c_ap)).key), rfc8_c_ap_key)
  assert_eq(rfc8_hex(@record.traffic(rfc8(rfc8_c_ap)).iv), rfc8_c_ap_iv)

  let server = @record.Cipher::new(rfc8(rfc8_s_hs))
  assert_eq(
    rfc8_hex(server.seal(@record.Kind::Handshake, rfc8(rfc8_flight3))),
    rfc8_hex(rfc8(rfc8_flight3_sealed)),
  )
  // The same record opens back into the flight, which is the direction a client takes.
  let client = @record.Cipher::new(rfc8(rfc8_c_hs))
  assert_eq(
    rfc8_hex(client.seal(@record.Kind::Handshake, rfc8(rfc8_fin_c3))),
    rfc8_hex(rfc8(rfc8_fin_c3_sealed)),
  )
  let (kind, opened) = @record.Cipher::new(rfc8(rfc8_s_hs)).open(
    rfc8(rfc8_flight3_sealed),
  )
  assert_eq(kind, @record.Kind::Handshake)
  assert_eq(rfc8_hex(opened), rfc8_hex(rfc8(rfc8_flight3)))
}

///|
/// The application keys, whose sequence numbers start at zero for the ticket and run on from
/// there: a ticket, then application data, then an alert, each under the next number.
test "rfc8448: the application records and the alert advance one sequence" {
  let server = @record.Cipher::new(rfc8(rfc8_s_ap))
  assert_eq(
    rfc8_hex(server.seal(@record.Kind::Handshake, rfc8(rfc8_nst3)))[0:20],
    "17030300de3a6b8f9041",
  )
  let app = rfc8(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
  )
  assert_eq(
    rfc8_hex(server.seal(@record.Kind::ApplicationData, app)),
    rfc8_hex(rfc8(rfc8_app_s3_sealed)),
  )

  let client = @record.Cipher::new(rfc8(rfc8_c_ap))
  assert_eq(
    rfc8_hex(client.seal(@record.Kind::ApplicationData, app)),
    rfc8_hex(rfc8(rfc8_app_c3_sealed)),
  )
  // RFC 8446 §6: an alert after the handshake travels under the application keys.
  assert_eq(
    rfc8_hex(client.seal(@record.Kind::Alert, b"\x01\x00")),
    rfc8_hex(rfc8(rfc8_alert_c3_sealed)),
  )
}

///|
/// §5: the transcript of a retried handshake begins with a synthetic message_hash in place of the
/// first ClientHello (RFC 8446 §4.4.1). The hash the RFC quotes after ServerHello is what says
/// the substitution was made the way the specification makes it.
test "rfc8448: a retried handshake's transcript starts with message_hash" {
  let ch1 = rfc8(rfc8_ch5)
  let hrr = rfc8(rfc8_hrr5)
  // The retry is a ServerHello on the wire, and its random is the one reserved for it.
  let retry = @msg.read_server_hello(hrr[4:])
  assert_true(retry is Some(_))
  assert_eq(
    rfc8_hex(hrr[6:38]),
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c",
  )

  let t = @keys.Transcript::new()
  t.add(@msg.frame(@msg.Other(254), @keys.digest.hash(ch1)))
  t.add(hrr)
  t.add(rfc8(rfc8_ch5b))
  t.add(rfc8(rfc8_sh5b))
  assert_eq(rfc8_hex(t.hash()), rfc8_hrr_hash)

  // And the ladder above it matches, which is what puts the substitution on the handshake's path
  // rather than only in this test.
  let hs = @keys.handshake(rfc8(rfc8_early), rfc8(rfc8_p256_shared))
  assert_eq(rfc8_hex(hs), rfc8_hrr_handshake)
  assert_eq(rfc8_hex(@keys.client_handshake(hs, t.hash())), rfc8_hrr_c_hs)
  assert_eq(rfc8_hex(@keys.server_handshake(hs, t.hash())), rfc8_hrr_s_hs)
  assert_eq(rfc8_hex(@keys.master(hs)), rfc8_hrr_master)
}

// ------------------------------------------------------------------ §4, resumption

// The PSK §4 resumes with is §3's resumption secret (`rfc8_resumption`), and everything below hangs
// off it: the Early Secret a PSK makes instead of a zero one, the binder that authenticates the
// hello carrying it, and the traffic secret the first 0-RTT record is written under.

///|
let rfc8_early_psk : String = "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c"

///|
let rfc8_binder_key : String = "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256"

///|
let rfc8_binder_finished_key : String = "5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa"

///|
let rfc8_binder : String = "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"
// The binder covers the hello with its binders removed; the early traffic secret covers the whole
// of it. The two hashes are the RFC's, and they are what keeps those two transcripts apart.

///|
let rfc8_binder_hash : String = "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14"

///|
let rfc8_early_hash : String = "08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913"

///|
let rfc8_c_e_traffic : String = "3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62"

///|
let rfc8_e_exp_master : String = "b2026866610937d7423e5be90862ccf24c0e6091186d34f812089ff5be2ef7df"

///|
/// §4: a handshake that resumes. The early secret is over the PSK rather than over zeros, the
/// binder is a Finished over the truncated hello, and the early traffic secret is what a client
/// writes its 0-RTT data under — three different transcripts, three different answers.
test "rfc8448: a PSK's early secret, its binder and its early traffic secret" {
  let psk = rfc8(rfc8_resumption)
  let early = @keys.early(psk=psk[:])
  assert_eq(rfc8_hex(early), rfc8_early_psk)

  let binder_key = @keys.binder_key(early)
  assert_eq(rfc8_hex(binder_key), rfc8_binder_key)
  assert_eq(rfc8_hex(@keys.finished_key(binder_key)), rfc8_binder_finished_key)
  assert_eq(
    rfc8_hex(@keys.finished(binder_key, rfc8(rfc8_binder_hash))),
    rfc8_binder,
  )
  // The same MAC over the whole hello's hash is a different value, which is what says the binder
  // is over the truncated hello and not the one that goes on the wire.
  assert_true(
    @keys.finished(binder_key, rfc8(rfc8_early_hash)) != rfc8(rfc8_binder),
  )

  assert_eq(
    rfc8_hex(@keys.client_early(early, rfc8(rfc8_early_hash))),
    rfc8_c_e_traffic,
  )
  assert_eq(
    rfc8_hex(@keys.derive_secret(early, b"e exp master", rfc8(rfc8_early_hash))),
    rfc8_e_exp_master,
  )
}
