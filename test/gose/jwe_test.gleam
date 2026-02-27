import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gose
import gose/jwa
import gose/jwe
import gose/jwk
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import kryptos/crypto
import qcheck

pub fn dir_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jwe_direct_generator(),
      qcheck.non_empty_byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JweDirectEncWithKey(enc, key), payload) = tuple

      let assert Ok(encrypted) =
        jwe.new_direct(enc)
        |> jwe.encrypt(key, payload)

      let assert Ok(token) = jwe.serialize_compact(encrypted)
      let assert Ok(parsed) = jwe.parse_compact(token)
      let assert Ok(decryptor) = jwe.key_decryptor(jwa.JweDirect, enc, [key])
      let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

      assert decrypted == payload
    },
  )
}

pub fn aes_kw_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jwe_aes_kw_generator(),
      qcheck.non_empty_byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JweAesKwWithKey(alg, enc, key), payload) = tuple

      let assert Ok(encrypted) =
        jwe.new_aes_kw(alg, enc)
        |> jwe.encrypt(key, payload)

      let assert Ok(token) = jwe.serialize_compact(encrypted)
      let assert Ok(parsed) = jwe.parse_compact(token)
      let assert Ok(decryptor) =
        jwe.key_decryptor(jwa.JweAesKeyWrap(jwa.AesKw, alg), enc, [key])
      let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

      assert decrypted == payload
    },
  )
}

pub fn aes_gcm_kw_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jwe_aes_gcm_kw_generator(),
      qcheck.non_empty_byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JweAesGcmKwWithKey(alg, enc, key), payload) = tuple

      let assert Ok(encrypted) =
        jwe.new_aes_gcm_kw(alg, enc)
        |> jwe.encrypt(key, payload)

      let assert Ok(token) = jwe.serialize_compact(encrypted)
      let assert Ok(parsed) = jwe.parse_compact(token)
      let assert Ok(decryptor) =
        jwe.key_decryptor(jwa.JweAesKeyWrap(jwa.AesGcmKw, alg), enc, [key])
      let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

      assert decrypted == payload
    },
  )
}

pub fn rsa_roundtrip_test() {
  let key = fixtures.rsa_private_key()
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jwe_rsa_alg_generator(),
      generators.jwe_enc_generator(),
    ),
    fn(tuple) {
      let #(alg, enc) = tuple
      let payload = <<"test payload for RSA":utf8>>

      let assert Ok(encrypted) =
        jwe.new_rsa(alg, enc)
        |> jwe.encrypt(key, payload)

      let assert Ok(token) = jwe.serialize_compact(encrypted)
      let assert Ok(parsed) = jwe.parse_compact(token)
      let assert Ok(decryptor) = jwe.key_decryptor(jwa.JweRsa(alg), enc, [key])
      let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

      assert decrypted == payload
    },
  )
}

pub fn ecdh_es_roundtrip_test() {
  let ec_p256_key = fixtures.ec_p256_key()
  let ec_p384_key = fixtures.ec_p384_key()
  let ec_p521_key = fixtures.ec_p521_key()
  let x25519_key = fixtures.x25519_key()
  let x448_key = fixtures.x448_key()
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jwe_ecdh_es_generator(
        ec_p256_key,
        ec_p384_key,
        ec_p521_key,
        x25519_key,
        x448_key,
      ),
      generators.jwe_enc_generator(),
    ),
    fn(tuple) {
      let #(generators.JweEcdhEsWithKey(alg, key), enc) = tuple
      let payload = <<"ECDH-ES test payload":utf8>>

      let assert Ok(encrypted) =
        jwe.new_ecdh_es(alg, enc)
        |> jwe.encrypt(key, payload)

      let assert Ok(token) = jwe.serialize_compact(encrypted)
      let assert Ok(parsed) = jwe.parse_compact(token)
      let assert Ok(decryptor) =
        jwe.key_decryptor(jwa.JweEcdhEs(alg), enc, [key])
      let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

      assert decrypted == payload
    },
  )
}

pub fn pbes2_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jwe_pbes2_alg_generator(),
      generators.jwe_enc_generator(),
    ),
    fn(tuple) {
      let #(alg, enc) = tuple
      let password = "too many secrets"
      let payload = <<"PBES2 test payload":utf8>>

      let assert Ok(unsigned) =
        jwe.new_pbes2(alg, enc)
        |> jwe.with_p2c(1000)

      let assert Ok(encrypted) =
        jwe.encrypt_with_password(unsigned, password, payload)
      let assert Ok(token) = jwe.serialize_compact(encrypted)
      let assert Ok(parsed) = jwe.parse_compact(token)
      let decryptor = jwe.password_decryptor(alg, enc, password)
      let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

      assert decrypted == payload
    },
  )
}

pub fn pbes2_default_p2c_roundtrip_test() {
  let password = "too many secrets"
  let payload = <<"PBES2 default p2c":utf8>>

  let unsigned = jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes256))

  let assert Ok(encrypted) =
    jwe.encrypt_with_password(unsigned, password, payload)
  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)
  let decryptor =
    jwe.password_decryptor(
      jwa.Pbes2Sha256Aes128Kw,
      jwa.AesGcm(jwa.Aes256),
      password,
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

  assert decrypted == payload
}

pub fn ecdh_es_apu_apv_roundtrip_test() {
  let ec_key = fixtures.ec_p256_key()
  let payload = <<"ECDH-ES with APU/APV":utf8>>
  let apu = <<"sender@example.com":utf8>>
  let apv = <<"recipient@example.com":utf8>>

  let assert Ok(encrypted) =
    jwe.new_ecdh_es(jwa.EcdhEsAesKw(jwa.Aes128), jwa.AesGcm(jwa.Aes256))
    |> jwe.with_apu(apu)
    |> jwe.with_apv(apv)
    |> jwe.encrypt(ec_key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes128)),
      jwa.AesGcm(jwa.Aes256),
      [ec_key],
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

  assert decrypted == payload
}

pub fn header_accessors_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"test payload":utf8>>

  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_kid("my-key-id")
    |> jwe.with_typ("JWT")
    |> jwe.with_cty("application/json")
    |> jwe.encrypt(key, plaintext)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)

  assert jwe.alg(parsed) == jwa.JweDirect
  assert jwe.enc(parsed) == jwa.AesGcm(jwa.Aes256)
  assert jwe.kid(parsed) == Ok("my-key-id")
  assert jwe.typ(parsed) == Ok("JWT")
  assert jwe.cty(parsed) == Ok("application/json")

  let assert Ok(encrypted2) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, plaintext)

  let assert Ok(token2) = jwe.serialize_compact(encrypted2)
  let assert Ok(parsed2) = jwe.parse_compact(token2)

  assert jwe.kid(parsed2) == Error(Nil)
  assert jwe.typ(parsed2) == Error(Nil)
  assert jwe.cty(parsed2) == Error(Nil)
}

pub fn json_roundtrip_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"hello world":utf8>>

  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, plaintext)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])

  let json_flat =
    jwe.serialize_json_flattened(encrypted)
    |> json.to_string
  let assert Ok(parsed_flat) = jwe.parse_json(json_flat)
  let assert Ok(decrypted_flat) = jwe.decrypt(decryptor, parsed_flat)
  assert decrypted_flat == plaintext

  let json_gen =
    jwe.serialize_json_general(encrypted)
    |> json.to_string
  let assert Ok(parsed_gen) = jwe.parse_json(json_gen)
  let assert Ok(decrypted_gen) = jwe.decrypt(decryptor, parsed_gen)
  assert decrypted_gen == plaintext
}

pub fn aad_json_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple3(
      generators.jwe_direct_generator(),
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JweDirectEncWithKey(enc, key), plaintext, aad) = tuple

      let assert Ok(encrypted) =
        jwe.new_direct(enc)
        |> jwe.with_aad(aad)
        |> jwe.encrypt(key, plaintext)

      let json_str =
        jwe.serialize_json_flattened(encrypted)
        |> json.to_string
      let assert Ok(parsed) = jwe.parse_json(json_str)
      let assert Ok(decryptor) = jwe.key_decryptor(jwa.JweDirect, enc, [key])
      let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

      assert decrypted == plaintext
      assert jwe.aad(parsed) == Ok(aad)
    },
  )
}

pub fn aad_compact_rejection_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))

  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_aad(<<"extra context":utf8>>)
    |> jwe.encrypt(key, <<"hello":utf8>>)

  let assert Error(gose.InvalidState(msg)) = jwe.serialize_compact(encrypted)
  assert msg
    == "cannot serialize to compact format: AAD is only supported in JSON serialization"

  let assert Ok(encrypted2) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, <<"hello":utf8>>)

  let assert Ok(_) = jwe.serialize_compact(encrypted2)
}

pub fn aad_accessor_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))

  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, <<"hello":utf8>>)

  assert jwe.aad(encrypted) == Error(Nil)
}

pub fn aad_accessor_on_built_jwe_with_aad_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))

  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_aad(<<"extra-context":utf8>>)
    |> jwe.encrypt(key, <<"hello":utf8>>)

  assert jwe.aad(encrypted) == Ok(<<"extra-context":utf8>>)
}

pub fn json_per_recipient_unprotected_header_test() {
  let assert Ok(parsed) =
    parse_json_with_extra([
      #("header", json.object([#("kid", json.string("my-key"))])),
    ])
  assert jwe.has_unprotected_header(parsed)
  assert !jwe.has_shared_unprotected_header(parsed)

  let decoder = {
    use kid <- decode.field("kid", decode.string)
    decode.success(kid)
  }
  let assert Ok("my-key") = jwe.decode_unprotected_header(parsed, decoder)
}

pub fn json_shared_unprotected_header_test() {
  let assert Ok(parsed) =
    parse_json_with_extra([
      #("unprotected", json.object([#("kid", json.string("shared-key"))])),
    ])
  assert jwe.has_shared_unprotected_header(parsed)
  assert !jwe.has_unprotected_header(parsed)

  let decoder = {
    use kid <- decode.field("kid", decode.string)
    decode.success(kid)
  }
  let assert Ok("shared-key") =
    jwe.decode_shared_unprotected_header(parsed, decoder)
}

pub fn wrong_key_type_test() {
  let rsa_key = fixtures.rsa_private_key()
  let octet_key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))

  let result1 =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(rsa_key, <<"test":utf8>>)

  assert result1
    == Error(gose.InvalidState("direct encryption requires an octet key"))

  let result2 =
    jwe.new_rsa(jwa.RsaOaepSha1, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(octet_key, <<"test":utf8>>)

  assert result2
    == Error(gose.InvalidState("RSA encryption requires an RSA key"))
}

pub fn wrong_key_size_test() {
  let small_key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes128))

  let result =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(small_key, <<"test":utf8>>)

  assert result
    == Error(gose.InvalidState(
      "direct encryption requires 32-byte key for A256GCM, got 16",
    ))
}

pub fn decrypt_with_wrong_key_test() {
  let key1 = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let key2 = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))

  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key1, <<"test":utf8>>)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key2])
  let result = jwe.decrypt(decryptor, encrypted)
  assert result == Error(gose.CryptoError("AES-GCM decryption failed"))
}

pub fn parse_invalid_format_test() {
  let result1 = jwe.parse_compact("not.a.valid.token")
  assert result1
    == Error(gose.ParseError("invalid compact serialization: expected 5 parts"))

  let result2 = jwe.parse_compact("!!!.AAA.BBB.CCC.DDD")
  assert result2 == Error(gose.ParseError("invalid header base64"))
}

pub fn crit_header_validation_test() {
  let result1 = parse_with_header([#("crit", json.array(["exp"], json.string))])
  assert result1 == Error(gose.ParseError("unsupported critical header: exp"))

  let result2 = parse_with_header([#("crit", json.preprocessed_array([]))])
  assert result2 == Error(gose.ParseError("crit array must not be empty"))

  let result3 = parse_with_header([#("crit", json.array(["alg"], json.string))])
  assert result3 == Error(gose.ParseError("standard header in crit: alg"))

  let result4 =
    parse_with_header([#("crit", json.array(["exp", "exp"], json.string))])
  assert result4
    == Error(gose.ParseError("crit array contains duplicate values"))
}

pub fn header_rejects_zip_test() {
  let result = parse_with_header([#("zip", json.string("DEF"))])
  assert result == Error(gose.ParseError("unsupported header: zip"))
}

pub fn header_rejects_epk_for_dir_test() {
  let epk =
    json.object([
      #("kty", json.string("EC")),
      #("crv", json.string("P-256")),
      #("x", json.string("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")),
      #("y", json.string("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")),
    ])
  let result = parse_with_header([#("epk", epk)])
  assert result == Error(gose.ParseError("epk header not allowed for dir"))
}

pub fn header_rejects_pbes2_fields_for_dir_test() {
  let result =
    parse_with_header([
      #("p2s", json.string("c2FsdA")),
      #("p2c", json.int(4096)),
    ])
  assert result == Error(gose.ParseError("p2s header not allowed for dir"))
}

pub fn encrypted_key_validation_test() {
  let header_json =
    json.to_string(
      json.object([
        #("alg", json.string("dir")),
        #("enc", json.string("A256GCM")),
      ]),
    )
    |> bit_array.from_string

  let protected_b64 = bit_array.base64_url_encode(header_json, False)
  let ek_b64 = bit_array.base64_url_encode(<<"fake-key":utf8>>, False)
  let iv_b64 = bit_array.base64_url_encode(<<0:96>>, False)
  let ct_b64 = bit_array.base64_url_encode(<<"ct":utf8>>, False)
  let tag_b64 = bit_array.base64_url_encode(<<0:128>>, False)

  let token1 =
    protected_b64
    <> "."
    <> ek_b64
    <> "."
    <> iv_b64
    <> "."
    <> ct_b64
    <> "."
    <> tag_b64
  let result1 = jwe.parse_compact(token1)
  assert result1
    == Error(gose.ParseError("encrypted_key must be empty for dir"))

  let kw_protected_b64 =
    json.to_string(
      json.object([
        #("alg", json.string("A128KW")),
        #("enc", json.string("A256GCM")),
      ]),
    )
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)

  let token2 =
    kw_protected_b64 <> ".." <> iv_b64 <> "." <> ct_b64 <> "." <> tag_b64
  let result2 = jwe.parse_compact(token2)
  assert result2 == Error(gose.ParseError("encrypted_key required for A128KW"))
}

pub fn p2c_builder_rejects_out_of_range_test() {
  let unsigned = jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes256))

  let result1 = jwe.with_p2c(unsigned, 10_000_001)
  assert result1
    == Error(gose.InvalidState("p2c must be >= 1000 and <= 10000000"))

  let result2 = jwe.with_p2c(unsigned, 999)
  assert result2
    == Error(gose.InvalidState("p2c must be >= 1000 and <= 10000000"))

  let result3 = jwe.with_p2c(unsigned, 0)
  assert result3
    == Error(gose.InvalidState("p2c must be >= 1000 and <= 10000000"))
}

pub fn p2c_builder_accepts_minimum_test() {
  let unsigned = jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes256))
  let assert Ok(_) = jwe.with_p2c(unsigned, 1000)
}

pub fn p2c_parse_rejects_too_low_test() {
  let result = parse_pbes2_with_p2c(999)
  assert result == Error(gose.ParseError("p2c must be >= 1000 and <= 10000000"))
}

pub fn p2c_parse_rejects_too_high_test() {
  let result = parse_pbes2_with_p2c(999_999_999)
  assert result == Error(gose.ParseError("p2c must be >= 1000 and <= 10000000"))
}

pub fn ecdh_es_curve_mismatch_test() {
  let ec_p256_key = fixtures.ec_p256_key()
  let ec_p384_key = fixtures.ec_p384_key()

  let assert Ok(encrypted) =
    jwe.new_ecdh_es(jwa.EcdhEsDirect, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(ec_p256_key, <<"test":utf8>>)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweEcdhEs(jwa.EcdhEsDirect), jwa.AesGcm(jwa.Aes256), [
      ec_p384_key,
    ])
  let result = jwe.decrypt(decryptor, parsed)
  assert result == Error(gose.InvalidState("ephemeral key curve mismatch"))
}

pub fn decryptor_algorithm_pinning_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))

  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, <<"test payload":utf8>>)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)

  let assert Ok(decryptor1) =
    jwe.key_decryptor(
      jwa.JweAesKeyWrap(jwa.AesKw, jwa.Aes128),
      jwa.AesGcm(jwa.Aes256),
      [
        key,
      ],
    )
  let assert Error(gose.InvalidState(msg1)) = jwe.decrypt(decryptor1, parsed)
  assert msg1 == "algorithm mismatch: expected A128KW, got dir"

  let assert Ok(decryptor2) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes128), [key])
  let assert Error(gose.InvalidState(msg2)) = jwe.decrypt(decryptor2, parsed)
  assert msg2 == "encryption mismatch: expected A128GCM, got A256GCM"

  let assert Ok(decryptor3) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor3, parsed)
  assert decrypted == <<"test payload":utf8>>
}

pub fn decryptor_multiple_keys_test() {
  let key1 = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let key1 = jwk.with_kid(key1, "key-1")
  let key2 = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let key2 = jwk.with_kid(key2, "key-2")

  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_kid("key-2")
    |> jwe.encrypt(key2, <<"test payload":utf8>>)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [
      key1,
      key2,
    ])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  assert decrypted == <<"test payload":utf8>>
}

pub fn key_alg_validation_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))

  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, <<"test":utf8>>)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)

  let key_wrong_alg =
    jwk.with_alg(key, jwk.Jwe(jwa.JweAesKeyWrap(jwa.AesKw, jwa.Aes128)))
  let assert Error(gose.InvalidState(msg)) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [
      key_wrong_alg,
    ])
  assert msg == "key algorithm mismatch: key has A128KW, expected dir"

  let key_matching_alg = jwk.with_alg(key, jwk.Jwe(jwa.JweDirect))
  let assert Ok(decryptor_match) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [
      key_matching_alg,
    ])
  let assert Ok(decrypted) = jwe.decrypt(decryptor_match, parsed)
  assert decrypted == <<"test":utf8>>

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted2) = jwe.decrypt(decryptor, parsed)
  assert decrypted2 == <<"test":utf8>>
}

pub fn key_decryptor_rsa_algorithm_pinning_test() {
  let key = fixtures.rsa_private_key()

  let assert Ok(encrypted) =
    jwe.new_rsa(jwa.RsaOaepSha256, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, <<"test payload":utf8>>)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)

  let assert Ok(decryptor1) =
    jwe.key_decryptor(jwa.JweRsa(jwa.RsaOaepSha1), jwa.AesGcm(jwa.Aes256), [key])
  let assert Error(gose.InvalidState(msg1)) = jwe.decrypt(decryptor1, parsed)
  assert msg1 == "algorithm mismatch: expected RSA-OAEP, got RSA-OAEP-256"

  let assert Ok(decryptor2) =
    jwe.key_decryptor(jwa.JweRsa(jwa.RsaOaepSha256), jwa.AesGcm(jwa.Aes128), [
      key,
    ])
  let assert Error(gose.InvalidState(msg2)) = jwe.decrypt(decryptor2, parsed)
  assert msg2 == "encryption mismatch: expected A128GCM, got A256GCM"

  let assert Ok(decryptor3) =
    jwe.key_decryptor(jwa.JweRsa(jwa.RsaOaepSha256), jwa.AesGcm(jwa.Aes256), [
      key,
    ])
  let assert Ok(decrypted) = jwe.decrypt(decryptor3, parsed)
  assert decrypted == <<"test payload":utf8>>
}

pub fn key_decryptor_rsa_multiple_keys_test() {
  let key1 = fixtures.rsa_private_key() |> jwk.with_kid("key-1")
  let assert Ok(key2) = jwk.generate_rsa(2048)
  let key2 = jwk.with_kid(key2, "key-2")

  let assert Ok(encrypted) =
    jwe.new_rsa(jwa.RsaOaepSha256, jwa.AesGcm(jwa.Aes256))
    |> jwe.with_kid("key-2")
    |> jwe.encrypt(key2, <<"test payload":utf8>>)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweRsa(jwa.RsaOaepSha256), jwa.AesGcm(jwa.Aes256), [
      key1,
      key2,
    ])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  assert decrypted == <<"test payload":utf8>>
}

pub fn password_decryptor_algorithm_pinning_test() {
  let password = "too many secrets"

  let assert Ok(unsigned) =
    jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes256))
    |> jwe.with_p2c(1000)

  let assert Ok(encrypted) =
    jwe.encrypt_with_password(unsigned, password, <<"test payload":utf8>>)
  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)

  let decryptor1 =
    jwe.password_decryptor(
      jwa.Pbes2Sha512Aes256Kw,
      jwa.AesGcm(jwa.Aes256),
      password,
    )
  let assert Error(gose.InvalidState(msg1)) = jwe.decrypt(decryptor1, parsed)
  assert msg1
    == "algorithm mismatch: expected PBES2-HS512+A256KW, got PBES2-HS256+A128KW"

  let decryptor2 =
    jwe.password_decryptor(
      jwa.Pbes2Sha256Aes128Kw,
      jwa.AesGcm(jwa.Aes128),
      password,
    )
  let assert Error(gose.InvalidState(msg2)) = jwe.decrypt(decryptor2, parsed)
  assert msg2 == "encryption mismatch: expected A128GCM, got A256GCM"

  let decryptor3 =
    jwe.password_decryptor(
      jwa.Pbes2Sha256Aes128Kw,
      jwa.AesGcm(jwa.Aes256),
      password,
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor3, parsed)
  assert decrypted == <<"test payload":utf8>>
}

fn parse_with_header(
  extra_fields: List(#(String, json.Json)),
) -> Result(jwe.Jwe(jwe.Encrypted, Nil, jwe.Parsed), gose.GoseError) {
  let header_json =
    json.object([
      #("alg", json.string("dir")),
      #("enc", json.string("A256GCM")),
      ..extra_fields
    ])
    |> json.to_string
    |> bit_array.from_string

  let protected_b64 = bit_array.base64_url_encode(header_json, False)
  let iv_b64 = bit_array.base64_url_encode(<<0:96>>, False)
  let ct_b64 = bit_array.base64_url_encode(<<"ct":utf8>>, False)
  let tag_b64 = bit_array.base64_url_encode(<<0:128>>, False)

  let token = protected_b64 <> ".." <> iv_b64 <> "." <> ct_b64 <> "." <> tag_b64
  jwe.parse_compact(token)
}

fn parse_json_with_extra(
  extra_fields: List(#(String, json.Json)),
) -> Result(jwe.Jwe(jwe.Encrypted, Nil, jwe.Parsed), gose.GoseError) {
  let header_json =
    json.object([
      #("alg", json.string("dir")),
      #("enc", json.string("A256GCM")),
    ])
    |> json.to_string
    |> bit_array.from_string

  let protected_b64 = bit_array.base64_url_encode(header_json, False)
  let iv_b64 = bit_array.base64_url_encode(<<0:96>>, False)
  let ct_b64 = bit_array.base64_url_encode(<<"ciphertext":utf8>>, False)
  let tag_b64 = bit_array.base64_url_encode(<<0:128>>, False)

  let json_str =
    json.object([
      #("protected", json.string(protected_b64)),
      #("iv", json.string(iv_b64)),
      #("ciphertext", json.string(ct_b64)),
      #("tag", json.string(tag_b64)),
      ..extra_fields
    ])
    |> json.to_string

  jwe.parse_json(json_str)
}

fn parse_pbes2_with_p2c(
  p2c: Int,
) -> Result(jwe.Jwe(jwe.Encrypted, Nil, jwe.Parsed), gose.GoseError) {
  let header_json =
    json.object([
      #("alg", json.string("PBES2-HS256+A128KW")),
      #("enc", json.string("A256GCM")),
      #("p2s", json.string("AAAA")),
      #("p2c", json.int(p2c)),
    ])
    |> json.to_string
    |> bit_array.from_string

  let protected_b64 = bit_array.base64_url_encode(header_json, False)
  let token = protected_b64 <> ".AAAA.AAAA.AAAA.AAAA"
  jwe.parse_compact(token)
}

pub fn rsa_pkcs1v15_tampered_encrypted_key_produces_aead_error_test() {
  let key = fixtures.rsa_private_key()
  let payload = <<"test payload":utf8>>

  let assert Ok(encrypted) =
    jwe.new_rsa(jwa.RsaPkcs1v15, jwa.AesGcm(jwa.Aes128))
    |> jwe.encrypt(key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let parts = split_compact_jwe(token)
  let tampered_encrypted_key = tamper_base64_component(parts.encrypted_key)
  let tampered_token =
    parts.protected
    <> "."
    <> tampered_encrypted_key
    <> "."
    <> parts.iv
    <> "."
    <> parts.ciphertext
    <> "."
    <> parts.tag

  let assert Ok(parsed) = jwe.parse_compact(tampered_token)

  // Decryption should fail with a CryptoError (AEAD failure),
  // NOT an RSA-specific error like "RSA PKCS1v15 decryption failed"
  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweRsa(jwa.RsaPkcs1v15), jwa.AesGcm(jwa.Aes128), [key])
  case jwe.decrypt(decryptor, parsed) {
    Error(gose.CryptoError(msg)) -> {
      // Per RFC 7516 Section 11.5: Must not distinguish RSA padding errors
      // The error should be from AEAD (AES-GCM), not from RSA unwrapping
      assert msg != "RSA PKCS1v15 decryption failed"
    }
    Ok(_) -> panic as "Decryption should have failed with tampered key"
    Error(other) ->
      panic as { "Expected CryptoError, got: " <> error_to_string(other) }
  }
}

pub fn rsa_pkcs1v15_valid_decryption_still_works_test() {
  let key = fixtures.rsa_private_key()
  let payload = <<"valid decryption test":utf8>>

  let assert Ok(encrypted) =
    jwe.new_rsa(jwa.RsaPkcs1v15, jwa.AesGcm(jwa.Aes128))
    |> jwe.encrypt(key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweRsa(jwa.RsaPkcs1v15), jwa.AesGcm(jwa.Aes128), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

  assert decrypted == payload
}

pub fn rsa_pkcs1v15_random_encrypted_key_produces_uniform_aead_failure_test() {
  let key = fixtures.rsa_private_key()

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(20),
    generators.jwe_enc_generator(),
    fn(enc) {
      let random_bytes = crypto.random_bytes(256)
      let payload = <<"test":utf8>>

      let assert Ok(encrypted) =
        jwe.new_rsa(jwa.RsaPkcs1v15, enc)
        |> jwe.encrypt(key, payload)

      let assert Ok(token) = jwe.serialize_compact(encrypted)
      let parts = split_compact_jwe(token)
      let garbage_key = bit_array.base64_url_encode(random_bytes, False)
      let garbage_token =
        parts.protected
        <> "."
        <> garbage_key
        <> "."
        <> parts.iv
        <> "."
        <> parts.ciphertext
        <> "."
        <> parts.tag

      let assert Ok(parsed) = jwe.parse_compact(garbage_token)

      let assert Ok(decryptor) =
        jwe.key_decryptor(jwa.JweRsa(jwa.RsaPkcs1v15), enc, [key])
      case jwe.decrypt(decryptor, parsed) {
        Error(gose.CryptoError(msg)) -> {
          assert msg != "RSA PKCS1v15 decryption failed"
        }
        Ok(_) -> panic as "Should not decrypt with garbage key"
        Error(_) -> panic as "Expected CryptoError"
      }
    },
  )
}

pub fn rsa_pkcs1v15_tampered_header_enc_produces_aead_error_test() {
  let key = fixtures.rsa_private_key()
  let payload = <<"test payload":utf8>>

  let assert Ok(encrypted) =
    jwe.new_rsa(jwa.RsaPkcs1v15, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let parts = split_compact_jwe(token)

  let tampered_header =
    json.object([
      #("alg", json.string("RSA1_5")),
      #("enc", json.string("A128GCM")),
    ])
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)

  let tampered_token =
    tampered_header
    <> "."
    <> parts.encrypted_key
    <> "."
    <> parts.iv
    <> "."
    <> parts.ciphertext
    <> "."
    <> parts.tag

  let assert Ok(parsed) = jwe.parse_compact(tampered_token)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweRsa(jwa.RsaPkcs1v15), jwa.AesGcm(jwa.Aes128), [key])
  assert jwe.decrypt(decryptor, parsed)
    == Error(gose.CryptoError("AES-GCM decryption failed"))
}

type JweParts {
  JweParts(
    protected: String,
    encrypted_key: String,
    iv: String,
    ciphertext: String,
    tag: String,
  )
}

fn split_compact_jwe(token: String) -> JweParts {
  let assert [protected, encrypted_key, iv, ciphertext, tag] =
    string.split(token, ".")
  JweParts(protected:, encrypted_key:, iv:, ciphertext:, tag:)
}

fn tamper_base64_component(b64: String) -> String {
  let assert Ok(decoded) = bit_array.base64_url_decode(b64)
  let tampered = case decoded {
    <<first, rest:bits>> -> {
      let modified = case first {
        255 -> 0
        n -> n + 1
      }
      <<modified, rest:bits>>
    }
    _ -> decoded
  }
  bit_array.base64_url_encode(tampered, False)
}

fn error_to_string(err: gose.GoseError) -> String {
  case err {
    gose.ParseError(msg) -> "ParseError: " <> msg
    gose.CryptoError(msg) -> "CryptoError: " <> msg
    gose.InvalidState(msg) -> "InvalidState: " <> msg
  }
}

pub fn unprotected_header_roundtrip_flattened_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"unprotected header test":utf8>>

  let assert Ok(unencrypted) = {
    let base = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    use j <- result.try(jwe.with_shared_unprotected(
      base,
      "x-shared",
      json.string("shared-value"),
    ))
    jwe.with_unprotected(j, "x-recipient", json.string("recipient-value"))
  }

  let assert Ok(encrypted) = jwe.encrypt(unencrypted, key, plaintext)
  let json_str = json.to_string(jwe.serialize_json_flattened(encrypted))

  let assert Ok(parsed) = jwe.parse_json(json_str)
  assert jwe.has_shared_unprotected_header(parsed)
  assert jwe.has_unprotected_header(parsed)

  let shared_decoder = {
    use shared <- decode.field("x-shared", decode.string)
    decode.success(shared)
  }
  let assert Ok("shared-value") =
    jwe.decode_shared_unprotected_header(parsed, shared_decoder)

  let recipient_decoder = {
    use recipient <- decode.field("x-recipient", decode.string)
    decode.success(recipient)
  }
  let assert Ok("recipient-value") =
    jwe.decode_unprotected_header(parsed, recipient_decoder)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn unprotected_header_roundtrip_general_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"unprotected header general test":utf8>>

  let assert Ok(unencrypted) = {
    let base = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    use j <- result.try(jwe.with_shared_unprotected(
      base,
      "x-shared",
      json.string("general-shared"),
    ))
    jwe.with_unprotected(j, "x-recipient", json.string("general-recipient"))
  }

  let assert Ok(encrypted) = jwe.encrypt(unencrypted, key, plaintext)
  let json_str = json.to_string(jwe.serialize_json_general(encrypted))

  let assert Ok(parsed) = jwe.parse_json(json_str)
  assert jwe.has_shared_unprotected_header(parsed)
  assert jwe.has_unprotected_header(parsed)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn per_recipient_only_roundtrip_flattened_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"per-recipient only flattened":utf8>>

  let assert Ok(unencrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_unprotected("x-recipient", json.string("recipient-value"))

  let assert Ok(encrypted) = jwe.encrypt(unencrypted, key, plaintext)
  let json_str = json.to_string(jwe.serialize_json_flattened(encrypted))

  let assert Ok(parsed) = jwe.parse_json(json_str)
  assert jwe.has_unprotected_header(parsed)
  assert !jwe.has_shared_unprotected_header(parsed)

  let decoder = {
    use v <- decode.field("x-recipient", decode.string)
    decode.success(v)
  }
  let assert Ok("recipient-value") =
    jwe.decode_unprotected_header(parsed, decoder)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn per_recipient_only_roundtrip_general_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"per-recipient only general":utf8>>

  let assert Ok(unencrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_unprotected("x-recipient", json.string("general-value"))

  let assert Ok(encrypted) = jwe.encrypt(unencrypted, key, plaintext)
  let json_str = json.to_string(jwe.serialize_json_general(encrypted))

  let assert Ok(parsed) = jwe.parse_json(json_str)
  assert jwe.has_unprotected_header(parsed)
  assert !jwe.has_shared_unprotected_header(parsed)

  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn jwe_header_disjointness_validation_test() {
  let header_json =
    json.to_string(
      json.object([
        #("alg", json.string("dir")),
        #("enc", json.string("A256GCM")),
        #("kid", json.string("protected-kid")),
      ]),
    )
    |> bit_array.from_string

  let protected_b64 = bit_array.base64_url_encode(header_json, False)
  let iv_b64 = bit_array.base64_url_encode(<<0:96>>, False)
  let ct_b64 = bit_array.base64_url_encode(<<"ciphertext":utf8>>, False)
  let tag_b64 = bit_array.base64_url_encode(<<0:128>>, False)

  let json_str =
    json.object([
      #("protected", json.string(protected_b64)),
      #("iv", json.string(iv_b64)),
      #("ciphertext", json.string(ct_b64)),
      #("tag", json.string(tag_b64)),
      #("unprotected", json.object([#("kid", json.string("shared-kid"))])),
    ])
    |> json.to_string

  let assert Error(gose.ParseError(msg)) = jwe.parse_json(json_str)
  assert msg
    == "header parameter appears in both protected and shared unprotected: kid"
}

pub fn jwe_alg_specific_disjointness_ecdh_es_apu_test() {
  let apu_b64 = bit_array.base64_url_encode(<<"Alice":utf8>>, False)
  let header_json =
    json.object([
      #("alg", json.string("ECDH-ES")),
      #("enc", json.string("A256GCM")),
      #("apu", json.string(apu_b64)),
    ])
    |> json.to_string
    |> bit_array.from_string

  let protected_b64 = bit_array.base64_url_encode(header_json, False)
  let iv_b64 = bit_array.base64_url_encode(<<0:96>>, False)
  let ct_b64 = bit_array.base64_url_encode(<<"ciphertext":utf8>>, False)
  let tag_b64 = bit_array.base64_url_encode(<<0:128>>, False)

  let json_str =
    json.object([
      #("protected", json.string(protected_b64)),
      #("iv", json.string(iv_b64)),
      #("ciphertext", json.string(ct_b64)),
      #("tag", json.string(tag_b64)),
      #("unprotected", json.object([#("apu", json.string(apu_b64))])),
    ])
    |> json.to_string

  let assert Error(gose.ParseError(msg)) = jwe.parse_json(json_str)
  assert msg
    == "header parameter appears in both protected and shared unprotected: apu"
}

pub fn jwe_alg_specific_disjointness_ecdh_es_apv_test() {
  let apv_b64 = bit_array.base64_url_encode(<<"Bob":utf8>>, False)
  let header_json =
    json.object([
      #("alg", json.string("ECDH-ES")),
      #("enc", json.string("A256GCM")),
      #("apv", json.string(apv_b64)),
    ])
    |> json.to_string
    |> bit_array.from_string

  let protected_b64 = bit_array.base64_url_encode(header_json, False)
  let iv_b64 = bit_array.base64_url_encode(<<0:96>>, False)
  let ct_b64 = bit_array.base64_url_encode(<<"ciphertext":utf8>>, False)
  let tag_b64 = bit_array.base64_url_encode(<<0:128>>, False)

  let json_str =
    json.object([
      #("protected", json.string(protected_b64)),
      #("iv", json.string(iv_b64)),
      #("ciphertext", json.string(ct_b64)),
      #("tag", json.string(tag_b64)),
      #("unprotected", json.object([#("apv", json.string(apv_b64))])),
    ])
    |> json.to_string

  let assert Error(gose.ParseError(msg)) = jwe.parse_json(json_str)
  assert msg
    == "header parameter appears in both protected and shared unprotected: apv"
}

pub fn jwe_alg_specific_disjointness_pbes2_p2s_test() {
  let p2s_b64 = bit_array.base64_url_encode(crypto.random_bytes(16), False)
  let header_json =
    json.object([
      #("alg", json.string("PBES2-HS256+A128KW")),
      #("enc", json.string("A256GCM")),
      #("p2s", json.string(p2s_b64)),
      #("p2c", json.int(4096)),
    ])
    |> json.to_string
    |> bit_array.from_string

  let protected_b64 = bit_array.base64_url_encode(header_json, False)
  let iv_b64 = bit_array.base64_url_encode(<<0:96>>, False)
  let ct_b64 = bit_array.base64_url_encode(<<"ciphertext":utf8>>, False)
  let tag_b64 = bit_array.base64_url_encode(<<0:128>>, False)

  let json_str =
    json.object([
      #("protected", json.string(protected_b64)),
      #("iv", json.string(iv_b64)),
      #("ciphertext", json.string(ct_b64)),
      #("tag", json.string(tag_b64)),
      #("unprotected", json.object([#("p2s", json.string(p2s_b64))])),
    ])
    |> json.to_string

  let assert Error(gose.ParseError(msg)) = jwe.parse_json(json_str)
  assert msg
    == "header parameter appears in both protected and shared unprotected: p2s"
}

pub fn jwe_alg_specific_disjointness_aes_gcm_kw_iv_test() {
  let iv_header_b64 =
    bit_array.base64_url_encode(crypto.random_bytes(12), False)
  let tag_header_b64 =
    bit_array.base64_url_encode(crypto.random_bytes(16), False)
  let header_json =
    json.object([
      #("alg", json.string("A256GCMKW")),
      #("enc", json.string("A256GCM")),
      #("iv", json.string(iv_header_b64)),
      #("tag", json.string(tag_header_b64)),
    ])
    |> json.to_string
    |> bit_array.from_string

  let protected_b64 = bit_array.base64_url_encode(header_json, False)
  let content_iv_b64 = bit_array.base64_url_encode(<<0:96>>, False)
  let ct_b64 = bit_array.base64_url_encode(<<"ciphertext":utf8>>, False)
  let content_tag_b64 = bit_array.base64_url_encode(<<0:128>>, False)

  let json_str =
    json.object([
      #("protected", json.string(protected_b64)),
      #("iv", json.string(content_iv_b64)),
      #("ciphertext", json.string(ct_b64)),
      #("tag", json.string(content_tag_b64)),
      #("unprotected", json.object([#("iv", json.string(iv_header_b64))])),
    ])
    |> json.to_string

  let assert Error(gose.ParseError(msg)) = jwe.parse_json(json_str)
  assert msg
    == "header parameter appears in both protected and shared unprotected: iv"
}

pub fn jwe_has_unprotected_header_false_when_none_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, <<"test":utf8>>)
  let json_str = json.to_string(jwe.serialize_json_flattened(encrypted))

  let assert Ok(parsed) = jwe.parse_json(json_str)
  assert !jwe.has_shared_unprotected_header(parsed)
  assert !jwe.has_unprotected_header(parsed)
}

pub fn compact_serialization_rejects_shared_unprotected_headers_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let assert Ok(unencrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_shared_unprotected("kid", json.string("key-1"))

  let assert Ok(encrypted) = jwe.encrypt(unencrypted, key, <<"test":utf8>>)
  let result = jwe.serialize_compact(encrypted)

  assert result
    == Error(gose.InvalidState(
      "cannot serialize to compact format: unprotected headers are only supported in JSON serialization",
    ))
}

pub fn compact_serialization_rejects_per_recipient_unprotected_headers_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let assert Ok(unencrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_unprotected("kid", json.string("key-1"))

  let assert Ok(encrypted) = jwe.encrypt(unencrypted, key, <<"test":utf8>>)
  let result = jwe.serialize_compact(encrypted)

  assert result
    == Error(gose.InvalidState(
      "cannot serialize to compact format: unprotected headers are only supported in JSON serialization",
    ))
}

pub fn with_shared_unprotected_last_write_wins_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let assert Ok(unencrypted) = {
    let base = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    use j <- result.try(jwe.with_shared_unprotected(
      base,
      "kid",
      json.string("first"),
    ))
    jwe.with_shared_unprotected(j, "kid", json.string("second"))
  }

  let assert Ok(encrypted) = jwe.encrypt(unencrypted, key, <<"test":utf8>>)
  let json_str = json.to_string(jwe.serialize_json_flattened(encrypted))

  let decoder = {
    use kid <- decode.field("kid", decode.string)
    decode.success(kid)
  }
  let assert Ok(parsed) = jwe.parse_json(json_str)
  let assert Ok("second") =
    jwe.decode_shared_unprotected_header(parsed, decoder)
}

pub fn with_unprotected_last_write_wins_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let assert Ok(unencrypted) = {
    let base = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    use j <- result.try(jwe.with_unprotected(base, "kid", json.string("first")))
    jwe.with_unprotected(j, "kid", json.string("second"))
  }

  let assert Ok(encrypted) = jwe.encrypt(unencrypted, key, <<"test":utf8>>)
  let json_str = json.to_string(jwe.serialize_json_flattened(encrypted))

  let decoder = {
    use kid <- decode.field("kid", decode.string)
    decode.success(kid)
  }
  let assert Ok(parsed) = jwe.parse_json(json_str)
  let assert Ok("second") = jwe.decode_unprotected_header(parsed, decoder)
}

pub fn parse_rejects_invalid_iv_length_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, <<"test":utf8>>)
  let assert Ok(token) = jwe.serialize_compact(encrypted)

  let parts = string.split(token, ".")
  let assert [protected, ek, _iv, ct, tag] = parts
  let bad_iv = bit_array.base64_url_encode(crypto.random_bytes(8), False)
  let bad_token =
    protected <> "." <> ek <> "." <> bad_iv <> "." <> ct <> "." <> tag

  let assert Error(gose.ParseError(msg)) = jwe.parse_compact(bad_token)
  assert msg == "invalid IV length: expected 12 bytes, got 8"
}

pub fn parse_rejects_invalid_tag_length_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, <<"test":utf8>>)
  let assert Ok(token) = jwe.serialize_compact(encrypted)

  let parts = string.split(token, ".")
  let assert [protected, ek, iv, ct, _tag] = parts
  let bad_tag = bit_array.base64_url_encode(crypto.random_bytes(8), False)
  let bad_token =
    protected <> "." <> ek <> "." <> iv <> "." <> ct <> "." <> bad_tag

  let assert Error(gose.ParseError(msg)) = jwe.parse_compact(bad_token)
  assert msg == "invalid tag length: expected 16 bytes, got 8"
}

pub fn parse_rejects_short_p2s_test() {
  let short_salt = bit_array.base64_url_encode(crypto.random_bytes(4), False)
  let header =
    json.object([
      #("alg", json.string("PBES2-HS256+A128KW")),
      #("enc", json.string("A128GCM")),
      #("p2s", json.string(short_salt)),
      #("p2c", json.int(1000)),
    ])
  let protected =
    bit_array.base64_url_encode(
      bit_array.from_string(json.to_string(header)),
      False,
    )
  let jwe_json =
    json.object([
      #("protected", json.string(protected)),
      #("encrypted_key", json.string("")),
      #(
        "iv",
        json.string(bit_array.base64_url_encode(crypto.random_bytes(12), False)),
      ),
      #("ciphertext", json.string("")),
      #(
        "tag",
        json.string(bit_array.base64_url_encode(crypto.random_bytes(16), False)),
      ),
    ])

  let assert Error(gose.ParseError(msg)) =
    jwe.parse_json(json.to_string(jwe_json))
  assert msg == "p2s must be at least 8 bytes"
}

pub fn with_shared_unprotected_rejects_reserved_headers_test() {
  let base = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
  list.each(["alg", "enc", "crit", "zip"], fn(name) {
    let result = jwe.with_shared_unprotected(base, name, json.string("test"))
    assert result
      == Error(gose.InvalidState(
        "protected-only header cannot be in unprotected: " <> name,
      ))
  })
}

pub fn with_unprotected_rejects_reserved_headers_test() {
  let base = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
  list.each(["alg", "enc", "crit", "zip"], fn(name) {
    let result = jwe.with_unprotected(base, name, json.string("test"))
    assert result
      == Error(gose.InvalidState(
        "protected-only header cannot be in unprotected: " <> name,
      ))
  })
}

pub fn parse_json_rejects_shared_unprotected_reserved_headers_test() {
  list.each(["alg", "enc", "crit", "zip"], fn(name) {
    let assert Error(gose.ParseError(msg)) =
      parse_json_with_extra([
        #("unprotected", json.object([#(name, json.string("test"))])),
      ])
    assert msg == "protected-only headers in unprotected: " <> name
  })
}

pub fn ecdh_es_apu_apv_must_be_distinct_encrypt_test() {
  let ec_key = fixtures.ec_p256_key()
  let payload = <<"test":utf8>>
  let same_value = <<"same@example.com":utf8>>

  let result =
    jwe.new_ecdh_es(jwa.EcdhEsAesKw(jwa.Aes128), jwa.AesGcm(jwa.Aes256))
    |> jwe.with_apu(same_value)
    |> jwe.with_apv(same_value)
    |> jwe.encrypt(ec_key, payload)

  assert result == Error(gose.InvalidState("apu and apv must be distinct"))
}

pub fn ecdh_es_apu_apv_must_be_distinct_parse_test() {
  let same_value_b64 =
    bit_array.base64_url_encode(<<"same@example.com":utf8>>, False)
  let epk =
    json.object([
      #("kty", json.string("EC")),
      #("crv", json.string("P-256")),
      #("x", json.string("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")),
      #("y", json.string("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")),
    ])
  let header =
    json.object([
      #("alg", json.string("ECDH-ES+A128KW")),
      #("enc", json.string("A256GCM")),
      #("epk", epk),
      #("apu", json.string(same_value_b64)),
      #("apv", json.string(same_value_b64)),
    ])
  let protected_b64 =
    header
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)

  let iv_b64 = bit_array.base64_url_encode(crypto.random_bytes(12), False)
  let ciphertext_b64 = bit_array.base64_url_encode(<<"ct":utf8>>, False)
  let tag_b64 = bit_array.base64_url_encode(crypto.random_bytes(16), False)
  let encrypted_key_b64 =
    bit_array.base64_url_encode(crypto.random_bytes(24), False)

  let json_str =
    json.object([
      #("protected", json.string(protected_b64)),
      #("encrypted_key", json.string(encrypted_key_b64)),
      #("iv", json.string(iv_b64)),
      #("ciphertext", json.string(ciphertext_b64)),
      #("tag", json.string(tag_b64)),
    ])
    |> json.to_string

  assert jwe.parse_json(json_str)
    == Error(gose.ParseError("apu and apv must be distinct"))
}

pub fn parse_json_general_zero_recipients_test() {
  assert parse_json_with_extra([
      #("recipients", json.preprocessed_array([])),
    ])
    == Error(gose.ParseError("JWE JSON (general) has no recipients"))
}

pub fn parse_json_general_multiple_recipients_test() {
  let recipient = json.object([#("encrypted_key", json.string(""))])
  assert parse_json_with_extra([
      #("recipients", json.preprocessed_array([recipient, recipient])),
    ])
    == Error(gose.ParseError(
      "JWE JSON (general) has multiple recipients (not supported)",
    ))
}

pub fn decode_shared_unprotected_header_none_present_test() {
  let assert Ok(parsed) = parse_json_with_extra([])
  let decoder = decode.field("kid", decode.string, decode.success)
  assert jwe.decode_shared_unprotected_header(parsed, decoder)
    == Error(gose.ParseError("no shared unprotected headers present"))
}

pub fn shared_and_per_recipient_unprotected_overlap_test() {
  let result =
    parse_json_with_extra([
      #("unprotected", json.object([#("kid", json.string("shared-kid"))])),
      #("header", json.object([#("kid", json.string("recipient-kid"))])),
    ])
  assert result
    == Error(gose.ParseError(
      "header parameter appears in both shared and per-recipient unprotected: kid",
    ))
}

pub fn decode_unprotected_header_none_present_test() {
  let assert Ok(parsed) = parse_json_with_extra([])
  let decoder = decode.field("kid", decode.string, decode.success)
  assert jwe.decode_unprotected_header(parsed, decoder)
    == Error(gose.ParseError("no per-recipient unprotected headers present"))
}

pub fn ecdh_es_distinct_apu_apv_succeeds_test() {
  let ec_key = fixtures.ec_p256_key()
  let payload = <<"test":utf8>>
  let apu = <<"sender@example.com":utf8>>
  let apv = <<"recipient@example.com":utf8>>

  let assert Ok(encrypted) =
    jwe.new_ecdh_es(jwa.EcdhEsAesKw(jwa.Aes128), jwa.AesGcm(jwa.Aes256))
    |> jwe.with_apu(apu)
    |> jwe.with_apv(apv)
    |> jwe.encrypt(ec_key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes128)),
      jwa.AesGcm(jwa.Aes256),
      [ec_key],
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

  assert decrypted == payload
}

pub fn ecdh_es_only_apu_succeeds_test() {
  let ec_key = fixtures.ec_p256_key()
  let payload = <<"test":utf8>>
  let apu = <<"sender@example.com":utf8>>

  let assert Ok(encrypted) =
    jwe.new_ecdh_es(jwa.EcdhEsAesKw(jwa.Aes128), jwa.AesGcm(jwa.Aes256))
    |> jwe.with_apu(apu)
    |> jwe.encrypt(ec_key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes128)),
      jwa.AesGcm(jwa.Aes256),
      [ec_key],
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

  assert decrypted == payload
}

pub fn ecdh_es_only_apv_succeeds_test() {
  let ec_key = fixtures.ec_p256_key()
  let payload = <<"test":utf8>>
  let apv = <<"recipient@example.com":utf8>>

  let assert Ok(encrypted) =
    jwe.new_ecdh_es(jwa.EcdhEsAesKw(jwa.Aes128), jwa.AesGcm(jwa.Aes256))
    |> jwe.with_apv(apv)
    |> jwe.encrypt(ec_key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes128)),
      jwa.AesGcm(jwa.Aes256),
      [ec_key],
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

  assert decrypted == payload
}

pub fn aes_gcm_kw_missing_iv_test() {
  let key = jwk.generate_aes_kw_key(jwa.Aes128)
  let payload = <<"test":utf8>>

  let assert Ok(encrypted) =
    jwe.new_aes_gcm_kw(jwa.Aes128, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert [_, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64] =
    string.split(token, ".")

  let header_no_iv =
    json.object([
      #("alg", json.string("A128GCMKW")),
      #("enc", json.string("A256GCM")),
      #("tag", json.string("AAAAAAAAAAAAAAAAAAAAAA")),
    ])
    |> json.to_string
  let header_no_iv_b64 =
    bit_array.base64_url_encode(<<header_no_iv:utf8>>, False)

  let token_no_iv =
    string.join(
      [header_no_iv_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64],
      ".",
    )
  let assert Ok(parsed_no_iv) = jwe.parse_compact(token_no_iv)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweAesKeyWrap(jwa.AesGcmKw, jwa.Aes128),
      jwa.AesGcm(jwa.Aes256),
      [key],
    )
  let result = jwe.decrypt(decryptor, parsed_no_iv)
  assert result
    == Error(gose.ParseError("missing iv header for AES-GCM Key Wrap"))
}

pub fn encrypt_rejects_key_with_wrong_jwe_alg_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let key_with_alg =
    jwk.with_alg(key, jwk.Jwe(jwa.JweAesKeyWrap(jwa.AesKw, jwa.Aes128)))

  let result =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key_with_alg, <<"test":utf8>>)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key algorithm mismatch: key has A128KW, expected dir"
}

pub fn encrypt_rsa_rejects_key_with_wrong_jwe_alg_test() {
  let key = fixtures.rsa_private_key()
  let key_with_alg = jwk.with_alg(key, jwk.Jwe(jwa.JweRsa(jwa.RsaOaepSha1)))

  let result =
    jwe.new_rsa(jwa.RsaPkcs1v15, jwa.AesGcm(jwa.Aes128))
    |> jwe.encrypt(key_with_alg, <<"test":utf8>>)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key algorithm mismatch: key has RSA-OAEP, expected RSA1_5"
}

pub fn encrypt_rejects_pbes2_with_key_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let payload = <<"test":utf8>>

  let result =
    jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes128))
    |> jwe.encrypt(key, payload)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "PBES2 algorithms require a password; use encrypt_with_password"
}

pub fn encrypt_rejects_key_with_jws_alg_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let key_with_alg = jwk.with_alg(key, jwk.Jws(jwa.JwsHmac(jwa.HmacSha256)))

  let result =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key_with_alg, <<"test":utf8>>)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "key algorithm mismatch: key has JWS algorithm, expected JWE algorithm"
}

pub fn decrypt_rejects_empty_key_list_test() {
  let assert Error(gose.InvalidState(_)) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [])
}

pub fn chacha20_kw_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jwe_chacha20_kw_generator(),
      qcheck.non_empty_byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JweChaCha20KwWithKey(variant, enc, key), payload) = tuple

      let assert Ok(encrypted) =
        jwe.new_chacha20_kw(variant, enc)
        |> jwe.encrypt(key, payload)

      let assert Ok(token) = jwe.serialize_compact(encrypted)
      let assert Ok(parsed) = jwe.parse_compact(token)
      let assert Ok(decryptor) =
        jwe.key_decryptor(jwa.JweChaCha20KeyWrap(variant), enc, [key])
      let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)

      assert decrypted == payload
    },
  )
}

pub fn chacha20_kw_missing_iv_test() {
  let key = jwk.generate_chacha20_kw_key()
  let payload = <<"test":utf8>>

  let assert Ok(encrypted) =
    jwe.new_chacha20_kw(jwa.C20PKw, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert [_, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64] =
    string.split(token, ".")

  let header_no_iv =
    json.object([
      #("alg", json.string("C20PKW")),
      #("enc", json.string("A256GCM")),
      #("tag", json.string("AAAAAAAAAAAAAAAAAAAAAA")),
    ])
    |> json.to_string
  let header_no_iv_b64 =
    bit_array.base64_url_encode(<<header_no_iv:utf8>>, False)

  let token_no_iv =
    string.join(
      [header_no_iv_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64],
      ".",
    )
  let assert Ok(parsed_no_iv) = jwe.parse_compact(token_no_iv)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweChaCha20KeyWrap(jwa.C20PKw),
      jwa.AesGcm(jwa.Aes256),
      [
        key,
      ],
    )
  let result = jwe.decrypt(decryptor, parsed_no_iv)
  assert result
    == Error(gose.ParseError("missing iv header for ChaCha20 Key Wrap"))
}

pub fn chacha20_kw_missing_tag_test() {
  let key = jwk.generate_chacha20_kw_key()
  let payload = <<"test":utf8>>

  let assert Ok(encrypted) =
    jwe.new_chacha20_kw(jwa.C20PKw, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, payload)

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert [_, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64] =
    string.split(token, ".")

  let header_no_tag =
    json.object([
      #("alg", json.string("C20PKW")),
      #("enc", json.string("A256GCM")),
      #("iv", json.string("AAAAAAAAAAAAAAAA")),
    ])
    |> json.to_string
  let header_no_tag_b64 =
    bit_array.base64_url_encode(<<header_no_tag:utf8>>, False)

  let token_no_tag =
    string.join(
      [header_no_tag_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64],
      ".",
    )
  let assert Ok(parsed_no_tag) = jwe.parse_compact(token_no_tag)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweChaCha20KeyWrap(jwa.C20PKw),
      jwa.AesGcm(jwa.Aes256),
      [
        key,
      ],
    )
  let result = jwe.decrypt(decryptor, parsed_no_tag)
  assert result
    == Error(gose.ParseError("missing tag header for ChaCha20 Key Wrap"))
}

pub fn encrypt_to_compact_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jwe_key_alg_enc_generator(),
      qcheck.non_empty_byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JweAlgEncWithKey(alg, enc, key), payload) = tuple

      let assert Ok(#(token, returned_alg)) =
        jwe.encrypt_to_compact(
          alg,
          enc,
          payload,
          key,
          option.None,
          option.None,
          option.None,
        )

      assert returned_alg == alg

      let assert Ok(parsed) = jwe.parse_compact(token)
      let assert Ok(decryptor) = jwe.key_decryptor(alg, enc, [key])
      let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
      assert decrypted == payload
    },
  )
}

pub fn encrypt_to_compact_rejects_pbes2_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  assert jwe.encrypt_to_compact(
      jwa.JwePbes2(jwa.Pbes2Sha256Aes128Kw),
      jwa.AesGcm(jwa.Aes256),
      <<"test":utf8>>,
      key,
      option.None,
      option.None,
      option.None,
    )
    == Error(gose.InvalidState("PBES2 algorithms require a password, not a key"))
}

pub fn with_cty_roundtrip_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let jwe_val =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_cty("JWT")
  assert jwe.cty(jwe_val) == Ok("JWT")

  let assert Ok(encrypted) = jwe.encrypt(jwe_val, key, <<"test":utf8>>)
  assert jwe.cty(encrypted) == Ok("JWT")

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)
  assert jwe.cty(parsed) == Ok("JWT")
}

pub fn with_typ_roundtrip_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let jwe_val =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_typ("JWT")
  assert jwe.typ(jwe_val) == Ok("JWT")

  let assert Ok(encrypted) = jwe.encrypt(jwe_val, key, <<"test":utf8>>)
  assert jwe.typ(encrypted) == Ok("JWT")

  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)
  assert jwe.typ(parsed) == Ok("JWT")
}

pub fn empty_plaintext_roundtrip_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, <<>>)
  let assert Ok(token) = jwe.serialize_compact(encrypted)
  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  assert decrypted == <<>>
}

pub fn parse_json_rejects_invalid_json_test() {
  let assert Error(gose.ParseError(_)) = jwe.parse_json("not valid json")
}

pub fn parse_json_rejects_empty_object_test() {
  let assert Error(gose.ParseError(_)) =
    jwe.parse_json(json.to_string(json.object([])))
}

pub fn has_unprotected_headers_on_built_jwe_test() {
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"built unprotected test":utf8>>

  let assert Ok(with_both) = {
    let base = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    use j <- result.try(jwe.with_shared_unprotected(
      base,
      "x-shared",
      json.string("val"),
    ))
    jwe.with_unprotected(j, "x-recipient", json.string("val"))
  }
  let assert Ok(encrypted) = jwe.encrypt(with_both, key, plaintext)
  assert jwe.has_shared_unprotected_header(encrypted)
  assert jwe.has_unprotected_header(encrypted)

  let base_no_headers = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
  let assert Ok(encrypted_plain) = jwe.encrypt(base_no_headers, key, plaintext)
  assert !jwe.has_shared_unprotected_header(encrypted_plain)
  assert !jwe.has_unprotected_header(encrypted_plain)
}
