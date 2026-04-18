import gleam/string
import gose
import gose/algorithm
import gose/jose/encrypted_key
import gose/jose/jwe
import gose/jose/jwk
import gose/key
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import kryptos/ec
import qcheck

fn key_generator() {
  qcheck.from_generators(
    qcheck.map(qcheck.return(Nil), fn(_) {
      let key = key.generate_hmac_key(algorithm.HmacSha256)
      key.with_kid(key, "octet-key")
    }),
    [
      qcheck.map(qcheck.return(Nil), fn(_) {
        fixtures.ec_p256_key()
        |> key.with_kid("ec-key")
      }),
      qcheck.map(qcheck.return(Nil), fn(_) {
        fixtures.ed25519_key()
        |> key.with_kid("eddsa-key")
      }),
      qcheck.map(qcheck.return(Nil), fn(_) {
        fixtures.x25519_key()
        |> key.with_kid("xdh-key")
      }),
    ],
  )
}

pub fn pbes2_roundtrip_test() {
  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(3),
    qcheck.tuple2(generators.pbes2_variant_generator(), key_generator()),
  )
  let #(generators.Pbes2Variant(alg, enc), key) = tuple

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_password(key, alg, enc, "test-password")

  let decryptor = jwe.password_decryptor(alg, enc, "test-password")
  let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)

  let assert Ok(original_kid) = key.kid(key)
  let assert Ok(recovered_kid) = key.kid(recovered)
  assert recovered_kid == original_kid
}

pub fn pbes2_wrong_password_fails_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_password(
      key,
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes256),
      "correct",
    )

  let decryptor =
    jwe.password_decryptor(
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes256),
      "wrong-password",
    )
  let assert Error(gose.CryptoError(_)) =
    encrypted_key.decrypt(decryptor, encrypted)
}

pub fn direct_symmetric_roundtrip_test() {
  let key = key.generate_ec(ec.P384)
  let key = key.with_kid(key, "ec-p384-key")

  let encryption_key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      encryption_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(algorithm.Direct, algorithm.AesGcm(algorithm.Aes256), [
      encryption_key,
    ])
  let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)

  let assert Ok(kid) = key.kid(recovered)
  assert kid == "ec-p384-key"
}

pub fn encryption_key_kid_propagates_to_jwe_header_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let encryption_key =
    key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
    |> key.with_kid("enc-key-id")

  let assert Ok(token) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      encryption_key,
    )

  let assert Ok(parsed) = jwe.parse_compact(token)
  assert jwe.kid(parsed) == Ok("enc-key-id")
}

pub fn direct_symmetric_wrong_key_fails_test() {
  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes128))

  let encryption_key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let wrong_key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      encryption_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(algorithm.Direct, algorithm.AesGcm(algorithm.Aes256), [
      wrong_key,
    ])
  let assert Error(gose.CryptoError(_)) =
    encrypted_key.decrypt(decryptor, encrypted)
}

pub fn aes_kw_roundtrip_test() {
  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple2(generators.aes_kw_variant_generator(), key_generator()),
  )
  let #(generators.AesKeyWrapVariant(alg, enc), key) = tuple

  let wrap_key = key.generate_aes_kw_key(alg)

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.AesKeyWrap(algorithm.AesKw, alg),
      enc,
      wrap_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(algorithm.AesKeyWrap(algorithm.AesKw, alg), enc, [
      wrap_key,
    ])
  let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)

  let assert Ok(original_kid) = key.kid(key)
  let assert Ok(recovered_kid) = key.kid(recovered)
  assert recovered_kid == original_kid
}

pub fn aes_gcm_kw_roundtrip_test() {
  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple2(generators.aes_kw_variant_generator(), key_generator()),
  )
  let #(generators.AesKeyWrapVariant(alg, enc), key) = tuple

  let wrap_key = key.generate_aes_kw_key(alg)

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.AesKeyWrap(algorithm.AesGcmKw, alg),
      enc,
      wrap_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(algorithm.AesKeyWrap(algorithm.AesGcmKw, alg), enc, [
      wrap_key,
    ])
  let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)

  let assert Ok(original_kid) = key.kid(key)
  let assert Ok(recovered_kid) = key.kid(recovered)
  assert recovered_kid == original_kid
}

pub fn rsa_roundtrip_test() {
  let rsa_key = fixtures.rsa_private_key()

  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple2(generators.rsa_variant_generator(), key_generator()),
  )
  let #(generators.RsaVariant(alg, enc), key) = tuple

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.RsaEncryption(alg),
      enc,
      rsa_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(algorithm.RsaEncryption(alg), enc, [rsa_key])
  let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)

  let assert Ok(original_kid) = key.kid(key)
  let assert Ok(recovered_kid) = key.kid(recovered)
  assert recovered_kid == original_kid
}

pub fn rsa_oaep_wrong_key_fails_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)

  let assert Ok(encrypt_key) = key.generate_rsa(2048)
  let assert Ok(wrong_key) = key.generate_rsa(2048)

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      algorithm.AesGcm(algorithm.Aes256),
      encrypt_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      algorithm.AesGcm(algorithm.Aes256),
      [
        wrong_key,
      ],
    )
  let assert Error(gose.CryptoError(_)) =
    encrypted_key.decrypt(decryptor, encrypted)
}

pub fn ecdh_es_roundtrip_test() {
  let ec_p256_key = fixtures.ec_p256_key()
  let ec_p384_key = fixtures.ec_p384_key()
  let xdh_key = fixtures.x25519_key()

  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple3(
      generators.ecdh_variant_generator(),
      qcheck.from_generators(qcheck.return(ec_p256_key), [
        qcheck.return(ec_p384_key),
        qcheck.return(xdh_key),
      ]),
      key_generator(),
    ),
  )
  let #(generators.EcdhVariant(alg, enc), encryption_key, key) = tuple

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.EcdhEs(alg),
      enc,
      encryption_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(algorithm.EcdhEs(alg), enc, [encryption_key])
  let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)

  let assert Ok(original_kid) = key.kid(key)
  let assert Ok(recovered_kid) = key.kid(recovered)
  assert recovered_kid == original_kid
}

pub fn ecdh_es_wrong_key_fails_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)

  let encrypt_key = key.generate_ec(ec.P256)
  let wrong_key = key.generate_ec(ec.P256)

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      algorithm.AesGcm(algorithm.Aes256),
      encrypt_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      algorithm.AesGcm(algorithm.Aes256),
      [
        wrong_key,
      ],
    )
  let assert Error(gose.CryptoError(_)) =
    encrypted_key.decrypt(decryptor, encrypted)
}

pub fn preserves_key_metadata_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let assert Ok(key) = key.with_key_ops(key, [key.Sign, key.Verify])
  let assert Ok(alg) = jwk.alg_from_string("HS256")
  let key = key.with_alg(key, alg)

  let wrap_key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      wrap_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(algorithm.Direct, algorithm.AesGcm(algorithm.Aes256), [
      wrap_key,
    ])
  let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)

  let assert Ok(use_) = key.key_use(recovered)
  assert use_ == key.Signing

  let assert Ok(ops) = key.key_ops(recovered)
  assert ops == [key.Sign, key.Verify]

  let assert Ok(recovered_alg) = key.alg(recovered)
  assert jwk.alg_to_string(recovered_alg) == "HS256"
}

pub fn invalid_jwe_format_fails_test() {
  let decryptor =
    jwe.password_decryptor(
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes256),
      "password",
    )
  let assert Error(gose.ParseError(_)) =
    encrypted_key.decrypt(decryptor, "not-a-jwe")
}

pub fn corrupted_ciphertext_fails_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_password(
      key,
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes256),
      "password",
    )

  let assert [header, ek, iv, _ct, tag] = string.split(encrypted, ".")

  let corrupted = string.join([header, ek, iv, "AAAA", tag], ".")

  let decryptor =
    jwe.password_decryptor(
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes256),
      "password",
    )
  let assert Error(gose.CryptoError(_)) =
    encrypted_key.decrypt(decryptor, corrupted)
}

pub fn pbes2_rejected_by_encrypt_with_key_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let some_key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))

  let assert Error(gose.InvalidState(_)) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.Pbes2(algorithm.Pbes2Sha256Aes128Kw),
      algorithm.AesGcm(algorithm.Aes256),
      some_key,
    )
}

pub fn chacha20_kw_roundtrip_test() {
  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple2(generators.jwe_chacha20_kw_generator(), key_generator()),
  )
  let #(generators.JweChaCha20KwWithKey(variant, enc, wrap_key), key) = tuple

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      key,
      algorithm.ChaCha20KeyWrap(variant),
      enc,
      wrap_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(algorithm.ChaCha20KeyWrap(variant), enc, [wrap_key])
  let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)

  let assert Ok(original_kid) = key.kid(key)
  let assert Ok(recovered_kid) = key.kid(recovered)
  assert recovered_kid == original_kid
}

pub fn rsa_private_key_encryption_roundtrip_test() {
  let assert Ok(rsa_key) = key.generate_rsa(2048)
  let wrapping_key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))

  let assert Ok(encrypted) =
    encrypted_key.encrypt_with_key(
      rsa_key,
      alg: algorithm.Direct,
      enc: algorithm.AesGcm(algorithm.Aes256),
      with: wrapping_key,
    )

  let assert Ok(decryptor) =
    jwe.key_decryptor(algorithm.Direct, algorithm.AesGcm(algorithm.Aes256), [
      wrapping_key,
    ])
  let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)

  let assert Ok(original_pub) = key.rsa_public_key(rsa_key)
  let assert Ok(recovered_pub) = key.rsa_public_key(recovered)
  assert original_pub == recovered_pub
}

pub fn cty_header_set_to_jwk_json_key_test() {
  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let wrapping_key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))

  let assert Ok(token) =
    encrypted_key.encrypt_with_key(
      key,
      alg: algorithm.Direct,
      enc: algorithm.AesGcm(algorithm.Aes256),
      with: wrapping_key,
    )
  let assert Ok(parsed) = jwe.parse_compact(token)
  assert jwe.cty(parsed) == Ok("jwk+json")
}

pub fn cty_header_set_to_jwk_json_password_test() {
  let key = key.generate_ec(ec.P256)

  let assert Ok(token) =
    encrypted_key.encrypt_with_password(
      key,
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes256),
      "my-password",
    )
  let assert Ok(parsed) = jwe.parse_compact(token)
  assert jwe.cty(parsed) == Ok("jwk+json")
}
