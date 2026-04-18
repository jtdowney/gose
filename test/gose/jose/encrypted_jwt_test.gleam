import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import gose
import gose/algorithm
import gose/jose/encrypted_jwt
import gose/jose/jwe
import gose/jose/jwt
import gose/key
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import gose/test_helpers/jwt_helpers
import qcheck

pub fn encrypt_decrypt_direct_roundtrip_test() {
  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple2(generators.jwe_direct_generator(), qcheck.non_empty_string()),
  )
  let #(generators.JweDirectEncWithKey(enc, key), subject) = tuple
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject(subject)
    |> jwt.with_expiration(exp)

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(claims, algorithm.Direct, enc, key)
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      enc,
      [key],
      jwt.default_validation(),
    )
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == subject
}

pub fn encrypt_decrypt_aes_kw_roundtrip_test() {
  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple2(generators.jwe_aes_kw_generator(), qcheck.non_empty_string()),
  )
  let #(generators.JweAesKwWithKey(alg, enc, key), subject) = tuple
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject(subject)
    |> jwt.with_expiration(exp)

  let jwe_alg = algorithm.AesKeyWrap(algorithm.AesKw, alg)
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(claims, jwe_alg, enc, key)
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(jwe_alg, enc, [key], jwt.default_validation())
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == subject
}

pub fn encrypt_decrypt_pbes2_roundtrip_test() {
  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(3),
    qcheck.tuple2(
      generators.jwe_pbes2_alg_generator(),
      qcheck.non_empty_string(),
    ),
  )
  let #(alg, subject) = tuple
  let enc = algorithm.AesGcm(algorithm.Aes256)
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))
  let password = "test-password-123"

  let claims =
    jwt.claims()
    |> jwt.with_subject(subject)
    |> jwt.with_expiration(exp)

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_password(
      claims,
      alg,
      enc,
      password,
      kid: option.None,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let decryptor =
    encrypted_jwt.password_decryptor(
      alg,
      enc,
      password,
      jwt.default_validation(),
    )
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == subject
}

pub fn encrypt_decrypt_rsa_roundtrip_test() {
  let rsa_key = fixtures.rsa_private_key()

  use variant <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(5),
    generators.rsa_variant_generator(),
  )
  let generators.RsaVariant(alg, enc) = variant
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let jwe_alg = algorithm.RsaEncryption(alg)
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(claims, jwe_alg, enc, rsa_key)
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      jwe_alg,
      enc,
      [rsa_key],
      jwt.default_validation(),
    )
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
}

pub fn encrypt_decrypt_ecdh_ec_roundtrip_test() {
  let ec_key = fixtures.ec_p256_key()

  use variant <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(5),
    generators.ecdh_variant_generator(),
  )
  let generators.EcdhVariant(alg, enc) = variant
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let jwe_alg = algorithm.EcdhEs(alg)
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(claims, jwe_alg, enc, ec_key)
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      jwe_alg,
      enc,
      [ec_key],
      jwt.default_validation(),
    )
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
}

pub fn encrypt_decrypt_ecdh_xdh_roundtrip_test() {
  let xdh_key = fixtures.x25519_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      algorithm.AesGcm(algorithm.Aes256),
      xdh_key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      algorithm.AesGcm(algorithm.Aes256),
      [xdh_key],
      jwt.default_validation(),
    )
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
}

pub fn algorithm_mismatch_rejected_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes128),
      [key],
      jwt.default_validation(),
    )
  assert encrypted_jwt.decrypt_and_validate(decryptor, token, now)
    == Error(jwt.JweAlgorithmMismatch(
      expected_alg: algorithm.Direct,
      expected_enc: algorithm.AesGcm(algorithm.Aes128),
      actual_alg: algorithm.Direct,
      actual_enc: algorithm.AesGcm(algorithm.Aes256),
    ))
}

pub fn key_alg_mismatch_rejected_test() {
  let key_128 = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes128))
  let key_256 = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key_256,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key_128],
      jwt.default_validation(),
    )
  let assert Error(jwt.DecryptionFailed(_)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn expired_token_rejected_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.expired_claims()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )
  let assert Error(jwt.TokenExpired(_)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn not_yet_valid_token_rejected_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.not_yet_valid_claims()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )
  let assert Error(jwt.TokenNotYetValid(_)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn issuer_mismatch_rejected_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.claims_with_issuer("actual-issuer")

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let options =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      issuer: option.Some("expected-issuer"),
    )
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      options,
    )
  let assert Error(jwt.IssuerMismatch(expected: "expected-issuer", actual: _)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn audience_mismatch_rejected_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims =
    jwt_helpers.default_claims_with_exp()
    |> jwt.with_audience("actual-audience")

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let options =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      audience: option.Some("expected-audience"),
    )
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      options,
    )
  let assert Error(jwt.AudienceMismatch(
    expected: "expected-audience",
    actual: _,
  )) = encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn missing_exp_rejected_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.claims_without_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )
  assert encrypted_jwt.decrypt_and_validate(decryptor, token, now)
    == Error(jwt.MissingExpiration)
}

pub fn decryptor_empty_keys_rejected_test() {
  assert encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [],
      jwt.default_validation(),
    )
    == Error(jwt.JoseError(gose.InvalidState("at least one key required")))

  assert encrypted_jwt.key_decryptor(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      algorithm.AesGcm(algorithm.Aes256),
      [],
      jwt.default_validation(),
    )
    == Error(jwt.JoseError(gose.InvalidState("at least one key required")))
}

pub fn decryptor_wrong_key_use_rejected_test() {
  let assert Ok(key) =
    key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
    |> key.with_key_use(key.Signing)

  assert encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )
    == Error(
      jwt.JoseError(gose.InvalidState(
        "key use is 'sig', cannot be used for decryption",
      )),
    )
}

pub fn decryptor_wrong_key_ops_rejected_test() {
  let assert Ok(key) =
    key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
    |> key.with_key_ops([key.Encrypt])

  assert encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )
    == Error(
      jwt.JoseError(gose.InvalidState(
        "key_ops does not include 'decrypt' or 'unwrapKey' operation",
      )),
    )
}

pub fn kid_no_requirement_policy_test() {
  let key1 = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let key1 = key.with_kid(key1, "key-1")
  let key2 = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let key2 = key.with_kid(key2, "key-2")

  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key2,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key1, key2],
      jwt.default_validation(),
    )
  let assert Ok(_) = encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn kid_require_match_policy_test() {
  let key1 = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let key1 = key.with_kid(key1, "key-1")
  let key2 = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let key2 = key.with_kid(key2, "key-2")

  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key.with_kid(key2, "unknown-key"),
    )
  let token = encrypted_jwt.serialize(encrypted)

  let options =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      kid_policy: jwt.RequireKidMatch,
    )
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key1, key2],
      options,
    )
  assert encrypted_jwt.decrypt_and_validate(decryptor, token, now)
    == Error(jwt.UnknownKid("unknown-key"))
}

pub fn kid_require_kid_missing_rejected_test() {
  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let options =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      kid_policy: jwt.RequireKid,
    )
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      options,
    )
  assert encrypted_jwt.decrypt_and_validate(decryptor, token, now)
    == Error(jwt.MissingKid)
}

pub fn dangerously_decrypt_and_skip_validation_test() {
  let key = jwt_helpers.hmac_key()
  let past = timestamp.add(jwt_helpers.fixed_timestamp(), duration.hours(-2))
  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(past)

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )

  let assert Error(jwt.TokenExpired(_)) =
    encrypted_jwt.decrypt_and_validate(
      decryptor,
      token,
      jwt_helpers.fixed_timestamp(),
    )

  let assert Ok(verified) =
    encrypted_jwt.dangerously_decrypt_and_skip_validation(decryptor, token)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
}

pub fn dangerously_decrypt_with_password_decryptor_test() {
  let past = timestamp.add(jwt_helpers.fixed_timestamp(), duration.hours(-2))
  let password = "test-password-123"
  let alg = algorithm.Pbes2Sha256Aes128Kw
  let enc = algorithm.AesGcm(algorithm.Aes256)

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(past)

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_password(
      claims,
      alg,
      enc,
      password,
      kid: option.None,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let decryptor =
    encrypted_jwt.password_decryptor(
      alg,
      enc,
      password,
      jwt.default_validation(),
    )

  let now = jwt_helpers.fixed_timestamp()
  let assert Error(jwt.TokenExpired(_)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)

  let assert Ok(verified) =
    encrypted_jwt.dangerously_decrypt_and_skip_validation(decryptor, token)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
}

pub fn dangerously_skip_still_enforces_algorithm_test() {
  let key = jwt_helpers.hmac_key()
  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes128),
      [key],
      jwt.default_validation(),
    )

  assert encrypted_jwt.dangerously_decrypt_and_skip_validation(decryptor, token)
    == Error(jwt.JweAlgorithmMismatch(
      expected_alg: algorithm.Direct,
      expected_enc: algorithm.AesGcm(algorithm.Aes128),
      actual_alg: algorithm.Direct,
      actual_enc: algorithm.AesGcm(algorithm.Aes256),
    ))
}

pub fn accessors_test() {
  let key = jwt_helpers.hmac_key() |> key.with_kid("my-key-id")
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )

  assert encrypted_jwt.alg(encrypted) == algorithm.Direct
  assert encrypted_jwt.enc(encrypted) == algorithm.AesGcm(algorithm.Aes256)
  assert encrypted_jwt.kid(encrypted) == Ok("my-key-id")
}

pub fn kid_returns_error_when_absent_test() {
  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  assert encrypted_jwt.kid(encrypted) == Error(Nil)
}

pub fn peek_headers_test() {
  let claims = jwt_helpers.default_claims_with_exp()

  let key_with_kid = jwt_helpers.hmac_key() |> key.with_kid("parsed-key-id")
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key_with_kid,
    )
  let token = encrypted_jwt.serialize(encrypted)
  let assert Ok(headers) = encrypted_jwt.peek_headers(token)
  assert headers.alg == algorithm.Direct
  assert headers.enc == algorithm.AesGcm(algorithm.Aes256)
  assert headers.kid == option.Some("parsed-key-id")

  let key = jwt_helpers.hmac_key()
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)
  let assert Ok(headers) = encrypted_jwt.peek_headers(token)
  assert headers.kid == option.None
}

pub fn peek_headers_invalid_token_test() {
  let assert Error(jwt.MalformedToken(_)) =
    encrypted_jwt.peek_headers("not.a.valid.token")
  let assert Error(jwt.MalformedToken(_)) =
    encrypted_jwt.peek_headers("invalid")
}

pub fn custom_claims_roundtrip_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let assert Ok(claims) =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_claim("role", json.string("admin"))

  let assert Ok(claims) =
    jwt.with_claim(
      claims,
      "permissions",
      json.preprocessed_array([json.string("read"), json.string("write")]),
    )

  let assert Ok(claims) =
    jwt.with_claim(
      claims,
      "nested",
      json.object([
        #("level", json.int(42)),
        #("active", json.bool(True)),
      ]),
    )

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )

  let flat_decoder = {
    use sub <- decode.field("sub", decode.string)
    use role <- decode.field("role", decode.string)
    use permissions <- decode.field("permissions", decode.list(decode.string))
    decode.success(#(sub, role, permissions))
  }

  let assert Ok(#(sub, role, permissions)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
    |> result.try(encrypted_jwt.decode(_, flat_decoder))
  assert sub == "user123"
  assert role == "admin"
  assert permissions == ["read", "write"]

  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)

  let nested_decoder = {
    use level <- decode.field("level", decode.int)
    use active <- decode.field("active", decode.bool)
    decode.success(#(level, active))
  }
  let decoder = {
    use role <- decode.field("role", decode.string)
    use nested <- decode.field("nested", nested_decoder)
    decode.success(#(role, nested))
  }
  let assert Ok(#(role, #(level, active))) =
    encrypted_jwt.decode(verified, decoder)
  assert role == "admin"
  assert level == 42
  assert active
}

pub fn encrypted_jwt_direct_snapshot_test() {
  let key = jwt_helpers.hmac_key()
  let now = timestamp.from_unix_seconds(1_700_000_000)
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_issuer("test-issuer")
    |> jwt.with_audience("test-audience")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(now)

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )

  let token = encrypted_jwt.serialize(encrypted)
  let parts = string.split(token, ".")
  assert list.length(parts) == 5

  let assert Ok(headers) = encrypted_jwt.peek_headers(token)
  assert headers.alg == algorithm.Direct
  assert headers.enc == algorithm.AesGcm(algorithm.Aes256)
}

pub fn wrong_key_decryption_fails_test() {
  let key1 = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let key2 = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key1,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key2],
      jwt.default_validation(),
    )
  let assert Error(jwt.DecryptionFailed(_)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn encrypt_decrypt_aes_gcm_kw_roundtrip_test() {
  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple2(
      generators.jwe_aes_gcm_kw_generator(),
      qcheck.non_empty_string(),
    ),
  )
  let #(generators.JweAesGcmKwWithKey(alg, enc, key), subject) = tuple
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject(subject)
    |> jwt.with_expiration(exp)

  let jwe_alg = algorithm.AesKeyWrap(algorithm.AesGcmKw, alg)
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(claims, jwe_alg, enc, key)
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(jwe_alg, enc, [key], jwt.default_validation())
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == subject
}

pub fn empty_audience_array_rejected_test() {
  let now = jwt_helpers.fixed_timestamp()
  let claims_json =
    json.object([
      #("sub", json.string("user123")),
      #("exp", json.int(1_700_003_600)),
      #("aud", json.preprocessed_array([])),
    ])
    |> json.to_string

  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let unencrypted = jwe.new_direct(algorithm.AesGcm(algorithm.Aes256))
  let assert Ok(encrypted) =
    jwe.encrypt(unencrypted, key, bit_array.from_string(claims_json))

  let assert Ok(token) = jwe.serialize_compact(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )
  assert encrypted_jwt.decrypt_and_validate(decryptor, token, now)
    == Error(jwt.MalformedToken("aud claim cannot be an empty array"))
}

pub fn encrypted_future_iat_with_max_token_age_fails_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(2))
  let iat = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(iat)

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let opts = jwt.default_validation() |> jwt.with_max_token_age(3600)
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      opts,
    )
  let assert Error(jwt.IssuedInFuture(_)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn encrypt_with_password_kid_roundtrip_test() {
  let enc = algorithm.AesGcm(algorithm.Aes256)
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()
  let password = "test-password-123"

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_password(
      claims,
      algorithm.Pbes2Sha256Aes128Kw,
      enc,
      password,
      kid: option.Some("my-password-kid"),
    )
  let token = encrypted_jwt.serialize(encrypted)

  assert encrypted_jwt.kid(encrypted) == Ok("my-password-kid")

  let decryptor =
    encrypted_jwt.password_decryptor(
      algorithm.Pbes2Sha256Aes128Kw,
      enc,
      password,
      jwt.default_validation(),
    )
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
  assert encrypted_jwt.kid(verified) == Ok("my-password-kid")
}

pub fn pbes2_wrong_password_fails_test() {
  let enc = algorithm.AesGcm(algorithm.Aes256)
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_password(
      claims,
      algorithm.Pbes2Sha256Aes128Kw,
      enc,
      "correct-password",
      kid: option.None,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let decryptor =
    encrypted_jwt.password_decryptor(
      algorithm.Pbes2Sha256Aes128Kw,
      enc,
      "wrong-password",
      jwt.default_validation(),
    )
  let assert Error(jwt.DecryptionFailed(_)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn pbes2_rejected_by_encrypt_with_key_test() {
  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Error(jwt.JoseError(gose.InvalidState(_))) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Pbes2(algorithm.Pbes2Sha256Aes128Kw),
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
}

pub fn encrypt_decrypt_chacha20_kw_roundtrip_test() {
  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple2(
      generators.jwe_chacha20_kw_generator(),
      qcheck.non_empty_string(),
    ),
  )
  let #(generators.JweChaCha20KwWithKey(variant, enc, key), subject) = tuple
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject(subject)
    |> jwt.with_expiration(exp)

  let jwe_alg = algorithm.ChaCha20KeyWrap(variant)
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(claims, jwe_alg, enc, key)
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(jwe_alg, enc, [key], jwt.default_validation())
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == subject
}

pub fn encrypt_decrypt_ecdh_es_chacha20_kw_roundtrip_test() {
  let ec_key = fixtures.ec_p256_key()
  let xdh_key = fixtures.x25519_key()

  use tuple <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(#(algorithm.C20PKw, ec_key)), [
        qcheck.return(#(algorithm.XC20PKw, ec_key)),
        qcheck.return(#(algorithm.C20PKw, xdh_key)),
        qcheck.return(#(algorithm.XC20PKw, xdh_key)),
      ]),
      qcheck.non_empty_string(),
    ),
  )
  let #(#(variant, key), subject) = tuple
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject(subject)
    |> jwt.with_expiration(exp)

  let jwe_alg = algorithm.EcdhEs(algorithm.EcdhEsChaCha20Kw(variant))
  let enc = algorithm.AesGcm(algorithm.Aes256)
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(claims, jwe_alg, enc, key)
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(jwe_alg, enc, [key], jwt.default_validation())
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(sub) = encrypted_jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == subject
}

pub fn clock_skew_tolerance_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(timestamp.add(now, duration.seconds(-30)))

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let options =
    jwt.JwtValidationOptions(..jwt.default_validation(), clock_skew: 60)
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      options,
    )
  let assert Ok(_) = encrypted_jwt.decrypt_and_validate(decryptor, token, now)
}

pub fn jti_validator_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_jwt_id("unique-id-123")

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let accept_options =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      jti_validator: option.Some(fn(jti) { jti == "unique-id-123" }),
    )
  let assert Ok(accept_decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      accept_options,
    )
  let assert Ok(_) =
    encrypted_jwt.decrypt_and_validate(accept_decryptor, token, now)

  let reject_options =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      jti_validator: option.Some(fn(_jti) { False }),
    )
  let assert Ok(reject_decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      reject_options,
    )
  assert encrypted_jwt.decrypt_and_validate(reject_decryptor, token, now)
    == Error(jwt.InvalidJti("unique-id-123"))
}

pub fn decode_with_failing_decoder_test() {
  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user")
    |> jwt.with_expiration(exp)

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )
  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)

  let bad_decoder = decode.field("nonexistent", decode.int, decode.success)
  assert encrypted_jwt.decode(verified, bad_decoder)
    == Error(jwt.ClaimDecodingFailed("failed to decode claims"))
}

pub fn dangerously_decrypt_rejects_malformed_token_test() {
  let key = jwt_helpers.hmac_key()

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      [key],
      jwt.default_validation(),
    )
  let assert Error(jwt.MalformedToken(_)) =
    encrypted_jwt.dangerously_decrypt_and_skip_validation(
      decryptor,
      "not-a-valid-token",
    )
}

pub fn peek_headers_pbes2_test() {
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_password(
      claims,
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes256),
      "my-password",
      kid: option.None,
    )
  let token = encrypted_jwt.serialize(encrypted)
  let assert Ok(headers) = encrypted_jwt.peek_headers(token)
  assert headers.alg == algorithm.Pbes2(algorithm.Pbes2Sha256Aes128Kw)
  assert headers.enc == algorithm.AesGcm(algorithm.Aes256)
  assert headers.kid == option.None
}

pub fn peek_headers_rsa_test() {
  let claims = jwt_helpers.default_claims_with_exp()
  let key = fixtures.rsa_private_key()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )
  let token = encrypted_jwt.serialize(encrypted)
  let assert Ok(headers) = encrypted_jwt.peek_headers(token)
  assert headers.alg == algorithm.RsaEncryption(algorithm.RsaOaepSha256)
  assert headers.enc == algorithm.AesGcm(algorithm.Aes256)
}

pub fn password_decryptor_algorithm_mismatch_test() {
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_password(
      claims,
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes256),
      "my-password",
      kid: option.None,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let decryptor =
    encrypted_jwt.password_decryptor(
      algorithm.Pbes2Sha384Aes192Kw,
      algorithm.AesGcm(algorithm.Aes256),
      "my-password",
      jwt.default_validation(),
    )
  assert encrypted_jwt.decrypt_and_validate(decryptor, token, now)
    == Error(jwt.JweAlgorithmMismatch(
      expected_alg: algorithm.Pbes2(algorithm.Pbes2Sha384Aes192Kw),
      expected_enc: algorithm.AesGcm(algorithm.Aes256),
      actual_alg: algorithm.Pbes2(algorithm.Pbes2Sha256Aes128Kw),
      actual_enc: algorithm.AesGcm(algorithm.Aes256),
    ))
}
