import birdie
import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/time/duration
import gleam/time/timestamp
import gose
import gose/jwa
import gose/jwk
import gose/jws
import gose/jwt.{JwtValidationOptions}
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import gose/test_helpers/jwt_helpers
import kryptos/crypto
import qcheck

pub fn claims_builder_round_trip_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))
  let nbf = timestamp.add(now, duration.seconds(-10))
  let #(now_seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(now)
  let #(exp_seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(exp)
  let #(nbf_seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(nbf)

  let assert Ok(claims) =
    jwt.claims()
    |> jwt.with_issuer("issuer")
    |> jwt.with_subject("subject")
    |> jwt.with_audience("audience")
    |> jwt.with_expiration(exp)
    |> jwt.with_not_before(nbf)
    |> jwt.with_issued_at(now)
    |> jwt.with_jwt_id("unique-id")
    |> jwt.with_claim("custom", json.string("value"))

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

  let decoder = {
    use iss <- decode.field("iss", decode.string)
    use sub <- decode.field("sub", decode.string)
    use aud <- decode.field("aud", decode.string)
    use exp <- decode.field("exp", decode.int)
    use nbf <- decode.field("nbf", decode.int)
    use iat <- decode.field("iat", decode.int)
    use jti <- decode.field("jti", decode.string)
    use custom <- decode.field("custom", decode.string)
    decode.success(#(iss, sub, aud, exp, nbf, iat, jti, custom))
  }
  let assert Ok(#(iss, sub, aud, exp_val, nbf_val, iat, jti, custom)) =
    jwt.decode(verified, decoder)

  assert iss == "issuer"
  assert sub == "subject"
  assert aud == "audience"
  assert exp_val == exp_seconds
  assert nbf_val == nbf_seconds
  assert iat == now_seconds
  assert jti == "unique-id"
  assert custom == "value"
}

pub fn reserved_claims_rejected_by_with_claim_test() {
  let claims = jwt.claims()
  assert jwt.with_claim(claims, "iss", json.string("test"))
    == Error(jwt.InvalidClaim("use dedicated setter for iss claim"))
  assert jwt.with_claim(claims, "sub", json.string("test"))
    == Error(jwt.InvalidClaim("use dedicated setter for sub claim"))
  assert jwt.with_claim(claims, "exp", json.int(123))
    == Error(jwt.InvalidClaim("use dedicated setter for exp claim"))
}

pub fn with_audiences_validation_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims = jwt.claims()
  assert jwt.with_audiences(claims, [])
    == Error(jwt.InvalidClaim("audience list cannot be empty"))

  let assert Ok(claims_with_aud) =
    jwt.claims()
    |> jwt.with_expiration(exp)
    |> jwt.with_audiences(["aud1", "aud2"])

  let assert Ok(signed) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims_with_aud, key)
  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(
      jwa.JwsHmac(jwa.HmacSha256),
      [key],
      JwtValidationOptions(..jwt.default_validation(), audience: Some("aud1")),
    )
  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

  let decoder = decode.field("aud", decode.list(decode.string), decode.success)
  let assert Ok(aud) = jwt.decode(verified, decoder)
  assert aud == ["aud1", "aud2"]
}

pub fn sign_verify_hmac_property_test() {
  let hmac_keys = generators.generate_hmac_keys()
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jws_hmac_alg_generator(hmac_keys),
      qcheck.non_empty_string(),
    ),
    fn(tuple) {
      let #(generators.JwsAlgWithKey(alg, key), subject) = tuple
      let now = jwt_helpers.fixed_timestamp()
      let exp = timestamp.add(now, duration.hours(1))

      let claims =
        jwt.claims()
        |> jwt.with_subject(subject)
        |> jwt.with_expiration(exp)

      let assert Ok(signed) = jwt.sign(alg, claims, key)
      let token = jwt.serialize(signed)

      let assert Ok(v) = jwt.verifier(alg, [key], jwt.default_validation())
      let assert Ok(verified) = jwt.verify_and_validate(v, token, now)
      let assert Ok(sub) = jwt.decode(verified, jwt_helpers.sub_decoder())
      assert sub == subject
    },
  )
}

pub fn sign_verify_ec_property_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jws_ecdsa_alg_generator(),
      qcheck.non_empty_string(),
    ),
    fn(tuple) {
      let #(generators.JwsAlgWithKey(alg, key), subject) = tuple
      let now = jwt_helpers.fixed_timestamp()
      let exp = timestamp.add(now, duration.hours(1))

      let claims =
        jwt.claims()
        |> jwt.with_subject(subject)
        |> jwt.with_expiration(exp)

      let assert Ok(signed) = jwt.sign(alg, claims, key)
      let token = jwt.serialize(signed)

      let assert Ok(v) = jwt.verifier(alg, [key], jwt.default_validation())
      let assert Ok(verified) = jwt.verify_and_validate(v, token, now)
      let assert Ok(sub) = jwt.decode(verified, jwt_helpers.sub_decoder())
      assert sub == subject
    },
  )
}

pub fn sign_verify_eddsa_property_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jws_eddsa_alg_generator(),
      qcheck.non_empty_string(),
    ),
    fn(tuple) {
      let #(generators.JwsAlgWithKey(alg, key), subject) = tuple
      let now = jwt_helpers.fixed_timestamp()
      let exp = timestamp.add(now, duration.hours(1))

      let claims =
        jwt.claims()
        |> jwt.with_subject(subject)
        |> jwt.with_expiration(exp)

      let assert Ok(signed) = jwt.sign(alg, claims, key)
      let token = jwt.serialize(signed)

      let assert Ok(v) = jwt.verifier(alg, [key], jwt.default_validation())
      let assert Ok(verified) = jwt.verify_and_validate(v, token, now)
      let assert Ok(sub) = jwt.decode(verified, jwt_helpers.sub_decoder())
      assert sub == subject
    },
  )
}

pub fn sign_verify_rsa_roundtrip_test() {
  let key = fixtures.rsa_private_key()
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) =
    jwt.sign(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(
      jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256),
      [key],
      jwt.default_validation(),
    )
  let assert Ok(verified) =
    jwt.verify_and_validate(v, token, jwt_helpers.fixed_timestamp())
  let assert Ok(sub) = jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
}

pub fn sign_verify_ec_roundtrip_test() {
  let key = fixtures.ec_p256_key()
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) = jwt.sign(jwa.JwsEcdsa(jwa.EcdsaP256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(jwa.JwsEcdsa(jwa.EcdsaP256), [key], jwt.default_validation())
  let assert Ok(verified) =
    jwt.verify_and_validate(v, token, jwt_helpers.fixed_timestamp())
  let assert Ok(sub) = jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
}

pub fn sign_verify_eddsa_roundtrip_test() {
  let key = fixtures.ed25519_key()
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) = jwt.sign(jwa.JwsEddsa, claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(v) = jwt.verifier(jwa.JwsEddsa, [key], jwt.default_validation())
  let assert Ok(verified) =
    jwt.verify_and_validate(v, token, jwt_helpers.fixed_timestamp())
  let assert Ok(sub) = jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
}

pub fn expired_token_rejected_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.expired_claims()
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Error(jwt.TokenExpired(_)) = jwt.verify_and_validate(v, token, now)
}

pub fn not_yet_valid_token_rejected_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.not_yet_valid_claims()
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Error(jwt.TokenNotYetValid(_)) =
    jwt.verify_and_validate(v, token, now)
}

pub fn clock_skew_tolerance_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(timestamp.add(now, duration.seconds(-30)))
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Ok(_) = jwt.verify_and_validate(v, token, now)

  let claims2 =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_not_before(timestamp.add(now, duration.seconds(30)))
    |> jwt.with_expiration(timestamp.add(now, duration.hours(1)))
  let assert Ok(signed2) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims2, key)
  let token2 = jwt.serialize(signed2)
  let assert Ok(_) = jwt.verify_and_validate(v, token2, now)
}

pub fn issuer_validation_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let claims = jwt_helpers.claims_with_issuer("correct-issuer")
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let correct_opts =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      issuer: Some("correct-issuer"),
    )
  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], correct_opts)
  let assert Ok(_) = jwt.verify_and_validate(v, token, now)

  let wrong_opts =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      issuer: Some("wrong-issuer"),
    )
  let assert Ok(v_wrong) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], wrong_opts)
  let assert Error(jwt.IssuerMismatch(expected: "wrong-issuer", actual: _)) =
    jwt.verify_and_validate(v_wrong, token, now)

  let claims_no_iss = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed_no_iss) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims_no_iss, key)
  assert jwt.verify_and_validate(v, jwt.serialize(signed_no_iss), now)
    == Error(jwt.IssuerMismatch(expected: "correct-issuer", actual: None))
}

pub fn audience_validation_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let assert Ok(claims) =
    jwt_helpers.default_claims_with_exp()
    |> jwt.with_audiences(["api.example.com", "web.example.com"])
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let correct_opts =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      audience: Some("api.example.com"),
    )
  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], correct_opts)
  let assert Ok(_) = jwt.verify_and_validate(v, token, now)

  let wrong_opts =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      audience: Some("other.example.com"),
    )
  let assert Ok(v_wrong) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], wrong_opts)
  let assert Error(jwt.AudienceMismatch(
    expected: "other.example.com",
    actual: _,
  )) = jwt.verify_and_validate(v_wrong, token, now)

  let claims_no_aud = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed_no_aud) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims_no_aud, key)
  assert jwt.verify_and_validate(v, jwt.serialize(signed_no_aud), now)
    == Error(jwt.AudienceMismatch(expected: "api.example.com", actual: None))
}

pub fn missing_exp_validation_test() {
  let key = jwt_helpers.hmac_key()
  let claims = jwt_helpers.claims_without_exp()
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  assert jwt.verify_and_validate(v, token, jwt_helpers.fixed_timestamp())
    == Error(jwt.MissingExpiration)

  let opts =
    jwt.JwtValidationOptions(..jwt.default_validation(), require_exp: False)
  let assert Ok(v_no_exp) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  let assert Ok(_) =
    jwt.verify_and_validate(v_no_exp, token, jwt_helpers.fixed_timestamp())
}

pub fn verifier_key_validation_test() {
  let hmac_key = jwk.generate_hmac_key(jwa.HmacSha256)

  assert jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [], jwt.default_validation())
    == Error(jwt.JoseError(gose.InvalidState("at least one key required")))

  assert jwt.verifier(
      jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256),
      [hmac_key],
      jwt.default_validation(),
    )
    == Error(
      jwt.JoseError(gose.InvalidState(
        "algorithm RS256 incompatible with key type",
      )),
    )

  let assert Ok(enc_key) =
    jwk.generate_hmac_key(jwa.HmacSha256)
    |> jwk.with_key_use(jwk.Encrypting)
  assert jwt.verifier(
      jwa.JwsHmac(jwa.HmacSha256),
      [enc_key],
      jwt.default_validation(),
    )
    == Error(
      jwt.JoseError(gose.InvalidState(
        "key use is 'enc', cannot be used for verification",
      )),
    )

  let assert Ok(sign_only_key) =
    jwk.generate_hmac_key(jwa.HmacSha256)
    |> jwk.with_key_ops([jwk.Sign])
  assert jwt.verifier(
      jwa.JwsHmac(jwa.HmacSha256),
      [sign_only_key],
      jwt.default_validation(),
    )
    == Error(
      jwt.JoseError(gose.InvalidState(
        "key_ops does not include 'verify' operation",
      )),
    )
}

pub fn verifier_hmac_key_size_validation_test() {
  let assert Ok(key16) = jwk.from_octet_bits(crypto.random_bytes(16))
  let key32 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key48 = jwk.generate_hmac_key(jwa.HmacSha384)
  let key64 = jwk.generate_hmac_key(jwa.HmacSha512)

  assert jwt.verifier(
      jwa.JwsHmac(jwa.HmacSha256),
      [key16],
      jwt.default_validation(),
    )
    == Error(
      jwt.JoseError(gose.InvalidState(
        "HS256 requires key of at least 32 bytes, got 16",
      )),
    )
  assert jwt.verifier(
      jwa.JwsHmac(jwa.HmacSha384),
      [key32],
      jwt.default_validation(),
    )
    == Error(
      jwt.JoseError(gose.InvalidState(
        "HS384 requires key of at least 48 bytes, got 32",
      )),
    )
  assert jwt.verifier(
      jwa.JwsHmac(jwa.HmacSha512),
      [key32],
      jwt.default_validation(),
    )
    == Error(
      jwt.JoseError(gose.InvalidState(
        "HS512 requires key of at least 64 bytes, got 32",
      )),
    )

  let assert Ok(_) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key32], jwt.default_validation())
  let assert Ok(_) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha384), [key48], jwt.default_validation())
  let assert Ok(_) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha512), [key64], jwt.default_validation())
  let assert Ok(_) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key64], jwt.default_validation())
}

pub fn verifier_ec_curve_validation_test() {
  let p256_key = fixtures.ec_p256_key()
  let p384_key = fixtures.ec_p384_key()

  assert jwt.verifier(
      jwa.JwsEcdsa(jwa.EcdsaP256),
      [p384_key],
      jwt.default_validation(),
    )
    == Error(
      jwt.JoseError(gose.InvalidState("EC key curve does not match algorithm")),
    )

  let assert Ok(_) =
    jwt.verifier(
      jwa.JwsEcdsa(jwa.EcdsaP256),
      [p256_key],
      jwt.default_validation(),
    )

  let x25519_key = fixtures.x25519_key()
  let assert Error(jwt.JoseError(gose.InvalidState(_))) =
    jwt.verifier(jwa.JwsEddsa, [x25519_key], jwt.default_validation())
}

pub fn verifier_rejects_algorithm_mismatch_in_token_test() {
  let key = jwt_helpers.hmac_key()
  let hs512_key = jwk.generate_hmac_key(jwa.HmacSha512)
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha512), claims, hs512_key)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  assert jwt.verify_and_validate(v, token, jwt_helpers.fixed_timestamp())
    == Error(jwt.JwsAlgorithmMismatch(
      expected: jwa.JwsHmac(jwa.HmacSha256),
      actual: jwa.JwsHmac(jwa.HmacSha512),
    ))
}

pub fn wrong_key_fails_verification_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key1)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key2], jwt.default_validation())
  assert jwt.verify_and_validate(v, token, jwt_helpers.fixed_timestamp())
    == Error(jwt.InvalidSignature)
}

pub fn kid_no_requirement_policy_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "key-1")
  let key2_raw = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2_raw, "key-2")

  let assert Ok(verifier) =
    jwt.verifier(
      jwa.JwsHmac(jwa.HmacSha256),
      [key1, key2],
      jwt.default_validation(),
    )
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(signed) =
    jwt.sign(
      jwa.JwsHmac(jwa.HmacSha256),
      claims,
      jwk.with_kid(key2, "unknown-key"),
    )
  let token = jwt.serialize(signed)
  let assert Ok(_) =
    jwt.verify_and_validate(verifier, token, jwt_helpers.fixed_timestamp())

  let assert Ok(signed_no_kid) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key2_raw)
  let assert Ok(_) =
    jwt.verify_and_validate(
      verifier,
      jwt.serialize(signed_no_kid),
      jwt_helpers.fixed_timestamp(),
    )
}

pub fn kid_require_kid_policy_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "key-1")
  let key2_raw = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2_raw, "key-2")

  let opts =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      kid_policy: jwt.RequireKid,
    )
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key1, key2], opts)
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(signed) =
    jwt.sign(
      jwa.JwsHmac(jwa.HmacSha256),
      claims,
      jwk.with_kid(key2, "unknown-kid"),
    )
  let assert Ok(_) =
    jwt.verify_and_validate(
      verifier,
      jwt.serialize(signed),
      jwt_helpers.fixed_timestamp(),
    )

  let assert Ok(signed_no_kid) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key2_raw)
  assert jwt.verify_and_validate(
      verifier,
      jwt.serialize(signed_no_kid),
      jwt_helpers.fixed_timestamp(),
    )
    == Error(jwt.MissingKid)
}

pub fn kid_require_match_policy_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "key-1")
  let key2_raw = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2_raw, "key-2")

  let opts =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      kid_policy: jwt.RequireKidMatch,
    )
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key1, key2], opts)
  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key2)
  let assert Ok(_) =
    jwt.verify_and_validate(
      verifier,
      jwt.serialize(signed),
      jwt_helpers.fixed_timestamp(),
    )

  let assert Ok(signed_unknown) =
    jwt.sign(
      jwa.JwsHmac(jwa.HmacSha256),
      claims,
      jwk.with_kid(key2, "unknown-key"),
    )
  assert jwt.verify_and_validate(
      verifier,
      jwt.serialize(signed_unknown),
      jwt_helpers.fixed_timestamp(),
    )
    == Error(jwt.UnknownKid("unknown-key"))

  let assert Ok(signed_no_kid) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key2_raw)
  assert jwt.verify_and_validate(
      verifier,
      jwt.serialize(signed_no_kid),
      jwt_helpers.fixed_timestamp(),
    )
    == Error(jwt.MissingKid)
}

pub fn multiple_keys_try_each_until_match_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key3 = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(verifier) =
    jwt.verifier(
      jwa.JwsHmac(jwa.HmacSha256),
      [key1, key2],
      jwt.default_validation(),
    )

  let claims = jwt_helpers.default_claims_with_exp()

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key2)
  let assert Ok(_) =
    jwt.verify_and_validate(
      verifier,
      jwt.serialize(signed),
      jwt_helpers.fixed_timestamp(),
    )

  let assert Ok(signed_bad) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key3)
  assert jwt.verify_and_validate(
      verifier,
      jwt.serialize(signed_bad),
      jwt_helpers.fixed_timestamp(),
    )
    == Error(jwt.InvalidSignature)
}

pub fn parse_invalid_token_test() {
  let assert Error(jwt.MalformedToken(_)) = jwt.parse("not.a.valid.token")
  let assert Error(jwt.MalformedToken(_)) = jwt.parse("invalid")
}

pub fn parse_rejects_non_json_payload_test() {
  let key = jwt_helpers.hmac_key()
  let payload = bit_array.from_string("not valid json")
  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)
  assert jwt.parse(token) == Error(jwt.MalformedToken("invalid claims JSON"))
}

pub fn parse_rejects_invalid_claim_types_test() {
  let key = jwt_helpers.hmac_key()

  let payload_bad_iss =
    json.to_string(
      json.object([
        #("iss", json.int(123)),
        #("sub", json.string("user")),
        #("exp", json.int(9_999_999_999)),
      ]),
    )
    |> bit_array.from_string
  let assert Ok(signed_bad_iss) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, payload_bad_iss)
  let assert Ok(token_bad_iss) = jws.serialize_compact(signed_bad_iss)
  assert jwt.parse(token_bad_iss)
    == Error(jwt.MalformedToken("iss claim must be a string"))

  let payload_bad_exp =
    json.to_string(
      json.object([
        #("sub", json.string("user")),
        #("exp", json.string("not-a-number")),
      ]),
    )
    |> bit_array.from_string

  let assert Ok(signed_bad_exp) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, payload_bad_exp)
  let assert Ok(token_bad_exp) = jws.serialize_compact(signed_bad_exp)
  assert jwt.parse(token_bad_exp)
    == Error(jwt.MalformedToken("exp claim must be a numeric value"))

  let payload_bad_aud =
    json.to_string(
      json.object([
        #("sub", json.string("user")),
        #("aud", json.int(123)),
        #("exp", json.int(9_999_999_999)),
      ]),
    )
    |> bit_array.from_string

  let assert Ok(signed_bad_aud) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, payload_bad_aud)
  let assert Ok(token_bad_aud) = jws.serialize_compact(signed_bad_aud)
  assert jwt.parse(token_bad_aud)
    == Error(jwt.MalformedToken(
      "aud claim must be a string or array of strings",
    ))
}

pub fn parse_accepts_fractional_exp_test() {
  let key = jwt_helpers.hmac_key()
  let payload =
    json.to_string(
      json.object([
        #("sub", json.string("user123")),
        #("exp", json.float(1_800_000_000.5)),
      ]),
    )
    |> bit_array.from_string

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)

  let assert Ok(_) = jwt.parse(token)
}

pub fn dangerously_decode_unverified_test() {
  let key = jwt_helpers.hmac_key()
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(parsed) = jwt.parse(token)
  let assert Ok(sub) =
    jwt.dangerously_decode_unverified(parsed, jwt_helpers.sub_decoder())
  assert sub == "user123"

  let decoder = decode.field("nonexistent", decode.string, decode.success)
  let assert Error(jwt.ClaimDecodingFailed(_)) =
    jwt.dangerously_decode_unverified(parsed, decoder)
}

pub fn decode_missing_field_error_test() {
  let key = jwt_helpers.hmac_key()
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Ok(verified) =
    jwt.verify_and_validate(verifier, token, jwt_helpers.fixed_timestamp())

  let decoder = decode.field("nonexistent", decode.string, decode.success)
  let assert Error(jwt.ClaimDecodingFailed(_)) = jwt.decode(verified, decoder)
}

pub fn jwt_accessors_test() {
  let key = jwt_helpers.hmac_key() |> jwk.with_kid("my-key-id")
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)

  assert jwt.alg(signed) == jwa.JwsHmac(jwa.HmacSha256)
  assert jwt.kid(signed) == Ok("my-key-id")

  let assert Ok(parsed) = jwt.parse(jwt.serialize(signed))
  assert jwt.alg(parsed) == jwa.JwsHmac(jwa.HmacSha256)
  assert jwt.kid(parsed) == Ok("my-key-id")
}

pub fn kid_returns_error_when_absent_test() {
  let key = jwt_helpers.hmac_key()
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  assert jwt.kid(signed) == Error(Nil)

  let assert Ok(parsed) = jwt.parse(jwt.serialize(signed))
  assert jwt.kid(parsed) == Error(Nil)
}

pub fn verify_and_dangerously_skip_validation_test() {
  let key = jwt_helpers.hmac_key()
  let past = timestamp.add(jwt_helpers.fixed_timestamp(), duration.hours(-2))
  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(past)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())

  let assert Error(jwt.TokenExpired(_)) =
    jwt.verify_and_validate(v, token, jwt_helpers.fixed_timestamp())

  let assert Ok(verified) = jwt.verify_and_dangerously_skip_validation(v, token)
  let assert Ok(sub) = jwt.decode(verified, jwt_helpers.sub_decoder())
  assert sub == "user123"
}

pub fn dangerously_skip_still_enforces_algorithm_test() {
  let key = jwt_helpers.hmac_key()
  let hs512_key = jwk.generate_hmac_key(jwa.HmacSha512)
  let claims = jwt_helpers.default_claims_with_exp()
  let assert Ok(signed) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha512), claims, hs512_key)
  let token = jwt.serialize(signed)

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  assert jwt.verify_and_dangerously_skip_validation(v, token)
    == Error(jwt.JwsAlgorithmMismatch(
      expected: jwa.JwsHmac(jwa.HmacSha256),
      actual: jwa.JwsHmac(jwa.HmacSha512),
    ))
}

pub fn jwt_rejects_detached_payload_test() {
  let key = jwt_helpers.hmac_key()
  let token =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IldUIn0..SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

  assert jwt.parse(token)
    == Error(jwt.MalformedToken("JWTs do not support detached payloads"))

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  assert jwt.verify_and_validate(v, token, jwt_helpers.fixed_timestamp())
    == Error(jwt.MalformedToken("JWTs do not support detached payloads"))
}

pub fn jwt_rejects_unencoded_payload_test() {
  let key = jwt_helpers.hmac_key()
  let payload =
    json.object([
      #("sub", json.string("user123")),
      #("exp", json.int(9_999_999_999)),
    ])
    |> json.to_string
    |> bit_array.from_string

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_unencoded()
    |> jws.sign(key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)

  assert jwt.parse(token)
    == Error(jwt.MalformedToken(
      "JWTs do not support unencoded payloads (b64=false)",
    ))

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  assert jwt.verify_and_validate(v, token, jwt_helpers.fixed_timestamp())
    == Error(jwt.MalformedToken(
      "JWTs do not support unencoded payloads (b64=false)",
    ))
}

pub fn single_audience_serialized_as_string_test() {
  let key = jwt_helpers.hmac_key()
  let claims =
    jwt_helpers.default_claims_with_exp()
    |> jwt.with_audience("single-audience")
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(parsed) = jwt.parse(token)
  let decoder = decode.field("aud", decode.string, decode.success)
  let assert Ok(aud) = jwt.dangerously_decode_unverified(parsed, decoder)
  assert aud == "single-audience"
}

pub fn multiple_audiences_serialized_as_array_test() {
  let key = jwt_helpers.hmac_key()
  let assert Ok(claims) =
    jwt_helpers.default_claims_with_exp()
    |> jwt.with_audiences(["aud1", "aud2"])
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(parsed) = jwt.parse(token)
  let decoder = decode.field("aud", decode.list(decode.string), decode.success)
  let assert Ok(aud) = jwt.dangerously_decode_unverified(parsed, decoder)
  assert aud == ["aud1", "aud2"]
}

pub fn custom_claims_roundtrip_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let profile =
    json.object([#("name", json.string("John")), #("age", json.int(30))])
  let assert Ok(claims) =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_claim("roles", json.array(["admin", "user"], json.string))
  let assert Ok(claims) = claims |> jwt.with_claim("score", json.float(3.14))
  let assert Ok(claims) = claims |> jwt.with_claim("profile", profile)
  let assert Ok(claims) = claims |> jwt.with_claim("optional", json.null())

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let profile_decoder = {
    use name <- decode.field("name", decode.string)
    use age <- decode.field("age", decode.int)
    decode.success(#(name, age))
  }
  let decoder = {
    use roles <- decode.field("roles", decode.list(decode.string))
    use score <- decode.field("score", decode.float)
    use profile <- decode.field("profile", profile_decoder)
    use optional <- decode.field("optional", decode.optional(decode.string))
    decode.success(#(roles, score, profile, optional))
  }

  let assert Ok(v) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Ok(validated) = jwt.verify_and_validate(v, token, now)
  let assert Ok(#(roles, score, #(name, age), optional)) =
    jwt.decode(validated, decoder)

  assert roles == ["admin", "user"]
  assert score == 3.14
  assert name == "John"
  assert age == 30
  assert optional == None
}

pub fn jwt_hs256_snapshot_test() {
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

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)

  jwt.serialize(signed)
  |> birdie.snap("JWT HS256 compact serialization")
}

pub fn jwt_with_kid_snapshot_test() {
  let key = jwt_helpers.hmac_key() |> jwk.with_kid("my-key-id")
  let now = timestamp.from_unix_seconds(1_700_000_000)
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)

  jwt.serialize(signed)
  |> birdie.snap("JWT HS256 with kid header")
}

pub fn jwt_rejects_unprotected_alg_test() {
  let header_b64 =
    json.object([#("alg", json.string("HS256"))])
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)

  let claims_json =
    json.object([
      #("sub", json.string("user123")),
      #("iat", json.int(1_234_567_890)),
    ])
  let payload_b64 =
    claims_json
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)

  let sig_b64 = bit_array.base64_url_encode(<<"fake-sig":utf8>>, False)

  let json_str =
    json.object([
      #("protected", json.string(header_b64)),
      #("payload", json.string(payload_b64)),
      #("signature", json.string(sig_b64)),
      #("header", json.object([#("alg", json.string("none"))])),
    ])
    |> json.to_string

  let assert Error(gose.ParseError(msg)) = jws.parse_json(json_str)
  assert msg == "header names must be disjoint, overlap: alg"
}

pub fn jwt_accepts_valid_unprotected_header_test() {
  let header_b64 =
    json.object([#("alg", json.string("HS256"))])
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)

  let claims_json =
    json.object([
      #("sub", json.string("user123")),
      #("iat", json.int(1_234_567_890)),
    ])
  let payload_b64 =
    claims_json
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)

  let sig_b64 = bit_array.base64_url_encode(<<"fake-sig":utf8>>, False)

  let json_str =
    json.object([
      #("protected", json.string(header_b64)),
      #("payload", json.string(payload_b64)),
      #("signature", json.string(sig_b64)),
      #("header", json.object([#("kid", json.string("my-key"))])),
    ])
    |> json.to_string

  let assert Ok(parsed_jws) = jws.parse_json(json_str)
  assert jws.has_unprotected_header(parsed_jws)

  let decoder = {
    use kid <- decode.field("kid", decode.string)
    decode.success(kid)
  }
  let assert Ok("my-key") = jws.decode_unprotected_header(parsed_jws, decoder)
}

pub fn empty_audience_array_rejected_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))
  let #(exp_seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(exp)
  let claims_json =
    json.object([
      #("sub", json.string("user123")),
      #("exp", json.int(exp_seconds)),
      #("aud", json.preprocessed_array([])),
    ])
    |> json.to_string

  let unsigned = jws.new(jwa.JwsHmac(jwa.HmacSha256))
  let assert Ok(signed) =
    jws.sign(unsigned, key, bit_array.from_string(claims_json))
  let assert Ok(token) = jws.serialize_compact(signed)

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  assert jwt.verify_and_validate(verifier, token, now)
    == Error(jwt.MalformedToken("aud claim cannot be an empty array"))
}

pub fn max_token_age_missing_iat_fails_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let opts = jwt.default_validation() |> jwt.with_max_token_age(3600)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  assert jwt.verify_and_validate(verifier, token, now)
    == Error(jwt.MissingIssuedAt)
}

pub fn max_token_age_with_iat_present_succeeds_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(now)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let opts = jwt.default_validation() |> jwt.with_max_token_age(3600)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  let assert Ok(_) = jwt.verify_and_validate(verifier, token, now)
}

pub fn max_token_age_old_token_fails_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))
  let iat = timestamp.add(now, duration.seconds(-3700))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(iat)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let opts = jwt.default_validation() |> jwt.with_max_token_age(3600)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  let assert Error(jwt.TokenTooOld(_, 3600)) =
    jwt.verify_and_validate(verifier, token, now)
}

pub fn max_token_age_fresh_token_succeeds_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))
  let iat = timestamp.add(now, duration.seconds(-1800))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(iat)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let opts = jwt.default_validation() |> jwt.with_max_token_age(3600)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  let assert Ok(_) = jwt.verify_and_validate(verifier, token, now)
}

pub fn max_token_age_zero_boundary_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))
  let opts = jwt.default_validation() |> jwt.with_max_token_age(0)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)

  let claims_at_now =
    jwt.claims()
    |> jwt.with_subject("user")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(now)
  let assert Ok(signed_now) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims_at_now, key)
  let assert Ok(_) =
    jwt.verify_and_validate(verifier, jwt.serialize(signed_now), now)

  let one_second_ago = timestamp.add(now, duration.seconds(-1))
  let claims_old =
    jwt.claims()
    |> jwt.with_subject("user")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(one_second_ago)
  let assert Ok(signed_old) =
    jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims_old, key)
  let assert Error(jwt.TokenTooOld(_, 0)) =
    jwt.verify_and_validate(verifier, jwt.serialize(signed_old), now)
}

pub fn no_max_token_age_no_iat_skips_check_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Ok(_) = jwt.verify_and_validate(verifier, token, now)
}

pub fn jti_validator_rejects_invalid_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_jwt_id("revoked-token-id")
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let revoked_ids = ["revoked-token-id"]
  let validator = fn(jti) { !list.contains(revoked_ids, jti) }
  let opts = jwt.default_validation() |> jwt.with_jti_validator(validator)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  assert jwt.verify_and_validate(verifier, token, now)
    == Error(jwt.InvalidJti("revoked-token-id"))
}

pub fn jti_validator_accepts_valid_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_jwt_id("valid-token-id")
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let revoked_ids = ["revoked-token-id"]
  let validator = fn(jti) { !list.contains(revoked_ids, jti) }
  let opts = jwt.default_validation() |> jwt.with_jti_validator(validator)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  let assert Ok(_) = jwt.verify_and_validate(verifier, token, now)
}

pub fn jti_validator_no_jti_skips_check_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let validator = fn(_jti) { False }
  let opts = jwt.default_validation() |> jwt.with_jti_validator(validator)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  let assert Ok(_) = jwt.verify_and_validate(verifier, token, now)
}

pub fn future_iat_with_max_token_age_fails_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(2))
  let iat = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(iat)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let opts = jwt.default_validation() |> jwt.with_max_token_age(3600)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  let assert Error(jwt.IssuedInFuture(_)) =
    jwt.verify_and_validate(verifier, token, now)
}

pub fn future_iat_within_clock_skew_succeeds_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(2))
  let iat = timestamp.add(now, duration.seconds(30))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(iat)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let opts = jwt.default_validation() |> jwt.with_max_token_age(3600)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  let assert Ok(_) = jwt.verify_and_validate(verifier, token, now)
}

pub fn future_iat_beyond_clock_skew_fails_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(2))
  let iat = timestamp.add(now, duration.seconds(61))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(iat)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let opts = jwt.default_validation() |> jwt.with_max_token_age(3600)
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], opts)
  let assert Error(jwt.IssuedInFuture(_)) =
    jwt.verify_and_validate(verifier, token, now)
}

pub fn future_iat_without_max_token_age_fails_test() {
  let key = jwt_helpers.hmac_key()
  let now = jwt_helpers.fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(2))
  let iat = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_expiration(exp)
    |> jwt.with_issued_at(iat)
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Error(jwt.IssuedInFuture(_)) =
    jwt.verify_and_validate(verifier, token, now)
}

pub fn select_keys_no_kid_no_requirement_returns_all_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(keys) =
    jwt.select_keys_by_policy([key1, key2], None, jwt.NoKidRequirement)
  assert list.length(keys) == 2
}

pub fn select_keys_no_kid_require_kid_errors_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  assert jwt.select_keys_by_policy([key], None, jwt.RequireKid)
    == Error(jwt.MissingKid)
}

pub fn select_keys_no_kid_require_kid_match_errors_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  assert jwt.select_keys_by_policy([key], None, jwt.RequireKidMatch)
    == Error(jwt.MissingKid)
}

pub fn select_keys_with_kid_require_match_filters_test() {
  let key1 =
    jwk.generate_hmac_key(jwa.HmacSha256)
    |> jwk.with_kid("key-1")
  let key2 =
    jwk.generate_hmac_key(jwa.HmacSha256)
    |> jwk.with_kid("key-2")
  let assert Ok(keys) =
    jwt.select_keys_by_policy([key1, key2], Some("key-1"), jwt.RequireKidMatch)
  assert list.length(keys) == 1
  assert list.first(keys) == Ok(key1)
}

pub fn select_keys_with_kid_require_match_unknown_errors_test() {
  let key =
    jwk.generate_hmac_key(jwa.HmacSha256)
    |> jwk.with_kid("key-1")
  assert jwt.select_keys_by_policy([key], Some("key-99"), jwt.RequireKidMatch)
    == Error(jwt.UnknownKid("key-99"))
}

pub fn select_keys_with_kid_no_requirement_prioritizes_match_test() {
  let key1 =
    jwk.generate_hmac_key(jwa.HmacSha256)
    |> jwk.with_kid("key-1")
  let key2 =
    jwk.generate_hmac_key(jwa.HmacSha256)
    |> jwk.with_kid("key-2")
  let assert Ok(keys) =
    jwt.select_keys_by_policy([key1, key2], Some("key-2"), jwt.NoKidRequirement)
  assert list.length(keys) == 2
  assert list.first(keys) == Ok(key2)
}

pub fn serialize_verified_roundtrip_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let now = timestamp.from_unix_seconds(1_000_000)
  let exp = timestamp.from_unix_seconds(2_000_000)

  let claims =
    jwt.claims()
    |> jwt.with_subject("test-user")
    |> jwt.with_expiration(exp)

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)
  assert jwt.serialize(verified) == token
}

pub fn decode_fails_with_bad_decoder_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let now = timestamp.from_unix_seconds(1_000_000)
  let exp = timestamp.from_unix_seconds(2_000_000)

  let claims =
    jwt.claims()
    |> jwt.with_subject("test-user")
    |> jwt.with_expiration(exp)

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

  let bad_decoder = decode.field("nonexistent", decode.int, decode.success)
  assert jwt.decode(verified, bad_decoder)
    == Error(jwt.ClaimDecodingFailed("failed to decode claims"))
}
