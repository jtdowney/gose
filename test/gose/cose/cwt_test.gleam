import gleam/int
import gleam/list
import gleam/option
import gleam/result
import gleam/time/duration
import gleam/time/timestamp
import gose
import gose/cbor
import gose/cose/cwt
import gose/cose/sign1
import gose/test_helpers/fixtures
import kryptos/ec

fn fixed_timestamp() {
  timestamp.from_unix_seconds(1_700_000_000)
}

pub fn claims_builder_accessors_test() {
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))
  let nbf = now
  let iat = now
  let cti_bytes = <<"unique-id":utf8>>

  let claims =
    cwt.new()
    |> cwt.with_issuer("my-app")
    |> cwt.with_subject("user123")
    |> cwt.with_audience("api.example.com")
    |> cwt.with_expiration(exp)
    |> cwt.with_not_before(nbf)
    |> cwt.with_issued_at(iat)
    |> cwt.with_cti(cti_bytes)

  assert cwt.issuer(claims) == Ok("my-app")
  assert cwt.subject(claims) == Ok("user123")
  assert cwt.audience(claims) == Ok(["api.example.com"])
  assert cwt.expiration(claims) == Ok(exp)
  assert cwt.not_before(claims) == Ok(nbf)
  assert cwt.issued_at(claims) == Ok(iat)
  assert cwt.cti(claims) == Ok(cti_bytes)
}

pub fn empty_claims_test() {
  let claims = cwt.new()
  assert cwt.issuer(claims) == Error(Nil)
  assert cwt.subject(claims) == Error(Nil)
  assert cwt.audience(claims) == Error(Nil)
  assert cwt.expiration(claims) == Error(Nil)
  assert cwt.not_before(claims) == Error(Nil)
  assert cwt.issued_at(claims) == Error(Nil)
  assert cwt.cti(claims) == Error(Nil)
}

pub fn sign_and_verify_es256_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_issuer("my-app")
    |> cwt.with_expiration(exp)

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) = cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)
  let verified_claims = cwt.verified_claims(verified)

  assert cwt.subject(verified_claims) == Ok("user123")
  assert cwt.issuer(verified_claims) == Ok("my-app")
  assert cwt.expiration(verified_claims) == Ok(exp)
}

pub fn sign_and_verify_eddsa_roundtrip_test() {
  let k = fixtures.ed25519_key()
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user789")
    |> cwt.with_expiration(exp)

  let assert Ok(token) = cwt.sign(claims, gose.Eddsa, k)
  let assert Ok(verifier) = cwt.verifier(gose.Eddsa, keys: [k])
  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)

  assert cwt.subject(cwt.verified_claims(verified)) == Ok("user789")
}

pub fn expired_token_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()
  let past_exp = timestamp.add(now, duration.hours(-1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_expiration(past_exp)

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) = cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
  let assert Error(cwt.TokenExpired(_)) =
    cwt.verify_and_validate(verifier, token, now)
}

pub fn not_yet_valid_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()
  let future_nbf = timestamp.add(now, duration.hours(1))
  let exp = timestamp.add(now, duration.hours(2))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_not_before(future_nbf)
    |> cwt.with_expiration(exp)

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) = cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
  let assert Error(cwt.TokenNotYetValid(_)) =
    cwt.verify_and_validate(verifier, token, now)
}

pub fn clock_skew_tolerance_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()
  let just_expired = timestamp.add(now, duration.seconds(-30))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_expiration(just_expired)

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
    |> result.map(cwt.with_clock_skew(_, 60))

  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)
  assert cwt.subject(cwt.verified_claims(verified)) == Ok("user123")
}

pub fn issuer_validation_mismatch_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_issuer("wrong-issuer")
    |> cwt.with_expiration(exp)

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
    |> result.map(cwt.with_issuer_validation(_, "expected-issuer"))

  let assert Error(cwt.IssuerMismatch(
    expected: "expected-issuer",
    actual: option.Some("wrong-issuer"),
  )) = cwt.verify_and_validate(verifier, token, now)
}

pub fn audience_validation_mismatch_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_audience("wrong-audience")
    |> cwt.with_expiration(exp)

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
    |> result.map(cwt.with_audience_validation(_, "expected-audience"))

  let assert Error(cwt.AudienceMismatch(
    expected: "expected-audience",
    actual: option.Some(["wrong-audience"]),
  )) = cwt.verify_and_validate(verifier, token, now)
}

pub fn custom_claims_roundtrip_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let base_claims =
    cwt.new()
    |> cwt.with_expiration(exp)
  let assert Ok(claims) =
    cwt.with_custom_claim(base_claims, cbor.Text("role"), cbor.Text("admin"))
  let assert Ok(claims) =
    cwt.with_custom_claim(claims, cbor.Int(100), cbor.Int(42))

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) = cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)
  let verified_claims = cwt.verified_claims(verified)

  assert cwt.custom_claim(verified_claims, cbor.Text("role"))
    == Ok(cbor.Text("admin"))
  assert cwt.custom_claim(verified_claims, cbor.Int(100)) == Ok(cbor.Int(42))
  assert cwt.custom_claim(verified_claims, cbor.Text("missing")) == Error(Nil)
}

pub fn cti_roundtrip_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))
  let cti_bytes = <<1, 2, 3, 4, 5, 6, 7, 8>>

  let claims =
    cwt.new()
    |> cwt.with_expiration(exp)
    |> cwt.with_cti(cti_bytes)

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) = cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)

  assert cwt.cti(cwt.verified_claims(verified)) == Ok(cti_bytes)
}

pub fn missing_expiration_required_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) = cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])

  let result = cwt.verify_and_validate(verifier, token, now)
  assert result == Error(cwt.MissingExpiration)
}

pub fn missing_expiration_not_required_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
    |> result.map(cwt.with_require_expiration(_, False))

  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)
  assert cwt.subject(cwt.verified_claims(verified)) == Ok("user123")
}

pub fn multiple_audiences_test() {
  let k = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let assert Ok(claims) =
    cwt.new()
    |> cwt.with_audiences(["api1.example.com", "api2.example.com"])
  let claims = cwt.with_expiration(claims, exp)

  let assert Ok(token) = cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), k)
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
    |> result.map(cwt.with_audience_validation(_, "api2.example.com"))
  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)

  assert cwt.audience(cwt.verified_claims(verified))
    == Ok(["api1.example.com", "api2.example.com"])
}

pub fn wrong_signing_key_verification_fails_test() {
  let signing_key = fixtures.ec_p256_key()
  let wrong_key = gose.generate_ec(ec.P256)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_expiration(exp)

  let assert Ok(token) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [wrong_key])
  let result = cwt.verify_and_validate(verifier, token, now)

  assert result == Error(cwt.InvalidSignature)
}

pub fn verifier_empty_keys_test() {
  let result = cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [])

  assert result
    == Error(cwt.CoseError(gose.InvalidState("at least one key required")))
}

pub fn cti_wrong_type_rejected_test() {
  let now = fixed_timestamp()
  let signing_key = gose.generate_ec(ec.P256)
  let alg = gose.Ecdsa(gose.EcdsaP256)

  // Build a CBOR payload with cti (label 7) as Int instead of Bytes
  let payload = cbor.encode(cbor.Map([#(cbor.Int(7), cbor.Int(42))]))

  let unsigned = sign1.new(alg)
  let assert Ok(signed) = sign1.sign(unsigned, signing_key, payload)
  let token = sign1.serialize(signed)

  let assert Ok(verifier) = cwt.verifier(alg, keys: [signing_key])
  let result = cwt.verify_and_validate(verifier, token, now)

  assert result == Error(cwt.MalformedToken("cti claim must be a byte string"))
}

pub fn iss_wrong_type_rejected_test() {
  let now = fixed_timestamp()
  let signing_key = gose.generate_ec(ec.P256)
  let alg = gose.Ecdsa(gose.EcdsaP256)

  let payload = cbor.encode(cbor.Map([#(cbor.Int(1), cbor.Int(42))]))

  let unsigned = sign1.new(alg)
  let assert Ok(signed) = sign1.sign(unsigned, signing_key, payload)
  let token = sign1.serialize(signed)

  let assert Ok(verifier) = cwt.verifier(alg, keys: [signing_key])
  let result = cwt.verify_and_validate(verifier, token, now)

  assert result == Error(cwt.MalformedToken("iss claim must be a text string"))
}

pub fn sub_wrong_type_rejected_test() {
  let now = fixed_timestamp()
  let signing_key = gose.generate_ec(ec.P256)
  let alg = gose.Ecdsa(gose.EcdsaP256)

  let payload = cbor.encode(cbor.Map([#(cbor.Int(2), cbor.Int(42))]))

  let unsigned = sign1.new(alg)
  let assert Ok(signed) = sign1.sign(unsigned, signing_key, payload)
  let token = sign1.serialize(signed)

  let assert Ok(verifier) = cwt.verifier(alg, keys: [signing_key])
  let result = cwt.verify_and_validate(verifier, token, now)

  assert result == Error(cwt.MalformedToken("sub claim must be a text string"))
}

pub fn aud_wrong_type_rejected_test() {
  let now = fixed_timestamp()
  let signing_key = gose.generate_ec(ec.P256)
  let alg = gose.Ecdsa(gose.EcdsaP256)

  let payload = cbor.encode(cbor.Map([#(cbor.Int(3), cbor.Int(42))]))

  let unsigned = sign1.new(alg)
  let assert Ok(signed) = sign1.sign(unsigned, signing_key, payload)
  let token = sign1.serialize(signed)

  let assert Ok(verifier) = cwt.verifier(alg, keys: [signing_key])
  let result = cwt.verify_and_validate(verifier, token, now)

  assert result
    == Error(cwt.MalformedToken(
      "aud claim must be a text string or array of text strings",
    ))
}

pub fn exp_wrong_type_rejected_test() {
  let now = fixed_timestamp()
  let signing_key = gose.generate_ec(ec.P256)
  let alg = gose.Ecdsa(gose.EcdsaP256)

  let payload = cbor.encode(cbor.Map([#(cbor.Int(4), cbor.Text("not-an-int"))]))

  let unsigned = sign1.new(alg)
  let assert Ok(signed) = sign1.sign(unsigned, signing_key, payload)
  let token = sign1.serialize(signed)

  let assert Ok(verifier) = cwt.verifier(alg, keys: [signing_key])
  let result = cwt.verify_and_validate(verifier, token, now)

  assert result == Error(cwt.MalformedToken("exp claim must be an integer"))
}

pub fn nbf_wrong_type_rejected_test() {
  let now = fixed_timestamp()
  let signing_key = gose.generate_ec(ec.P256)
  let alg = gose.Ecdsa(gose.EcdsaP256)

  let payload = cbor.encode(cbor.Map([#(cbor.Int(5), cbor.Text("not-an-int"))]))

  let unsigned = sign1.new(alg)
  let assert Ok(signed) = sign1.sign(unsigned, signing_key, payload)
  let token = sign1.serialize(signed)

  let assert Ok(verifier) = cwt.verifier(alg, keys: [signing_key])
  let result = cwt.verify_and_validate(verifier, token, now)

  assert result == Error(cwt.MalformedToken("nbf claim must be an integer"))
}

pub fn iat_wrong_type_rejected_test() {
  let now = fixed_timestamp()
  let signing_key = gose.generate_ec(ec.P256)
  let alg = gose.Ecdsa(gose.EcdsaP256)

  let payload = cbor.encode(cbor.Map([#(cbor.Int(6), cbor.Text("not-an-int"))]))

  let unsigned = sign1.new(alg)
  let assert Ok(signed) = sign1.sign(unsigned, signing_key, payload)
  let token = sign1.serialize(signed)

  let assert Ok(verifier) = cwt.verifier(alg, keys: [signing_key])
  let result = cwt.verify_and_validate(verifier, token, now)

  assert result == Error(cwt.MalformedToken("iat claim must be an integer"))
}

pub fn non_map_payload_rejected_test() {
  let now = fixed_timestamp()
  let signing_key = gose.generate_ec(ec.P256)
  let alg = gose.Ecdsa(gose.EcdsaP256)

  let payload = cbor.encode(cbor.Array([cbor.Int(1), cbor.Int(2)]))

  let unsigned = sign1.new(alg)
  let assert Ok(signed) = sign1.sign(unsigned, signing_key, payload)
  let token = sign1.serialize(signed)

  let assert Ok(verifier) = cwt.verifier(alg, keys: [signing_key])
  let result = cwt.verify_and_validate(verifier, token, now)

  assert result == Error(cwt.MalformedToken("CWT claims must be a CBOR map"))
}

pub fn custom_claim_registered_label_rejected_test() {
  let claims = cwt.new()
  list.each([1, 2, 3, 4, 5, 6, 7], fn(label) {
    assert cwt.with_custom_claim(claims, cbor.Int(label), cbor.Text("x"))
      == Error(cwt.MalformedToken(
        "custom claim key collides with registered CWT label "
        <> int.to_string(label),
      ))
  })
}

pub fn custom_claim_duplicate_replaces_test() {
  let claims = cwt.new()
  let assert Ok(claims) =
    cwt.with_custom_claim(claims, cbor.Text("role"), cbor.Text("user"))
  let assert Ok(claims) =
    cwt.with_custom_claim(claims, cbor.Text("role"), cbor.Text("admin"))
  assert cwt.custom_claim(claims, cbor.Text("role")) == Ok(cbor.Text("admin"))
}

pub fn custom_claim_non_registered_int_allowed_test() {
  let claims = cwt.new()
  let assert Ok(claims) =
    cwt.with_custom_claim(claims, cbor.Int(100), cbor.Int(42))
  assert cwt.custom_claim(claims, cbor.Int(100)) == Ok(cbor.Int(42))
}
