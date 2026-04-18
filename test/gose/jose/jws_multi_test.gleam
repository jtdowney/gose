import gleam/json
import gleam/string
import gose
import gose/algorithm
import gose/jose/jws_multi
import gose/key
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import kryptos/ec
import qcheck

pub fn property_sign_verify_roundtrip_test() {
  use alg_with_key <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.from_generators(generators.jws_rsa_alg_generator(), [
      generators.jws_ecdsa_alg_generator(),
      generators.jws_eddsa_alg_generator(),
    ]),
  )
  let generators.JwsAlgWithKey(alg, k) = alg_with_key
  let payload = <<"property test":utf8>>

  let assert Ok(body) =
    jws_multi.new(payload:)
    |> jws_multi.sign(alg, key: k)
  let multi = jws_multi.assemble(body)
  let json_str = jws_multi.serialize_json(multi) |> json.to_string
  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  assert jws_multi.payload(parsed) == payload
  let assert Ok(v) = jws_multi.verifier(alg, keys: [k])
  assert jws_multi.verify(v, parsed) == Ok(Nil)
}

pub fn multi_signer_verify_each_test() {
  let payload = <<"multi signer":utf8>>
  let hmac_key = key.generate_hmac_key(algorithm.HmacSha256)
  let ec_key = fixtures.ec_p256_key()
  let ed_key = fixtures.ed25519_key()

  let assert Ok(body) =
    jws_multi.new(payload:)
    |> jws_multi.sign(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      key: hmac_key,
    )
  let assert Ok(body) =
    body
    |> jws_multi.sign(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      key: ec_key,
    )
  let assert Ok(body) =
    body
    |> jws_multi.sign(algorithm.DigitalSignature(algorithm.Eddsa), key: ed_key)
  let multi = jws_multi.assemble(body)
  let json_str = jws_multi.serialize_json(multi) |> json.to_string
  let assert Ok(parsed) = jws_multi.parse_json(json_str)

  let assert Ok(v1) =
    jws_multi.verifier(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      keys: [hmac_key],
    )
  assert jws_multi.verify(v1, parsed) == Ok(Nil)

  let assert Ok(v2) =
    jws_multi.verifier(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      keys: [ec_key],
    )
  assert jws_multi.verify(v2, parsed) == Ok(Nil)

  let assert Ok(v3) =
    jws_multi.verifier(algorithm.DigitalSignature(algorithm.Eddsa), keys: [
      ed_key,
    ])
  assert jws_multi.verify(v3, parsed) == Ok(Nil)
}

pub fn verify_wrong_key_test() {
  let payload = <<"wrong key":utf8>>
  let k = fixtures.ec_p256_key()
  let other = key.generate_ec(ec.P256)
  let alg = algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256))

  let assert Ok(body) = jws_multi.new(payload:) |> jws_multi.sign(alg, key: k)
  let multi = jws_multi.assemble(body)
  let json_str = jws_multi.serialize_json(multi) |> json.to_string
  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  let assert Ok(v) = jws_multi.verifier(alg, keys: [other])
  assert jws_multi.verify(v, parsed) == Error(gose.VerificationFailed)
}

pub fn verify_no_matching_signer_test() {
  let payload = <<"no match":utf8>>
  let k = fixtures.ec_p256_key()
  let rsa_key = fixtures.rsa_private_key()

  let assert Ok(body) =
    jws_multi.new(payload:)
    |> jws_multi.sign(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      key: k,
    )
  let multi = jws_multi.assemble(body)
  let json_str = jws_multi.serialize_json(multi) |> json.to_string
  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  let assert Ok(v) =
    jws_multi.verifier(
      algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256)),
      keys: [rsa_key],
    )
  assert jws_multi.verify(v, parsed) == Error(gose.VerificationFailed)
}

pub fn verifier_empty_keys_test() {
  assert jws_multi.verifier(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      keys: [],
    )
    == Error(gose.InvalidState("at least one key required"))
}

pub fn verifier_wrong_key_type_test() {
  let hmac_key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Error(gose.InvalidState(_)) =
    jws_multi.verifier(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      keys: [hmac_key],
    )
}

pub fn parse_invalid_json_test() {
  let assert Error(gose.ParseError(_)) = jws_multi.parse_json("not json")
}

pub fn detached_roundtrip_test() {
  let alg = algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256))
  let k = fixtures.ec_p256_key()
  let payload = <<"detached payload":utf8>>

  let assert Ok(body) =
    jws_multi.new(payload:)
    |> jws_multi.with_detached
    |> jws_multi.sign(alg, key: k)
  let multi = jws_multi.assemble(body)
  assert jws_multi.is_detached(multi)

  let json_str = jws_multi.serialize_json(multi) |> json.to_string
  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  assert jws_multi.is_detached(parsed)
  assert jws_multi.payload(parsed) == <<>>

  let assert Ok(v) = jws_multi.verifier(alg, keys: [k])
  assert jws_multi.verify_detached(v, parsed, payload) == Ok(Nil)
}

pub fn verify_detached_with_wrong_payload_fails_test() {
  let alg = algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256))
  let k = fixtures.ec_p256_key()
  let correct_payload = <<"correct payload":utf8>>
  let wrong_payload = <<"wrong payload":utf8>>

  let assert Ok(body) =
    jws_multi.new(payload: correct_payload)
    |> jws_multi.with_detached
    |> jws_multi.sign(alg, key: k)
  let multi = jws_multi.assemble(body)
  let json_str = jws_multi.serialize_json(multi) |> json.to_string
  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  let assert Ok(v) = jws_multi.verifier(alg, keys: [k])
  assert jws_multi.verify_detached(v, parsed, wrong_payload)
    == Error(gose.VerificationFailed)
}

pub fn detached_serialized_json_omits_payload_test() {
  let alg = algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256))
  let k = fixtures.ec_p256_key()

  let assert Ok(body) =
    jws_multi.new(payload: <<"x":utf8>>)
    |> jws_multi.with_detached
    |> jws_multi.sign(alg, key: k)
  let multi = jws_multi.assemble(body)
  let json_str = jws_multi.serialize_json(multi) |> json.to_string

  assert !string.contains(json_str, "\"payload\"")
}

pub fn verify_rejects_detached_test() {
  let alg = algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256))
  let k = fixtures.ec_p256_key()

  let assert Ok(body) =
    jws_multi.new(payload: <<"x":utf8>>)
    |> jws_multi.with_detached
    |> jws_multi.sign(alg, key: k)
  let multi = jws_multi.assemble(body)
  let assert Ok(parsed) =
    jws_multi.parse_json(jws_multi.serialize_json(multi) |> json.to_string)
  let assert Ok(v) = jws_multi.verifier(alg, keys: [k])
  assert jws_multi.verify(v, parsed)
    == Error(gose.InvalidState(
      "JWS payload is detached; use verify_detached instead",
    ))
}

pub fn verify_detached_rejects_attached_test() {
  let alg = algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256))
  let k = fixtures.ec_p256_key()

  let assert Ok(body) =
    jws_multi.new(payload: <<"x":utf8>>) |> jws_multi.sign(alg, key: k)
  let multi = jws_multi.assemble(body)
  let assert Ok(v) = jws_multi.verifier(alg, keys: [k])
  assert jws_multi.verify_detached(v, multi, <<"x":utf8>>)
    == Error(gose.InvalidState(
      "JWS payload is not detached; use verify instead",
    ))
}
