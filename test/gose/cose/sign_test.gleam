import gose
import gose/algorithm
import gose/cbor
import gose/cose
import gose/cose/sign
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
  let assert algorithm.DigitalSignature(sig_alg) = alg
  let payload = <<"property test payload":utf8>>
  let assert Ok(body) = sign.sign(sign.new(payload:), sig_alg, key: k)
  let signed = sign.assemble(body)

  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)
  assert sign.payload(parsed) == Ok(payload)

  let assert Ok(v) = sign.verifier(sig_alg, keys: [k])
  assert sign.verify(v, parsed) == Ok(Nil)
}

pub fn property_tagged_roundtrip_test() {
  use alg_with_key <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.from_generators(generators.jws_ecdsa_alg_generator(), [
      generators.jws_eddsa_alg_generator(),
    ]),
  )
  let generators.JwsAlgWithKey(alg, k) = alg_with_key
  let assert algorithm.DigitalSignature(sig_alg) = alg
  let payload = <<"tagged roundtrip":utf8>>
  let assert Ok(body) = sign.sign(sign.new(payload:), sig_alg, key: k)
  let signed = sign.assemble(body)

  let data = sign.serialize_tagged(signed)
  let assert Ok(parsed) = sign.parse(data)
  assert sign.payload(parsed) == Ok(payload)

  let assert Ok(v) = sign.verifier(sig_alg, keys: [k])
  assert sign.verify(v, parsed) == Ok(Nil)
}

pub fn multi_signer_verify_each_test() {
  let payload = <<"multi signer":utf8>>
  let ec_key = fixtures.ec_p256_key()
  let ed_key = fixtures.ed25519_key()

  let assert Ok(body) =
    sign.sign(
      sign.new(payload:),
      algorithm.Ecdsa(algorithm.EcdsaP256),
      key: ec_key,
    )
  let assert Ok(body) = sign.sign(body, algorithm.Eddsa, key: ed_key)
  let signed = sign.assemble(body)

  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)

  let assert Ok(v1) =
    sign.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [ec_key])
  assert sign.verify(v1, parsed) == Ok(Nil)

  let assert Ok(v2) = sign.verifier(algorithm.Eddsa, keys: [ed_key])
  assert sign.verify(v2, parsed) == Ok(Nil)
}

pub fn multi_signer_same_alg_verify_non_first_test() {
  let payload = <<"same alg two signers":utf8>>
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)
  let held_key = fixtures.ec_p256_key()
  let other_key = key.generate_ec(ec.P256)

  let assert Ok(body) = sign.sign(sign.new(payload:), alg, key: other_key)
  let assert Ok(body) = sign.sign(body, alg, key: held_key)
  let signed = sign.assemble(body)

  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(v) = sign.verifier(alg, keys: [held_key])
  assert sign.verify(v, parsed) == Ok(Nil)
}

pub fn verify_wrong_key_test() {
  let payload = <<"wrong key":utf8>>
  let k = fixtures.ec_p256_key()
  let other_key = key.generate_ec(ec.P256)
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(body) = sign.sign(sign.new(payload:), alg, key: k)
  let signed = sign.assemble(body)
  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(v) = sign.verifier(alg, keys: [other_key])
  assert sign.verify(v, parsed) == Error(gose.VerificationFailed)
}

pub fn verify_no_matching_signer_test() {
  let payload = <<"no match":utf8>>
  let k = fixtures.ec_p256_key()
  let rsa_key = fixtures.rsa_private_key()

  let assert Ok(body) =
    sign.sign(sign.new(payload:), algorithm.Ecdsa(algorithm.EcdsaP256), key: k)
  let signed = sign.assemble(body)
  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(v) =
    sign.verifier(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256), keys: [rsa_key])
  assert sign.verify(v, parsed) == Error(gose.VerificationFailed)
}

pub fn sign_with_aad_test() {
  let payload = <<"aad test":utf8>>
  let aad = <<"extra context":utf8>>
  let k = fixtures.ec_p256_key()
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(body) =
    sign.new(payload:)
    |> sign.with_aad(aad:)
    |> sign.sign(alg, key: k)
  let signed = sign.assemble(body)

  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(v) = sign.verifier(alg, keys: [k])
  assert sign.verify_with_aad(v, message: parsed, aad:) == Ok(Nil)
  assert sign.verify(v, parsed) == Error(gose.VerificationFailed)
}

pub fn detached_sign_verify_test() {
  let payload = <<"detached":utf8>>
  let k = fixtures.ec_p256_key()
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(body) =
    sign.new(payload:)
    |> sign.with_detached()
    |> sign.sign(alg, key: k)
  let signed = sign.assemble(body)

  assert sign.payload(signed) == Error(Nil)

  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(v) = sign.verifier(alg, keys: [k])
  assert sign.verify_detached(v, message: parsed, payload:) == Ok(Nil)
}

pub fn detached_sign_verify_with_aad_test() {
  let payload = <<"detached":utf8>>
  let aad = <<"extra context":utf8>>
  let k = fixtures.ec_p256_key()
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(body) =
    sign.new(payload:)
    |> sign.with_detached()
    |> sign.with_aad(aad:)
    |> sign.sign(alg, key: k)
  let signed = sign.assemble(body)

  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(v) = sign.verifier(alg, keys: [k])
  assert sign.verify_detached_with_aad(v, message: parsed, payload:, aad:)
    == Ok(Nil)
}

pub fn verify_detached_with_wrong_aad_fails_test() {
  let payload = <<"detached":utf8>>
  let correct_aad = <<"correct context":utf8>>
  let wrong_aad = <<"wrong context":utf8>>
  let k = fixtures.ec_p256_key()
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(body) =
    sign.new(payload:)
    |> sign.with_detached()
    |> sign.with_aad(aad: correct_aad)
    |> sign.sign(alg, key: k)
  let signed = sign.assemble(body)

  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(v) = sign.verifier(alg, keys: [k])
  assert sign.verify_detached_with_aad(
      v,
      message: parsed,
      payload:,
      aad: wrong_aad,
    )
    == Error(gose.VerificationFailed)
}

pub fn verify_rejects_detached_payload_test() {
  let payload = <<"hello":utf8>>
  let k = fixtures.ec_p256_key()
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(body) =
    sign.new(payload:)
    |> sign.with_detached()
    |> sign.sign(alg, key: k)
  let signed = sign.assemble(body)
  let assert Ok(v) = sign.verifier(alg, keys: [k])
  assert sign.verify(v, signed)
    == Error(gose.InvalidState(
      "message has detached payload; use verify_detached",
    ))
}

pub fn verify_detached_rejects_embedded_test() {
  let payload = <<"hello":utf8>>
  let k = fixtures.ec_p256_key()
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(body) = sign.sign(sign.new(payload:), alg, key: k)
  let signed = sign.assemble(body)
  let assert Ok(v) = sign.verifier(alg, keys: [k])
  assert sign.verify_detached(v, message: signed, payload:)
    == Error(gose.InvalidState("message has embedded payload; use verify"))
}

pub fn verifier_empty_keys_test() {
  assert sign.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [])
    == Error(gose.InvalidState("at least one key required"))
}

pub fn verifier_wrong_key_type_test() {
  let hmac_key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Error(gose.InvalidState(_)) =
    sign.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [hmac_key])
}

pub fn parse_invalid_cbor_test() {
  let assert Error(gose.ParseError(_)) = sign.parse(<<0xff>>)
}

pub fn parse_rejects_overlapping_body_headers_test() {
  let protected = cbor.encode(cbor.Map([#(cbor.Int(1), cbor.Int(-7))]))
  let sig_protected = cbor.encode(cbor.Map([#(cbor.Int(1), cbor.Int(-7))]))
  let data =
    cbor.encode(
      cbor.Array([
        cbor.Bytes(protected),
        cbor.Map([#(cbor.Int(1), cbor.Int(-35))]),
        cbor.Bytes(<<"payload":utf8>>),
        cbor.Array([
          cbor.Array([
            cbor.Bytes(sig_protected),
            cbor.Map([]),
            cbor.Bytes(<<0:256>>),
          ]),
        ]),
      ]),
    )
  assert sign.parse(data)
    == Error(gose.ParseError(
      "duplicate label in protected and unprotected headers",
    ))
}

pub fn with_kid_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(body) =
    sign.new(payload: <<"payload":utf8>>)
    |> sign.with_kid(<<"key-1":utf8>>)
    |> sign.sign(algorithm.Ecdsa(algorithm.EcdsaP256), key: k)
  let signed = sign.assemble(body)
  assert sign.kid(signed) == Ok(<<"key-1":utf8>>)
}

pub fn kid_survives_serialize_parse_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(body) =
    sign.new(payload: <<"payload":utf8>>)
    |> sign.with_kid(<<"key-1":utf8>>)
    |> sign.sign(algorithm.Ecdsa(algorithm.EcdsaP256), key: k)
  let signed = sign.assemble(body)
  let assert Ok(parsed) = sign.parse(sign.serialize(signed))
  assert sign.kid(parsed) == Ok(<<"key-1":utf8>>)
}

pub fn protected_headers_empty_by_default_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(body) =
    sign.sign(
      sign.new(payload: <<"payload":utf8>>),
      algorithm.Ecdsa(algorithm.EcdsaP256),
      key: k,
    )
  let signed = sign.assemble(body)
  assert sign.protected_headers(signed) == []
}

pub fn unprotected_headers_exposes_kid_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(body) =
    sign.new(payload: <<"payload":utf8>>)
    |> sign.with_kid(<<"k1":utf8>>)
    |> sign.sign(algorithm.Ecdsa(algorithm.EcdsaP256), key: k)
  let signed = sign.assemble(body)
  assert cose.kid(sign.unprotected_headers(signed)) == Ok(<<"k1":utf8>>)
}

pub fn with_content_type_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(body) =
    sign.new(payload: <<"payload":utf8>>)
    |> sign.with_content_type(ct: cose.Json)
    |> sign.sign(algorithm.Ecdsa(algorithm.EcdsaP256), key: k)
  let signed = sign.assemble(body)
  assert sign.content_type(signed) == Ok(cose.Json)
}

pub fn with_critical_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(body) =
    sign.new(payload: <<"payload":utf8>>)
    |> sign.with_critical(labels: [42])
    |> sign.sign(algorithm.Ecdsa(algorithm.EcdsaP256), key: k)
  let signed = sign.assemble(body)
  assert sign.critical(signed) == Ok([42])
}

pub fn verify_rejects_unsupported_body_crit_test() {
  let payload = <<"crit test":utf8>>
  let k = fixtures.ec_p256_key()
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(body) =
    sign.new(payload:)
    |> sign.with_critical(labels: [42])
    |> sign.sign(alg, key: k)
  let signed = sign.assemble(body)

  let data = sign.serialize(signed)
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(v) = sign.verifier(alg, keys: [k])
  assert sign.verify(v, parsed)
    == Error(gose.ParseError(
      "crit references label not in protected headers: 42",
    ))
}
