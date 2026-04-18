import gleam/bit_array
import gose
import gose/algorithm
import gose/cbor
import gose/cose
import gose/cose/key as cose_key
import gose/cose/sign1
import gose/key
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import kryptos/ec
import qcheck

pub fn serialize_parse_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"roundtrip test":utf8>>
  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  assert sign1.payload(parsed) == Ok(payload)
}

pub fn serialize_tagged_parse_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"tagged test":utf8>>
  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.sign(k, payload)

  let data = sign1.serialize_tagged(signed)
  let assert Ok(parsed) = sign1.parse(data)
  assert sign1.payload(parsed) == Ok(payload)
}

pub fn serialize_untagged_parse_test() {
  let k = fixtures.ed25519_key()
  let payload = <<"untagged":utf8>>
  let assert Ok(signed) =
    sign1.new(algorithm.Eddsa)
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  assert sign1.payload(parsed) == Ok(payload)
}

pub fn sign_serialize_parse_verify_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"verify me":utf8>>
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(v) = sign1.verifier(alg, keys: [k])
  assert sign1.verify(v, parsed) == Ok(Nil)
}

pub fn verify_algorithm_mismatch_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"mismatch":utf8>>

  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)

  let rsa_key = fixtures.rsa_private_key()
  let assert Ok(v) =
    sign1.verifier(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256), keys: [
      rsa_key,
    ])
  let assert Error(gose.InvalidState(_)) = sign1.verify(v, parsed)
}

pub fn verify_wrong_key_test() {
  let k = fixtures.ec_p256_key()
  let other_key = key.generate_ec(ec.P256)
  let payload = <<"wrong key":utf8>>
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(v) = sign1.verifier(alg, keys: [other_key])
  assert sign1.verify(v, parsed) == Error(gose.VerificationFailed)
}

pub fn verify_eddsa_roundtrip_test() {
  let k = fixtures.ed25519_key()
  let payload = <<"eddsa verify":utf8>>
  let alg = algorithm.Eddsa

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(v) = sign1.verifier(alg, keys: [k])
  assert sign1.verify(v, parsed) == Ok(Nil)
}

pub fn sign_with_aad_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"aad test":utf8>>
  let aad = <<"extra context":utf8>>
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.with_aad(aad:)
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(v) = sign1.verifier(alg, keys: [k])
  assert sign1.verify_with_aad(v, parsed, aad) == Ok(Nil)
}

pub fn wrong_aad_verify_fails_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"aad test":utf8>>
  let correct_aad = <<"correct context":utf8>>
  let wrong_aad = <<"wrong context":utf8>>
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.with_aad(aad: correct_aad)
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(v) = sign1.verifier(alg, keys: [k])
  assert sign1.verify_with_aad(v, parsed, wrong_aad)
    == Error(gose.VerificationFailed)
}

pub fn sign_detached_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"detached payload":utf8>>
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.with_detached()
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(v) = sign1.verifier(alg, keys: [k])
  assert sign1.verify_detached(v, message: parsed, payload:) == Ok(Nil)
}

pub fn sign_detached_with_aad_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"detached payload":utf8>>
  let aad = <<"extra context":utf8>>
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.with_detached()
    |> sign1.with_aad(aad:)
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(v) = sign1.verifier(alg, keys: [k])
  assert sign1.verify_detached_with_aad(v, parsed, payload, aad) == Ok(Nil)
}

pub fn verify_detached_with_wrong_aad_fails_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"detached payload":utf8>>
  let correct_aad = <<"correct context":utf8>>
  let wrong_aad = <<"wrong context":utf8>>
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.with_detached()
    |> sign1.with_aad(aad: correct_aad)
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(v) = sign1.verifier(alg, keys: [k])
  assert sign1.verify_detached_with_aad(v, parsed, payload, wrong_aad)
    == Error(gose.VerificationFailed)
}

pub fn verifier_empty_keys_test() {
  assert sign1.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [])
    == Error(gose.InvalidState("at least one key required"))
}

pub fn parse_invalid_cbor_test() {
  let assert Error(gose.ParseError(_)) = sign1.parse(<<0xff>>)
}

pub fn verifier_wrong_key_type_test() {
  let hmac_key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Error(gose.InvalidState(_)) =
    sign1.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [hmac_key])
}

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

  let assert Ok(signed) =
    sign1.new(sig_alg)
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  assert sign1.payload(parsed) == Ok(payload)

  let assert Ok(v) = sign1.verifier(sig_alg, keys: [k])
  assert sign1.verify(v, parsed) == Ok(Nil)
}

pub fn verify_rejects_detached_payload_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"hello":utf8>>

  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.sign(k, payload)

  let detached = make_detached_sign1(signed)
  let assert Ok(parsed) = sign1.parse(detached)

  let assert Ok(v) =
    sign1.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [k])
  assert sign1.verify(v, parsed)
    == Error(gose.InvalidState(
      "message has detached payload; use verify_detached",
    ))
}

pub fn verify_detached_succeeds_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"hello":utf8>>

  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.sign(k, payload)

  let detached = make_detached_sign1(signed)
  let assert Ok(parsed) = sign1.parse(detached)

  let assert Ok(v) =
    sign1.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [k])
  assert sign1.verify_detached(v, parsed, payload) == Ok(Nil)
}

pub fn verify_detached_rejects_embedded_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"hello":utf8>>

  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.sign(k, payload)

  let assert Ok(v) =
    sign1.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [k])
  assert sign1.verify_detached(v, signed, payload)
    == Error(gose.InvalidState("message has embedded payload; use verify"))
}

pub fn parse_rejects_overlapping_headers_test() {
  let protected = cbor.encode(cbor.Map([#(cbor.Int(1), cbor.Int(-7))]))
  let unprotected = cbor.Map([#(cbor.Int(1), cbor.Int(-35))])
  let data =
    cbor.encode(
      cbor.Array([
        cbor.Bytes(protected),
        unprotected,
        cbor.Bytes(<<"payload":utf8>>),
        cbor.Bytes(<<0:256>>),
      ]),
    )
  assert sign1.parse(data)
    == Error(gose.ParseError(
      "duplicate label in protected and unprotected headers",
    ))
}

pub fn with_kid_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.with_kid(<<"key-1":utf8>>)
    |> sign1.sign(k, <<"payload":utf8>>)
  assert sign1.kid(signed) == Ok(<<"key-1":utf8>>)
}

pub fn kid_survives_serialize_parse_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.with_kid(<<"key-1":utf8>>)
    |> sign1.sign(k, <<"payload":utf8>>)
  let assert Ok(parsed) = sign1.parse(sign1.serialize(signed))
  assert sign1.kid(parsed) == Ok(<<"key-1":utf8>>)
}

pub fn kid_missing_returns_error_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.sign(k, <<"payload":utf8>>)
  assert sign1.kid(signed)
    == Error(gose.ParseError("missing header label 4 (kid)"))
}

pub fn with_content_type_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.with_content_type(ct: cose.Json)
    |> sign1.sign(k, <<"payload":utf8>>)
  assert sign1.content_type(signed) == Ok(cose.Json)
}

pub fn with_critical_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.with_critical(labels: [42])
    |> sign1.sign(k, <<"payload":utf8>>)
  assert sign1.critical(signed) == Ok([42])
}

pub fn protected_headers_exposes_alg_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.sign(k, <<"payload":utf8>>)
  assert cose.algorithm(sign1.protected_headers(signed)) == Ok(-7)
}

pub fn unprotected_headers_exposes_kid_test() {
  let k = fixtures.ec_p256_key()
  let assert Ok(signed) =
    sign1.new(algorithm.Ecdsa(algorithm.EcdsaP256))
    |> sign1.with_kid(<<"k1":utf8>>)
    |> sign1.sign(k, <<"payload":utf8>>)
  assert cose.kid(sign1.unprotected_headers(signed)) == Ok(<<"k1":utf8>>)
}

fn make_detached_sign1(signed: sign1.Sign1(sign1.Signed)) -> BitArray {
  let data = sign1.serialize(signed)
  let assert Ok(cbor.Array([protected, unprotected, _, signature])) =
    cbor.decode(data)
  cbor.encode(cbor.Array([protected, unprotected, cbor.Null, signature]))
}

pub fn verify_rejects_unsupported_crit_test() {
  let k = fixtures.ec_p256_key()
  let payload = <<"crit test":utf8>>
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.with_critical(labels: [42])
    |> sign1.sign(k, payload)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(v) = sign1.verifier(alg, keys: [k])
  assert sign1.verify(v, parsed)
    == Error(gose.ParseError(
      "crit references label not in protected headers: 42",
    ))
}

pub fn cose_wg_sign_pass_03_test() {
  let assert Ok(x) =
    bit_array.base64_url_decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
  let assert Ok(y) =
    bit_array.base64_url_decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
  let assert Ok(d) =
    bit_array.base64_url_decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM")
  let cose_key_cbor =
    cbor.encode(
      cbor.Map([
        #(cbor.Int(1), cbor.Int(2)),
        #(cbor.Int(-1), cbor.Int(1)),
        #(cbor.Int(-2), cbor.Bytes(x)),
        #(cbor.Int(-3), cbor.Bytes(y)),
        #(cbor.Int(-4), cbor.Bytes(d)),
      ]),
    )
  let assert Ok(k) = cose_key.from_cbor(cose_key_cbor)

  let assert Ok(cbor_bytes) =
    bit_array.base16_decode(
      "8443A10126A10442313154546869732069732074686520636F6E74656E742E58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36",
    )

  let assert Ok(parsed) = sign1.parse(cbor_bytes)
  assert sign1.payload(parsed) == Ok(<<"This is the content.":utf8>>)

  let assert Ok(verifier) =
    sign1.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [k])
  assert sign1.verify(verifier, message: parsed) == Ok(Nil)
}

pub fn verifier_multiple_keys_with_kid_test() {
  let alg = algorithm.Ecdsa(algorithm.EcdsaP256)
  let key1 = key.generate_ec(ec.P256) |> key.with_kid_bits(<<"key-1":utf8>>)
  let key2 = key.generate_ec(ec.P256) |> key.with_kid_bits(<<"key-2":utf8>>)

  let assert Ok(signed) =
    sign1.new(alg)
    |> sign1.with_kid(<<"key-2":utf8>>)
    |> sign1.sign(key2, <<"payload":utf8>>)

  let data = sign1.serialize(signed)
  let assert Ok(parsed) = sign1.parse(data)
  assert sign1.kid(parsed) == Ok(<<"key-2":utf8>>)

  let assert Ok(verifier) = sign1.verifier(alg, keys: [key1, key2])
  assert sign1.verify(verifier, message: parsed) == Ok(Nil)
}
