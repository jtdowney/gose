import gleam/bit_array
import gleam/json
import gleam/list
import gleam/string
import gose
import gose/internal/signing
import gose/jose/jws_multi
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import kryptos/ec
import qcheck

fn protected_header(fields: List(#(String, json.Json))) -> String {
  json.object(fields)
  |> json.to_string
  |> bit_array.from_string
  |> bit_array.base64_url_encode(False)
}

fn general_json(payload: String, sigs: List(#(String, BitArray))) -> String {
  let sig_objects =
    list.map(sigs, fn(sig) {
      let #(protected, signature) = sig
      json.object([
        #("protected", json.string(protected)),
        #(
          "signature",
          json.string(bit_array.base64_url_encode(signature, False)),
        ),
      ])
    })

  json.object([
    #("payload", json.string(payload)),
    #("signatures", json.preprocessed_array(sig_objects)),
  ])
  |> json.to_string
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
  let hmac_key = gose.generate_hmac_key(gose.HmacSha256)
  let ec_key = fixtures.ec_p256_key()
  let ed_key = fixtures.ed25519_key()

  let assert Ok(body) =
    jws_multi.new(payload:)
    |> jws_multi.sign(gose.Mac(gose.Hmac(gose.HmacSha256)), key: hmac_key)
  let assert Ok(body) =
    body
    |> jws_multi.sign(
      gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)),
      key: ec_key,
    )
  let assert Ok(body) =
    body
    |> jws_multi.sign(gose.DigitalSignature(gose.Eddsa), key: ed_key)
  let multi = jws_multi.assemble(body)
  let json_str = jws_multi.serialize_json(multi) |> json.to_string
  let assert Ok(parsed) = jws_multi.parse_json(json_str)

  let assert Ok(v1) =
    jws_multi.verifier(gose.Mac(gose.Hmac(gose.HmacSha256)), keys: [hmac_key])
  assert jws_multi.verify(v1, parsed) == Ok(Nil)

  let assert Ok(v2) =
    jws_multi.verifier(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)), keys: [
      ec_key,
    ])
  assert jws_multi.verify(v2, parsed) == Ok(Nil)

  let assert Ok(v3) =
    jws_multi.verifier(gose.DigitalSignature(gose.Eddsa), keys: [
      ed_key,
    ])
  assert jws_multi.verify(v3, parsed) == Ok(Nil)
}

pub fn verify_wrong_key_test() {
  let payload = <<"wrong key":utf8>>
  let k = fixtures.ec_p256_key()
  let other = gose.generate_ec(ec.P256)
  let alg = gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256))

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
    |> jws_multi.sign(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)), key: k)
  let multi = jws_multi.assemble(body)
  let json_str = jws_multi.serialize_json(multi) |> json.to_string
  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  let assert Ok(v) =
    jws_multi.verifier(
      gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha256)),
      keys: [rsa_key],
    )
  assert jws_multi.verify(v, parsed) == Error(gose.VerificationFailed)
}

pub fn verifier_empty_keys_test() {
  assert jws_multi.verifier(
      gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)),
      keys: [],
    )
    == Error(gose.InvalidState("at least one key required"))
}

pub fn verifier_wrong_key_type_test() {
  let hmac_key = gose.generate_hmac_key(gose.HmacSha256)
  let assert Error(gose.InvalidState(_)) =
    jws_multi.verifier(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)), keys: [
      hmac_key,
    ])
}

pub fn parse_invalid_json_test() {
  let assert Error(gose.ParseError(_)) = jws_multi.parse_json("not json")
}

pub fn detached_roundtrip_test() {
  let alg = gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256))
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
  let alg = gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256))
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
  let alg = gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256))
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
  let alg = gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256))
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
  let alg = gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256))
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

pub fn unencoded_payload_roundtrip_test() {
  let payload = <<"$.02":utf8>>
  let key = gose.generate_hmac_key(gose.HmacSha256)
  let alg = gose.Mac(gose.Hmac(gose.HmacSha256))

  let assert Ok(body) =
    jws_multi.new(payload:)
    |> jws_multi.with_unencoded
    |> jws_multi.sign(alg, key:)
  let multi = jws_multi.assemble(body)
  let json_str = jws_multi.serialize_json(multi) |> json.to_string

  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  assert jws_multi.has_unencoded_payload(parsed)
  assert jws_multi.payload(parsed) == payload

  let assert Ok(v) = jws_multi.verifier(alg, keys: [key])
  assert jws_multi.verify(v, parsed) == Ok(Nil)
}

pub fn unencoded_payload_exposes_authenticated_bytes_test() {
  let key = gose.generate_hmac_key(gose.HmacSha256)
  let alg = gose.Mac(gose.Hmac(gose.HmacSha256))
  let protected =
    protected_header([
      #("alg", json.string("HS256")),
      #("b64", json.bool(False)),
      #("crit", json.array(["b64"], json.string)),
    ])

  let signed_text = "eyJzdWIiOiJndWVzdCJ9"
  let assert Ok(sig) =
    signing.compute_signature(
      alg,
      key:,
      message: bit_array.from_string(protected <> "." <> signed_text),
    )

  let assert Ok(parsed) =
    jws_multi.parse_json(general_json(signed_text, [#(protected, sig)]))
  let assert Ok(v) = jws_multi.verifier(alg, keys: [key])

  assert jws_multi.verify(v, parsed) == Ok(Nil)
  assert jws_multi.payload(parsed) == bit_array.from_string(signed_text)
}

pub fn parse_rejects_unsupported_crit_test() {
  let protected =
    protected_header([
      #("alg", json.string("HS256")),
      #("crit", json.array(["http://example.com/UNDEFINED"], json.string)),
    ])

  assert jws_multi.parse_json(
      general_json("cGF5bG9hZA", [#(protected, <<1, 2, 3>>)]),
    )
    == Error(gose.ParseError(
      "unsupported critical header: http://example.com/UNDEFINED",
    ))
}

pub fn parse_rejects_mixed_b64_test() {
  let unencoded =
    protected_header([
      #("alg", json.string("HS256")),
      #("b64", json.bool(False)),
      #("crit", json.array(["b64"], json.string)),
    ])
  let encoded = protected_header([#("alg", json.string("HS256"))])

  assert jws_multi.parse_json(
      general_json("cGF5bG9hZA", [#(unencoded, <<1>>), #(encoded, <<2>>)]),
    )
    == Error(gose.ParseError(
      "signatures disagree on b64; RFC 7797 requires a single value",
    ))
}

pub fn property_payload_roundtrips_under_both_encodings_test() {
  use #(text, unencoded) <- qcheck.given(qcheck.tuple2(
    qcheck.string(),
    qcheck.bool(),
  ))
  let payload = bit_array.from_string(text)
  let key = gose.generate_hmac_key(gose.HmacSha256)
  let alg = gose.Mac(gose.Hmac(gose.HmacSha256))

  let built = jws_multi.new(payload:)
  let built = case unencoded {
    True -> jws_multi.with_unencoded(built)
    False -> built
  }
  let assert Ok(body) = built |> jws_multi.sign(alg, key:)
  let json_str =
    jws_multi.assemble(body)
    |> jws_multi.serialize_json
    |> json.to_string

  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  let assert Ok(v) = jws_multi.verifier(alg, keys: [key])

  assert jws_multi.verify(v, parsed) == Ok(Nil)
  assert jws_multi.payload(parsed) == payload
  assert jws_multi.has_unencoded_payload(parsed) == unencoded
}

pub fn detached_unencoded_roundtrip_test() {
  let payload = <<"$.02 detached":utf8>>
  let key = gose.generate_hmac_key(gose.HmacSha256)
  let alg = gose.Mac(gose.Hmac(gose.HmacSha256))

  let assert Ok(body) =
    jws_multi.new(payload:)
    |> jws_multi.with_unencoded
    |> jws_multi.with_detached
    |> jws_multi.sign(alg, key:)
  let json_str =
    jws_multi.assemble(body)
    |> jws_multi.serialize_json
    |> json.to_string

  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  assert jws_multi.is_detached(parsed)
  assert jws_multi.has_unencoded_payload(parsed)

  let assert Ok(v) = jws_multi.verifier(alg, keys: [key])
  assert jws_multi.verify_detached(v, parsed, payload) == Ok(Nil)
  assert jws_multi.verify_detached(v, parsed, <<"other":utf8>>)
    == Error(gose.VerificationFailed)
}

pub fn parse_rejects_empty_signatures_test() {
  assert jws_multi.parse_json(general_json("cGF5bG9hZA", []))
    == Error(gose.ParseError("JWS JSON (general) has no signatures"))
}
