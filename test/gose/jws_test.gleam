import birdie
import gleam/bit_array
import gleam/dict
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gose
import gose/jwa
import gose/jwk
import gose/jws
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import gose/test_helpers/jwt_helpers
import kryptos/crypto
import qcheck

fn json_object_keys_decoder() -> decode.Decoder(List(String)) {
  decode.dict(decode.string, decode.dynamic)
  |> decode.map(dict.keys)
}

fn encode_test_parts(
  header_fields: List(#(String, json.Json)),
) -> #(String, String, String) {
  let header_b64 =
    json.object(header_fields)
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)
  let payload_b64 = bit_array.base64_url_encode(<<"test":utf8>>, False)
  let sig_b64 = bit_array.base64_url_encode(<<"fake-sig":utf8>>, False)
  #(header_b64, payload_b64, sig_b64)
}

fn make_flattened_json_token(
  header_fields: List(#(String, json.Json)),
  unprotected: List(#(String, json.Json)),
) -> String {
  let #(header_b64, payload_b64, sig_b64) = encode_test_parts(header_fields)
  json.object([
    #("protected", json.string(header_b64)),
    #("payload", json.string(payload_b64)),
    #("signature", json.string(sig_b64)),
    #("header", json.object(unprotected)),
  ])
  |> json.to_string
}

fn make_compact_token(header_fields: List(#(String, json.Json))) -> String {
  let #(header_b64, payload_b64, sig_b64) = encode_test_parts(header_fields)
  header_b64 <> "." <> payload_b64 <> "." <> sig_b64
}

pub fn sign_verify_roundtrip_test() {
  let hmac_keys = generators.generate_hmac_keys()
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jws_alg_generator(hmac_keys),
      qcheck.non_empty_byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JwsAlgWithKey(alg, key), payload) = tuple
      let assert Ok(signed) =
        jws.new(alg)
        |> jws.sign(key, payload)
      let assert Ok(verifier) = jws.verifier(alg, [key])
      assert jws.verify(verifier, signed) == Ok(True)
      Nil
    },
  )
}

pub fn sign_verify_with_public_key_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.from_generators(generators.jws_rsa_alg_generator(), [
      generators.jws_ecdsa_alg_generator(),
      generators.jws_eddsa_alg_generator(),
    ]),
    fn(alg_key) {
      let generators.JwsAlgWithKey(alg, key) = alg_key
      let payload = <<"test":utf8>>
      let assert Ok(signed) =
        jws.new(alg)
        |> jws.sign(key, payload)
      let assert Ok(public_key) = jwk.public_key(key)
      let assert Ok(verifier) = jws.verifier(alg, [public_key])
      assert jws.verify(verifier, signed) == Ok(True)
      Nil
    },
  )
}

pub fn compact_serialization_roundtrip_test() {
  let hmac_keys = generators.generate_hmac_keys()
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jws_alg_generator(hmac_keys),
      qcheck.non_empty_byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JwsAlgWithKey(alg, key), payload) = tuple
      let assert Ok(signed) =
        jws.new(alg)
        |> jws.sign(key, payload)
      let assert Ok(token) = jws.serialize_compact(signed)

      let parts = string.split(token, ".")
      assert list.length(parts) == 3

      let assert Ok(parsed) = jws.parse_compact(token)
      assert jws.payload(parsed) == payload
      let assert Ok(verifier) = jws.verifier(alg, [key])
      assert jws.verify(verifier, parsed) == Ok(True)
      Nil
    },
  )
}

pub fn json_flattened_roundtrip_test() {
  let hmac_keys = generators.generate_hmac_keys()
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jws_alg_generator(hmac_keys),
      qcheck.non_empty_byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JwsAlgWithKey(alg, key), payload) = tuple
      let assert Ok(signed) =
        jws.new(alg)
        |> jws.sign(key, payload)
      let json_str = jws.serialize_json_flattened(signed) |> json.to_string
      let assert Ok(keys) = json.parse(json_str, json_object_keys_decoder())
      assert list.contains(keys, "protected")
      assert list.contains(keys, "payload")
      assert list.contains(keys, "signature")

      let assert Ok(parsed) = jws.parse_json(json_str)
      assert jws.payload(parsed) == payload
      let assert Ok(verifier) = jws.verifier(alg, [key])
      assert jws.verify(verifier, parsed) == Ok(True)
      Nil
    },
  )
}

pub fn json_general_roundtrip_test() {
  let hmac_keys = generators.generate_hmac_keys()
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jws_alg_generator(hmac_keys),
      qcheck.non_empty_byte_aligned_bit_array(),
    ),
    fn(tuple) {
      let #(generators.JwsAlgWithKey(alg, key), payload) = tuple
      let assert Ok(signed) =
        jws.new(alg)
        |> jws.sign(key, payload)
      let json_str = jws.serialize_json_general(signed) |> json.to_string
      let assert Ok(keys) = json.parse(json_str, json_object_keys_decoder())
      assert list.contains(keys, "signatures")

      let assert Ok(parsed) = jws.parse_json(json_str)
      assert jws.payload(parsed) == payload
      let assert Ok(verifier) = jws.verifier(alg, [key])
      assert jws.verify(verifier, parsed) == Ok(True)
      Nil
    },
  )
}

pub fn header_kid_roundtrip_test() {
  qcheck.run(qcheck.default_config(), qcheck.non_empty_string(), fn(kid) {
    let key = jwk.generate_hmac_key(jwa.HmacSha256)
    let unsigned =
      jws.new(jwa.JwsHmac(jwa.HmacSha256))
      |> jws.with_kid(kid)

    let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
    let assert Ok(token) = jws.serialize_compact(signed)
    let assert Ok(parsed) = jws.parse_compact(token)
    assert jws.kid(parsed) == Ok(kid)
    Nil
  })
}

pub fn header_typ_roundtrip_test() {
  qcheck.run(qcheck.default_config(), qcheck.non_empty_string(), fn(typ) {
    let key = jwk.generate_hmac_key(jwa.HmacSha256)
    let unsigned =
      jws.new(jwa.JwsHmac(jwa.HmacSha256))
      |> jws.with_typ(typ)

    let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
    let assert Ok(token) = jws.serialize_compact(signed)
    let assert Ok(parsed) = jws.parse_compact(token)
    assert jws.typ(parsed) == Ok(typ)
    Nil
  })
}

pub fn header_cty_roundtrip_test() {
  qcheck.run(qcheck.default_config(), qcheck.non_empty_string(), fn(cty) {
    let key = jwk.generate_hmac_key(jwa.HmacSha256)
    let unsigned =
      jws.new(jwa.JwsHmac(jwa.HmacSha256))
      |> jws.with_cty(cty)

    let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
    let assert Ok(token) = jws.serialize_compact(signed)
    let assert Ok(parsed) = jws.parse_compact(token)
    assert jws.cty(parsed) == Ok(cty)
    Nil
  })
}

pub fn wrong_key_fails_verification_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.non_empty_byte_aligned_bit_array(),
    fn(payload) {
      let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
      let key2 = jwk.generate_hmac_key(jwa.HmacSha256)

      let assert Ok(signed) =
        jws.new(jwa.JwsHmac(jwa.HmacSha256))
        |> jws.sign(key1, payload)
      let assert Ok(verifier) =
        jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key2])
      assert jws.verify(verifier, signed) == Ok(False)
      Nil
    },
  )
}

pub fn jws_hs256_compact_snapshot_test() {
  let key = jwt_helpers.hmac_key()
  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, <<"hello world":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  token |> birdie.snap("JWS HS256 compact serialization")
}

pub fn jws_hs256_json_flattened_snapshot_test() {
  let key = jwt_helpers.hmac_key()
  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, <<"hello world":utf8>>)
  jws.serialize_json_flattened(signed)
  |> json.to_string
  |> birdie.snap("JWS HS256 JSON flattened serialization")
}

pub fn jws_hs256_json_general_snapshot_test() {
  let key = jwt_helpers.hmac_key()
  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, <<"hello world":utf8>>)
  jws.serialize_json_general(signed)
  |> json.to_string
  |> birdie.snap("JWS HS256 JSON general serialization")
}

pub fn jws_hs256_with_headers_snapshot_test() {
  let key = jwt_helpers.hmac_key()
  let unsigned =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_kid("my-key-id")
    |> jws.with_typ("JWT")

  let assert Ok(signed) = jws.sign(unsigned, key, <<"hello world":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  token |> birdie.snap("JWS HS256 compact with kid and typ headers")
}

pub fn jws_ed25519_compact_snapshot_test() {
  let key = fixtures.ed25519_key()
  let assert Ok(signed) =
    jws.new(jwa.JwsEddsa)
    |> jws.sign(key, <<"hello world":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  token |> birdie.snap("JWS EdDSA Ed25519 compact serialization")
}

pub fn jws_ed448_compact_snapshot_test() {
  let key = fixtures.ed448_key()
  let assert Ok(signed) =
    jws.new(jwa.JwsEddsa)
    |> jws.sign(key, <<"hello world":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  token |> birdie.snap("JWS EdDSA Ed448 compact serialization")
}

pub fn jws_detached_payload_compact_snapshot_test() {
  let key = jwt_helpers.hmac_key()
  let unsigned =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_detached

  let assert Ok(signed) = jws.sign(unsigned, key, <<"detached content":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  token |> birdie.snap("JWS HS256 detached payload compact serialization")
}

pub fn jws_detached_payload_json_snapshot_test() {
  let key = jwt_helpers.hmac_key()
  let unsigned =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_detached

  let assert Ok(signed) = jws.sign(unsigned, key, <<"detached content":utf8>>)
  jws.serialize_json_flattened(signed)
  |> json.to_string
  |> birdie.snap("JWS HS256 detached payload JSON serialization")
}

pub fn jws_es256_rejects_wrong_curve_test() {
  let key = fixtures.ec_p384_key()
  let payload = <<"wrong curve":utf8>>

  let assert Error(gose.InvalidState(_)) =
    jws.new(jwa.JwsEcdsa(jwa.EcdsaP256))
    |> jws.sign(key, payload)
}

pub fn jws_invalid_token_format_test() {
  let assert Error(gose.ParseError(_)) = jws.parse_compact("not.valid")
  let assert Error(gose.ParseError(_)) =
    jws.parse_compact("too.many.parts.here")
}

pub fn parse_compact_empty_payload_is_detached_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_detached
    |> jws.sign(key, <<"test":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)
  assert jws.is_detached(parsed)
  assert jws.payload(parsed) == <<>>
}

pub fn jws_invalid_base64_test() {
  let assert Error(gose.ParseError(_)) =
    jws.parse_compact("!!!.payload.signature")
}

pub fn has_unencoded_payload_false_for_standard_jws_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let unsigned = jws.new(jwa.JwsHmac(jwa.HmacSha256))
  assert !jws.has_unencoded_payload(unsigned)

  let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)
  assert !jws.has_unencoded_payload(parsed)
}

pub fn jws_rejects_wrong_key_type_for_hmac_test() {
  let key = fixtures.rsa_private_key()
  let assert Error(gose.InvalidState(_)) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, <<"test":utf8>>)
}

pub fn jws_rejects_wrong_key_type_for_rsa_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Error(gose.InvalidState(_)) =
    jws.new(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256))
    |> jws.sign(key, <<"test":utf8>>)
}

pub fn jws_rejects_wrong_key_type_for_ecdsa_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Error(gose.InvalidState(_)) =
    jws.new(jwa.JwsEcdsa(jwa.EcdsaP256))
    |> jws.sign(key, <<"test":utf8>>)
}

pub fn jws_rejects_wrong_key_type_for_eddsa_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Error(gose.InvalidState(_)) =
    jws.new(jwa.JwsEddsa)
    |> jws.sign(key, <<"test":utf8>>)
}

pub fn jws_detects_tampered_payload_test() {
  let key = jwt_helpers.hmac_key()
  let payload = <<"original":utf8>>

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)

  let parts = string.split(token, ".")
  let assert [header, _payload, sig] = parts
  let tampered_payload = bit_array.base64_url_encode(<<"tampered":utf8>>, False)
  let tampered_token = header <> "." <> tampered_payload <> "." <> sig

  let assert Ok(parsed) = jws.parse_compact(tampered_token)
  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify(verifier, parsed) == Ok(False)
}

pub fn jws_verify_detached_without_payload_returns_error_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let unsigned =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_detached

  let assert Ok(signed) = jws.sign(unsigned, key, <<"detached content":utf8>>)
  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  let assert Error(gose.InvalidState(_)) = jws.verify(verifier, signed)
}

pub fn jws_rejects_unknown_crit_header_test() {
  let token =
    make_compact_token([
      #("alg", json.string("HS256")),
      #("crit", json.preprocessed_array([json.string("exp")])),
    ])

  let assert Error(gose.ParseError(msg)) = jws.parse_compact(token)
  assert msg == "unsupported critical header: exp"
}

pub fn jws_accepts_known_crit_b64_test() {
  let header_b64 =
    json.object([
      #("alg", json.string("HS256")),
      #("crit", json.preprocessed_array([json.string("b64")])),
      #("b64", json.bool(False)),
    ])
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)
  let payload = "test payload"
  let sig_b64 = bit_array.base64_url_encode(<<"fake-sig":utf8>>, False)
  let token = header_b64 <> "." <> payload <> "." <> sig_b64

  let assert Ok(_) = jws.parse_compact(token)
}

pub fn jws_crit_rejects_empty_array_test() {
  let token =
    make_compact_token([
      #("alg", json.string("HS256")),
      #("crit", json.preprocessed_array([])),
    ])

  let assert Error(gose.ParseError(msg)) = jws.parse_compact(token)
  assert msg == "crit array must not be empty"
}

pub fn jws_crit_rejects_standard_header_test() {
  let token =
    make_compact_token([
      #("alg", json.string("HS256")),
      #("crit", json.preprocessed_array([json.string("alg")])),
    ])

  let assert Error(gose.ParseError(msg)) = jws.parse_compact(token)
  assert msg == "standard header in crit: alg"
}

pub fn jws_crit_rejects_duplicates_test() {
  let token =
    make_compact_token([
      #("alg", json.string("HS256")),
      #("b64", json.bool(False)),
      #(
        "crit",
        json.preprocessed_array([json.string("b64"), json.string("b64")]),
      ),
    ])

  let result = jws.parse_compact(token)
  assert result
    == Error(gose.ParseError("crit array contains duplicate values"))
}

pub fn jws_b64_requires_crit_test() {
  let token =
    make_compact_token([
      #("alg", json.string("HS256")),
      #("b64", json.bool(False)),
    ])

  let assert Error(gose.ParseError(msg)) = jws.parse_compact(token)
  assert msg == "b64 header present but not in crit"
}

pub fn parse_compact_detached_roundtrip_test() {
  qcheck.run(
    qcheck.default_config(),
    qcheck.non_empty_byte_aligned_bit_array(),
    fn(payload) {
      let key = jwk.generate_hmac_key(jwa.HmacSha256)
      let assert Ok(signed) =
        jws.new(jwa.JwsHmac(jwa.HmacSha256))
        |> jws.with_detached
        |> jws.sign(key, payload)
      let assert Ok(token) = jws.serialize_compact(signed)
      let assert Ok(parsed) = jws.parse_compact(token)
      let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
      assert jws.verify_detached(verifier, parsed, payload) == Ok(True)
      Nil
    },
  )
}

pub fn parse_json_detached_flattened_roundtrip_test() {
  qcheck.run(
    qcheck.default_config(),
    qcheck.non_empty_byte_aligned_bit_array(),
    fn(payload) {
      let key = jwk.generate_hmac_key(jwa.HmacSha256)
      let assert Ok(signed) =
        jws.new(jwa.JwsHmac(jwa.HmacSha256))
        |> jws.with_detached
        |> jws.sign(key, payload)
      let json_str = jws.serialize_json_flattened(signed) |> json.to_string
      let assert Ok(parsed) = jws.parse_json(json_str)
      let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
      assert jws.verify_detached(verifier, parsed, payload) == Ok(True)
      Nil
    },
  )
}

pub fn jws_json_general_rejects_multiple_signatures_test() {
  let header_b64 =
    json.object([#("alg", json.string("HS256"))])
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)
  let payload_b64 = bit_array.base64_url_encode(<<"test":utf8>>, False)
  let sig_b64 = bit_array.base64_url_encode(<<"fake-sig":utf8>>, False)

  let sig_obj =
    json.object([
      #("protected", json.string(header_b64)),
      #("signature", json.string(sig_b64)),
    ])

  let json_str =
    json.object([
      #("payload", json.string(payload_b64)),
      #("signatures", json.preprocessed_array([sig_obj, sig_obj])),
    ])
    |> json.to_string

  let assert Error(gose.ParseError(msg)) = jws.parse_json(json_str)
  assert msg == "JWS JSON (general) has multiple signatures (not supported)"
}

pub fn jws_hmac_rejects_undersized_key_test() {
  list.each(
    [
      #(jwa.HmacSha256, 31, "HS256 requires key of at least 32 bytes, got 31"),
      #(jwa.HmacSha384, 47, "HS384 requires key of at least 48 bytes, got 47"),
      #(jwa.HmacSha512, 63, "HS512 requires key of at least 64 bytes, got 63"),
    ],
    fn(entry) {
      let #(alg, size, expected_msg) = entry
      let assert Ok(key) = jwk.from_octet_bits(crypto.random_bytes(size))
      let assert Error(gose.InvalidState(msg)) =
        jws.new(jwa.JwsHmac(alg))
        |> jws.sign(key, <<"test":utf8>>)
      assert msg == expected_msg
    },
  )
}

pub fn jws_hmac_verify_rejects_undersized_key_test() {
  let assert Ok(undersized_key) = jwk.from_octet_bits(crypto.random_bytes(31))
  let assert Error(gose.InvalidState(msg)) =
    jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [undersized_key])
  assert msg == "HS256 requires key of at least 32 bytes, got 31"
}

pub fn jws_json_flattened_parses_unprotected_header_test() {
  let json_str =
    make_flattened_json_token([#("alg", json.string("HS256"))], [
      #("kid", json.string("my-key")),
    ])

  let assert Ok(parsed) = jws.parse_json(json_str)
  assert jws.has_unprotected_header(parsed)

  let decoder = {
    use kid <- decode.field("kid", decode.string)
    decode.success(kid)
  }
  let assert Ok("my-key") = jws.decode_unprotected_header(parsed, decoder)
}

pub fn jws_json_general_parses_per_signature_header_test() {
  let header_b64 =
    json.object([#("alg", json.string("HS256"))])
    |> json.to_string
    |> bit_array.from_string
    |> bit_array.base64_url_encode(False)
  let payload_b64 = bit_array.base64_url_encode(<<"test":utf8>>, False)
  let sig_b64 = bit_array.base64_url_encode(<<"fake-sig":utf8>>, False)

  let sig_obj =
    json.object([
      #("protected", json.string(header_b64)),
      #("signature", json.string(sig_b64)),
      #("header", json.object([#("kid", json.string("my-key"))])),
    ])

  let json_str =
    json.object([
      #("payload", json.string(payload_b64)),
      #("signatures", json.preprocessed_array([sig_obj])),
    ])
    |> json.to_string

  let assert Ok(parsed) = jws.parse_json(json_str)
  assert jws.has_unprotected_header(parsed)

  let decoder = {
    use kid <- decode.field("kid", decode.string)
    decode.success(kid)
  }
  let assert Ok("my-key") = jws.decode_unprotected_header(parsed, decoder)
}

pub fn with_header_single_test() {
  let key = jwt_helpers.hmac_key()
  let assert Ok(unsigned) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_header("nonce", json.string("abc123"))

  let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)

  let assert [header_b64, _, _] = string.split(token, ".")
  let assert Ok(header_bits) = bit_array.base64_url_decode(header_b64)
  let assert Ok(header_str) = bit_array.to_string(header_bits)
  header_str |> birdie.snap("JWS with single custom header")
}

pub fn with_header_multiple_test() {
  let key = jwt_helpers.hmac_key()
  let assert Ok(unsigned) = {
    let base = jws.new(jwa.JwsHmac(jwa.HmacSha256))
    use j <- result.try(jws.with_header(base, "first", json.string("1")))
    use j <- result.try(jws.with_header(j, "second", json.string("2")))
    jws.with_header(j, "third", json.string("3"))
  }

  let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)

  let assert [header_b64, _, _] = string.split(token, ".")
  let assert Ok(header_bits) = bit_array.base64_url_decode(header_b64)
  let assert Ok(header_str) = bit_array.to_string(header_bits)
  header_str |> birdie.snap("JWS with multiple custom headers preserves order")
}

pub fn with_header_complex_json_test() {
  let key = jwt_helpers.hmac_key()
  let nested_value =
    json.object([
      #("kty", json.string("EC")),
      #("crv", json.string("P-256")),
      #("x", json.string("test-x")),
      #("y", json.string("test-y")),
    ])

  let assert Ok(unsigned) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_header("custom_object", nested_value)

  let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)

  let assert [header_b64, _, _] = string.split(token, ".")
  let assert Ok(header_bits) = bit_array.base64_url_decode(header_b64)
  let assert Ok(header_str) = bit_array.to_string(header_bits)
  header_str |> birdie.snap("JWS with nested JSON object custom header")
}

pub fn with_header_acme_style_test() {
  let key = jwt_helpers.hmac_key()

  let assert Ok(unsigned) = {
    let base = jws.new(jwa.JwsHmac(jwa.HmacSha256))
    use j <- result.try(jws.with_header(
      base,
      "nonce",
      json.string("nonce-value-123"),
    ))
    jws.with_header(j, "url", json.string("https://acme.example.com/new-order"))
  }

  let assert Ok(signed) = jws.sign(unsigned, key, <<"{}":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)

  let assert [header_b64, _, _] = string.split(token, ".")
  let assert Ok(header_bits) = bit_array.base64_url_decode(header_b64)
  let assert Ok(header_str) = bit_array.to_string(header_bits)
  header_str |> birdie.snap("JWS with ACME-style custom headers")
  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify(verifier, signed) == Ok(True)
}

pub fn jws_b64_false_payload_roundtrip_test() {
  let hmac_keys = generators.generate_hmac_keys()
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    qcheck.tuple2(
      generators.jws_hmac_alg_generator(hmac_keys),
      qcheck.non_empty_string(),
    ),
    fn(tuple) {
      let #(generators.JwsAlgWithKey(alg, key), payload_str) = tuple
      // RFC 7797: period characters MUST NOT be used in unencoded payloads
      // with compact serialization (they conflict with the segment separator)
      let payload = <<string.replace(payload_str, ".", "_"):utf8>>
      let unsigned =
        jws.new(alg)
        |> jws.with_unencoded()

      let assert Ok(signed) = jws.sign(unsigned, key, payload)
      let assert Ok(token) = jws.serialize_compact(signed)

      let assert Ok(parsed) = jws.parse_compact(token)
      assert jws.payload(parsed) == payload
      assert jws.has_unencoded_payload(parsed)
      let assert Ok(verifier) = jws.verifier(alg, [key])
      assert jws.verify(verifier, parsed) == Ok(True)
      Nil
    },
  )
}

pub fn jws_b64_false_serialization_snapshot_test() {
  let key = jwt_helpers.hmac_key()
  let unsigned =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_unencoded()

  let assert Ok(signed) = jws.sign(unsigned, key, <<"hello world":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  token |> birdie.snap("JWS HS256 b64=false compact serialization")
}

pub fn jws_b64_false_rejects_period_in_payload_for_compact_test() {
  let key = jwt_helpers.hmac_key()
  let unsigned =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_unencoded()

  let assert Ok(signed) = jws.sign(unsigned, key, <<"hello.world":utf8>>)

  let result = jws.serialize_compact(signed)
  assert result
    == Error(gose.InvalidState(
      "unencoded payload cannot contain '.' for compact serialization",
    ))
}

pub fn jws_b64_false_allows_period_in_payload_for_json_test() {
  let key = jwt_helpers.hmac_key()
  let unsigned =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_unencoded()

  let assert Ok(signed) = jws.sign(unsigned, key, <<"hello.world":utf8>>)

  let json_str = jws.serialize_json_flattened(signed) |> json.to_string
  let payload_decoder = {
    use payload <- decode.field("payload", decode.string)
    decode.success(payload)
  }
  let assert Ok(payload_value) = json.parse(json_str, payload_decoder)
  assert payload_value == "hello.world"
}

pub fn sign_rejects_key_with_wrong_jws_alg_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha512)
  let key_with_alg = jwk.with_alg(key, jwk.Jws(jwa.JwsHmac(jwa.HmacSha512)))

  let result =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key_with_alg, <<"test":utf8>>)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key algorithm mismatch: key has HS512, expected HS256"
}

pub fn sign_rejects_key_with_jwe_alg_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let key_with_alg = jwk.with_alg(key, jwk.Jwe(jwa.JweDirect))

  let result =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key_with_alg, <<"test":utf8>>)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "key algorithm mismatch: key has JWE algorithm, expected JWS algorithm"
}

pub fn sign_rejects_key_with_enc_use_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(enc_key) = jwk.with_key_use(key, jwk.Encrypting)
  let result =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(enc_key, <<"test":utf8>>)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key use is 'enc', cannot be used for signing"
}

pub fn sign_rejects_key_without_sign_ops_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(verify_only_key) = jwk.with_key_ops(key, [jwk.Verify])
  let result =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(verify_only_key, <<"test":utf8>>)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key_ops does not include 'sign' operation"
}

pub fn verify_rejects_key_with_wrong_jws_alg_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let key_with_wrong_alg =
    jwk.with_alg(key, jwk.Jws(jwa.JwsHmac(jwa.HmacSha512)))

  let assert Error(gose.InvalidState(msg)) =
    jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key_with_wrong_alg])
  assert msg == "key algorithm mismatch: key has HS512, expected HS256"
}

pub fn sign_allows_key_with_or_without_alg_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let key_with_alg = jwk.with_alg(key, jwk.Jws(jwa.JwsHmac(jwa.HmacSha256)))

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key_with_alg, <<"test":utf8>>)
  let assert Ok(verifier) =
    jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key_with_alg])
  assert jws.verify(verifier, signed) == Ok(True)

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, <<"test":utf8>>)
  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify(verifier, signed) == Ok(True)
}

pub fn custom_header_roundtrip_compact_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"custom header test":utf8>>

  let assert Ok(unsigned) = {
    let base = jws.new(jwa.JwsHmac(jwa.HmacSha256))
    use j <- result.try(jws.with_header(
      base,
      "x-custom-string",
      json.string("hello"),
    ))
    use j <- result.try(jws.with_header(j, "x-custom-int", json.int(42)))
    jws.with_header(j, "x-custom-bool", json.bool(True))
  }

  let assert Ok(signed) = jws.sign(unsigned, key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)

  let assert Ok(parsed) = jws.parse_compact(token)
  assert jws.payload(parsed) == payload
  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify(verifier, parsed) == Ok(True)

  let decoder = {
    use custom_string <- decode.field("x-custom-string", decode.string)
    use custom_int <- decode.field("x-custom-int", decode.int)
    use custom_bool <- decode.field("x-custom-bool", decode.bool)
    decode.success(#(custom_string, custom_int, custom_bool))
  }
  let assert Ok(#("hello", 42, True)) =
    jws.decode_custom_headers(parsed, decoder)
}

pub fn decode_custom_headers_mismatched_decoder_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"mismatched decoder test":utf8>>

  let unsigned = jws.new(jwa.JwsHmac(jwa.HmacSha256))
  let assert Ok(signed) = jws.sign(unsigned, key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)

  let decoder = decode.field("nonexistent-field", decode.string, decode.success)
  assert jws.decode_custom_headers(parsed, decoder)
    == Error(gose.ParseError("failed to decode custom headers"))
}

pub fn decode_unprotected_header_none_present_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"no unprotected headers":utf8>>

  let unsigned = jws.new(jwa.JwsHmac(jwa.HmacSha256))
  let assert Ok(signed) = jws.sign(unsigned, key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)

  let decoder = decode.field("kid", decode.string, decode.success)
  assert jws.decode_unprotected_header(parsed, decoder)
    == Error(gose.ParseError("no unprotected headers present"))
}

pub fn parse_compact_invalid_base64_signature_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let unsigned = jws.new(jwa.JwsHmac(jwa.HmacSha256))
  let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)

  let assert [header, payload, _sig] = string.split(token, ".")
  let tampered = header <> "." <> payload <> ".!!!"
  let assert Error(gose.ParseError(_)) = jws.parse_compact(tampered)
}

pub fn parse_json_invalid_json_test() {
  assert jws.parse_json("not json")
    == Error(gose.ParseError("invalid JWS JSON (flattened)"))
}

pub fn custom_header_roundtrip_json_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"custom header json test":utf8>>

  let assert Ok(unsigned) = {
    let base = jws.new(jwa.JwsHmac(jwa.HmacSha256))
    use j <- result.try(jws.with_header(
      base,
      "x-array",
      json.array([1, 2, 3], json.int),
    ))
    jws.with_header(
      j,
      "x-object",
      json.object([#("nested", json.string("value"))]),
    )
  }

  let assert Ok(signed) = jws.sign(unsigned, key, payload)
  let json_str = json.to_string(jws.serialize_json_flattened(signed))

  let assert Ok(parsed) = jws.parse_json(json_str)
  assert jws.payload(parsed) == payload
  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify(verifier, parsed) == Ok(True)

  let array_decoder = {
    use x_array <- decode.field("x-array", decode.list(decode.int))
    decode.success(x_array)
  }
  let assert Ok([1, 2, 3]) = jws.decode_custom_headers(parsed, array_decoder)

  let nested_decoder = decode.at(["x-object", "nested"], decode.string)
  let assert Ok("value") = jws.decode_custom_headers(parsed, nested_decoder)
}

pub fn unprotected_header_roundtrip_flattened_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"unprotected header test":utf8>>

  let assert Ok(unsigned) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_kid("my-key-id")
    |> jws.with_unprotected("x-custom", json.string("custom-value"))

  let assert Ok(signed) = jws.sign(unsigned, key, payload)
  let json_str = json.to_string(jws.serialize_json_flattened(signed))

  let assert Ok(parsed) = jws.parse_json(json_str)
  assert jws.has_unprotected_header(parsed)

  let assert Ok("my-key-id") = jws.kid(parsed)

  let decoder = {
    use custom <- decode.field("x-custom", decode.string)
    decode.success(custom)
  }
  let assert Ok("custom-value") = jws.decode_unprotected_header(parsed, decoder)

  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify(verifier, parsed) == Ok(True)
}

pub fn unprotected_header_roundtrip_general_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"unprotected header general test":utf8>>

  let assert Ok(unsigned) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_unprotected("x-custom", json.string("general-value"))

  let assert Ok(signed) = jws.sign(unsigned, key, payload)
  let json_str = json.to_string(jws.serialize_json_general(signed))

  let assert Ok(parsed) = jws.parse_json(json_str)
  assert jws.has_unprotected_header(parsed)

  let decoder = {
    use custom <- decode.field("x-custom", decode.string)
    decode.success(custom)
  }
  let assert Ok("general-value") =
    jws.decode_unprotected_header(parsed, decoder)

  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify(verifier, parsed) == Ok(True)
}

pub fn header_disjointness_validation_test() {
  let json_str =
    make_flattened_json_token(
      [#("alg", json.string("HS256")), #("kid", json.string("protected-kid"))],
      [#("kid", json.string("unprotected-kid"))],
    )

  assert jws.parse_json(json_str)
    == Error(gose.ParseError("header names must be disjoint, overlap: kid"))
}

pub fn custom_header_disjointness_validation_test() {
  let json_str =
    make_flattened_json_token(
      [
        #("alg", json.string("HS256")),
        #("x-custom", json.string("protected-value")),
      ],
      [#("x-custom", json.string("unprotected-value"))],
    )

  assert jws.parse_json(json_str)
    == Error(gose.ParseError("header names must be disjoint, overlap: x-custom"))
}

pub fn has_unprotected_header_false_when_none_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, <<"test":utf8>>)
  let json_str = json.to_string(jws.serialize_json_flattened(signed))

  let assert Ok(parsed) = jws.parse_json(json_str)
  assert !jws.has_unprotected_header(parsed)
}

pub fn compact_serialization_rejects_unprotected_headers_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(unsigned) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_unprotected("kid", json.string("key-1"))

  let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
  let result = jws.serialize_compact(signed)

  assert result
    == Error(gose.InvalidState(
      "cannot serialize to compact format: unprotected headers are only supported in JSON serialization",
    ))
}

pub fn with_header_last_write_wins_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(unsigned) = {
    let base = jws.new(jwa.JwsHmac(jwa.HmacSha256))
    use j <- result.try(jws.with_header(base, "nonce", json.string("first")))
    jws.with_header(j, "nonce", json.string("second"))
  }

  let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)

  let decoder = {
    use nonce <- decode.field("nonce", decode.string)
    decode.success(nonce)
  }
  let assert Ok("second") = jws.decode_custom_headers(parsed, decoder)
}

pub fn with_unprotected_last_write_wins_test() {
  let assert Ok(unsigned) = {
    let base = jws.new(jwa.JwsHmac(jwa.HmacSha256))
    use j <- result.try(jws.with_unprotected(base, "kid", json.string("first")))
    jws.with_unprotected(j, "kid", json.string("second"))
  }

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(signed) = jws.sign(unsigned, key, <<"test":utf8>>)
  let json_str = json.to_string(jws.serialize_json_flattened(signed))

  let decoder = {
    use kid <- decode.field("kid", decode.string)
    decode.success(kid)
  }
  let assert Ok(parsed) = jws.parse_json(json_str)
  let assert Ok("second") = jws.decode_unprotected_header(parsed, decoder)
}

pub fn with_header_rejects_reserved_headers_test() {
  let base = jws.new(jwa.JwsHmac(jwa.HmacSha256))
  list.each(["alg", "kid", "typ", "cty", "crit", "b64"], fn(name) {
    let result = jws.with_header(base, name, json.string("test"))
    assert result
      == Error(gose.InvalidState(
        "cannot set reserved header via with_header: " <> name,
      ))
  })
}

pub fn with_unprotected_rejects_reserved_headers_test() {
  let base = jws.new(jwa.JwsHmac(jwa.HmacSha256))
  list.each(["crit", "b64"], fn(name) {
    let result = jws.with_unprotected(base, name, json.string("test"))
    assert result
      == Error(gose.InvalidState(
        "protected-only header cannot be in unprotected: " <> name,
      ))
  })
}

pub fn parse_json_rejects_unprotected_reserved_headers_test() {
  list.each(["crit", "b64"], fn(name) {
    let json_str =
      make_flattened_json_token([#("alg", json.string("HS256"))], [
        #(name, json.string("test")),
      ])
    assert jws.parse_json(json_str)
      == Error(gose.ParseError(
        "protected-only headers in unprotected: " <> name,
      ))
  })
}

pub fn verify_rejects_algorithm_mismatch_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha512)
  let payload = <<"test":utf8>>

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha512))
    |> jws.sign(key, payload)

  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])

  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)
  assert jws.verify(verifier, parsed)
    == Error(gose.InvalidState("algorithm mismatch: expected HS256, got HS512"))

  assert jws.verify(verifier, signed)
    == Error(gose.InvalidState("algorithm mismatch: expected HS256, got HS512"))
}

pub fn verify_detached_rejects_algorithm_mismatch_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha512)
  let payload = <<"test":utf8>>

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha512))
    |> jws.with_detached
    |> jws.sign(key, payload)

  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify_detached(verifier, signed, payload)
    == Error(gose.InvalidState("algorithm mismatch: expected HS256, got HS512"))
}

pub fn verify_detached_rejects_non_detached_jws_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"test":utf8>>

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, payload)

  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify_detached(verifier, signed, payload)
    == Error(gose.InvalidState(
      "JWS payload is not detached; use verify instead",
    ))
}

pub fn verifier_empty_keys_rejected_test() {
  let result = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [])
  assert result == Error(gose.InvalidState("at least one key required"))
}

pub fn verifier_key_type_validation_test() {
  let octet_key = jwk.generate_hmac_key(jwa.HmacSha256)
  assert jws.verifier(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256), [octet_key])
    == Error(gose.InvalidState("algorithm RS256 incompatible with key type"))
}

pub fn verifier_kid_prioritization_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "key-1")
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2, "key-2")
  let payload = <<"test":utf8>>

  let unsigned =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_kid("key-2")
  let assert Ok(signed) = jws.sign(unsigned, key2, payload)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)

  let assert Ok(verifier) =
    jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key1, key2])
  assert jws.verify(verifier, parsed) == Ok(True)
}

pub fn verifier_multiple_keys_tries_all_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key3 = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"test":utf8>>

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key2, payload)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)

  let assert Ok(verifier) =
    jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key1, key2])
  assert jws.verify(verifier, parsed) == Ok(True)

  let assert Ok(verifier3) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key3])
  assert jws.verify(verifier3, parsed) == Ok(False)
}

pub fn verifier_with_detached_payload_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"detached content":utf8>>

  let unsigned =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_detached
  let assert Ok(signed) = jws.sign(unsigned, key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)

  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify_detached(verifier, parsed, payload) == Ok(True)
  assert jws.verify_detached(verifier, parsed, <<"wrong":utf8>>) == Ok(False)
}

pub fn verifier_rejects_key_with_wrong_use_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(enc_key) = jwk.with_key_use(key, jwk.Encrypting)
  assert jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [enc_key])
    == Error(gose.InvalidState(
      "key use is 'enc', cannot be used for verification",
    ))
}

pub fn verifier_rejects_key_without_verify_ops_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(sign_only_key) = jwk.with_key_ops(key, [jwk.Sign])
  assert jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [sign_only_key])
    == Error(gose.InvalidState("key_ops does not include 'verify' operation"))
}

pub fn b64_in_crit_but_absent_from_header_test() {
  let token =
    make_compact_token([
      #("alg", json.string("HS256")),
      #("crit", json.preprocessed_array([json.string("b64")])),
    ])

  let assert Error(gose.ParseError(msg)) = jws.parse_compact(token)
  assert msg == "b64 listed in crit but not present in header"
}

pub fn parse_json_detached_general_roundtrip_test() {
  qcheck.run(
    qcheck.default_config(),
    qcheck.non_empty_byte_aligned_bit_array(),
    fn(payload) {
      let key = jwk.generate_hmac_key(jwa.HmacSha256)
      let assert Ok(signed) =
        jws.new(jwa.JwsHmac(jwa.HmacSha256))
        |> jws.with_detached
        |> jws.sign(key, payload)
      let json_str = jws.serialize_json_general(signed) |> json.to_string
      let assert Ok(parsed) = jws.parse_json(json_str)
      let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
      assert jws.verify_detached(verifier, parsed, payload) == Ok(True)
      Nil
    },
  )
}

pub fn es256k_sign_verify_roundtrip_test() {
  let key = fixtures.ec_secp256k1_key()
  let payload = <<"ES256K test payload":utf8>>
  let assert Ok(signed) =
    jws.new(jwa.JwsEcdsa(jwa.EcdsaSecp256k1))
    |> jws.sign(key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) =
    jws.verifier(jwa.JwsEcdsa(jwa.EcdsaSecp256k1), [key])
  assert jws.verify(verifier, parsed) == Ok(True)
  assert jws.payload(parsed) == payload
}

pub fn es256k_public_key_verification_test() {
  let key = fixtures.ec_secp256k1_key()
  let assert Ok(pub_key) = jwk.public_key(key)
  let payload = <<"ES256K public key verify":utf8>>
  let assert Ok(signed) =
    jws.new(jwa.JwsEcdsa(jwa.EcdsaSecp256k1))
    |> jws.sign(key, payload)
  let assert Ok(token) = jws.serialize_compact(signed)
  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) =
    jws.verifier(jwa.JwsEcdsa(jwa.EcdsaSecp256k1), [pub_key])
  assert jws.verify(verifier, parsed) == Ok(True)
}

pub fn es256k_rejects_wrong_curve_key_test() {
  let p256_key = fixtures.ec_p256_key()
  let result =
    jws.new(jwa.JwsEcdsa(jwa.EcdsaSecp256k1))
    |> jws.sign(p256_key, <<"test":utf8>>)
  assert result
    == Error(gose.InvalidState("EC key curve does not match algorithm"))
}

pub fn rfc7515_appendix_a1_hs256_test() {
  let key_json =
    json.object([
      #("kty", json.string("oct")),
      #(
        "k",
        json.string(
          "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        ),
      ),
    ])
    |> json.to_string
  let assert Ok(key) = jwk.from_json(key_json)

  let token =
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  assert jws.verify(verifier, parsed) == Ok(True)

  let payload = jws.payload(parsed)
  let assert Ok(payload_str) = bit_array.to_string(payload)
  payload_str |> birdie.snap("RFC 7515 Appendix A.1 HS256 payload")
}

pub fn rfc8037_eddsa_sign_verify_test() {
  let key_json =
    json.object([
      #("kty", json.string("OKP")),
      #("crv", json.string("Ed25519")),
      #("d", json.string("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")),
      #("x", json.string("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")),
    ])
    |> json.to_string
  let assert Ok(key) = jwk.from_json(key_json)

  let token =
    "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) = jws.verifier(jwa.JwsEddsa, [key])
  assert jws.verify(verifier, parsed) == Ok(True)
}

pub fn cross_family_algorithm_confusion_test() {
  let hmac_key = jwk.generate_hmac_key(jwa.HmacSha256)
  let rsa_key = fixtures.rsa_private_key()

  let assert Ok(hmac_signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(hmac_key, <<"test":utf8>>)
  let assert Ok(hmac_token) = jws.serialize_compact(hmac_signed)
  let assert Ok(parsed_hmac) = jws.parse_compact(hmac_token)
  let assert Ok(rsa_verifier) =
    jws.verifier(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256), [rsa_key])
  assert jws.verify(rsa_verifier, parsed_hmac)
    == Error(gose.InvalidState("algorithm mismatch: expected RS256, got HS256"))

  let assert Ok(rsa_signed) =
    jws.new(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256))
    |> jws.sign(rsa_key, <<"test":utf8>>)
  let assert Ok(rsa_token) = jws.serialize_compact(rsa_signed)
  let assert Ok(parsed_rsa) = jws.parse_compact(rsa_token)
  let assert Ok(hmac_verifier) =
    jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [hmac_key])
  assert jws.verify(hmac_verifier, parsed_rsa)
    == Error(gose.InvalidState("algorithm mismatch: expected HS256, got RS256"))
}

pub fn general_json_empty_signatures_test() {
  let payload_b64 = bit_array.base64_url_encode(<<"test":utf8>>, False)

  let json_str =
    json.object([
      #("payload", json.string(payload_b64)),
      #("signatures", json.preprocessed_array([])),
    ])
    |> json.to_string

  let assert Error(gose.ParseError(msg)) = jws.parse_json(json_str)
  assert msg == "JWS JSON (general) has no signatures"
}
