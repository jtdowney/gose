import gleam/bit_array
import gose
import gose/cbor
import gose/cose
import gose/cose/mac0
import kryptos/ec
import qcheck

pub fn tag_verify_roundtrip_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"verify me":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.tag(k, payload)

  let assert Ok(v) = mac0.verifier(alg, keys: [k])
  assert mac0.verify(v, tagged) == Ok(Nil)
}

pub fn serialize_parse_verify_roundtrip_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"roundtrip test":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  assert mac0.payload(parsed) == Ok(payload)

  let assert Ok(v) = mac0.verifier(alg, keys: [k])
  assert mac0.verify(v, parsed) == Ok(Nil)
}

pub fn serialize_tagged_parse_roundtrip_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"tagged test":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.tag(k, payload)

  let data = mac0.serialize_tagged(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  assert mac0.payload(parsed) == Ok(payload)

  let assert Ok(v) = mac0.verifier(alg, keys: [k])
  assert mac0.verify(v, parsed) == Ok(Nil)
}

pub fn serialize_untagged_parse_test() {
  let k = gose.generate_hmac_key(gose.HmacSha384)
  let payload = <<"untagged":utf8>>
  let alg = gose.Hmac(gose.HmacSha384)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  assert mac0.payload(parsed) == Ok(payload)
}

pub fn aad_roundtrip_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"aad test":utf8>>
  let aad = <<"extra context":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.with_aad(aad:)
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(v) = mac0.verifier(alg, keys: [k])
  assert mac0.verify_with_aad(v, parsed, aad) == Ok(Nil)
}

pub fn wrong_aad_verify_fails_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"aad test":utf8>>
  let correct_aad = <<"correct context":utf8>>
  let wrong_aad = <<"wrong context":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.with_aad(aad: correct_aad)
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(v) = mac0.verifier(alg, keys: [k])
  assert mac0.verify_with_aad(v, parsed, wrong_aad)
    == Error(gose.VerificationFailed)
}

pub fn tag_detached_roundtrip_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"detached payload":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.with_detached()
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(v) = mac0.verifier(alg, keys: [k])
  assert mac0.verify_detached(v, message: parsed, payload:) == Ok(Nil)
}

pub fn tag_detached_with_aad_roundtrip_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"detached payload":utf8>>
  let aad = <<"extra context":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.with_detached()
    |> mac0.with_aad(aad:)
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(v) = mac0.verifier(alg, keys: [k])
  assert mac0.verify_detached_with_aad(v, parsed, payload, aad) == Ok(Nil)
}

pub fn verify_detached_with_wrong_aad_fails_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"detached payload":utf8>>
  let correct_aad = <<"correct context":utf8>>
  let wrong_aad = <<"wrong context":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.with_detached()
    |> mac0.with_aad(aad: correct_aad)
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(v) = mac0.verifier(alg, keys: [k])
  assert mac0.verify_detached_with_aad(v, parsed, payload, wrong_aad)
    == Error(gose.VerificationFailed)
}

pub fn wrong_key_verification_fails_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let other_key = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"wrong key":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(v) = mac0.verifier(alg, keys: [other_key])
  assert mac0.verify(v, parsed) == Error(gose.VerificationFailed)
}

pub fn algorithm_mismatch_rejected_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"mismatch":utf8>>

  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)

  let other_key = gose.generate_hmac_key(gose.HmacSha512)
  let assert Ok(v) =
    mac0.verifier(gose.Hmac(gose.HmacSha512), keys: [other_key])
  let assert Error(gose.InvalidState(_)) = mac0.verify(v, parsed)
}

pub fn payload_access_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"access me":utf8>>

  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.tag(k, payload)

  assert mac0.payload(tagged) == Ok(payload)
}

pub fn verifier_empty_keys_test() {
  assert mac0.verifier(gose.Hmac(gose.HmacSha256), keys: [])
    == Error(gose.InvalidState("at least one key required"))
}

pub fn parse_invalid_cbor_test() {
  let assert Error(gose.ParseError(_)) = mac0.parse(<<0xff>>)
}

pub fn verifier_wrong_key_type_test() {
  let ec_key = gose.generate_ec(ec.P256)
  let assert Error(gose.InvalidState(_)) =
    mac0.verifier(gose.Hmac(gose.HmacSha256), keys: [ec_key])
}

pub fn property_based_tag_verify_roundtrip_test() {
  let gen = hmac_alg_with_key_generator()
  use pair <- qcheck.given(gen)
  let payload = <<"pbt payload":utf8>>

  let assert Ok(tagged) =
    mac0.new(gose.Hmac(pair.hmac_alg))
    |> mac0.tag(pair.key, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(v) = mac0.verifier(gose.Hmac(pair.hmac_alg), keys: [pair.key])
  assert mac0.verify(v, parsed) == Ok(Nil)
}

type HmacAlgWithKey(kid) {
  HmacAlgWithKey(hmac_alg: gose.HmacAlg, key: gose.Key(kid))
}

fn hmac_alg_with_key_generator() -> qcheck.Generator(HmacAlgWithKey(kid)) {
  qcheck.from_generators(
    qcheck.return(HmacAlgWithKey(
      gose.HmacSha256,
      gose.generate_hmac_key(gose.HmacSha256),
    )),
    [
      qcheck.return(HmacAlgWithKey(
        gose.HmacSha384,
        gose.generate_hmac_key(gose.HmacSha384),
      )),
      qcheck.return(HmacAlgWithKey(
        gose.HmacSha512,
        gose.generate_hmac_key(gose.HmacSha512),
      )),
    ],
  )
}

pub fn verify_rejects_detached_payload_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"hello":utf8>>

  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.tag(k, payload)

  let detached = make_detached_mac0(tagged)
  let assert Ok(parsed) = mac0.parse(detached)

  let assert Ok(v) = mac0.verifier(gose.Hmac(gose.HmacSha256), keys: [k])
  assert mac0.verify(v, parsed)
    == Error(gose.InvalidState(
      "message has detached payload; use verify_detached",
    ))
}

pub fn verify_detached_succeeds_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"hello":utf8>>

  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.tag(k, payload)

  let detached = make_detached_mac0(tagged)
  let assert Ok(parsed) = mac0.parse(detached)

  let assert Ok(v) = mac0.verifier(gose.Hmac(gose.HmacSha256), keys: [k])
  assert mac0.verify_detached(v, parsed, payload) == Ok(Nil)
}

pub fn verify_detached_rejects_embedded_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"hello":utf8>>

  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.tag(k, payload)

  let assert Ok(v) = mac0.verifier(gose.Hmac(gose.HmacSha256), keys: [k])
  assert mac0.verify_detached(v, tagged, payload)
    == Error(gose.InvalidState("message has embedded payload; use verify"))
}

pub fn parse_rejects_overlapping_headers_test() {
  let protected = cbor.encode(cbor.Map([#(cbor.Int(1), cbor.Int(5))]))
  let unprotected = cbor.Map([#(cbor.Int(1), cbor.Int(6))])
  let data =
    cbor.encode(
      cbor.Array([
        cbor.Bytes(protected),
        unprotected,
        cbor.Bytes(<<"payload":utf8>>),
        cbor.Bytes(<<0:256>>),
      ]),
    )
  assert mac0.parse(data)
    == Error(gose.ParseError(
      "duplicate label in protected and unprotected headers",
    ))
}

pub fn with_kid_roundtrip_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.with_kid(<<"key-1":utf8>>)
    |> mac0.tag(k, <<"payload":utf8>>)
  assert mac0.kid(tagged) == Ok(<<"key-1":utf8>>)
}

pub fn kid_survives_serialize_parse_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.with_kid(<<"key-1":utf8>>)
    |> mac0.tag(k, <<"payload":utf8>>)
  let assert Ok(parsed) = mac0.parse(mac0.serialize(tagged))
  assert mac0.kid(parsed) == Ok(<<"key-1":utf8>>)
}

pub fn kid_missing_returns_error_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.tag(k, <<"payload":utf8>>)
  assert mac0.kid(tagged)
    == Error(gose.ParseError("missing header label 4 (kid)"))
}

pub fn protected_headers_exposes_alg_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.tag(k, <<"payload":utf8>>)
  assert cose.algorithm(mac0.protected_headers(tagged)) == Ok(5)
}

pub fn unprotected_headers_exposes_kid_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.with_kid(<<"k1":utf8>>)
    |> mac0.tag(k, <<"payload":utf8>>)
  assert cose.kid(mac0.unprotected_headers(tagged)) == Ok(<<"k1":utf8>>)
}

pub fn with_content_type_roundtrip_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.with_content_type(ct: cose.Json)
    |> mac0.tag(k, <<"payload":utf8>>)
  assert mac0.content_type(tagged) == Ok(cose.Json)
}

pub fn with_critical_roundtrip_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.with_critical(labels: [42])
    |> mac0.tag(k, <<"payload":utf8>>)
  assert mac0.critical(tagged) == Ok([42])
}

fn make_detached_mac0(tagged: mac0.Mac0(mac0.Tagged)) -> BitArray {
  let data = mac0.serialize(tagged)
  let assert Ok(cbor.Array([protected, unprotected, _, mac_tag])) =
    cbor.decode(data)
  cbor.encode(cbor.Array([protected, unprotected, cbor.Null, mac_tag]))
}

pub fn verify_rejects_unsupported_crit_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"crit test":utf8>>
  let alg = gose.Hmac(gose.HmacSha256)

  let assert Ok(tagged) =
    mac0.new(alg)
    |> mac0.with_critical(labels: [42])
    |> mac0.tag(k, payload)

  let data = mac0.serialize(tagged)
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(v) = mac0.verifier(alg, keys: [k])
  assert mac0.verify(v, parsed)
    == Error(gose.ParseError(
      "crit references label not in protected headers: 42",
    ))
}

pub fn cose_wg_hmac_01_test() {
  let assert Ok(secret) =
    bit_array.base64_url_decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg")
  let assert Ok(k) = gose.from_octet_bits(secret)

  let assert Ok(cbor_bytes) =
    bit_array.base16_decode(
      "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
    )

  let assert Ok(parsed) = mac0.parse(cbor_bytes)
  assert mac0.payload(parsed) == Ok(<<"This is the content.":utf8>>)

  let assert Ok(verifier) = mac0.verifier(gose.Hmac(gose.HmacSha256), keys: [k])
  assert mac0.verify(verifier, message: parsed) == Ok(Nil)
}
