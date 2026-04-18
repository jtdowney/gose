import gleam/json
import gose
import gose/jose/jwe_multi
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import qcheck

pub fn property_aes_kw_roundtrip_test() {
  use combo <- qcheck.given(generators.jwe_aes_kw_generator())
  let generators.JweAesKwWithKey(size, enc, aes_key) = combo
  let plaintext = <<"property aes kw":utf8>>

  let message = jwe_multi.new(enc)
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.AesKeyWrap(gose.AesKw, size),
      key: aes_key,
    )
  let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)
  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)
  let assert Ok(dec) =
    jwe_multi.decryptor(gose.AesKeyWrap(gose.AesKw, size), enc, keys: [
      aes_key,
    ])
  assert jwe_multi.decrypt(dec, parsed) == Ok(plaintext)
}

pub fn two_recipients_decrypt_each_test() {
  let aes_key = gose.generate_aes_kw_key(gose.Aes256)
  let rsa_key = fixtures.rsa_private_key()
  let plaintext = <<"two recipients":utf8>>
  let enc = gose.AesGcm(gose.Aes256)

  let message = jwe_multi.new(enc)
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.AesKeyWrap(gose.AesKw, gose.Aes256),
      key: aes_key,
    )
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.RsaEncryption(gose.RsaOaepSha256),
      key: rsa_key,
    )
  let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)
  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)

  let assert Ok(aes_dec) =
    jwe_multi.decryptor(gose.AesKeyWrap(gose.AesKw, gose.Aes256), enc, keys: [
      aes_key,
    ])
  assert jwe_multi.decrypt(aes_dec, parsed) == Ok(plaintext)

  let assert Ok(rsa_dec) =
    jwe_multi.decryptor(gose.RsaEncryption(gose.RsaOaepSha256), enc, keys: [
      rsa_key,
    ])
  assert jwe_multi.decrypt(rsa_dec, parsed) == Ok(plaintext)
}

pub fn no_matching_recipient_test() {
  let aes_key = gose.generate_aes_kw_key(gose.Aes256)
  let other_key = gose.generate_aes_kw_key(gose.Aes128)
  let enc = gose.AesGcm(gose.Aes256)

  let message = jwe_multi.new(enc)
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.AesKeyWrap(gose.AesKw, gose.Aes256),
      key: aes_key,
    )
  let assert Ok(encrypted) =
    jwe_multi.encrypt(message, plaintext: <<"test":utf8>>)
  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)

  let assert Ok(dec) =
    jwe_multi.decryptor(gose.AesKeyWrap(gose.AesKw, gose.Aes128), enc, keys: [
      other_key,
    ])
  let assert Error(_) = jwe_multi.decrypt(dec, parsed)
}

pub fn property_aes_gcm_kw_roundtrip_test() {
  use combo <- qcheck.given(generators.jwe_aes_gcm_kw_generator())
  let generators.JweAesGcmKwWithKey(size, enc, aes_key) = combo
  let plaintext = <<"property aes gcm kw":utf8>>

  let message = jwe_multi.new(enc)
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.AesKeyWrap(gose.AesGcmKw, size),
      key: aes_key,
    )
  let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)
  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)
  let assert Ok(dec) =
    jwe_multi.decryptor(gose.AesKeyWrap(gose.AesGcmKw, size), enc, keys: [
      aes_key,
    ])
  assert jwe_multi.decrypt(dec, parsed) == Ok(plaintext)
}

pub fn property_chacha20_kw_roundtrip_test() {
  use combo <- qcheck.given(generators.jwe_chacha20_kw_generator())
  let generators.JweChaCha20KwWithKey(variant, enc, chacha_key) = combo
  let plaintext = <<"property chacha20 kw":utf8>>

  let message = jwe_multi.new(enc)
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.ChaCha20KeyWrap(variant),
      key: chacha_key,
    )
  let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)
  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)
  let assert Ok(dec) =
    jwe_multi.decryptor(gose.ChaCha20KeyWrap(variant), enc, keys: [
      chacha_key,
    ])
  assert jwe_multi.decrypt(dec, parsed) == Ok(plaintext)
}

pub fn ecdh_es_aes_kw_roundtrip_test() {
  let k = fixtures.ec_p256_key()
  let enc = gose.AesGcm(gose.Aes256)
  let alg = gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128))
  let plaintext = <<"ecdh-es+a128kw multi":utf8>>

  let message = jwe_multi.new(enc)
  let assert Ok(message) = jwe_multi.add_recipient(message, alg, key: k)
  let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)
  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)
  let assert Ok(dec) = jwe_multi.decryptor(alg, enc, keys: [k])
  assert jwe_multi.decrypt(dec, parsed) == Ok(plaintext)
}

pub fn ecdh_es_chacha20_kw_roundtrip_test() {
  let k = fixtures.x25519_key()
  let enc = gose.AesGcm(gose.Aes256)
  let alg = gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.C20PKw))
  let plaintext = <<"ecdh-es+c20pkw multi":utf8>>

  let message = jwe_multi.new(enc)
  let assert Ok(message) = jwe_multi.add_recipient(message, alg, key: k)
  let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)
  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)
  let assert Ok(dec) = jwe_multi.decryptor(alg, enc, keys: [k])
  assert jwe_multi.decrypt(dec, parsed) == Ok(plaintext)
}

pub fn reject_direct_algorithm_test() {
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes256))
  let message = jwe_multi.new(gose.AesGcm(gose.Aes256))
  let assert Error(gose.InvalidState(msg)) =
    jwe_multi.add_recipient(message, gose.Direct, key: k)
  assert msg == "Direct key agreement cannot be used with multi-recipient JWE"
}

pub fn reject_ecdh_es_direct_algorithm_test() {
  let k = fixtures.ec_p256_key()
  let message = jwe_multi.new(gose.AesGcm(gose.Aes256))
  let assert Error(gose.InvalidState(msg)) =
    jwe_multi.add_recipient(message, gose.EcdhEs(gose.EcdhEsDirect), key: k)
  assert msg == "Direct key agreement cannot be used with multi-recipient JWE"
}

pub fn encrypt_empty_recipients_test() {
  let message = jwe_multi.new(gose.AesGcm(gose.Aes256))
  assert jwe_multi.encrypt(message, plaintext: <<"x":utf8>>)
    == Error(gose.InvalidState("at least one recipient required"))
}

pub fn decryptor_empty_keys_test() {
  assert jwe_multi.decryptor(
      gose.AesKeyWrap(gose.AesKw, gose.Aes256),
      gose.AesGcm(gose.Aes256),
      keys: [],
    )
    == Error(gose.InvalidState("at least one key required"))
}

pub fn decryptor_wrong_key_type_test() {
  let aes_key = gose.generate_aes_kw_key(gose.Aes256)
  let assert Error(gose.InvalidState(_)) =
    jwe_multi.decryptor(
      gose.RsaEncryption(gose.RsaOaepSha256),
      gose.AesGcm(gose.Aes256),
      keys: [aes_key],
    )
}

pub fn decrypt_content_alg_mismatch_test() {
  let aes_key = gose.generate_aes_kw_key(gose.Aes256)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes256)
  let message = jwe_multi.new(gose.AesGcm(gose.Aes256))
  let assert Ok(message) =
    jwe_multi.add_recipient(message, kw_alg, key: aes_key)
  let assert Ok(encrypted) =
    jwe_multi.encrypt(message, plaintext: <<"mismatch":utf8>>)
  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)

  let aes128_key = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let assert Ok(dec) =
    jwe_multi.decryptor(kw_alg, gose.AesGcm(gose.Aes128), keys: [
      aes128_key,
    ])
  let assert Error(gose.InvalidState(_)) = jwe_multi.decrypt(dec, parsed)
}

pub fn add_recipient_rejects_pbes2_test() {
  let k = gose.generate_aes_kw_key(gose.Aes256)
  let message = jwe_multi.new(gose.AesGcm(gose.Aes256))
  let assert Error(gose.InvalidState(msg)) =
    jwe_multi.add_recipient(
      message,
      gose.Pbes2(gose.Pbes2Sha256Aes128Kw),
      key: k,
    )
  assert msg
    == "PBES2 algorithms require a password; use the single-recipient JWE API"
}

pub fn parse_invalid_json_test() {
  let assert Error(gose.ParseError(_)) = jwe_multi.parse_json("not json")
}
