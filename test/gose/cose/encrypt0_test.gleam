import gleam/bit_array
import gose
import gose/algorithm
import gose/cbor
import gose/cose
import gose/cose/encrypt0
import gose/key
import kryptos/ec
import qcheck

pub fn serialize_parse_decrypt_roundtrip_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let plaintext = <<"roundtrip test":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) = encrypt0.encrypt(message, k, plaintext)

  let data = encrypt0.serialize(encrypted)
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: k)
  let assert Ok(decrypted) = encrypt0.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn serialize_tagged_parse_decrypt_roundtrip_test() {
  let alg = algorithm.AesGcm(algorithm.Aes256)
  let k = key.generate_enc_key(alg)
  let plaintext = <<"tagged roundtrip":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) = encrypt0.encrypt(message, k, plaintext)

  let tagged_data = encrypt0.serialize_tagged(encrypted)
  let assert Ok(parsed) = encrypt0.parse(tagged_data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: k)
  let assert Ok(decrypted) = encrypt0.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn untagged_serialization_test() {
  let alg = algorithm.ChaCha20Poly1305
  let k = key.generate_enc_key(alg)
  let plaintext = <<"untagged":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) = encrypt0.encrypt(message, k, plaintext)

  let data = encrypt0.serialize(encrypted)
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: k)
  let assert Ok(decrypted) = encrypt0.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn aad_roundtrip_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let plaintext = <<"aad test":utf8>>
  let aad = <<"extra context":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) =
    message
    |> encrypt0.with_aad(aad:)
    |> encrypt0.encrypt(k, plaintext)

  let data = encrypt0.serialize(encrypted)
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: k)
  let assert Ok(decrypted) =
    encrypt0.decrypt_with_aad(decryptor, message: parsed, aad:)
  assert decrypted == plaintext
}

pub fn wrong_key_decrypt_fails_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let wrong_key = key.generate_enc_key(alg)
  let plaintext = <<"secret data":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) = encrypt0.encrypt(message, k, plaintext)

  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: wrong_key)
  let assert Error(gose.CryptoError(_)) = encrypt0.decrypt(decryptor, encrypted)
}

pub fn parse_invalid_cbor_test() {
  let assert Error(gose.ParseError(_)) = encrypt0.parse(<<0xff>>)
}

pub fn parse_rejects_overlapping_headers_test() {
  let protected =
    cbor.encode(
      cbor.Map([#(cbor.Int(1), cbor.Int(1)), #(cbor.Int(99), cbor.Int(0))]),
    )
  let unprotected = cbor.Map([#(cbor.Int(99), cbor.Int(1))])
  let data =
    cbor.encode(
      cbor.Array([cbor.Bytes(protected), unprotected, cbor.Bytes(<<0:128>>)]),
    )
  assert encrypt0.parse(data)
    == Error(gose.ParseError(
      "duplicate label in protected and unprotected headers",
    ))
}

pub fn decrypt_missing_iv_fails_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)

  let protected = cbor.encode(cbor.Map([#(cbor.Int(1), cbor.Int(1))]))
  let data =
    cbor.encode(
      cbor.Array([cbor.Bytes(protected), cbor.Map([]), cbor.Bytes(<<0:128>>)]),
    )
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: k)
  let assert Error(gose.ParseError(msg)) = encrypt0.decrypt(decryptor, parsed)
  assert msg == "missing header label 5 (IV)"
}

pub fn decrypt_ciphertext_too_short_fails_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)

  let protected = cbor.encode(cbor.Map([#(cbor.Int(1), cbor.Int(1))]))
  let unprotected = cbor.Map([#(cbor.Int(5), cbor.Bytes(<<0:96>>))])
  let data =
    cbor.encode(
      cbor.Array([cbor.Bytes(protected), unprotected, cbor.Bytes(<<1, 2, 3>>)]),
    )
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: k)
  let assert Error(gose.ParseError(msg)) = encrypt0.decrypt(decryptor, parsed)
  assert msg == "ciphertext too short to contain authentication tag"
}

pub fn wrong_key_type_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let ec_key = key.generate_ec(ec.P256)
  let plaintext = <<"test":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let assert Error(gose.InvalidState(_)) =
    encrypt0.encrypt(message, ec_key, plaintext)
}

pub fn wrong_aad_decrypt_fails_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let plaintext = <<"aad mismatch":utf8>>
  let correct_aad = <<"correct context":utf8>>
  let wrong_aad = <<"wrong context":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) =
    message
    |> encrypt0.with_aad(aad: correct_aad)
    |> encrypt0.encrypt(k, plaintext)

  let data = encrypt0.serialize(encrypted)
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: k)
  let assert Error(gose.CryptoError(_)) =
    encrypt0.decrypt_with_aad(decryptor, message: parsed, aad: wrong_aad)
}

pub fn encrypt_wrong_key_use_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let assert Ok(k) =
    key.generate_enc_key(alg)
    |> key.with_key_use(key.Signing)

  let assert Ok(message) = encrypt0.new(alg)
  let assert Error(gose.InvalidState(_)) =
    encrypt0.encrypt(message, k, <<"test":utf8>>)
}

pub fn decrypt_wrong_key_ops_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let assert Ok(decrypt_key) =
    key.generate_enc_key(alg)
    |> key.with_key_ops([key.Encrypt])

  let assert Error(gose.InvalidState(_)) =
    encrypt0.decryptor(alg, key: decrypt_key)
}

pub fn encrypt_wrong_alg_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k =
    key.generate_enc_key(alg)
    |> key.with_alg(key.ContentAlg(algorithm.AesGcm(algorithm.Aes256)))

  let assert Ok(message) = encrypt0.new(alg)
  let assert Error(gose.InvalidState(_)) =
    encrypt0.encrypt(message, k, <<"test":utf8>>)
}

pub fn property_based_content_alg_roundtrip_test() {
  let gen = cose_content_alg_with_key_generator()
  use pair <- qcheck.given(gen)
  let plaintext = <<"property-based test":utf8>>

  let assert Ok(message) = encrypt0.new(pair.alg)
  let assert Ok(encrypted) = encrypt0.encrypt(message, pair.key, plaintext)

  let data = encrypt0.serialize(encrypted)
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(pair.alg, key: pair.key)
  let assert Ok(decrypted) = encrypt0.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

type ContentAlgWithKey(kid) {
  ContentAlgWithKey(alg: algorithm.ContentAlg, key: key.Key(kid))
}

fn cose_content_alg_with_key_generator() -> qcheck.Generator(
  ContentAlgWithKey(kid),
) {
  qcheck.from_generators(
    cose_content_alg_with_key(algorithm.AesGcm(algorithm.Aes128)),
    [
      cose_content_alg_with_key(algorithm.AesGcm(algorithm.Aes192)),
      cose_content_alg_with_key(algorithm.AesGcm(algorithm.Aes256)),
      cose_content_alg_with_key(algorithm.ChaCha20Poly1305),
    ],
  )
}

pub fn with_kid_roundtrip_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) =
    message
    |> encrypt0.with_kid(<<"key-1":utf8>>)
    |> encrypt0.encrypt(k, <<"payload":utf8>>)
  assert encrypt0.kid(encrypted) == Ok(<<"key-1":utf8>>)
}

pub fn kid_survives_serialize_parse_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) =
    message
    |> encrypt0.with_kid(<<"key-1":utf8>>)
    |> encrypt0.encrypt(k, <<"payload":utf8>>)
  let assert Ok(parsed) = encrypt0.parse(encrypt0.serialize(encrypted))
  assert encrypt0.kid(parsed) == Ok(<<"key-1":utf8>>)
}

pub fn protected_headers_exposes_alg_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) = encrypt0.encrypt(message, k, <<"payload":utf8>>)
  let assert Ok(1) = cose.algorithm(encrypt0.protected_headers(encrypted))
}

pub fn unprotected_headers_exposes_iv_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) = encrypt0.encrypt(message, k, <<"payload":utf8>>)
  let assert Ok(_iv) = cose.iv(encrypt0.unprotected_headers(encrypted))
}

fn cose_content_alg_with_key(
  alg: algorithm.ContentAlg,
) -> qcheck.Generator(ContentAlgWithKey(kid)) {
  let k = key.generate_enc_key(alg)
  qcheck.return(ContentAlgWithKey(alg, k))
}

pub fn with_content_type_roundtrip_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let plaintext = <<"ct test":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let message = encrypt0.with_content_type(message, ct: cose.Json)
  let assert Ok(encrypted) = encrypt0.encrypt(message, k, plaintext)
  assert encrypt0.content_type(encrypted) == Ok(cose.Json)
}

pub fn with_critical_roundtrip_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let plaintext = <<"crit roundtrip":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let message = encrypt0.with_critical(message, [42])
  let assert Ok(encrypted) = encrypt0.encrypt(message, k, plaintext)
  assert encrypt0.critical(encrypted) == Ok([42])
}

pub fn decrypt_rejects_unsupported_crit_test() {
  let alg = algorithm.AesGcm(algorithm.Aes128)
  let k = key.generate_enc_key(alg)
  let plaintext = <<"crit test":utf8>>

  let assert Ok(message) = encrypt0.new(alg)
  let message = encrypt0.with_critical(message, [42])
  let assert Ok(encrypted) = encrypt0.encrypt(message, k, plaintext)

  let data = encrypt0.serialize(encrypted)
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: k)
  assert encrypt0.decrypt(decryptor, parsed)
    == Error(gose.ParseError(
      "crit references label not in protected headers: 42",
    ))
}

pub fn cose_wg_aes_gcm_01_test() {
  let assert Ok(secret) = bit_array.base64_url_decode("hJtXIZ2uSN5kbQfbtTNWbg")
  let assert Ok(k) = key.from_octet_bits(secret)

  let assert Ok(cbor_bytes) =
    bit_array.base16_decode(
      "D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A",
    )

  let assert Ok(parsed) = encrypt0.parse(cbor_bytes)
  let assert Ok(decryptor) =
    encrypt0.decryptor(algorithm.AesGcm(algorithm.Aes128), key: k)
  let assert Ok(plaintext) = encrypt0.decrypt(decryptor, parsed)
  assert plaintext == <<"This is the content.":utf8>>
}
