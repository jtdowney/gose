import gleam/bit_array
import gleam/option
import gose
import gose/cose
import gose/cose/encrypt
import gose/test_helpers/fixtures
import kryptos/ec
import kryptos/hash
import kryptos/xdh

pub fn aes128_kw_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let plaintext = <<"hello COSE_Encrypt":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) = encrypt.decryptor(kw_alg, content_alg, keys: [k])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn aes256_kw_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes256)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes256)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes256))
  let plaintext = <<"AES-256-KW payload":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes256, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) = encrypt.decryptor(kw_alg, content_alg, keys: [k])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn aes_kw_chacha20_content_roundtrip_test() {
  let content_alg = gose.ChaCha20Poly1305
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes256)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes256))
  let plaintext = <<"ChaCha20 content":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes256, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) = encrypt.decryptor(kw_alg, content_alg, keys: [k])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn direct_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_enc_key(content_alg)
  let plaintext = <<"direct encryption":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_direct_recipient(key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) =
    encrypt.decryptor(gose.Direct, content_alg, keys: [k])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn direct_multiple_recipients_rejected_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k1 = gose.generate_enc_key(content_alg)
  let k2 = gose.generate_enc_key(gose.AesGcm(gose.Aes128))

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r1) = encrypt.new_direct_recipient(key: k1)
  let assert Ok(r2) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k2)
  let message =
    message
    |> encrypt.add_recipient(r1)
    |> encrypt.add_recipient(r2)
  let assert Error(gose.InvalidState(_)) =
    encrypt.encrypt(message, plaintext: <<"test":utf8>>)
}

pub fn rsa_oaep_sha256_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes256)
  let rsa_alg = gose.RsaEncryption(gose.RsaOaepSha256)
  let k = fixtures.rsa_private_key()
  let plaintext = <<"RSA-OAEP encrypted":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_rsa_recipient(gose.RsaOaepSha256, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) = encrypt.decryptor(rsa_alg, content_alg, keys: [k])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn ecdh_es_direct_p256_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_ec(ec.P256)
  let plaintext = <<"ECDH-ES direct":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) =
    encrypt.new_ecdh_es_direct_recipient(encrypt.EcdhEsHkdf256, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) =
    encrypt.ecdh_es_direct_decryptor(encrypt.EcdhEsHkdf256, content_alg, keys: [
      k,
    ])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn ecdh_es_direct_hkdf512_p256_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_ec(ec.P256)
  let plaintext = <<"ECDH-ES HKDF-512":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) =
    encrypt.new_ecdh_es_direct_recipient(encrypt.EcdhEsHkdf512, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) =
    encrypt.ecdh_es_direct_decryptor(encrypt.EcdhEsHkdf512, content_alg, keys: [
      k,
    ])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn ecdh_es_direct_x25519_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes256)
  let k = gose.generate_xdh(xdh.X25519)
  let plaintext = <<"ECDH-ES X25519":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) =
    encrypt.new_ecdh_es_direct_recipient(encrypt.EcdhEsHkdf256, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) =
    encrypt.ecdh_es_direct_decryptor(encrypt.EcdhEsHkdf256, content_alg, keys: [
      k,
    ])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn ecdh_es_aes_kw_p256_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let ecdh_kw_alg = gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128))
  let k = gose.generate_ec(ec.P256)
  let plaintext = <<"ECDH-ES+A128KW":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_ecdh_es_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) =
    encrypt.decryptor(ecdh_kw_alg, content_alg, keys: [k])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn ecdh_es_aes_kw_x25519_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes256)
  let ecdh_kw_alg = gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes256))
  let k = gose.generate_xdh(xdh.X25519)
  let plaintext = <<"ECDH-ES+A256KW X25519":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_ecdh_es_aes_kw_recipient(gose.Aes256, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) =
    encrypt.decryptor(ecdh_kw_alg, content_alg, keys: [k])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn multi_recipient_aes_kw_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes128)
  let k1 = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let k2 = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let plaintext = <<"multi-recipient":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r1) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k1)
  let assert Ok(r2) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k2)
  let message =
    message
    |> encrypt.add_recipient(r1)
    |> encrypt.add_recipient(r2)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed1) = encrypt.parse(data)
  let assert Ok(parsed2) = encrypt.parse(data)

  let assert Ok(d1) = encrypt.decryptor(kw_alg, content_alg, keys: [k1])
  let assert Ok(decrypted1) = encrypt.decrypt(d1, parsed1)
  assert decrypted1 == plaintext

  let assert Ok(d2) = encrypt.decryptor(kw_alg, content_alg, keys: [k2])
  let assert Ok(decrypted2) = encrypt.decrypt(d2, parsed2)
  assert decrypted2 == plaintext
}

pub fn mixed_aes_kw_and_rsa_recipients_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let rsa_alg = gose.RsaEncryption(gose.RsaOaepSha256)
  let sym_key = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let rsa_key = fixtures.rsa_private_key()
  let plaintext = <<"mixed recipients":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(sym_r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: sym_key)
  let assert Ok(rsa_r) =
    encrypt.new_rsa_recipient(gose.RsaOaepSha256, key: rsa_key)
  let message =
    message
    |> encrypt.add_recipient(sym_r)
    |> encrypt.add_recipient(rsa_r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)

  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(d) = encrypt.decryptor(rsa_alg, content_alg, keys: [rsa_key])
  let assert Ok(decrypted) = encrypt.decrypt(d, parsed)
  assert decrypted == plaintext
}

pub fn tagged_serialization_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let plaintext = <<"tagged test":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize_tagged(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) = encrypt.decryptor(kw_alg, content_alg, keys: [k])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn aad_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let plaintext = <<"aad test":utf8>>
  let aad = <<"extra context":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) =
    message
    |> encrypt.with_aad(aad:)
    |> encrypt.encrypt(plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) = encrypt.decryptor(kw_alg, content_alg, keys: [k])
  let assert Ok(decrypted) =
    encrypt.decrypt_with_aad(decryptor, message: parsed, aad:)
  assert decrypted == plaintext
}

pub fn wrong_aad_fails_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let plaintext = <<"aad mismatch":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) =
    message
    |> encrypt.with_aad(aad: <<"correct":utf8>>)
    |> encrypt.encrypt(plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) = encrypt.decryptor(kw_alg, content_alg, keys: [k])
  let assert Error(gose.CryptoError(_)) =
    encrypt.decrypt_with_aad(decryptor, message: parsed, aad: <<"wrong":utf8>>)
}

pub fn wrong_key_fails_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let wrong_key = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let plaintext = <<"secret":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) =
    encrypt.decryptor(kw_alg, content_alg, keys: [wrong_key])
  let assert Error(_) = encrypt.decrypt(decryptor, parsed)
}

pub fn wrong_content_alg_pinning_fails_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let plaintext = <<"alg pin":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) =
    encrypt.decryptor(kw_alg, gose.AesGcm(gose.Aes256), keys: [k])
  let assert Error(gose.InvalidState(_)) = encrypt.decrypt(decryptor, parsed)
}

pub fn no_recipients_fails_test() {
  let assert Ok(message) = encrypt.new(gose.AesGcm(gose.Aes128))
  let assert Error(gose.InvalidState(_)) =
    encrypt.encrypt(message, plaintext: <<"test":utf8>>)
}

pub fn parse_invalid_cbor_test() {
  let assert Error(gose.ParseError(_)) = encrypt.parse(<<0xff>>)
}

pub fn ecdh_es_direct_multiple_recipients_rejected_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k1 = gose.generate_ec(ec.P256)
  let k2 = gose.generate_ec(ec.P256)

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r1) =
    encrypt.new_ecdh_es_direct_recipient(encrypt.EcdhEsHkdf256, key: k1)
  let assert Ok(r2) =
    encrypt.new_ecdh_es_direct_recipient(encrypt.EcdhEsHkdf256, key: k2)
  let message =
    message
    |> encrypt.add_recipient(r1)
    |> encrypt.add_recipient(r2)
  let assert Error(gose.InvalidState(_)) =
    encrypt.encrypt(message, plaintext: <<"test":utf8>>)
}

pub fn decryptor_rejects_ecdh_es_direct_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_ec(ec.P256)

  assert encrypt.decryptor(gose.EcdhEs(gose.EcdhEsDirect), content_alg, keys: [
      k,
    ])
    == Error(gose.InvalidState(
      "use ecdh_es_direct_decryptor to choose HKDF variant",
    ))
}

pub fn recipient_builder_ecdh_es_direct_with_apu_apv_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_ec(ec.P256)
  let plaintext = <<"recipient builder + apu/apv":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) =
    encrypt.new_ecdh_es_direct_recipient(encrypt.EcdhEsHkdf256, key: k)
  let r =
    r
    |> encrypt.with_apu(<<"alice":utf8>>)
    |> encrypt.with_apv(<<"bob":utf8>>)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) =
    encrypt.ecdh_es_direct_decryptor(encrypt.EcdhEsHkdf256, content_alg, keys: [
      k,
    ])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn recipient_builder_ecdh_es_aes_kw_with_apu_apv_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let ecdh_kw_alg = gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128))
  let k = gose.generate_ec(ec.P256)
  let plaintext = <<"ECDH-ES+KW + apu/apv":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_ecdh_es_aes_kw_recipient(gose.Aes128, key: k)
  let r = encrypt.with_apu(r, <<"alice":utf8>>)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let assert Ok(parsed) = encrypt.parse(encrypt.serialize(encrypted))
  let assert Ok(decryptor) =
    encrypt.decryptor(ecdh_kw_alg, content_alg, keys: [k])
  let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
  assert decrypted == plaintext
}

pub fn hkdf_derive_key_returns_correct_length_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(derived) =
    encrypt.derive_cose_ecdh_key(
      secret,
      hash_algorithm: hash.Sha256,
      algorithm_id: 1,
      key_data_length: 16,
      recipient_protected: <<>>,
      party_u_identity: option.None,
      party_v_identity: option.None,
    )
  assert bit_array.byte_size(derived) == 16
}

pub fn hkdf_different_algorithm_id_produces_different_key_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(key_a) =
    encrypt.derive_cose_ecdh_key(
      secret,
      hash_algorithm: hash.Sha256,
      algorithm_id: 1,
      key_data_length: 16,
      recipient_protected: <<>>,
      party_u_identity: option.None,
      party_v_identity: option.None,
    )
  let assert Ok(key_b) =
    encrypt.derive_cose_ecdh_key(
      secret,
      hash_algorithm: hash.Sha256,
      algorithm_id: 3,
      key_data_length: 16,
      recipient_protected: <<>>,
      party_u_identity: option.None,
      party_v_identity: option.None,
    )
  assert key_a != key_b
}

pub fn hkdf_nil_vs_empty_bytes_identity_produces_different_key_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(key_nil) =
    encrypt.derive_cose_ecdh_key(
      secret,
      hash_algorithm: hash.Sha256,
      algorithm_id: 1,
      key_data_length: 16,
      recipient_protected: <<>>,
      party_u_identity: option.None,
      party_v_identity: option.None,
    )
  let assert Ok(key_empty) =
    encrypt.derive_cose_ecdh_key(
      secret,
      hash_algorithm: hash.Sha256,
      algorithm_id: 1,
      key_data_length: 16,
      recipient_protected: <<>>,
      party_u_identity: option.Some(<<>>),
      party_v_identity: option.None,
    )
  assert key_nil != key_empty
}

pub fn hkdf_different_recipient_protected_produces_different_key_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(key_empty) =
    encrypt.derive_cose_ecdh_key(
      secret,
      hash_algorithm: hash.Sha256,
      algorithm_id: 1,
      key_data_length: 16,
      recipient_protected: <<>>,
      party_u_identity: option.None,
      party_v_identity: option.None,
    )
  let assert Ok(key_with_protected) =
    encrypt.derive_cose_ecdh_key(
      secret,
      hash_algorithm: hash.Sha256,
      algorithm_id: 1,
      key_data_length: 16,
      recipient_protected: <<0xa1, 0x01, 0x38, 0x18>>,
      party_u_identity: option.None,
      party_v_identity: option.None,
    )
  assert key_empty != key_with_protected
}

pub fn hkdf_deterministic_derivation_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(key1) =
    encrypt.derive_cose_ecdh_key(
      secret,
      hash_algorithm: hash.Sha256,
      algorithm_id: 1,
      key_data_length: 16,
      recipient_protected: <<>>,
      party_u_identity: option.None,
      party_v_identity: option.None,
    )
  let assert Ok(key2) =
    encrypt.derive_cose_ecdh_key(
      secret,
      hash_algorithm: hash.Sha256,
      algorithm_id: 1,
      key_data_length: 16,
      recipient_protected: <<>>,
      party_u_identity: option.None,
      party_v_identity: option.None,
    )
  assert key1 == key2
}

pub fn encrypt_wrong_key_use_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let assert Ok(k) =
    gose.generate_enc_key(content_alg)
    |> gose.with_key_use(gose.Signing)

  let assert Error(gose.InvalidState(_)) =
    encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
}

pub fn decryptor_wrong_key_ops_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes128)
  let assert Ok(decrypt_key) =
    gose.generate_enc_key(content_alg)
    |> gose.with_key_ops([gose.Encrypt])

  let assert Error(gose.InvalidState(_)) =
    encrypt.decryptor(kw_alg, content_alg, keys: [decrypt_key])
}

pub fn encrypt_wrong_alg_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k =
    gose.generate_enc_key(content_alg)
    |> gose.with_alg(gose.ContentAlg(gose.AesGcm(gose.Aes256)))

  let assert Error(gose.InvalidState(_)) =
    encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
}

pub fn with_kid_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))

  let assert Ok(message) = encrypt.new(content_alg)
  let message = encrypt.with_kid(message, <<"key-1":utf8>>)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext: <<"hi":utf8>>)
  assert encrypt.kid(encrypted) == Ok(<<"key-1":utf8>>)
}

pub fn kid_survives_serialize_parse_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))

  let assert Ok(message) = encrypt.new(content_alg)
  let message = encrypt.with_kid(message, <<"key-1":utf8>>)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext: <<"hi":utf8>>)
  let assert Ok(parsed) = encrypt.parse(encrypt.serialize(encrypted))
  assert encrypt.kid(parsed) == Ok(<<"key-1":utf8>>)
}

pub fn protected_headers_exposes_alg_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext: <<"hi":utf8>>)
  let assert Ok(1) = cose.algorithm(encrypt.protected_headers(encrypted))
}

pub fn unprotected_headers_exposes_iv_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))

  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext: <<"hi":utf8>>)
  let assert Ok(_iv) = cose.iv(encrypt.unprotected_headers(encrypted))
}

pub fn with_content_type_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_enc_key(content_alg)
  let plaintext = <<"ct test":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let message = encrypt.with_content_type(message, ct: cose.Json)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)
  assert encrypt.content_type(encrypted) == Ok(cose.Json)
}

pub fn with_critical_roundtrip_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let k = gose.generate_enc_key(content_alg)
  let plaintext = <<"crit roundtrip":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let message = encrypt.with_critical(message, [42])
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)
  assert encrypt.critical(encrypted) == Ok([42])
}

pub fn decrypt_rejects_unsupported_crit_test() {
  let content_alg = gose.AesGcm(gose.Aes128)
  let kw_alg = gose.AesKeyWrap(gose.AesKw, gose.Aes128)
  let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
  let plaintext = <<"crit test":utf8>>

  let assert Ok(message) = encrypt.new(content_alg)
  let message = encrypt.with_critical(message, [42])
  let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(decryptor) = encrypt.decryptor(kw_alg, content_alg, keys: [k])
  assert encrypt.decrypt(decryptor, parsed)
    == Error(gose.ParseError(
      "crit references label not in protected headers: 42",
    ))
}
