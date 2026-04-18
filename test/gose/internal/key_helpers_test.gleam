import gleam/option
import gose
import gose/algorithm
import gose/internal/key_helpers
import gose/key
import gose/test_helpers/fixtures

pub fn require_matching_signing_algorithm_match_test() {
  let result =
    key_helpers.require_matching_signing_algorithm(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
    )
  assert result == Ok(Nil)
}

pub fn require_matching_signing_algorithm_mismatch_test() {
  let result =
    key_helpers.require_matching_signing_algorithm(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha512)),
    )
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "algorithm mismatch: expected Mac(Hmac(HmacSha256)), got Mac(Hmac(HmacSha512))"
}

pub fn order_keys_by_kid_none_target_test() {
  let key1 = key.generate_hmac_key(algorithm.HmacSha256)
  let key2 = key.generate_hmac_key(algorithm.HmacSha256)
  let keys = [key1, key2]
  let result = key_helpers.order_keys_by_kid(keys, option.None)
  assert result == keys
}

pub fn order_keys_by_kid_matching_test() {
  let key1 = key.generate_hmac_key(algorithm.HmacSha256)
  let key1 = key.with_kid(key1, "key-1")
  let key2 = key.generate_hmac_key(algorithm.HmacSha256)
  let key2 = key.with_kid(key2, "key-2")
  let result = key_helpers.order_keys_by_kid([key1, key2], option.Some("key-2"))
  assert result == [key2, key1]
}

pub fn order_keys_by_kid_no_match_test() {
  let key1 = key.generate_hmac_key(algorithm.HmacSha256)
  let key1 = key.with_kid(key1, "key-1")
  let key2 = key.generate_hmac_key(algorithm.HmacSha256)
  let key2 = key.with_kid(key2, "key-2")
  let keys = [key1, key2]
  let result = key_helpers.order_keys_by_kid(keys, option.Some("key-3"))
  assert result == keys
}

pub fn order_keys_by_kid_empty_list_test() {
  let result = key_helpers.order_keys_by_kid([], option.Some("any-kid"))
  assert result == []
}

pub fn require_non_empty_keys_with_empty_list_test() {
  let result = key_helpers.require_non_empty_keys([], fn() { Ok(42) })
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "at least one key required"
}

pub fn require_non_empty_keys_with_one_key_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let result = key_helpers.require_non_empty_keys([key], fn() { Ok(42) })
  assert result == Ok(42)
}

pub fn require_non_empty_keys_with_multiple_keys_test() {
  let key1 = key.generate_hmac_key(algorithm.HmacSha256)
  let key2 = key.generate_hmac_key(algorithm.HmacSha256)
  let result =
    key_helpers.require_non_empty_keys([key1, key2], fn() { Ok("success") })
  assert result == Ok("success")
}

pub fn validate_signing_key_type_hmac_ok_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let result =
    key_helpers.validate_signing_key_type(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      key,
    )
  assert result == Ok(Nil)
}

pub fn validate_signing_key_type_hmac_undersized_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let result =
    key_helpers.validate_signing_key_type(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha512)),
      key,
    )
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "Mac(Hmac(HmacSha512)) requires key of at least 64 bytes, got 32"
}

pub fn validate_signing_key_type_rsa_pkcs1_ok_test() {
  let key = fixtures.rsa_private_key()
  let result =
    key_helpers.validate_signing_key_type(
      algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256)),
      key,
    )
  assert result == Ok(Nil)
}

pub fn validate_signing_key_type_rsa_pss_ok_test() {
  let key = fixtures.rsa_private_key()
  let result =
    key_helpers.validate_signing_key_type(
      algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha256)),
      key,
    )
  assert result == Ok(Nil)
}

pub fn validate_signing_key_type_ec_p256_ok_test() {
  let key = fixtures.ec_p256_key()
  let result =
    key_helpers.validate_signing_key_type(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      key,
    )
  assert result == Ok(Nil)
}

pub fn validate_signing_key_type_ec_curve_mismatch_test() {
  let key = fixtures.ec_p384_key()
  let result =
    key_helpers.validate_signing_key_type(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      key,
    )
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "EC key curve does not match algorithm"
}

pub fn validate_signing_key_type_eddsa_ok_test() {
  let key = fixtures.ed25519_key()
  let result =
    key_helpers.validate_signing_key_type(
      algorithm.DigitalSignature(algorithm.Eddsa),
      key,
    )
  assert result == Ok(Nil)
}

pub fn validate_signing_key_type_xdh_rejected_for_eddsa_test() {
  let key = fixtures.x25519_key()
  let result =
    key_helpers.validate_signing_key_type(
      algorithm.DigitalSignature(algorithm.Eddsa),
      key,
    )
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "EdDSA algorithm requires an EdDSA key (Ed25519/Ed448), not XDH"
}

pub fn validate_signing_key_type_wrong_key_type_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let result =
    key_helpers.validate_signing_key_type(
      algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256)),
      key,
    )
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "algorithm DigitalSignature(RsaPkcs1(RsaPkcs1Sha256)) incompatible with key type"
}

pub fn validate_key_use_no_use_field_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let result = key_helpers.validate_key_use(key, key_helpers.ForSigning)
  assert result == Ok(Nil)
}

pub fn validate_key_use_sig_for_signing_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let result = key_helpers.validate_key_use(key, key_helpers.ForSigning)
  assert result == Ok(Nil)
}

pub fn validate_key_use_sig_for_verification_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let result = key_helpers.validate_key_use(key, key_helpers.ForVerification)
  assert result == Ok(Nil)
}

pub fn validate_key_use_enc_for_encryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Encrypting)
  let result = key_helpers.validate_key_use(key, key_helpers.ForEncryption)
  assert result == Ok(Nil)
}

pub fn validate_key_use_enc_for_decryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Encrypting)
  let result = key_helpers.validate_key_use(key, key_helpers.ForDecryption)
  assert result == Ok(Nil)
}

pub fn validate_key_use_enc_rejected_for_signing_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Encrypting)
  let result = key_helpers.validate_key_use(key, key_helpers.ForSigning)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key use is 'enc', cannot be used for signing"
}

pub fn validate_key_use_enc_rejected_for_verification_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Encrypting)
  let result = key_helpers.validate_key_use(key, key_helpers.ForVerification)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key use is 'enc', cannot be used for verification"
}

pub fn validate_key_use_sig_rejected_for_encryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let result = key_helpers.validate_key_use(key, key_helpers.ForEncryption)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key use is 'sig', cannot be used for encryption"
}

pub fn validate_key_use_sig_rejected_for_decryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let result = key_helpers.validate_key_use(key, key_helpers.ForDecryption)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key use is 'sig', cannot be used for decryption"
}

pub fn validate_key_ops_no_ops_field_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let result = key_helpers.validate_key_ops(key, key_helpers.ForSigning)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_sign_permits_signing_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.Sign])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForSigning)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_verify_permits_verification_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.Verify])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForVerification)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_encrypt_permits_encryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.Encrypt])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForEncryption)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_wrap_key_permits_encryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.WrapKey])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForEncryption)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_decrypt_permits_decryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.Decrypt])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForDecryption)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_unwrap_key_permits_decryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.UnwrapKey])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForDecryption)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_sign_rejected_for_verification_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.Sign])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForVerification)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key_ops does not include 'verify' operation"
}

pub fn validate_key_ops_verify_rejected_for_signing_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.Verify])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForSigning)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key_ops does not include 'sign' operation"
}

pub fn validate_key_ops_encrypt_rejected_for_decryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.Encrypt])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForDecryption)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key_ops does not include 'decrypt' or 'unwrapKey' operation"
}

pub fn validate_key_ops_decrypt_rejected_for_encryption_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.Decrypt])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForEncryption)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key_ops does not include 'encrypt' or 'wrapKey' operation"
}

pub fn validate_key_ops_derive_key_permits_ecdh_encryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_ops(key, [key.DeriveKey])
  assert key_helpers.validate_key_for_jwe_encryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_ops_derive_bits_permits_ecdh_encryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_ops(key, [key.DeriveBits])
  assert key_helpers.validate_key_for_jwe_encryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_ops_derive_key_permits_ecdh_decryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_ops(key, [key.DeriveKey])
  assert key_helpers.validate_key_for_jwe_decryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_ops_derive_bits_permits_ecdh_decryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_ops(key, [key.DeriveBits])
  assert key_helpers.validate_key_for_jwe_decryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_ops_derive_key_rejected_for_rsa_encryption_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = key.with_key_ops(key, [key.DeriveKey])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg == "key_ops does not include 'encrypt' or 'wrapKey' operation"
}

pub fn validate_key_ops_derive_key_rejected_for_rsa_decryption_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = key.with_key_ops(key, [key.DeriveKey])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg == "key_ops does not include 'decrypt' or 'unwrapKey' operation"
}

pub fn validate_key_ops_encrypt_rejected_for_ecdh_encryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_ops(key, [key.Encrypt])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
  assert msg == "key_ops does not include 'deriveKey' or 'deriveBits' operation"
}

pub fn validate_key_ops_decrypt_rejected_for_ecdh_decryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_ops(key, [key.Decrypt])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
  assert msg == "key_ops does not include 'deriveKey' or 'deriveBits' operation"
}

pub fn validate_key_use_enc_permits_ecdh_encryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_use(key, key.Encrypting)
  assert key_helpers.validate_key_for_jwe_encryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_use_enc_permits_ecdh_decryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_use(key, key.Encrypting)
  assert key_helpers.validate_key_for_jwe_decryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_use_sig_rejected_for_ecdh_encryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
  assert msg == "key use is 'sig', cannot be used for key agreement"
}

pub fn validate_key_use_sig_rejected_for_ecdh_decryption_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
  assert msg == "key use is 'sig', cannot be used for key agreement"
}

pub fn validate_key_algorithm_signing_no_alg_field_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let result =
    key_helpers.validate_key_algorithm_signing(
      key,
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
    )
  assert result == Ok(Nil)
}

pub fn validate_key_algorithm_signing_matching_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let key =
    key.with_alg(
      key,
      key.SigningAlg(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256))),
    )
  let result =
    key_helpers.validate_key_algorithm_signing(
      key,
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
    )
  assert result == Ok(Nil)
}

pub fn validate_key_algorithm_signing_mismatch_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha512)
  let key =
    key.with_alg(
      key,
      key.SigningAlg(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha512))),
    )
  let result =
    key_helpers.validate_key_algorithm_signing(
      key,
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
    )
  let assert Error(gose.InvalidState(_)) = result
}

pub fn validate_key_algorithm_signing_jwe_on_jws_key_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let key = key.with_alg(key, key.KeyEncryptionAlg(algorithm.Direct))
  let result =
    key_helpers.validate_key_algorithm_signing(
      key,
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
    )
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "key algorithm mismatch: key has JWE algorithm, expected JWS algorithm"
}

pub fn validate_key_algorithm_jwe_no_alg_field_test() {
  let key = fixtures.rsa_private_key()
  let result =
    key_helpers.validate_key_algorithm_jwe(
      key,
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
    )
  assert result == Ok(Nil)
}

pub fn validate_key_algorithm_jwe_matching_test() {
  let key = fixtures.rsa_private_key()
  let key =
    key.with_alg(
      key,
      key.KeyEncryptionAlg(algorithm.RsaEncryption(algorithm.RsaOaepSha256)),
    )
  let result =
    key_helpers.validate_key_algorithm_jwe(
      key,
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
    )
  assert result == Ok(Nil)
}

pub fn validate_key_algorithm_jwe_mismatch_test() {
  let key = fixtures.rsa_private_key()
  let key =
    key.with_alg(
      key,
      key.KeyEncryptionAlg(algorithm.RsaEncryption(algorithm.RsaOaepSha256)),
    )
  let result =
    key_helpers.validate_key_algorithm_jwe(
      key,
      algorithm.RsaEncryption(algorithm.RsaOaepSha1),
    )
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "key algorithm mismatch: key has RsaEncryption(RsaOaepSha256), expected RsaEncryption(RsaOaepSha1)"
}

pub fn validate_key_algorithm_jwe_jws_on_jwe_key_test() {
  let key = fixtures.rsa_private_key()
  let key =
    key.with_alg(
      key,
      key.SigningAlg(
        algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256)),
      ),
    )
  let result =
    key_helpers.validate_key_algorithm_jwe(
      key,
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
    )
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "key algorithm mismatch: key has JWS algorithm, expected JWE algorithm"
}

pub fn validate_hmac_key_size_accepts_sufficient_key_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  assert key_helpers.validate_hmac_key_size(key, 32, "HS256") == Ok(Nil)
}

pub fn validate_hmac_key_size_rejects_undersized_key_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_hmac_key_size(key, 64, "HS512")
  assert msg == "HS512 requires key of at least 64 bytes, got 32"
}

pub fn validate_hmac_key_size_non_octet_key_test() {
  let key = fixtures.rsa_private_key()
  assert key_helpers.validate_hmac_key_size(key, 32, "HS256")
    == Error(gose.InvalidState("key is not an octet key"))
}

pub fn validate_key_for_signing_verification_happy_path_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  assert key_helpers.validate_key_for_signing_verification(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_for_signing_verification_wrong_key_type_test() {
  let key = fixtures.rsa_private_key()
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_signing_verification(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      key,
    )
  assert msg == "algorithm Mac(Hmac(HmacSha256)) incompatible with key type"
}

pub fn validate_key_for_signing_verification_wrong_use_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_use(key, key.Encrypting)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_signing_verification(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      key,
    )
  assert msg == "key use is 'enc', cannot be used for verification"
}

pub fn validate_key_for_signing_verification_wrong_ops_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Ok(key) = key.with_key_ops(key, [key.Sign])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_signing_verification(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      key,
    )
  assert msg == "key_ops does not include 'verify' operation"
}

pub fn validate_key_for_signing_verification_wrong_alg_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha512)
  let key =
    key.with_alg(
      key,
      key.SigningAlg(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha512))),
    )
  let assert Error(gose.InvalidState(_)) =
    key_helpers.validate_key_for_signing_verification(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      key,
    )
}

pub fn validate_key_for_jwe_decryption_happy_path_test() {
  let key = fixtures.rsa_private_key()
  assert key_helpers.validate_key_for_jwe_decryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_for_jwe_decryption_wrong_use_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg == "key use is 'sig', cannot be used for decryption"
}

pub fn validate_key_for_jwe_decryption_wrong_ops_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = key.with_key_ops(key, [key.Encrypt])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg == "key_ops does not include 'decrypt' or 'unwrapKey' operation"
}

pub fn validate_key_for_jwe_decryption_wrong_alg_test() {
  let key = fixtures.rsa_private_key()
  let key =
    key.with_alg(
      key,
      key.KeyEncryptionAlg(algorithm.RsaEncryption(algorithm.RsaOaepSha1)),
    )
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg
    == "key algorithm mismatch: key has RsaEncryption(RsaOaepSha1), expected RsaEncryption(RsaOaepSha256)"
}

pub fn validate_key_for_jwe_encryption_happy_path_test() {
  let key = fixtures.rsa_private_key()
  assert key_helpers.validate_key_for_jwe_encryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_for_jwe_encryption_wrong_use_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg == "key use is 'sig', cannot be used for encryption"
}

pub fn validate_key_for_jwe_encryption_wrong_ops_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = key.with_key_ops(key, [key.Decrypt])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg == "key_ops does not include 'encrypt' or 'wrapKey' operation"
}

pub fn validate_key_for_jwe_encryption_wrong_alg_test() {
  let key = fixtures.rsa_private_key()
  let key =
    key.with_alg(
      key,
      key.KeyEncryptionAlg(algorithm.RsaEncryption(algorithm.RsaOaepSha1)),
    )
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg
    == "key algorithm mismatch: key has RsaEncryption(RsaOaepSha1), expected RsaEncryption(RsaOaepSha256)"
}

pub fn validate_jwe_key_type_oct_alg_ok_test() {
  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes128))
  let result = key_helpers.validate_jwe_key_type(algorithm.Direct, key)
  assert result == Ok(Nil)
}

pub fn validate_jwe_key_type_rsa_ok_test() {
  let key = fixtures.rsa_private_key()
  let result =
    key_helpers.validate_jwe_key_type(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert result == Ok(Nil)
}

pub fn validate_jwe_key_type_ecdh_es_ec_ok_test() {
  let key = fixtures.ec_p256_key()
  let result =
    key_helpers.validate_jwe_key_type(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
  assert result == Ok(Nil)
}

pub fn validate_jwe_key_type_ecdh_es_xdh_ok_test() {
  let key = fixtures.x25519_key()
  let result =
    key_helpers.validate_jwe_key_type(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
  assert result == Ok(Nil)
}

pub fn validate_jwe_key_type_ecdh_es_rejects_eddsa_test() {
  let key = fixtures.ed25519_key()
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_jwe_key_type(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      key,
    )
  assert msg
    == "ECDH-ES algorithm requires an EC or XDH key (X25519/X448), not EdDSA"
}

pub fn validate_jwe_key_type_pbes2_rejects_any_key_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_jwe_key_type(
      algorithm.Pbes2(algorithm.Pbes2Sha256Aes128Kw),
      key,
    )
  assert msg == "use password_decryptor for PBES2 algorithms"
}

pub fn validate_jwe_key_type_wrong_key_type_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_jwe_key_type(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg
    == "algorithm RsaEncryption(RsaOaepSha256) incompatible with key type"
}

pub fn validate_key_for_jwe_decryption_wrong_key_type_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg
    == "algorithm RsaEncryption(RsaOaepSha256) incompatible with key type"
}

pub fn validate_key_for_jwe_encryption_wrong_key_type_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      algorithm.RsaEncryption(algorithm.RsaOaepSha256),
      key,
    )
  assert msg
    == "algorithm RsaEncryption(RsaOaepSha256) incompatible with key type"
}
