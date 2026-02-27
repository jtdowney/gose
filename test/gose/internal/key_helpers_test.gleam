import gleam/option
import gose
import gose/internal/key_helpers
import gose/jwa
import gose/jwk
import gose/test_helpers/fixtures

pub fn require_matching_jws_algorithm_match_test() {
  let result =
    key_helpers.require_matching_jws_algorithm(
      jwa.JwsHmac(jwa.HmacSha256),
      jwa.JwsHmac(jwa.HmacSha256),
    )
  assert result == Ok(Nil)
}

pub fn require_matching_jws_algorithm_mismatch_test() {
  let result =
    key_helpers.require_matching_jws_algorithm(
      jwa.JwsHmac(jwa.HmacSha256),
      jwa.JwsHmac(jwa.HmacSha512),
    )
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "algorithm mismatch: expected HS256, got HS512"
}

pub fn order_keys_by_kid_none_target_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let keys = [key1, key2]
  let result = key_helpers.order_keys_by_kid(keys, option.None)
  assert result == keys
}

pub fn order_keys_by_kid_matching_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "key-1")
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2, "key-2")
  let result = key_helpers.order_keys_by_kid([key1, key2], option.Some("key-2"))
  assert result == [key2, key1]
}

pub fn order_keys_by_kid_no_match_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "key-1")
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2, "key-2")
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
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let result = key_helpers.require_non_empty_keys([key], fn() { Ok(42) })
  assert result == Ok(42)
}

pub fn require_non_empty_keys_with_multiple_keys_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let result =
    key_helpers.require_non_empty_keys([key1, key2], fn() { Ok("success") })
  assert result == Ok("success")
}

pub fn validate_jws_key_type_hmac_ok_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let result =
    key_helpers.validate_jws_key_type(jwa.JwsHmac(jwa.HmacSha256), key)
  assert result == Ok(Nil)
}

pub fn validate_jws_key_type_hmac_undersized_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let result =
    key_helpers.validate_jws_key_type(jwa.JwsHmac(jwa.HmacSha512), key)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "HS512 requires key of at least 64 bytes, got 32"
}

pub fn validate_jws_key_type_rsa_pkcs1_ok_test() {
  let key = fixtures.rsa_private_key()
  let result =
    key_helpers.validate_jws_key_type(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256), key)
  assert result == Ok(Nil)
}

pub fn validate_jws_key_type_rsa_pss_ok_test() {
  let key = fixtures.rsa_private_key()
  let result =
    key_helpers.validate_jws_key_type(jwa.JwsRsaPss(jwa.RsaPssSha256), key)
  assert result == Ok(Nil)
}

pub fn validate_jws_key_type_ec_p256_ok_test() {
  let key = fixtures.ec_p256_key()
  let result =
    key_helpers.validate_jws_key_type(jwa.JwsEcdsa(jwa.EcdsaP256), key)
  assert result == Ok(Nil)
}

pub fn validate_jws_key_type_ec_curve_mismatch_test() {
  let key = fixtures.ec_p384_key()
  let result =
    key_helpers.validate_jws_key_type(jwa.JwsEcdsa(jwa.EcdsaP256), key)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "EC key curve does not match algorithm"
}

pub fn validate_jws_key_type_eddsa_ok_test() {
  let key = fixtures.ed25519_key()
  let result = key_helpers.validate_jws_key_type(jwa.JwsEddsa, key)
  assert result == Ok(Nil)
}

pub fn validate_jws_key_type_xdh_rejected_for_eddsa_test() {
  let key = fixtures.x25519_key()
  let result = key_helpers.validate_jws_key_type(jwa.JwsEddsa, key)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "EdDSA algorithm requires an EdDSA key (Ed25519/Ed448), not XDH"
}

pub fn validate_jws_key_type_wrong_key_type_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let result =
    key_helpers.validate_jws_key_type(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256), key)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "algorithm RS256 incompatible with key type"
}

pub fn validate_key_use_no_use_field_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let result = key_helpers.validate_key_use(key, key_helpers.ForSigning)
  assert result == Ok(Nil)
}

pub fn validate_key_use_sig_for_signing_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_use(key, jwk.Signing)
  let result = key_helpers.validate_key_use(key, key_helpers.ForSigning)
  assert result == Ok(Nil)
}

pub fn validate_key_use_sig_for_verification_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_use(key, jwk.Signing)
  let result = key_helpers.validate_key_use(key, key_helpers.ForVerification)
  assert result == Ok(Nil)
}

pub fn validate_key_use_enc_for_encryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_use(key, jwk.Encrypting)
  let result = key_helpers.validate_key_use(key, key_helpers.ForEncryption)
  assert result == Ok(Nil)
}

pub fn validate_key_use_enc_for_decryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_use(key, jwk.Encrypting)
  let result = key_helpers.validate_key_use(key, key_helpers.ForDecryption)
  assert result == Ok(Nil)
}

pub fn validate_key_use_enc_rejected_for_signing_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_use(key, jwk.Encrypting)
  let result = key_helpers.validate_key_use(key, key_helpers.ForSigning)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key use is 'enc', cannot be used for signing"
}

pub fn validate_key_use_enc_rejected_for_verification_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_use(key, jwk.Encrypting)
  let result = key_helpers.validate_key_use(key, key_helpers.ForVerification)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key use is 'enc', cannot be used for verification"
}

pub fn validate_key_use_sig_rejected_for_encryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_use(key, jwk.Signing)
  let result = key_helpers.validate_key_use(key, key_helpers.ForEncryption)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key use is 'sig', cannot be used for encryption"
}

pub fn validate_key_use_sig_rejected_for_decryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_use(key, jwk.Signing)
  let result = key_helpers.validate_key_use(key, key_helpers.ForDecryption)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key use is 'sig', cannot be used for decryption"
}

pub fn validate_key_ops_no_ops_field_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let result = key_helpers.validate_key_ops(key, key_helpers.ForSigning)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_sign_permits_signing_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Sign])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForSigning)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_verify_permits_verification_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Verify])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForVerification)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_encrypt_permits_encryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Encrypt])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForEncryption)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_wrap_key_permits_encryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.WrapKey])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForEncryption)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_decrypt_permits_decryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Decrypt])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForDecryption)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_unwrap_key_permits_decryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.UnwrapKey])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForDecryption)
  assert result == Ok(Nil)
}

pub fn validate_key_ops_sign_rejected_for_verification_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Sign])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForVerification)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key_ops does not include 'verify' operation"
}

pub fn validate_key_ops_verify_rejected_for_signing_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Verify])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForSigning)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key_ops does not include 'sign' operation"
}

pub fn validate_key_ops_encrypt_rejected_for_decryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Encrypt])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForDecryption)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key_ops does not include 'decrypt' or 'unwrapKey' operation"
}

pub fn validate_key_ops_decrypt_rejected_for_encryption_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Decrypt])
  let result = key_helpers.validate_key_ops(key, key_helpers.ForEncryption)
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key_ops does not include 'encrypt' or 'wrapKey' operation"
}

pub fn validate_key_algorithm_jws_no_alg_field_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let result =
    key_helpers.validate_key_algorithm_jws(key, jwa.JwsHmac(jwa.HmacSha256))
  assert result == Ok(Nil)
}

pub fn validate_key_algorithm_jws_matching_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let key = jwk.with_alg(key, jwk.Jws(jwa.JwsHmac(jwa.HmacSha256)))
  let result =
    key_helpers.validate_key_algorithm_jws(key, jwa.JwsHmac(jwa.HmacSha256))
  assert result == Ok(Nil)
}

pub fn validate_key_algorithm_jws_mismatch_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha512)
  let key = jwk.with_alg(key, jwk.Jws(jwa.JwsHmac(jwa.HmacSha512)))
  let result =
    key_helpers.validate_key_algorithm_jws(key, jwa.JwsHmac(jwa.HmacSha256))
  let assert Error(gose.InvalidState(msg)) = result
  assert msg == "key algorithm mismatch: key has HS512, expected HS256"
}

pub fn validate_key_algorithm_jws_jwe_on_jws_key_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let key = jwk.with_alg(key, jwk.Jwe(jwa.JweDirect))
  let result =
    key_helpers.validate_key_algorithm_jws(key, jwa.JwsHmac(jwa.HmacSha256))
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "key algorithm mismatch: key has JWE algorithm, expected JWS algorithm"
}

pub fn validate_key_algorithm_jwe_no_alg_field_test() {
  let key = fixtures.rsa_private_key()
  let result =
    key_helpers.validate_key_algorithm_jwe(key, jwa.JweRsa(jwa.RsaOaepSha256))
  assert result == Ok(Nil)
}

pub fn validate_key_algorithm_jwe_matching_test() {
  let key = fixtures.rsa_private_key()
  let key = jwk.with_alg(key, jwk.Jwe(jwa.JweRsa(jwa.RsaOaepSha256)))
  let result =
    key_helpers.validate_key_algorithm_jwe(key, jwa.JweRsa(jwa.RsaOaepSha256))
  assert result == Ok(Nil)
}

pub fn validate_key_algorithm_jwe_mismatch_test() {
  let key = fixtures.rsa_private_key()
  let key = jwk.with_alg(key, jwk.Jwe(jwa.JweRsa(jwa.RsaOaepSha256)))
  let result =
    key_helpers.validate_key_algorithm_jwe(key, jwa.JweRsa(jwa.RsaOaepSha1))
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "key algorithm mismatch: key has RSA-OAEP-256, expected RSA-OAEP"
}

pub fn validate_key_algorithm_jwe_jws_on_jwe_key_test() {
  let key = fixtures.rsa_private_key()
  let key = jwk.with_alg(key, jwk.Jws(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256)))
  let result =
    key_helpers.validate_key_algorithm_jwe(key, jwa.JweRsa(jwa.RsaOaepSha256))
  let assert Error(gose.InvalidState(msg)) = result
  assert msg
    == "key algorithm mismatch: key has JWS algorithm, expected JWE algorithm"
}

pub fn validate_hmac_key_size_accepts_sufficient_key_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  assert key_helpers.validate_hmac_key_size(key, 32, "HS256") == Ok(Nil)
}

pub fn validate_hmac_key_size_rejects_undersized_key_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_hmac_key_size(key, 64, "HS512")
  assert msg == "HS512 requires key of at least 64 bytes, got 32"
}

pub fn validate_hmac_key_size_non_octet_key_test() {
  let key = fixtures.rsa_private_key()
  assert key_helpers.validate_hmac_key_size(key, 32, "HS256")
    == Error(gose.InvalidState("key is not an octet key"))
}

pub fn validate_key_for_jws_verification_happy_path_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  assert key_helpers.validate_key_for_jws_verification(
      jwa.JwsHmac(jwa.HmacSha256),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_for_jws_verification_wrong_key_type_test() {
  let key = fixtures.rsa_private_key()
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jws_verification(
      jwa.JwsHmac(jwa.HmacSha256),
      key,
    )
  assert msg == "algorithm HS256 incompatible with key type"
}

pub fn validate_key_for_jws_verification_wrong_use_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_use(key, jwk.Encrypting)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jws_verification(
      jwa.JwsHmac(jwa.HmacSha256),
      key,
    )
  assert msg == "key use is 'enc', cannot be used for verification"
}

pub fn validate_key_for_jws_verification_wrong_ops_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Sign])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jws_verification(
      jwa.JwsHmac(jwa.HmacSha256),
      key,
    )
  assert msg == "key_ops does not include 'verify' operation"
}

pub fn validate_key_for_jws_verification_wrong_alg_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha512)
  let key = jwk.with_alg(key, jwk.Jws(jwa.JwsHmac(jwa.HmacSha512)))
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jws_verification(
      jwa.JwsHmac(jwa.HmacSha256),
      key,
    )
  assert msg == "key algorithm mismatch: key has HS512, expected HS256"
}

pub fn validate_key_for_jwe_decryption_happy_path_test() {
  let key = fixtures.rsa_private_key()
  assert key_helpers.validate_key_for_jwe_decryption(
      jwa.JweRsa(jwa.RsaOaepSha256),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_for_jwe_decryption_wrong_use_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = jwk.with_key_use(key, jwk.Signing)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      jwa.JweRsa(jwa.RsaOaepSha256),
      key,
    )
  assert msg == "key use is 'sig', cannot be used for decryption"
}

pub fn validate_key_for_jwe_decryption_wrong_ops_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Encrypt])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      jwa.JweRsa(jwa.RsaOaepSha256),
      key,
    )
  assert msg == "key_ops does not include 'decrypt' or 'unwrapKey' operation"
}

pub fn validate_key_for_jwe_decryption_wrong_alg_test() {
  let key = fixtures.rsa_private_key()
  let key = jwk.with_alg(key, jwk.Jwe(jwa.JweRsa(jwa.RsaOaepSha1)))
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_decryption(
      jwa.JweRsa(jwa.RsaOaepSha256),
      key,
    )
  assert msg
    == "key algorithm mismatch: key has RSA-OAEP, expected RSA-OAEP-256"
}

pub fn validate_key_for_jwe_encryption_happy_path_test() {
  let key = fixtures.rsa_private_key()
  assert key_helpers.validate_key_for_jwe_encryption(
      jwa.JweRsa(jwa.RsaOaepSha256),
      key,
    )
    == Ok(Nil)
}

pub fn validate_key_for_jwe_encryption_wrong_use_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = jwk.with_key_use(key, jwk.Signing)
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      jwa.JweRsa(jwa.RsaOaepSha256),
      key,
    )
  assert msg == "key use is 'sig', cannot be used for encryption"
}

pub fn validate_key_for_jwe_encryption_wrong_ops_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Decrypt])
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      jwa.JweRsa(jwa.RsaOaepSha256),
      key,
    )
  assert msg == "key_ops does not include 'encrypt' or 'wrapKey' operation"
}

pub fn validate_key_for_jwe_encryption_wrong_alg_test() {
  let key = fixtures.rsa_private_key()
  let key = jwk.with_alg(key, jwk.Jwe(jwa.JweRsa(jwa.RsaOaepSha1)))
  let assert Error(gose.InvalidState(msg)) =
    key_helpers.validate_key_for_jwe_encryption(
      jwa.JweRsa(jwa.RsaOaepSha256),
      key,
    )
  assert msg
    == "key algorithm mismatch: key has RSA-OAEP, expected RSA-OAEP-256"
}
