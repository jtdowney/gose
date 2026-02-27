//// Shared key validation and ordering helpers for JWK operations.

import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gose
import gose/jwa
import gose/jwk
import kryptos/ec

/// Order keys so that keys with a matching `kid` come first.
/// If no target kid is provided, keys are returned in their original order.
pub fn order_keys_by_kid(
  keys: List(jwk.Jwk),
  target_kid: Option(String),
) -> List(jwk.Jwk) {
  case target_kid {
    option.None -> keys
    option.Some(target) -> {
      let #(matching, others) =
        list.partition(keys, fn(key) { jwk.kid(key) == Ok(target) })
      list.append(matching, others)
    }
  }
}

/// Verify that the actual JWS algorithm matches the expected one.
/// Returns an error if there is a mismatch (algorithm pinning).
pub fn require_matching_jws_algorithm(
  expected: jwa.JwsAlg,
  actual: jwa.JwsAlg,
) -> Result(Nil, gose.GoseError) {
  case expected == actual {
    True -> Ok(Nil)
    False ->
      Error(gose.InvalidState(
        "algorithm mismatch: expected "
        <> jwa.jws_alg_to_string(expected)
        <> ", got "
        <> jwa.jws_alg_to_string(actual),
      ))
  }
}

/// Purpose of key usage - signing/verification or encryption/decryption.
pub type KeyPurpose {
  /// Sign a JWS or derive a CEK for JWE
  ForSigning
  /// Verify a JWS signature
  ForVerification
  /// Encrypt content or wrap a CEK
  ForEncryption
  /// Decrypt content or unwrap a CEK
  ForDecryption
}

/// Validate that a key list is non-empty, then continue with the provided function.
///
/// Returns an error if the key list is empty, otherwise calls the continuation.
pub fn require_non_empty_keys(
  keys: List(jwk.Jwk),
  continue: fn() -> Result(a, gose.GoseError),
) -> Result(a, gose.GoseError) {
  case keys {
    [] -> Error(gose.InvalidState("at least one key required"))
    _ -> continue()
  }
}

/// Validate that an HMAC key meets the minimum size requirements for the algorithm.
pub fn validate_hmac_key_size(
  key: jwk.Jwk,
  min_bytes: Int,
  alg_name: String,
) -> Result(Nil, gose.GoseError) {
  case jwk.octet_key_size(key) {
    Ok(size) if size < min_bytes ->
      Error(gose.InvalidState(
        alg_name
        <> " requires key of at least "
        <> int.to_string(min_bytes)
        <> " bytes, got "
        <> int.to_string(size),
      ))
    Ok(_) -> Ok(Nil)
    Error(err) -> Error(err)
  }
}

/// Validate that a key is compatible with a JWS algorithm.
///
/// Checks:
/// - Key type matches algorithm requirements (e.g., HMAC needs octet key)
/// - HMAC keys meet minimum size requirements
/// - EC keys use the correct curve for the algorithm
/// - EdDSA keys are signing keys (Ed25519/Ed448), not key agreement (X25519/X448)
pub fn validate_jws_key_type(
  alg: jwa.JwsAlg,
  key: jwk.Jwk,
) -> Result(Nil, gose.GoseError) {
  let key_type = jwk.key_type(key)
  case alg, key_type {
    jwa.JwsHmac(hmac_alg), jwk.OctKeyType ->
      validate_hmac_key_size(
        key,
        jwa.hmac_alg_octet_key_size(hmac_alg),
        jwa.jws_alg_to_string(alg),
      )

    jwa.JwsRsaPkcs1(_), jwk.RsaKeyType | jwa.JwsRsaPss(_), jwk.RsaKeyType ->
      Ok(Nil)

    jwa.JwsEcdsa(jwa.EcdsaP256), jwk.EcKeyType ->
      validate_ec_curve(key, ec.P256)
    jwa.JwsEcdsa(jwa.EcdsaP384), jwk.EcKeyType ->
      validate_ec_curve(key, ec.P384)
    jwa.JwsEcdsa(jwa.EcdsaP521), jwk.EcKeyType ->
      validate_ec_curve(key, ec.P521)
    jwa.JwsEcdsa(jwa.EcdsaSecp256k1), jwk.EcKeyType ->
      validate_ec_curve(key, ec.Secp256k1)

    jwa.JwsEddsa, jwk.OkpKeyType -> validate_eddsa_key(key)

    _, _ ->
      Error(gose.InvalidState(
        "algorithm "
        <> jwa.jws_alg_to_string(alg)
        <> " incompatible with key type",
      ))
  }
}

fn validate_ec_curve(
  key: jwk.Jwk,
  expected: ec.Curve,
) -> Result(Nil, gose.GoseError) {
  case jwk.ec_curve(key) {
    Ok(actual) if actual == expected -> Ok(Nil)
    Ok(_) -> Error(gose.InvalidState("EC key curve does not match algorithm"))
    Error(_) -> Error(gose.InvalidState("could not determine EC key curve"))
  }
}

fn validate_eddsa_key(key: jwk.Jwk) -> Result(Nil, gose.GoseError) {
  case jwk.eddsa_curve(key) {
    Ok(_) -> Ok(Nil)
    Error(_) ->
      Error(gose.InvalidState(
        "EdDSA algorithm requires an EdDSA key (Ed25519/Ed448), not XDH",
      ))
  }
}

/// Validate that a key's `alg` field matches the expected JWE algorithm.
///
/// If the key has no `alg` field set, validation passes (any algorithm allowed).
/// If the key has an `alg` field, it must match the expected algorithm.
pub fn validate_key_algorithm_jwe(
  key: jwk.Jwk,
  expected: jwa.JweAlg,
) -> Result(Nil, gose.GoseError) {
  case jwk.alg(key) {
    Error(Nil) -> Ok(Nil)
    Ok(jwk.Jwe(alg)) if alg == expected -> Ok(Nil)
    Ok(jwk.Jwe(alg)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has "
        <> jwa.jwe_alg_to_string(alg)
        <> ", expected "
        <> jwa.jwe_alg_to_string(expected),
      ))
    Ok(jwk.Jws(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has JWS algorithm, expected JWE algorithm",
      ))
  }
}

/// Validate that a key's `alg` field matches the expected JWS algorithm.
///
/// If the key has no `alg` field set, validation passes (any algorithm allowed).
/// If the key has an `alg` field, it must match the expected algorithm.
pub fn validate_key_algorithm_jws(
  key: jwk.Jwk,
  expected: jwa.JwsAlg,
) -> Result(Nil, gose.GoseError) {
  case jwk.alg(key) {
    Error(Nil) -> Ok(Nil)
    Ok(jwk.Jws(alg)) if alg == expected -> Ok(Nil)
    Ok(jwk.Jws(alg)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has "
        <> jwa.jws_alg_to_string(alg)
        <> ", expected "
        <> jwa.jws_alg_to_string(expected),
      ))
    Ok(jwk.Jwe(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has JWE algorithm, expected JWS algorithm",
      ))
  }
}

/// Validate that a key is suitable for JWS verification.
///
/// Checks key type compatibility, key use, key ops, and algorithm matching.
pub fn validate_key_for_jws_verification(
  alg: jwa.JwsAlg,
  key: jwk.Jwk,
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(validate_jws_key_type(alg, key))
  use _ <- result.try(validate_key_use(key, ForVerification))
  use _ <- result.try(validate_key_ops(key, ForVerification))
  validate_key_algorithm_jws(key, alg)
}

/// Validate that a key is suitable for JWE decryption.
///
/// Checks key use, key ops, and algorithm matching.
pub fn validate_key_for_jwe_decryption(
  alg: jwa.JweAlg,
  key: jwk.Jwk,
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(validate_key_use(key, ForDecryption))
  use _ <- result.try(validate_key_ops(key, ForDecryption))
  validate_key_algorithm_jwe(key, alg)
}

/// Validate that a key is suitable for JWE encryption.
///
/// Checks key use, key ops, and algorithm matching.
pub fn validate_key_for_jwe_encryption(
  alg: jwa.JweAlg,
  key: jwk.Jwk,
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(validate_key_use(key, ForEncryption))
  use _ <- result.try(validate_key_ops(key, ForEncryption))
  validate_key_algorithm_jwe(key, alg)
}

/// Validate that a key's `key_ops` field permits the intended purpose.
/// Returns Ok(Nil) if validation passes, or an error if the key cannot be used.
pub fn validate_key_ops(
  key: jwk.Jwk,
  purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  case jwk.key_ops(key) {
    Error(Nil) -> Ok(Nil)
    Ok(ops) -> validate_ops_for_purpose(ops, purpose)
  }
}

fn validate_ops_for_purpose(
  ops: List(jwk.KeyOp),
  purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  let #(required_ops, error_msg) = case purpose {
    ForSigning -> #([jwk.Sign], "key_ops does not include 'sign' operation")
    ForVerification -> #(
      [jwk.Verify],
      "key_ops does not include 'verify' operation",
    )
    ForEncryption -> #(
      [jwk.Encrypt, jwk.WrapKey],
      "key_ops does not include 'encrypt' or 'wrapKey' operation",
    )
    ForDecryption -> #(
      [jwk.Decrypt, jwk.UnwrapKey],
      "key_ops does not include 'decrypt' or 'unwrapKey' operation",
    )
  }

  case list.any(required_ops, list.contains(ops, _)) {
    True -> Ok(Nil)
    False -> Error(gose.InvalidState(error_msg))
  }
}

/// Validate that a key's `use` field permits the intended purpose.
/// Returns Ok(Nil) if validation passes, or an error if the key cannot be used.
pub fn validate_key_use(
  key: jwk.Jwk,
  purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  case jwk.key_use(key) {
    Error(Nil) -> Ok(Nil)
    Ok(use_value) -> validate_use_value(use_value, purpose)
  }
}

fn validate_use_value(
  use_value: jwk.KeyUse,
  purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  case use_value, purpose {
    jwk.Signing, ForSigning | jwk.Signing, ForVerification -> Ok(Nil)
    jwk.Encrypting, ForEncryption | jwk.Encrypting, ForDecryption -> Ok(Nil)
    jwk.Encrypting, ForSigning ->
      Error(gose.InvalidState("key use is 'enc', cannot be used for signing"))
    jwk.Encrypting, ForVerification ->
      Error(gose.InvalidState(
        "key use is 'enc', cannot be used for verification",
      ))
    jwk.Signing, ForEncryption ->
      Error(gose.InvalidState("key use is 'sig', cannot be used for encryption"))
    jwk.Signing, ForDecryption ->
      Error(gose.InvalidState("key use is 'sig', cannot be used for decryption"))
  }
}
