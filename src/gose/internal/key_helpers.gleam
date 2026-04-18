//// Shared key validation and ordering helpers for JWK operations.

import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import gose
import gose/algorithm
import gose/key
import kryptos/ec

/// Order keys so that keys with a matching `kid` come first.
/// If no target kid is provided, keys are returned in their original order.
pub fn order_keys_by_kid(
  keys: List(key.Key(String)),
  target_kid target_kid: Option(String),
) -> List(key.Key(String)) {
  case target_kid {
    option.None -> keys
    option.Some(target) -> {
      let #(matching, others) =
        list.partition(keys, fn(key) { key.kid(key) == Ok(target) })
      list.append(matching, others)
    }
  }
}

/// Verify that the actual JWS algorithm matches the expected one.
/// Returns an error if there is a mismatch (algorithm pinning).
pub fn require_matching_signing_algorithm(
  expected: algorithm.SigningAlg,
  actual actual: algorithm.SigningAlg,
) -> Result(Nil, gose.GoseError) {
  case expected == actual {
    True -> Ok(Nil)
    False ->
      Error(gose.InvalidState(
        "algorithm mismatch: expected "
        <> string.inspect(expected)
        <> ", got "
        <> string.inspect(actual),
      ))
  }
}

pub fn require_matching_content_algorithm(
  expected: algorithm.ContentAlg,
  actual actual: algorithm.ContentAlg,
) -> Result(Nil, gose.GoseError) {
  case expected == actual {
    True -> Ok(Nil)
    False ->
      Error(gose.InvalidState(
        "algorithm mismatch: expected "
        <> string.inspect(expected)
        <> ", got "
        <> string.inspect(actual),
      ))
  }
}

/// Purpose of key usage - signing/verification, encryption/decryption,
/// or key agreement.
pub type KeyPurpose {
  /// Sign a JWS or derive a CEK for JWE
  ForSigning
  /// Verify a JWS signature
  ForVerification
  /// Encrypt content or wrap a CEK
  ForEncryption
  /// Decrypt content or unwrap a CEK
  ForDecryption
  /// ECDH key agreement (deriveKey/deriveBits)
  ForKeyAgreement
}

/// Validate that a key list is non-empty, then continue with the provided function.
///
/// Returns an error if the key list is empty, otherwise calls the continuation.
pub fn require_non_empty_keys(
  keys: List(key.Key(kid)),
  continue: fn() -> Result(a, gose.GoseError),
) -> Result(a, gose.GoseError) {
  case keys {
    [] -> Error(gose.InvalidState("at least one key required"))
    _ -> continue()
  }
}

/// Validate that an HMAC key meets the minimum size requirements for the algorithm.
pub fn validate_hmac_key_size(
  key: key.Key(kid),
  min_bytes min_bytes: Int,
  alg_name alg_name: String,
) -> Result(Nil, gose.GoseError) {
  case key.octet_key_size(key) {
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
pub fn validate_signing_key_type(
  alg: algorithm.SigningAlg,
  key key: key.Key(kid),
) -> Result(Nil, gose.GoseError) {
  let key_type = key.key_type(key)
  case alg, key_type {
    algorithm.Mac(algorithm.Hmac(hmac_alg)), key.OctKeyType ->
      validate_hmac_key_size(
        key,
        algorithm.hmac_alg_key_size(hmac_alg),
        string.inspect(alg),
      )

    algorithm.DigitalSignature(algorithm.RsaPkcs1(_)), key.RsaKeyType
    | algorithm.DigitalSignature(algorithm.RsaPss(_)), key.RsaKeyType
    -> Ok(Nil)

    algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      key.EcKeyType
    -> validate_ec_curve(key, ec.P256)
    algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP384)),
      key.EcKeyType
    -> validate_ec_curve(key, ec.P384)
    algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP521)),
      key.EcKeyType
    -> validate_ec_curve(key, ec.P521)
    algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaSecp256k1)),
      key.EcKeyType
    -> validate_ec_curve(key, ec.Secp256k1)

    algorithm.DigitalSignature(algorithm.Eddsa), key.OkpKeyType ->
      validate_eddsa_key(key)

    _, _ ->
      Error(gose.InvalidState(
        "algorithm " <> string.inspect(alg) <> " incompatible with key type",
      ))
  }
}

pub fn validate_jwe_key_type(
  alg: algorithm.KeyEncryptionAlg,
  key key: key.Key(kid),
) -> Result(Nil, gose.GoseError) {
  let key_type = key.key_type(key)
  case alg, key_type {
    algorithm.Direct, key.OctKeyType
    | algorithm.AesKeyWrap(_, _), key.OctKeyType
    | algorithm.ChaCha20KeyWrap(_), key.OctKeyType
    -> Ok(Nil)

    algorithm.RsaEncryption(_), key.RsaKeyType -> Ok(Nil)

    algorithm.EcdhEs(_), key.EcKeyType -> Ok(Nil)
    algorithm.EcdhEs(_), key.OkpKeyType -> validate_xdh_key(key)

    algorithm.Pbes2(_), _ ->
      Error(gose.InvalidState("use password_decryptor for PBES2 algorithms"))

    _, _ ->
      Error(gose.InvalidState(
        "algorithm " <> string.inspect(alg) <> " incompatible with key type",
      ))
  }
}

fn validate_ec_curve(
  key: key.Key(kid),
  expected: ec.Curve,
) -> Result(Nil, gose.GoseError) {
  case key.ec_curve(key) {
    Ok(actual) if actual == expected -> Ok(Nil)
    Ok(_) -> Error(gose.InvalidState("EC key curve does not match algorithm"))
    Error(_) -> Error(gose.InvalidState("could not determine EC key curve"))
  }
}

fn validate_eddsa_key(key: key.Key(kid)) -> Result(Nil, gose.GoseError) {
  case key.eddsa_curve(key) {
    Ok(_) -> Ok(Nil)
    Error(_) ->
      Error(gose.InvalidState(
        "EdDSA algorithm requires an EdDSA key (Ed25519/Ed448), not XDH",
      ))
  }
}

fn validate_xdh_key(key: key.Key(kid)) -> Result(Nil, gose.GoseError) {
  case key.xdh_curve(key) {
    Ok(_) -> Ok(Nil)
    Error(_) ->
      Error(gose.InvalidState(
        "ECDH-ES algorithm requires an EC or XDH key (X25519/X448), not EdDSA",
      ))
  }
}

/// Validate that a key's `alg` field matches the expected JWE algorithm.
///
/// If the key has no `alg` field set, validation passes (any algorithm allowed).
/// If the key has an `alg` field, it must match the expected algorithm.
pub fn validate_key_algorithm_jwe(
  key: key.Key(kid),
  expected expected: algorithm.KeyEncryptionAlg,
) -> Result(Nil, gose.GoseError) {
  case key.alg(key) {
    Error(Nil) -> Ok(Nil)
    Ok(key.KeyEncryptionAlg(alg)) if alg == expected -> Ok(Nil)
    Ok(key.KeyEncryptionAlg(alg)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has "
        <> string.inspect(alg)
        <> ", expected "
        <> string.inspect(expected),
      ))
    Ok(key.SigningAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has JWS algorithm, expected JWE algorithm",
      ))
    Ok(key.ContentAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has content algorithm, expected JWE algorithm",
      ))
  }
}

/// Validate that a key's `alg` field matches the expected JWS algorithm.
///
/// If the key has no `alg` field set, validation passes (any algorithm allowed).
/// If the key has an `alg` field, it must match the expected algorithm.
pub fn validate_key_algorithm_signing(
  key: key.Key(kid),
  expected expected: algorithm.SigningAlg,
) -> Result(Nil, gose.GoseError) {
  case key.alg(key) {
    Error(Nil) -> Ok(Nil)
    Ok(key.SigningAlg(alg)) if alg == expected -> Ok(Nil)
    Ok(key.SigningAlg(alg)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has "
        <> string.inspect(alg)
        <> ", expected "
        <> string.inspect(expected),
      ))
    Ok(key.KeyEncryptionAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has JWE algorithm, expected JWS algorithm",
      ))
    Ok(key.ContentAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has content algorithm, expected JWS algorithm",
      ))
  }
}

/// Validate that a key is suitable for JWS verification.
///
/// Checks key type compatibility, key use, key ops, and algorithm matching.
pub fn validate_key_for_signing_verification(
  alg: algorithm.SigningAlg,
  key key: key.Key(kid),
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(validate_signing_key_type(alg, key:))
  use _ <- result.try(validate_key_use(key, purpose: ForVerification))
  use _ <- result.try(validate_key_ops(key, purpose: ForVerification))
  validate_key_algorithm_signing(key, expected: alg)
}

/// Validate that a key is suitable for JWE decryption.
///
/// Checks key use, key ops, and algorithm matching.
pub fn validate_key_for_jwe_decryption(
  alg: algorithm.KeyEncryptionAlg,
  key key: key.Key(kid),
) -> Result(Nil, gose.GoseError) {
  let ops_purpose = jwe_key_ops_purpose(alg, ForDecryption)
  use _ <- result.try(validate_jwe_key_type(alg, key:))
  use _ <- result.try(validate_key_use(key, purpose: ops_purpose))
  use _ <- result.try(validate_key_ops(key, purpose: ops_purpose))
  validate_key_algorithm_jwe(key, alg)
}

/// Validate that a key is suitable for JWE encryption.
///
/// Checks key use, key ops, and algorithm matching.
pub fn validate_key_for_jwe_encryption(
  alg: algorithm.KeyEncryptionAlg,
  key key: key.Key(kid),
) -> Result(Nil, gose.GoseError) {
  let ops_purpose = jwe_key_ops_purpose(alg, ForEncryption)
  use _ <- result.try(validate_jwe_key_type(alg, key:))
  use _ <- result.try(validate_key_use(key, purpose: ops_purpose))
  use _ <- result.try(validate_key_ops(key, purpose: ops_purpose))
  validate_key_algorithm_jwe(key, alg)
}

fn jwe_key_ops_purpose(
  alg: algorithm.KeyEncryptionAlg,
  base_purpose: KeyPurpose,
) -> KeyPurpose {
  case alg {
    algorithm.EcdhEs(_) -> ForKeyAgreement
    _ -> base_purpose
  }
}

/// Validate that a key is compatible with a content encryption algorithm.
///
/// All content encryption algorithms require symmetric (octet) keys.
pub fn validate_content_key_type(
  alg: algorithm.ContentAlg,
  key key: key.Key(kid),
) -> Result(Nil, gose.GoseError) {
  case key.key_type(key) {
    key.OctKeyType -> Ok(Nil)
    _ ->
      Error(gose.InvalidState(
        "algorithm " <> string.inspect(alg) <> " incompatible with key type",
      ))
  }
}

/// Validate that a key's `alg` field matches the expected content encryption algorithm.
///
/// If the key has no `alg` field set, validation passes (any algorithm allowed).
/// If the key has an `alg` field, it must match the expected algorithm.
pub fn validate_key_algorithm_content(
  key: key.Key(kid),
  expected expected: algorithm.ContentAlg,
) -> Result(Nil, gose.GoseError) {
  case key.alg(key) {
    Error(Nil) -> Ok(Nil)
    Ok(key.ContentAlg(alg)) if alg == expected -> Ok(Nil)
    Ok(key.ContentAlg(alg)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has "
        <> string.inspect(alg)
        <> ", expected "
        <> string.inspect(expected),
      ))
    Ok(key.SigningAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has signing algorithm, expected content algorithm",
      ))
    Ok(key.KeyEncryptionAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has key encryption algorithm, expected content algorithm",
      ))
  }
}

/// Validate that a key is suitable for content encryption.
///
/// Checks key type compatibility, key use, key ops, and algorithm matching.
pub fn validate_key_for_content_encryption(
  alg: algorithm.ContentAlg,
  key key: key.Key(kid),
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(validate_content_key_type(alg, key:))
  use _ <- result.try(validate_key_use(key, purpose: ForEncryption))
  use _ <- result.try(validate_key_ops(key, purpose: ForEncryption))
  validate_key_algorithm_content(key, expected: alg)
}

/// Validate that a key is suitable for content decryption.
///
/// Checks key type compatibility, key use, key ops, and algorithm matching.
pub fn validate_key_for_content_decryption(
  alg: algorithm.ContentAlg,
  key key: key.Key(kid),
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(validate_content_key_type(alg, key:))
  use _ <- result.try(validate_key_use(key, purpose: ForDecryption))
  use _ <- result.try(validate_key_ops(key, purpose: ForDecryption))
  validate_key_algorithm_content(key, expected: alg)
}

/// Validate that a key's `key_ops` field permits the intended purpose.
/// Returns Ok(Nil) if validation passes, or an error if the key cannot be used.
pub fn validate_key_ops(
  key: key.Key(kid),
  purpose purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  case key.key_ops(key) {
    Error(Nil) -> Ok(Nil)
    Ok(ops) -> validate_ops_for_purpose(ops, purpose)
  }
}

fn validate_ops_for_purpose(
  ops: List(key.KeyOp),
  purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  let #(required_ops, error_msg) = case purpose {
    ForSigning -> #([key.Sign], "key_ops does not include 'sign' operation")
    ForVerification -> #(
      [key.Verify],
      "key_ops does not include 'verify' operation",
    )
    ForEncryption -> #(
      [key.Encrypt, key.WrapKey],
      "key_ops does not include 'encrypt' or 'wrapKey' operation",
    )
    ForDecryption -> #(
      [key.Decrypt, key.UnwrapKey],
      "key_ops does not include 'decrypt' or 'unwrapKey' operation",
    )
    ForKeyAgreement -> #(
      [key.DeriveKey, key.DeriveBits],
      "key_ops does not include 'deriveKey' or 'deriveBits' operation",
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
  key: key.Key(kid),
  purpose purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  case key.key_use(key) {
    Error(Nil) -> Ok(Nil)
    Ok(use_value) -> validate_use_value(use_value, purpose)
  }
}

fn validate_use_value(
  use_value: key.KeyUse,
  purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  case use_value, purpose {
    key.Signing, ForSigning | key.Signing, ForVerification -> Ok(Nil)
    key.Encrypting, ForEncryption | key.Encrypting, ForDecryption -> Ok(Nil)
    key.Encrypting, ForSigning ->
      Error(gose.InvalidState("key use is 'enc', cannot be used for signing"))
    key.Encrypting, ForVerification ->
      Error(gose.InvalidState(
        "key use is 'enc', cannot be used for verification",
      ))
    key.Encrypting, ForKeyAgreement -> Ok(Nil)
    key.Signing, ForEncryption ->
      Error(gose.InvalidState("key use is 'sig', cannot be used for encryption"))
    key.Signing, ForDecryption ->
      Error(gose.InvalidState("key use is 'sig', cannot be used for decryption"))
    key.Signing, ForKeyAgreement ->
      Error(gose.InvalidState(
        "key use is 'sig', cannot be used for key agreement",
      ))
  }
}
