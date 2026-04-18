//// Shared key validation and ordering helpers for JWK operations.

import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import gose
import kryptos/ec

/// Order keys so that keys with a matching `kid` come first.
/// If no target kid is provided, keys are returned in their original order.
pub fn order_keys_by_kid(
  keys: List(gose.Key(String)),
  target_kid target_kid: Option(String),
) -> List(gose.Key(String)) {
  case target_kid {
    option.None -> keys
    option.Some(target) -> {
      let #(matching, others) =
        list.partition(keys, fn(key) { gose.kid(key) == Ok(target) })
      list.append(matching, others)
    }
  }
}

/// Verify that the actual JWS algorithm matches the expected one.
/// Returns an error if there is a mismatch (algorithm pinning).
pub fn require_matching_signing_algorithm(
  expected: gose.SigningAlg,
  actual actual: gose.SigningAlg,
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
  expected: gose.ContentAlg,
  actual actual: gose.ContentAlg,
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
  keys: List(gose.Key(kid)),
  continue: fn() -> Result(a, gose.GoseError),
) -> Result(a, gose.GoseError) {
  case keys {
    [] -> Error(gose.InvalidState("at least one key required"))
    _ -> continue()
  }
}

/// Validate that an HMAC key meets the minimum size requirements for the algorithm.
pub fn validate_hmac_key_size(
  key: gose.Key(kid),
  min_bytes min_bytes: Int,
  alg_name alg_name: String,
) -> Result(Nil, gose.GoseError) {
  case gose.octet_key_size(key) {
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
  alg: gose.SigningAlg,
  key key: gose.Key(kid),
) -> Result(Nil, gose.GoseError) {
  let key_type = gose.key_type(key)
  case alg, key_type {
    gose.Mac(gose.Hmac(hmac_alg)), gose.OctKeyType ->
      validate_hmac_key_size(
        key,
        gose.hmac_alg_key_size(hmac_alg),
        string.inspect(alg),
      )

    gose.DigitalSignature(gose.RsaPkcs1(_)), gose.RsaKeyType
    | gose.DigitalSignature(gose.RsaPss(_)), gose.RsaKeyType
    -> Ok(Nil)

    gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)), gose.EcKeyType ->
      validate_ec_curve(key, ec.P256)
    gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP384)), gose.EcKeyType ->
      validate_ec_curve(key, ec.P384)
    gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP521)), gose.EcKeyType ->
      validate_ec_curve(key, ec.P521)
    gose.DigitalSignature(gose.Ecdsa(gose.EcdsaSecp256k1)), gose.EcKeyType ->
      validate_ec_curve(key, ec.Secp256k1)

    gose.DigitalSignature(gose.Eddsa), gose.OkpKeyType ->
      validate_eddsa_key(key)

    _, _ ->
      Error(gose.InvalidState(
        "algorithm " <> string.inspect(alg) <> " incompatible with key type",
      ))
  }
}

pub fn validate_jwe_key_type(
  alg: gose.KeyEncryptionAlg,
  key key: gose.Key(kid),
) -> Result(Nil, gose.GoseError) {
  let key_type = gose.key_type(key)
  case alg, key_type {
    gose.Direct, gose.OctKeyType
    | gose.AesKeyWrap(_, _), gose.OctKeyType
    | gose.ChaCha20KeyWrap(_), gose.OctKeyType
    -> Ok(Nil)

    gose.RsaEncryption(_), gose.RsaKeyType -> Ok(Nil)

    gose.EcdhEs(_), gose.EcKeyType -> Ok(Nil)
    gose.EcdhEs(_), gose.OkpKeyType -> validate_xdh_key(key)

    gose.Pbes2(_), _ ->
      Error(gose.InvalidState("use password_decryptor for PBES2 algorithms"))

    _, _ ->
      Error(gose.InvalidState(
        "algorithm " <> string.inspect(alg) <> " incompatible with key type",
      ))
  }
}

fn validate_ec_curve(
  key: gose.Key(kid),
  expected: ec.Curve,
) -> Result(Nil, gose.GoseError) {
  case gose.ec_curve(key) {
    Ok(actual) if actual == expected -> Ok(Nil)
    Ok(_) -> Error(gose.InvalidState("EC key curve does not match algorithm"))
    Error(_) -> Error(gose.InvalidState("could not determine EC key curve"))
  }
}

fn validate_eddsa_key(key: gose.Key(kid)) -> Result(Nil, gose.GoseError) {
  case gose.eddsa_curve(key) {
    Ok(_) -> Ok(Nil)
    Error(_) ->
      Error(gose.InvalidState(
        "EdDSA algorithm requires an EdDSA key (Ed25519/Ed448), not XDH",
      ))
  }
}

fn validate_xdh_key(key: gose.Key(kid)) -> Result(Nil, gose.GoseError) {
  case gose.xdh_curve(key) {
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
  key: gose.Key(kid),
  expected expected: gose.KeyEncryptionAlg,
) -> Result(Nil, gose.GoseError) {
  case gose.alg(key) {
    Error(Nil) -> Ok(Nil)
    Ok(gose.KeyEncryptionAlg(alg)) if alg == expected -> Ok(Nil)
    Ok(gose.KeyEncryptionAlg(alg)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has "
        <> string.inspect(alg)
        <> ", expected "
        <> string.inspect(expected),
      ))
    Ok(gose.SigningAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has JWS algorithm, expected JWE algorithm",
      ))
    Ok(gose.ContentAlg(_)) ->
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
  key: gose.Key(kid),
  expected expected: gose.SigningAlg,
) -> Result(Nil, gose.GoseError) {
  case gose.alg(key) {
    Error(Nil) -> Ok(Nil)
    Ok(gose.SigningAlg(alg)) if alg == expected -> Ok(Nil)
    Ok(gose.SigningAlg(alg)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has "
        <> string.inspect(alg)
        <> ", expected "
        <> string.inspect(expected),
      ))
    Ok(gose.KeyEncryptionAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has JWE algorithm, expected JWS algorithm",
      ))
    Ok(gose.ContentAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has content algorithm, expected JWS algorithm",
      ))
  }
}

/// Validate that a key is suitable for JWS verification.
///
/// Checks key type compatibility, key use, key ops, and algorithm matching.
pub fn validate_key_for_signing_verification(
  alg: gose.SigningAlg,
  key key: gose.Key(kid),
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
  alg: gose.KeyEncryptionAlg,
  key key: gose.Key(kid),
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
  alg: gose.KeyEncryptionAlg,
  key key: gose.Key(kid),
) -> Result(Nil, gose.GoseError) {
  let ops_purpose = jwe_key_ops_purpose(alg, ForEncryption)
  use _ <- result.try(validate_jwe_key_type(alg, key:))
  use _ <- result.try(validate_key_use(key, purpose: ops_purpose))
  use _ <- result.try(validate_key_ops(key, purpose: ops_purpose))
  validate_key_algorithm_jwe(key, alg)
}

fn jwe_key_ops_purpose(
  alg: gose.KeyEncryptionAlg,
  base_purpose: KeyPurpose,
) -> KeyPurpose {
  case alg {
    gose.EcdhEs(_) -> ForKeyAgreement
    _ -> base_purpose
  }
}

/// Validate that a key is compatible with a content encryption algorithm.
///
/// All content encryption algorithms require symmetric (octet) keys.
pub fn validate_content_key_type(
  alg: gose.ContentAlg,
  key key: gose.Key(kid),
) -> Result(Nil, gose.GoseError) {
  case gose.key_type(key) {
    gose.OctKeyType -> Ok(Nil)
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
  key: gose.Key(kid),
  expected expected: gose.ContentAlg,
) -> Result(Nil, gose.GoseError) {
  case gose.alg(key) {
    Error(Nil) -> Ok(Nil)
    Ok(gose.ContentAlg(alg)) if alg == expected -> Ok(Nil)
    Ok(gose.ContentAlg(alg)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has "
        <> string.inspect(alg)
        <> ", expected "
        <> string.inspect(expected),
      ))
    Ok(gose.SigningAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has signing algorithm, expected content algorithm",
      ))
    Ok(gose.KeyEncryptionAlg(_)) ->
      Error(gose.InvalidState(
        "key algorithm mismatch: key has key encryption algorithm, expected content algorithm",
      ))
  }
}

/// Validate that a key is suitable for content encryption.
///
/// Checks key type compatibility, key use, key ops, and algorithm matching.
pub fn validate_key_for_content_encryption(
  alg: gose.ContentAlg,
  key key: gose.Key(kid),
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
  alg: gose.ContentAlg,
  key key: gose.Key(kid),
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(validate_content_key_type(alg, key:))
  use _ <- result.try(validate_key_use(key, purpose: ForDecryption))
  use _ <- result.try(validate_key_ops(key, purpose: ForDecryption))
  validate_key_algorithm_content(key, expected: alg)
}

/// Validate that a key's `key_ops` field permits the intended purpose.
/// Returns Ok(Nil) if validation passes, or an error if the key cannot be used.
pub fn validate_key_ops(
  key: gose.Key(kid),
  purpose purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  case gose.key_ops(key) {
    Error(Nil) -> Ok(Nil)
    Ok(ops) -> validate_ops_for_purpose(ops, purpose)
  }
}

fn validate_ops_for_purpose(
  ops: List(gose.KeyOp),
  purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  let #(required_ops, error_msg) = case purpose {
    ForSigning -> #([gose.Sign], "key_ops does not include 'sign' operation")
    ForVerification -> #(
      [gose.Verify],
      "key_ops does not include 'verify' operation",
    )
    ForEncryption -> #(
      [gose.Encrypt, gose.WrapKey],
      "key_ops does not include 'encrypt' or 'wrapKey' operation",
    )
    ForDecryption -> #(
      [gose.Decrypt, gose.UnwrapKey],
      "key_ops does not include 'decrypt' or 'unwrapKey' operation",
    )
    ForKeyAgreement -> #(
      [gose.DeriveKey, gose.DeriveBits],
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
  key: gose.Key(kid),
  purpose purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  case gose.key_use(key) {
    Error(Nil) -> Ok(Nil)
    Ok(use_value) -> validate_use_value(use_value, purpose)
  }
}

fn validate_use_value(
  use_value: gose.KeyUse,
  purpose: KeyPurpose,
) -> Result(Nil, gose.GoseError) {
  case use_value, purpose {
    gose.Signing, ForSigning | gose.Signing, ForVerification -> Ok(Nil)
    gose.Encrypting, ForEncryption | gose.Encrypting, ForDecryption -> Ok(Nil)
    gose.Encrypting, ForSigning ->
      Error(gose.InvalidState("key use is 'enc', cannot be used for signing"))
    gose.Encrypting, ForVerification ->
      Error(gose.InvalidState(
        "key use is 'enc', cannot be used for verification",
      ))
    gose.Encrypting, ForKeyAgreement -> Ok(Nil)
    gose.Signing, ForEncryption ->
      Error(gose.InvalidState("key use is 'sig', cannot be used for encryption"))
    gose.Signing, ForDecryption ->
      Error(gose.InvalidState("key use is 'sig', cannot be used for decryption"))
    gose.Signing, ForKeyAgreement ->
      Error(gose.InvalidState(
        "key use is 'sig', cannot be used for key agreement",
      ))
  }
}
