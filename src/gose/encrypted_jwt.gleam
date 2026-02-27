//// Encrypted JWT (JWE-based) - [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)
////
//// This module provides encrypted JWT functionality built on top of JWE.
//// Encrypted JWTs protect the claims payload through encryption rather than
//// just signing, ensuring confidentiality in addition to integrity.
////
//// Use `peek_headers()` to inspect a token's headers without decrypting.
//// Use `decrypt_and_validate()` to
//// decrypt and validate, producing a `EncryptedJwt` whose claims can be
//// trusted.
////
//// ## Example
////
//// ```gleam
//// import gleam/dynamic/decode
//// import gleam/time/duration
//// import gleam/time/timestamp
//// import gose/encrypted_jwt
//// import gose/jwa
//// import gose/jwk
//// import gose/jwt
////
//// let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
//// let now = timestamp.system_time()
////
//// // Create claims and encrypt
//// let claims = jwt.claims()
////   |> jwt.with_subject("user123")
////   |> jwt.with_issuer("my-app")
////   |> jwt.with_expiration(timestamp.add(now, duration.hours(1)))
////
//// let assert Ok(encrypted) = encrypted_jwt.encrypt_with_key(
////   claims, jwa.JweDirect, jwa.AesGcm(jwa.Aes256), key)
//// let token = encrypted_jwt.serialize(encrypted)
////
//// // Decrypt and validate using Decryptor (enforces algorithm pinning)
//// let assert Ok(decryptor) = encrypted_jwt.key_decryptor(
////   jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key], jwt.default_validation())
//// let assert Ok(verified) = encrypted_jwt.decrypt_and_validate(decryptor, token, now)
////
//// // Decode verified claims
//// let decoder = decode.field("sub", decode.string, decode.success)
//// let assert Ok(subject) = encrypted_jwt.decode(verified, decoder)
//// ```

import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import gose
import gose/internal/key_helpers
import gose/jwa
import gose/jwe
import gose/jwk
import gose/jwt

/// A JWT whose plaintext claims are available and have been validated.
/// This type is produced by `decrypt_and_validate()` after successful
/// decryption and claim verification.
pub opaque type EncryptedJwt {
  EncryptedJwt(
    alg: jwa.JweAlg,
    enc: jwa.Enc,
    kid: Option(String),
    claims: jwt.Claims,
    claims_json: BitArray,
    token: String,
  )
}

/// A decryptor that pins the expected algorithms and validates keys.
///
/// Create with `key_decryptor()` or `password_decryptor()`. The decryptor
/// validates that:
/// - Token's `alg` header matches the expected key encryption algorithm
/// - Token's `enc` header matches the expected content encryption algorithm
/// - Each key's `use` field (if set) is `Encrypting`
/// - Each key's `key_ops` field (if set) includes `Decrypt` or `UnwrapKey`
pub opaque type Decryptor {
  KeyDecryptor(
    alg: jwa.JweAlg,
    enc: jwa.Enc,
    keys: List(jwk.Jwk),
    options: jwt.JwtValidationOptions,
  )
  PasswordDecryptor(
    alg: jwa.Pbes2Alg,
    enc: jwa.Enc,
    password: String,
    options: jwt.JwtValidationOptions,
  )
}

fn validate_decryption_keys(
  alg: jwa.JweAlg,
  keys: List(jwk.Jwk),
) -> Result(Nil, gose.GoseError) {
  use <- key_helpers.require_non_empty_keys(keys)
  list.try_each(keys, key_helpers.validate_key_for_jwe_decryption(alg, _))
}

/// Create a key-based decryptor for symmetric (dir, AES-KW, AES-GCM-KW) or
/// asymmetric (RSA-OAEP, ECDH-ES) algorithms.
///
/// The decryptor pins the expected algorithms. Tokens with different
/// algorithms will be rejected.
///
/// ## Parameters
///
/// - `alg` - The expected key encryption algorithm.
/// - `enc` - The expected content encryption algorithm.
/// - `keys` - One or more keys for decryption.
/// - `options` - Validation options for JWT claims.
///
/// ## Returns
///
/// `Ok(Decryptor)` configured and ready for use with
/// `decrypt_and_validate`, or `Error(JoseError(_))` if the key list is
/// empty, any key's `use` field is set but not `Encrypting`, or any key's
/// `key_ops` doesn't include `Decrypt` or `UnwrapKey`.
pub fn key_decryptor(
  alg: jwa.JweAlg,
  enc: jwa.Enc,
  keys keys: List(jwk.Jwk),
  options options: jwt.JwtValidationOptions,
) -> Result(Decryptor, jwt.JwtError) {
  validate_decryption_keys(alg, keys)
  |> result.replace(KeyDecryptor(alg:, enc:, keys:, options:))
  |> result.map_error(jwt.JoseError)
}

/// Create a password-based decryptor for PBES2 algorithms.
///
/// The decryptor pins the expected algorithms. Tokens with different
/// algorithms will be rejected.
///
/// ## Parameters
///
/// - `alg` - The expected PBES2 algorithm.
/// - `enc` - The expected content encryption algorithm.
/// - `password` - The password for key derivation.
/// - `options` - Validation options for JWT claims.
///
/// ## Returns
///
/// A `Decryptor` configured for use with `decrypt_and_validate`.
pub fn password_decryptor(
  alg: jwa.Pbes2Alg,
  enc: jwa.Enc,
  password password: String,
  options options: jwt.JwtValidationOptions,
) -> Decryptor {
  PasswordDecryptor(alg:, enc:, password:, options:)
}

/// Encrypt claims using a key-based algorithm.
///
/// Supports all key-based JWE algorithms: direct symmetric (dir), AES Key Wrap,
/// AES-GCM Key Wrap, RSA-OAEP, and ECDH-ES. PBES2 password-based algorithms
/// return an error — use `encrypt_with_password` instead.
///
/// Sets `typ: "JWT"` in the header. If the encryption key has a `kid`, it is
/// included in the JWE header.
///
/// ## Parameters
///
/// - `claims` - The JWT claims to encrypt.
/// - `alg` - The key encryption algorithm.
/// - `enc` - The content encryption algorithm.
/// - `key` - The encryption key.
///
/// ## Returns
///
/// `Ok(EncryptedJwt)` with the encrypted JWT ready for
/// serialization, or `Error(JoseError(_))` if key validation or encryption
/// fails.
pub fn encrypt_with_key(
  claims: jwt.Claims,
  alg: jwa.JweAlg,
  enc: jwa.Enc,
  key key: jwk.Jwk,
) -> Result(EncryptedJwt, jwt.JwtError) {
  let kid = option.from_result(jwk.kid(key))
  do_encrypt_with_key(claims, alg, enc, key, kid)
  |> result.map_error(jwt.JoseError)
}

fn do_encrypt_with_key(
  claims: jwt.Claims,
  alg: jwa.JweAlg,
  enc: jwa.Enc,
  key: jwk.Jwk,
  kid: Option(String),
) -> Result(EncryptedJwt, gose.GoseError) {
  let claims_json = claims_to_plaintext(claims)
  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(alg, key))
  jwe.encrypt_to_compact(alg, enc, claims_json, key, kid, Some("JWT"), None)
  |> result.map(fn(pair) {
    let #(token, jwe_alg) = pair
    EncryptedJwt(alg: jwe_alg, enc:, kid:, claims:, claims_json:, token:)
  })
}

/// Encrypt claims using PBES2 password-based encryption.
///
/// Sets `typ: "JWT"` in the header.
///
/// ## Parameters
///
/// - `claims` - The JWT claims to encrypt.
/// - `alg` - The PBES2 algorithm.
/// - `enc` - The content encryption algorithm.
/// - `password` - The password for key derivation.
/// - `kid` - Optional key ID to include in the header.
///
/// ## Returns
///
/// `Ok(EncryptedJwt)` with the encrypted JWT ready for
/// serialization, or `Error(JoseError(_))` if encryption fails.
pub fn encrypt_with_password(
  claims: jwt.Claims,
  alg: jwa.Pbes2Alg,
  enc: jwa.Enc,
  password password: String,
  kid kid: Option(String),
) -> Result(EncryptedJwt, jwt.JwtError) {
  do_encrypt_with_password(claims, alg, enc, password, kid)
  |> result.map_error(jwt.JoseError)
}

fn do_encrypt_with_password(
  claims: jwt.Claims,
  alg: jwa.Pbes2Alg,
  enc: jwa.Enc,
  password: String,
  kid: Option(String),
) -> Result(EncryptedJwt, gose.GoseError) {
  let claims_json = claims_to_plaintext(claims)
  let unencrypted =
    jwe.new_pbes2(alg, enc)
    |> jwe.with_typ("JWT")
  let unencrypted = case kid {
    Some(k) -> jwe.with_kid(unencrypted, k)
    None -> unencrypted
  }
  use encrypted <- result.try(jwe.encrypt_with_password(
    unencrypted,
    password,
    claims_json,
  ))

  jwe.serialize_compact(encrypted)
  |> result.map(fn(token) {
    EncryptedJwt(
      alg: jwe.alg(encrypted),
      enc:,
      kid:,
      claims:,
      claims_json:,
      token:,
    )
  })
}

fn claims_to_plaintext(claims: jwt.Claims) -> BitArray {
  jwt.claims_to_json_string(claims)
  |> bit_array.from_string
}

/// Serialize a decrypted encrypted JWT to compact format.
///
/// ## Parameters
///
/// - `jwt` - A `EncryptedJwt` from `encrypt_with_key`,
///   `encrypt_with_password`, or `decrypt_and_validate`.
///
/// ## Returns
///
/// The JWE compact serialization string.
pub fn serialize(jwt: EncryptedJwt) -> String {
  jwt.token
}

/// Header fields from an encrypted JWT token, extracted without decrypting.
pub type PeekHeaders {
  PeekHeaders(alg: jwa.JweAlg, enc: jwa.Enc, kid: Option(String))
}

/// Peek at the header fields from a token without decrypting.
///
/// ## Parameters
///
/// - `token` - The JWE compact serialization string.
///
/// ## Returns
///
/// `Ok(PeekHeaders)` with the algorithm, encryption, and optional key ID
/// from the header, or `Error(MalformedToken(_))` if the token cannot be
/// parsed.
pub fn peek_headers(token: String) -> Result(PeekHeaders, jwt.JwtError) {
  parse_jwe(token)
  |> result.map(fn(parsed_jwe) {
    PeekHeaders(
      alg: jwe.alg(parsed_jwe),
      enc: jwe.enc(parsed_jwe),
      kid: option.from_result(jwe.kid(parsed_jwe)),
    )
  })
}

fn parse_jwe(
  token: String,
) -> Result(jwe.Jwe(jwe.Encrypted, Nil, jwe.Parsed), jwt.JwtError) {
  jwe.parse_compact(token)
  |> result.map_error(jwt.gose_error_to_malformed_token_error)
}

/// Decrypt an encrypted JWT, skipping all claim validation.
///
/// **Warning:** This skips expiration, not-before, issuer, and audience checks.
/// Use only when you have a legitimate reason to bypass validation, such as
/// inspecting claims before deciding on validation policy.
///
/// Still enforces algorithm pinning for security. **Note:** `kid_policy` only
/// applies to key-based decryptors, not password-based decryptors.
///
/// ## Parameters
///
/// - `decryptor` - A `Decryptor` created by `key_decryptor` or
///   `password_decryptor`.
/// - `token` - The JWE compact serialization string.
///
/// ## Returns
///
/// `Ok(EncryptedJwt)` with the decrypted JWT and accessible
/// claims, `Error(JweAlgorithmMismatch(_))` if the token's algorithms
/// don't match, or `Error(DecryptionFailed(_))` if decryption fails.
pub fn dangerously_decrypt_and_skip_validation(
  decryptor: Decryptor,
  token: String,
) -> Result(EncryptedJwt, jwt.JwtError) {
  use #(plaintext, actual_alg, actual_enc, kid) <- result.try(decrypt_token(
    decryptor,
    token,
  ))
  parse_plaintext_claims(plaintext)
  |> result.map(fn(claims) {
    EncryptedJwt(
      alg: actual_alg,
      enc: actual_enc,
      kid:,
      claims:,
      claims_json: plaintext,
      token:,
    )
  })
}

/// Decrypt an encrypted JWT and validate its claims using a Decryptor.
///
/// Checks:
/// 1. Token's `alg` and `enc` headers match the decryptor's expected algorithms
/// 2. Decryption succeeds with one of the decryptor's keys
/// 3. Claims pass validation (exp, nbf, iss, aud per options)
///
/// When multiple keys are configured:
/// - Keys with matching `kid` are tried first (if token has `kid` header)
/// - `kid_policy` controls kid header enforcement (see `KidPolicy` type)
/// - With `NoKidRequirement`, all keys are tried with matching keys prioritized
///
/// ## Parameters
///
/// - `decryptor` - A `Decryptor` created by `key_decryptor` or
///   `password_decryptor`.
/// - `token` - The JWE compact serialization string.
/// - `now` - The current timestamp for time-based claim validation.
///
/// ## Returns
///
/// `Ok(EncryptedJwt)` with the decrypted and validated JWT,
/// `Error(JweAlgorithmMismatch(_))` if the token's algorithms don't match
/// the decryptor's expected algorithms, `Error(DecryptionFailed(_))` if
/// decryption fails, or a claim validation error (`TokenExpired`,
/// `TokenNotYetValid`, etc.) if claim validation fails.
pub fn decrypt_and_validate(
  decryptor: Decryptor,
  token: String,
  now now: Timestamp,
) -> Result(EncryptedJwt, jwt.JwtError) {
  use #(plaintext, actual_alg, actual_enc, kid) <- result.try(decrypt_token(
    decryptor,
    token,
  ))
  use claims <- result.try(parse_plaintext_claims(plaintext))
  let options = decryptor_options(decryptor)
  jwt.validate_claims(claims, now, options)
  |> result.replace(EncryptedJwt(
    alg: actual_alg,
    enc: actual_enc,
    kid:,
    claims:,
    claims_json: plaintext,
    token:,
  ))
}

/// Decode an encrypted JWT's claims using a custom decoder.
///
/// This allows extracting claims directly into your own types using
/// `gleam/dynamic/decode`. The decoder receives the raw claims JSON.
///
/// ## Parameters
///
/// - `jwt` - A verified (decrypted) encrypted JWT.
/// - `decoder` - A `gleam/dynamic/decode` decoder for the claims.
///
/// ## Returns
///
/// `Ok(a)` with the decoded claims value, or
/// `Error(ClaimDecodingFailed(_))` if decoding fails.
pub fn decode(
  jwt: EncryptedJwt,
  decoder: decode.Decoder(a),
) -> Result(a, jwt.JwtError) {
  json.parse_bits(jwt.claims_json, decoder)
  |> result.replace_error(jwt.ClaimDecodingFailed("failed to decode claims"))
}

/// Get the key encryption algorithm (`alg`) from a verified encrypted JWT.
///
/// ## Parameters
///
/// - `jwt` - The verified encrypted JWT.
///
/// ## Returns
///
/// The `JweAlg` from the token's header.
pub fn alg(jwt: EncryptedJwt) -> jwa.JweAlg {
  jwt.alg
}

/// Get the content encryption algorithm (`enc`) from a verified encrypted JWT.
///
/// ## Parameters
///
/// - `jwt` - The verified encrypted JWT.
///
/// ## Returns
///
/// The `Enc` from the token's header.
pub fn enc(jwt: EncryptedJwt) -> jwa.Enc {
  jwt.enc
}

/// Get the key ID (kid) from a verified encrypted JWT header.
///
/// **Security Warning:** The `kid` value comes from the token and is untrusted
/// input. If you use it to look up keys (from a database, filesystem, or key
/// store), you must sanitize it first to prevent injection attacks.
///
/// ## Parameters
///
/// - `jwt` - The verified encrypted JWT.
///
/// ## Returns
///
/// `Ok(String)` with the key ID, or `Error(Nil)` if no kid was set.
pub fn kid(jwt: EncryptedJwt) -> Result(String, Nil) {
  option.to_result(jwt.kid, Nil)
}

fn decryptor_options(decryptor: Decryptor) -> jwt.JwtValidationOptions {
  decryptor.options
}

fn decrypt_token(
  decryptor: Decryptor,
  token: String,
) -> Result(#(BitArray, jwa.JweAlg, jwa.Enc, Option(String)), jwt.JwtError) {
  use parsed_jwe <- result.try(
    jwe.parse_compact(token)
    |> result.map_error(jwt.gose_error_to_malformed_token_error),
  )

  let actual_alg = jwe.alg(parsed_jwe)
  let actual_enc = jwe.enc(parsed_jwe)
  let token_kid = option.from_result(jwe.kid(parsed_jwe))

  use _ <- result.try(require_matching_algorithms(
    decryptor,
    actual_alg,
    actual_enc,
  ))

  let options = decryptor_options(decryptor)
  use decryption_keys <- result.try(select_decryption_keys(
    decryptor,
    token_kid,
    options.kid_policy,
  ))

  use jwe_decryptor <- result.try(build_jwe_decryptor(
    decryptor,
    decryption_keys,
  ))
  use plaintext <- result.try(
    jwe.decrypt(jwe_decryptor, parsed_jwe)
    |> result.map_error(gose_error_to_decryption_failed),
  )

  Ok(#(plaintext, actual_alg, actual_enc, token_kid))
}

fn build_jwe_decryptor(
  decryptor: Decryptor,
  decryption_keys: List(jwk.Jwk),
) -> Result(jwe.Decryptor, jwt.JwtError) {
  case decryptor {
    KeyDecryptor(alg:, enc:, ..) ->
      jwe.key_decryptor(alg, enc, decryption_keys)
      |> result.map_error(jwt.JoseError)
    PasswordDecryptor(alg:, enc:, password:, ..) ->
      Ok(jwe.password_decryptor(alg, enc, password:))
  }
}

fn gose_error_to_decryption_failed(err: gose.GoseError) -> jwt.JwtError {
  jwt.DecryptionFailed(gose.error_message(err))
}

fn parse_plaintext_claims(
  plaintext: BitArray,
) -> Result(jwt.Claims, jwt.JwtError) {
  jwt.parse_claims_bits(plaintext)
}

fn require_matching_algorithms(
  decryptor: Decryptor,
  actual_alg: jwa.JweAlg,
  actual_enc: jwa.Enc,
) -> Result(Nil, jwt.JwtError) {
  let #(expected_alg, expected_enc) = case decryptor {
    KeyDecryptor(alg:, enc:, ..) -> #(alg, enc)
    PasswordDecryptor(alg:, enc:, ..) -> #(jwa.JwePbes2(alg), enc)
  }

  case expected_alg != actual_alg || expected_enc != actual_enc {
    True ->
      Error(jwt.JweAlgorithmMismatch(
        expected_alg:,
        expected_enc:,
        actual_alg:,
        actual_enc:,
      ))
    False -> Ok(Nil)
  }
}

fn select_decryption_keys(
  decryptor: Decryptor,
  token_kid: Option(String),
  kid_policy: jwt.KidPolicy,
) -> Result(List(jwk.Jwk), jwt.JwtError) {
  case decryptor {
    PasswordDecryptor(..) -> Ok([])
    KeyDecryptor(keys:, ..) ->
      jwt.select_keys_by_policy(keys, token_kid, kid_policy)
  }
}
