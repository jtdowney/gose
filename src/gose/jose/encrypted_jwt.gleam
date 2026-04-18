//// Encrypted JWT (JWE-based) - [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)
////
//// Encrypted JWTs built on JWE protect the claims payload through
//// encryption, providing confidentiality and ciphertext integrity.
//// **Encryption alone does not
//// authenticate the issuer.** For asymmetric algorithms (RSA-OAEP, ECDH-ES),
//// anyone with the recipient's public key can produce a valid encrypted token.
////
//// If your application requires proof of origin, use sign-then-encrypt
//// (nested JWT): sign the claims with JWS first, then encrypt the signed
//// token with JWE.
////
//// Use `peek_headers()` to inspect a token's headers without decrypting.
//// Use `decrypt_and_validate()` to decrypt and validate claim fields (exp,
//// nbf, iss, aud), producing an `EncryptedJwt` whose claims have been
//// decrypted and validated.
////
//// ## Example
////
//// ```gleam
//// import gleam/dynamic/decode
//// import gleam/time/duration
//// import gleam/time/timestamp
//// import gose/jose/encrypted_jwt
//// import gose/algorithm
//// import gose/key
//// import gose/jose/jwt
////
//// let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
//// let now = timestamp.system_time()
////
//// // Create claims and encrypt
//// let claims = jwt.claims()
////   |> jwt.with_subject("user123")
////   |> jwt.with_issuer("my-app")
////   |> jwt.with_expiration(timestamp.add(now, duration.hours(1)))
////
//// let assert Ok(encrypted) = encrypted_jwt.encrypt_with_key(
////   claims, algorithm.Direct, algorithm.AesGcm(algorithm.Aes256), key)
//// let token = encrypted_jwt.serialize(encrypted)
////
//// // Decrypt and validate using Decryptor (enforces algorithm pinning)
//// let assert Ok(decryptor) = encrypted_jwt.key_decryptor(
////   algorithm.Direct, algorithm.AesGcm(algorithm.Aes256), [key], jwt.default_validation())
//// let assert Ok(decrypted) = encrypted_jwt.decrypt_and_validate(decryptor, token, now)
////
//// // Decode decrypted and validated claims
//// let decoder = decode.field("sub", decode.string, decode.success)
//// let assert Ok(subject) = encrypted_jwt.decode(decrypted, decoder)
//// ```

import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import gose
import gose/algorithm
import gose/internal/key_helpers
import gose/jose/jwe
import gose/jose/jwt
import gose/key

/// A JWT whose claims have been decrypted and whose claim fields (exp, nbf,
/// iss, aud) have been validated. Produced by `decrypt_and_validate()`.
/// Note that encryption provides confidentiality, not issuer authentication.
pub opaque type EncryptedJwt {
  EncryptedJwt(
    alg: algorithm.KeyEncryptionAlg,
    enc: algorithm.ContentAlg,
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
    alg: algorithm.KeyEncryptionAlg,
    enc: algorithm.ContentAlg,
    keys: List(key.Key(String)),
    options: jwt.JwtValidationOptions,
  )
  PasswordDecryptor(
    alg: algorithm.Pbes2Alg,
    enc: algorithm.ContentAlg,
    password: String,
    options: jwt.JwtValidationOptions,
  )
}

fn validate_decryption_keys(
  alg: algorithm.KeyEncryptionAlg,
  keys: List(key.Key(String)),
) -> Result(Nil, gose.GoseError) {
  use <- key_helpers.require_non_empty_keys(keys)
  list.try_each(keys, key_helpers.validate_key_for_jwe_decryption(alg, _))
}

/// Create a key-based decryptor for symmetric (dir, AES-KW, AES-GCM-KW) or
/// asymmetric (RSA-OAEP, ECDH-ES) algorithms.
///
/// The decryptor pins the expected algorithms. Tokens with different
/// algorithms will be rejected.
pub fn key_decryptor(
  alg alg: algorithm.KeyEncryptionAlg,
  enc enc: algorithm.ContentAlg,
  keys keys: List(key.Key(String)),
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
pub fn password_decryptor(
  alg alg: algorithm.Pbes2Alg,
  enc enc: algorithm.ContentAlg,
  password password: String,
  options options: jwt.JwtValidationOptions,
) -> Decryptor {
  PasswordDecryptor(alg:, enc:, password:, options:)
}

/// Encrypt claims using a key-based algorithm.
///
/// Supports all key-based JWE algorithms: direct symmetric (dir), AES Key Wrap,
/// AES-GCM Key Wrap, RSA-OAEP, and ECDH-ES. PBES2 password-based algorithms
/// return an error. Use `encrypt_with_password` for those.
///
/// Sets `typ: "JWT"` in the header. If the encryption key has a `kid`, it is
/// included in the JWE header.
pub fn encrypt_with_key(
  claims: jwt.Claims,
  alg alg: algorithm.KeyEncryptionAlg,
  enc enc: algorithm.ContentAlg,
  key key: key.Key(String),
) -> Result(EncryptedJwt, jwt.JwtError) {
  let kid = option.from_result(key.kid(key))
  do_encrypt_with_key(claims, alg, enc, key, kid)
  |> result.map_error(jwt.JoseError)
}

fn do_encrypt_with_key(
  claims: jwt.Claims,
  alg: algorithm.KeyEncryptionAlg,
  enc: algorithm.ContentAlg,
  key: key.Key(String),
  kid: Option(String),
) -> Result(EncryptedJwt, gose.GoseError) {
  let claims_json = claims_to_plaintext(claims)
  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(alg, key))
  jwe.encrypt_to_compact(
    alg,
    enc,
    claims_json,
    key,
    kid,
    option.Some("JWT"),
    option.None,
  )
  |> result.map(fn(pair) {
    let #(token, jwe_alg) = pair
    EncryptedJwt(alg: jwe_alg, enc:, kid:, claims:, claims_json:, token:)
  })
}

/// Encrypt claims using PBES2 password-based encryption.
///
/// Sets `typ: "JWT"` in the header.
pub fn encrypt_with_password(
  claims: jwt.Claims,
  alg alg: algorithm.Pbes2Alg,
  enc enc: algorithm.ContentAlg,
  password password: String,
  kid kid: Option(String),
) -> Result(EncryptedJwt, jwt.JwtError) {
  do_encrypt_with_password(claims, alg, enc, password, kid)
  |> result.map_error(jwt.JoseError)
}

fn do_encrypt_with_password(
  claims: jwt.Claims,
  alg: algorithm.Pbes2Alg,
  enc: algorithm.ContentAlg,
  password: String,
  kid: Option(String),
) -> Result(EncryptedJwt, gose.GoseError) {
  let claims_json = claims_to_plaintext(claims)
  let unencrypted =
    jwe.new_pbes2(alg, enc)
    |> jwe.with_typ("JWT")
  let unencrypted = case kid {
    option.Some(k) -> jwe.with_kid(unencrypted, k)
    option.None -> unencrypted
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

/// Return the compact serialization of an encrypted JWT.
pub fn serialize(jwt: EncryptedJwt) -> String {
  jwt.token
}

/// Header fields from an encrypted JWT token, extracted without decrypting.
pub type PeekHeaders {
  PeekHeaders(
    alg: algorithm.KeyEncryptionAlg,
    enc: algorithm.ContentAlg,
    kid: Option(String),
  )
}

/// Peek at the header fields from a token without decrypting.
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
pub fn decode(
  jwt: EncryptedJwt,
  using decoder: decode.Decoder(a),
) -> Result(a, jwt.JwtError) {
  json.parse_bits(jwt.claims_json, decoder)
  |> result.replace_error(jwt.ClaimDecodingFailed("failed to decode claims"))
}

/// Get the key encryption algorithm (`alg`) from a decrypted and validated encrypted JWT.
pub fn alg(jwt: EncryptedJwt) -> algorithm.KeyEncryptionAlg {
  jwt.alg
}

/// Get the content encryption algorithm (`enc`) from a decrypted and validated encrypted JWT.
pub fn enc(jwt: EncryptedJwt) -> algorithm.ContentAlg {
  jwt.enc
}

/// Get the key ID (kid) from a decrypted and validated encrypted JWT header.
///
/// **Security Warning:** The `kid` value comes from the token and is untrusted
/// input. If you use it to look up keys (from a database, filesystem, or key
/// store), you must sanitize it first to prevent injection attacks.
pub fn kid(jwt: EncryptedJwt) -> Result(String, Nil) {
  option.to_result(jwt.kid, Nil)
}

fn decryptor_options(decryptor: Decryptor) -> jwt.JwtValidationOptions {
  decryptor.options
}

fn decrypt_token(
  decryptor: Decryptor,
  token: String,
) -> Result(
  #(BitArray, algorithm.KeyEncryptionAlg, algorithm.ContentAlg, Option(String)),
  jwt.JwtError,
) {
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
  decryption_keys: List(key.Key(String)),
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
  actual_alg: algorithm.KeyEncryptionAlg,
  actual_enc: algorithm.ContentAlg,
) -> Result(Nil, jwt.JwtError) {
  let #(expected_alg, expected_enc) = case decryptor {
    KeyDecryptor(alg:, enc:, ..) -> #(alg, enc)
    PasswordDecryptor(alg:, enc:, ..) -> #(algorithm.Pbes2(alg), enc)
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
) -> Result(List(key.Key(String)), jwt.JwtError) {
  case decryptor {
    PasswordDecryptor(..) -> Ok([])
    KeyDecryptor(keys:, ..) ->
      jwt.select_keys_by_policy(keys, token_kid, kid_policy)
  }
}
