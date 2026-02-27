//// Encrypted JWK Export/Import - [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html)
////
//// This module provides functions to export and import JWKs as encrypted JSON
//// using JWE. The plaintext JWK JSON becomes the JWE payload with `cty: "jwk+json"`.
////
//// ## Example
////
//// Key-based encryption:
////
//// ```gleam
//// import gose/encrypted_jwk
//// import gose/jwa
//// import gose/jwe
//// import gose/jwk
//// import kryptos/ec
////
//// // Generate a wrapping key and an EC key to protect
//// let wrapping_key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
//// let key = jwk.generate_ec(ec.P256)
////
//// // Export with key-based encryption
//// let assert Ok(encrypted) = encrypted_jwk.encrypt_with_key(
////   key,
////   alg: jwa.JweDirect,
////   enc: jwa.AesGcm(jwa.Aes256),
////   with: wrapping_key,
//// )
////
//// // Import it back
//// let decryptor = jwe.key_decryptor(
////   jwa.JweDirect,
////   jwa.AesGcm(jwa.Aes256),
////   wrapping_key,
//// )
//// let assert Ok(recovered) = encrypted_jwk.decrypt(decryptor, encrypted)
//// ```
////
//// Password-based encryption:
////
//// ```gleam
//// import gose/encrypted_jwk
//// import gose/jwa
//// import gose/jwe
//// import gose/jwk
//// import kryptos/ec
////
//// let key = jwk.generate_ec(ec.P256)
////
//// // Export with password protection
//// let assert Ok(encrypted) = encrypted_jwk.encrypt_with_password(
////   key,
////   jwa.Pbes2Sha256Aes128Kw,
////   jwa.AesGcm(jwa.Aes256),
////   "my-secure-password",
//// )
////
//// // Import it back using a decryptor
//// let decryptor = jwe.password_decryptor(
////   jwa.Pbes2Sha256Aes128Kw,
////   jwa.AesGcm(jwa.Aes256),
////   "my-secure-password",
//// )
//// let assert Ok(recovered) = encrypted_jwk.decrypt(decryptor, encrypted)
//// ```

import gleam/bit_array
import gleam/json
import gleam/option.{None, Some}
import gleam/pair
import gleam/result
import gose
import gose/jwa
import gose/jwe
import gose/jwk

/// Import a JWK from encrypted JSON using a decryptor with algorithm pinning.
///
/// Works for all algorithms. Create a decryptor with `jwe.key_decryptor`
/// for key-based algorithms or `jwe.password_decryptor` for PBES2.
///
/// ## Parameters
///
/// - `decryptor` - A decryptor created with `jwe.key_decryptor` or `jwe.password_decryptor`.
/// - `encrypted` - The encrypted JWE in compact format.
///
/// ## Returns
///
/// `Ok(Jwk)` with the decrypted and parsed key, or `Error(GoseError)` if
/// decryption or parsing fails.
///
/// ## Example
///
/// ```gleam
/// let decryptor =
///   jwe.password_decryptor(
///     jwa.Pbes2Sha256Aes128Kw,
///     jwa.AesGcm(jwa.Aes256),
///     "my-password",
///   )
/// let assert Ok(key) = encrypted_jwk.decrypt(decryptor, encrypted_token)
/// ```
pub fn decrypt(
  decryptor: jwe.Decryptor,
  encrypted: String,
) -> Result(jwk.Jwk, gose.GoseError) {
  use parsed <- result.try(jwe.parse_compact(encrypted))
  use plaintext <- result.try(jwe.decrypt(decryptor, parsed))
  jwk.from_json_bits(plaintext)
}

/// Export a JWK as encrypted JSON using a key-based algorithm.
///
/// Supports all key-based JWE algorithms: direct symmetric (dir), AES Key Wrap,
/// AES-GCM Key Wrap, RSA-OAEP, and ECDH-ES. PBES2 password-based algorithms
/// return an error — use `encrypt_with_password` instead.
///
/// The encryption key type must match the algorithm:
/// - `JweDirect`: octet key matching the content encryption key size
/// - `JweAesKeyWrap(AesKw, _)`: octet key (16, 24, or 32 bytes)
/// - `JweAesKeyWrap(AesGcmKw, _)`: octet key (16, 24, or 32 bytes)
/// - `JweChaCha20Kw(_)`: octet key (32 bytes)
/// - `JweRsa(_)`: RSA key
/// - `JweEcdhEs(_)`: EC or XDH key
///
/// If the encryption key has a `kid`, it is included in the JWE header.
///
/// ## Parameters
///
/// - `key` - The JWK to export.
/// - `alg` - The JWE key encryption algorithm to use.
/// - `enc` - The content encryption algorithm to use.
/// - `encryption_key` - The key used to encrypt the JWK.
///
/// ## Returns
///
/// `Ok(String)` with the encrypted JWE in compact format, or
/// `Error(GoseError)` if serialization or encryption fails.
pub fn encrypt_with_key(
  key: jwk.Jwk,
  alg alg: jwa.JweAlg,
  enc enc: jwa.Enc,
  with encryption_key: jwk.Jwk,
) -> Result(String, gose.GoseError) {
  let plaintext = jwk_to_plaintext(key)
  let kid = option.from_result(jwk.kid(encryption_key))
  jwe.encrypt_to_compact(
    alg,
    enc,
    plaintext,
    encryption_key,
    kid,
    None,
    Some("jwk+json"),
  )
  |> result.map(pair.first)
}

/// Export a JWK as encrypted JSON using PBES2 password-based encryption.
///
/// This is the most common method for protecting stored keys with a password.
/// The JWK is serialized to JSON, then encrypted using the specified PBES2
/// algorithm and content encryption algorithm.
///
/// ## Parameters
///
/// - `key` - The JWK to export.
/// - `alg` - The PBES2 algorithm variant to use.
/// - `enc` - The content encryption algorithm to use.
/// - `password` - The password to protect the key with.
///
/// ## Returns
///
/// `Ok(String)` with the encrypted JWE in compact format, or
/// `Error(GoseError)` if serialization or encryption fails.
pub fn encrypt_with_password(
  key: jwk.Jwk,
  alg alg: jwa.Pbes2Alg,
  enc enc: jwa.Enc,
  password password: String,
) -> Result(String, gose.GoseError) {
  let plaintext = jwk_to_plaintext(key)

  let encryptor =
    jwe.new_pbes2(alg, enc)
    |> jwe.with_cty("jwk+json")

  jwe.encrypt_with_password(encryptor, password, plaintext)
  |> result.try(jwe.serialize_compact)
}

fn jwk_to_plaintext(key: jwk.Jwk) -> BitArray {
  jwk.to_json(key)
  |> json.to_string
  |> bit_array.from_string
}
