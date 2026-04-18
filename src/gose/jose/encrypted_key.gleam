//// Encrypted JWK Export/Import - [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html)
////
//// Export and import JWKs as encrypted JSON using JWE. The plaintext JWK
//// JSON becomes the JWE payload with `cty: "jwk+json"`.
////
//// ## Example
////
//// Key-based encryption:
////
//// ```gleam
//// import gose
//// import gose/jose/encrypted_key
//// import gose/jose/jwe
//// import kryptos/ec
////
//// // Generate a wrapping key and an EC key to protect
//// let wrapping_key = gose.generate_enc_key(gose.AesGcm(gose.Aes256))
//// let k = gose.generate_ec(ec.P256)
////
//// // Export with key-based encryption
//// let assert Ok(encrypted) = encrypted_key.encrypt_with_key(
////   k,
////   alg: gose.Direct,
////   enc: gose.AesGcm(gose.Aes256),
////   with: wrapping_key,
//// )
////
//// // Import it back
//// let assert Ok(decryptor) = jwe.key_decryptor(
////   gose.Direct,
////   gose.AesGcm(gose.Aes256),
////   keys: [wrapping_key],
//// )
//// let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)
//// ```
////
//// Password-based encryption:
////
//// ```gleam
//// import gose
//// import gose/jose/encrypted_key
//// import gose/jose/jwe
//// import kryptos/ec
////
//// let k = gose.generate_ec(ec.P256)
////
//// // Export with password protection
//// let assert Ok(encrypted) = encrypted_key.encrypt_with_password(
////   k,
////   gose.Pbes2Sha256Aes128Kw,
////   gose.AesGcm(gose.Aes256),
////   "my-secure-password",
//// )
////
//// // Import it back using a decryptor
//// let decryptor = jwe.password_decryptor(
////   gose.Pbes2Sha256Aes128Kw,
////   gose.AesGcm(gose.Aes256),
////   "my-secure-password",
//// )
//// let assert Ok(recovered) = encrypted_key.decrypt(decryptor, encrypted)
//// ```

import gleam/bit_array
import gleam/json
import gleam/option
import gleam/pair
import gleam/result
import gose
import gose/jose/jwe
import gose/jose/jwk

/// Import a JWK from encrypted JSON using a decryptor with algorithm pinning.
///
/// Works for all algorithms. Create a decryptor with `jwe.key_decryptor`
/// for key-based algorithms or `jwe.password_decryptor` for PBES2.
///
/// ## Example
///
/// ```gleam
/// let decryptor =
///   jwe.password_decryptor(
///     gose.Pbes2Sha256Aes128Kw,
///     gose.AesGcm(gose.Aes256),
///     "my-password",
///   )
/// let assert Ok(key) = encrypted_key.decrypt(decryptor, encrypted_token)
/// ```
pub fn decrypt(
  decryptor: jwe.Decryptor,
  encrypted: String,
) -> Result(gose.Key(String), gose.GoseError) {
  use parsed <- result.try(jwe.parse_compact(encrypted))
  use plaintext <- result.try(jwe.decrypt(decryptor, parsed))
  jwk.from_json_bits(plaintext)
}

/// Export a JWK as encrypted JSON using a key-based algorithm.
///
/// Supports all key-based JWE algorithms: direct symmetric (dir), AES Key Wrap,
/// AES-GCM Key Wrap, RSA-OAEP, and ECDH-ES. PBES2 password-based algorithms
/// return an error. Use `encrypt_with_password` for those.
///
/// The encryption key type must match the algorithm:
/// - `Direct`: octet key matching the content encryption key size
/// - `AesKeyWrap(AesKw, _)`: octet key (16, 24, or 32 bytes)
/// - `AesKeyWrap(AesGcmKw, _)`: octet key (16, 24, or 32 bytes)
/// - `ChaCha20KeyWrap(_)`: octet key (32 bytes)
/// - `RsaEncryption(_)`: RSA key
/// - `EcdhEs(_)`: EC or XDH key
///
/// If the encryption key has a `kid`, it is included in the JWE header.
pub fn encrypt_with_key(
  key: gose.Key(String),
  alg alg: gose.KeyEncryptionAlg,
  enc enc: gose.ContentAlg,
  with encryption_key: gose.Key(String),
) -> Result(String, gose.GoseError) {
  let plaintext = jwk_to_plaintext(key)
  let kid = option.from_result(gose.kid(encryption_key))
  jwe.encrypt_to_compact(
    alg,
    enc,
    plaintext,
    encryption_key,
    kid,
    option.None,
    option.Some("jwk+json"),
  )
  |> result.map(pair.first)
}

/// Export a JWK as encrypted JSON using PBES2 password-based encryption.
///
/// This is the most common method for protecting stored keys with a password.
/// The JWK is serialized to JSON, then encrypted using the specified PBES2
/// algorithm and content encryption algorithm.
pub fn encrypt_with_password(
  key: gose.Key(String),
  alg alg: gose.Pbes2Alg,
  enc enc: gose.ContentAlg,
  password password: String,
) -> Result(String, gose.GoseError) {
  let plaintext = jwk_to_plaintext(key)

  let encryptor =
    jwe.new_pbes2(alg, enc)
    |> jwe.with_cty("jwk+json")

  jwe.encrypt_with_password(encryptor, password, plaintext)
  |> result.try(jwe.serialize_compact)
}

fn jwk_to_plaintext(key: gose.Key(String)) -> BitArray {
  jwk.to_json(key)
  |> json.to_string
  |> bit_array.from_string
}
