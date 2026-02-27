//// JSON Web Encryption (JWE) - [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html)
////
//// This module provides encryption functionality using algorithms from
//// [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html):
//// key encryption (RSA-OAEP, ECDH-ES, AES Key Wrap, AES-GCM Key Wrap, PBES2, dir)
//// and content encryption (AES-GCM, AES-CBC-HMAC).
////
//// Non-standard extensions are also supported: ChaCha20 Key Wrap (C20PKW,
//// XC20PKW), ECDH-ES+ChaCha20KW, and ChaCha20-Poly1305/XChaCha20-Poly1305
//// content encryption.
////
//// ## Example
////
//// ```gleam
//// import gose/jwe
//// import gose/jwa
//// import gose/jwk
////
//// let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
//// let plaintext = <<"hello world":utf8>>
////
//// // Create and encrypt a JWE using direct encryption
//// let assert Ok(encrypted) = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
////   |> jwe.encrypt(key, plaintext)
////
//// // Serialize to compact format
//// let assert Ok(token) = jwe.serialize_compact(encrypted)
////
//// // Parse and decrypt with algorithm pinning
//// let assert Ok(parsed) = jwe.parse_compact(token)
//// let assert Ok(decryptor) = jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
//// let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
//// ```
////
//// ## Phantom Types
////
//// `Jwe(state, family, origin)` uses three phantom type parameters:
////
//// - **State** tracks encryption progress:
////   - `Unencrypted` — created via a builder, ready to encrypt
////   - `Encrypted` — encrypted or parsed, can be serialized or decrypted
//// - **Family** restricts which algorithm-specific options are available:
////   - `Direct`, `AesKw`, `AesGcmKw`, `Rsa`, `EcdhEs`, `Pbes2`
////   - For example, `with_apu`/`with_apv` only compile on `EcdhEs` JWEs
////     and `with_p2c` only compiles on `Pbes2` JWEs
//// - **Origin** tracks how the JWE was obtained:
////   - `Built` — created via a `new_*` builder and `encrypt`
////   - `Parsed` — obtained from `parse_compact` or `parse_json`
////
//// ## Algorithm Pinning
////
//// Algorithm pinning prevents algorithm confusion attacks:
////
//// 1. **JWK `alg` metadata**: If a key has `alg` set via `jwk.with_alg`,
////    the JWE algorithm must match during encryption and decryption.
//// 2. **Decryptor API**: `jwe.decrypt()` with a `Decryptor` pins both key
////    encryption and content encryption algorithms; mismatches are rejected.
//// 3. **Key type validation**: The key type must match the algorithm (RSA for
////    RSA-OAEP, EC for ECDH-ES, etc.).
////
//// For strongest security, always set the `alg` field on keys or use decryptors.
////
//// ## Unprotected Headers
////
//// JWE supports unprotected headers at two levels in JSON serialization:
//// - **Shared unprotected** (`unprotected`): Applies to all recipients
//// - **Per-recipient unprotected** (`header`): Specific to one recipient
////
//// **Security Warning:** Unprotected headers are NOT integrity protected. They can be
//// modified by an attacker without detection. Security-critical parameters
//// (`alg`, `enc`, `crit`, `zip`) are rejected and must be integrity protected.
////
//// Use `with_shared_unprotected` and `with_unprotected` to add headers during
//// creation. Use `decode_shared_unprotected_header` and `decode_unprotected_header`
//// to read parsed headers.
////
//// ## Critical Header Support
////
//// The `crit` header is validated per RFC 7516:
//// - Empty arrays are rejected
//// - Standard headers cannot appear in `crit`
//// - No extensions are currently implemented, so any critical extension is rejected
////
//// ## Key Metadata
////
//// JWK metadata (`use`, `key_ops`) is enforced during encryption and decryption.
//// Keys with incompatible metadata are rejected.
////
//// ## Compression Not Supported
////
//// The `zip` header (DEFLATE compression) is intentionally not supported.
//// Compression before encryption leaks information about plaintext through
//// ciphertext size variations (CRIME/BREACH-style attacks). JWEs with `zip`
//// set are rejected during parsing.
////
//// ## JSON Serialization Limitations
////
//// - **Single recipient only**: General JSON Serialization rejects JWE with
////   multiple recipients. Use separate JWE objects for each recipient.

import gleam/bit_array
import gleam/bool
import gleam/dict
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set
import gleam/string
import gose
import gose/internal/jwe/content_encryption
import gose/internal/jwe/key_wrap
import gose/internal/key_helpers
import gose/internal/utils
import gose/jwa
import gose/jwk
import kryptos/block
import kryptos/crypto
import kryptos/hash.{type HashAlgorithm}

/// Minimum required PBES2 iteration count.
const min_p2c = 1000

/// Maximum allowed PBES2 iteration count to prevent DoS attacks.
const max_p2c = 10_000_000

/// Standard JWE header parameters that cannot appear in `crit`.
const standard_headers = [
  "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256",
  "typ", "cty", "apu", "apv", "epk", "iv", "tag", "p2s", "p2c", "crit",
]

/// Headers that MUST be integrity protected.
const protected_only_headers = ["alg", "enc", "crit", "zip"]

/// Phantom type for unencrypted JWE (plaintext set, ready to encrypt).
pub type Unencrypted

/// Phantom type for encrypted JWE (ciphertext present, can serialize/decrypt).
pub type Encrypted

/// Phantom type for JWE created via builder (new_*).
pub type Built

/// Phantom type for JWE obtained by parsing a token.
pub type Parsed

/// Phantom type for direct key encryption (dir).
pub type Direct

/// Phantom type for AES Key Wrap algorithms (A128KW, A192KW, A256KW).
pub type AesKw

/// Phantom type for RSA key encryption algorithms (RSA1_5, RSA-OAEP, RSA-OAEP-256).
pub type Rsa

/// Phantom type for ECDH-ES algorithms (ECDH-ES, ECDH-ES+A*KW).
pub type EcdhEs

/// Phantom type for PBES2 algorithms (PBES2-HS*+A*KW).
pub type Pbes2

/// Phantom type for AES-GCM Key Wrap algorithms (A128GCMKW, A192GCMKW, A256GCMKW).
pub type AesGcmKw

/// Phantom type for ChaCha20-Poly1305 Key Wrap algorithms (C20PKW, XC20PKW).
pub type ChaCha20Kw

type JweHeader {
  JweHeader(
    alg: jwa.JweAlg,
    enc: jwa.Enc,
    kid: Option(String),
    typ: Option(String),
    cty: Option(String),
  )
}

type AlgFields {
  NoAlgFields
  EcdhEsFields(
    epk: Option(key_wrap.EphemeralPublicKey),
    apu: Option(BitArray),
    apv: Option(BitArray),
  )
  Pbes2Fields(p2s: Option(BitArray), p2c: Option(Int))
  AesGcmKwFields(kw_iv: Option(BitArray), kw_tag: Option(BitArray))
  ChaCha20KwFields(kw_iv: Option(BitArray), kw_tag: Option(BitArray))
  EcdhEsChaCha20KwFields(
    epk: Option(key_wrap.EphemeralPublicKey),
    apu: Option(BitArray),
    apv: Option(BitArray),
    kw_iv: Option(BitArray),
    kw_tag: Option(BitArray),
  )
}

type ParsedHeader {
  ParsedHeader(header: JweHeader, alg_fields: AlgFields)
}

/// A JSON Web Encryption with phantom types for state, algorithm family, and origin.
///
/// The origin phantom type distinguishes between JWE created via builders
/// (`Built`) and JWE obtained by parsing tokens (`Parsed`). This enables
/// compile-time enforcement that `decode_*_unprotected_header` only works on
/// parsed instances.
pub opaque type Jwe(state, family, origin) {
  Jwe(
    header: JweHeader,
    aad: Option(BitArray),
    shared_unprotected: dict.Dict(String, json.Json),
    per_recipient_unprotected: dict.Dict(String, json.Json),
    alg_fields: AlgFields,
  )
  EncryptedJwe(
    header: JweHeader,
    protected_b64: String,
    encrypted_key: BitArray,
    iv: BitArray,
    ciphertext: BitArray,
    tag: BitArray,
    alg_fields: AlgFields,
    aad: Option(BitArray),
    shared_unprotected: dict.Dict(String, json.Json),
    shared_unprotected_raw: Option(decode.Dynamic),
    per_recipient_unprotected: dict.Dict(String, json.Json),
    per_recipient_unprotected_raw: Option(decode.Dynamic),
  )
}

/// A JWE decryptor that pins the expected algorithm and encryption method.
///
/// Use decryptors to prevent algorithm confusion attacks by specifying
/// the expected algorithms upfront, rather than trusting the token's header.
pub opaque type Decryptor {
  KeyDecryptor(alg: jwa.JweAlg, enc: jwa.Enc, keys: List(jwk.Jwk))
  PasswordDecryptor(alg: jwa.Pbes2Alg, enc: jwa.Enc, password: String)
}

/// Create a key-based decryptor for symmetric (dir, AES-KW, AES-GCM-KW) or
/// asymmetric (RSA-OAEP, ECDH-ES) algorithms with multiple keys.
///
/// The decryptor pins the expected algorithm and encryption method.
/// Tokens with different algorithms will be rejected.
///
/// When decrypting, keys are tried in order. If the JWE has a `kid` header,
/// a key with matching `kid` is prioritized.
///
/// ## Parameters
///
/// - `alg` - The expected key encryption algorithm.
/// - `enc` - The expected content encryption algorithm.
/// - `keys` - Candidate decryption keys, tried in order.
///
/// ## Returns
///
/// `Ok(Decryptor)` that can be passed to `decrypt`, or `Error(GoseError)` if
/// the key list is empty or any key fails validation (all provided keys must
/// pass algorithm-compatibility validation).
///
/// ## Example
///
/// ```gleam
/// let assert Ok(decryptor) = jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
/// let assert Ok(plaintext) = jwe.decrypt(decryptor, encrypted_jwe)
/// ```
pub fn key_decryptor(
  alg: jwa.JweAlg,
  enc: jwa.Enc,
  keys keys: List(jwk.Jwk),
) -> Result(Decryptor, gose.GoseError) {
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_jwe_decryption(alg, _)),
  )
  Ok(KeyDecryptor(alg:, enc:, keys:))
}

/// Create a new unencrypted JWE for AES-GCM Key Wrap encryption. A random CEK
/// is generated and wrapped using AES-GCM with the provided symmetric key.
///
/// ## Parameters
///
/// - `size` - The AES key size variant to use.
/// - `enc` - The content encryption algorithm to use.
///
/// ## Returns
///
/// An unencrypted `Jwe` with the AES-GCM Key Wrap family ready for encryption.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(encrypted) = jwe.new_aes_gcm_kw(jwa.Aes256, jwa.AesGcm(jwa.Aes256))
///   |> jwe.encrypt(key, <<"hello":utf8>>)
/// ```
pub fn new_aes_gcm_kw(
  size: jwa.AesKeySize,
  enc: jwa.Enc,
) -> Jwe(Unencrypted, AesGcmKw, Built) {
  Jwe(
    header: JweHeader(
      alg: jwa.JweAesKeyWrap(jwa.AesGcmKw, size),
      enc:,
      kid: None,
      typ: None,
      cty: None,
    ),
    shared_unprotected: dict.new(),
    aad: None,
    per_recipient_unprotected: dict.new(),
    alg_fields: AesGcmKwFields(kw_iv: None, kw_tag: None),
  )
}

/// Create a new unencrypted JWE for AES Key Wrap encryption. A random CEK is
/// generated and wrapped with the provided symmetric key.
///
/// ## Parameters
///
/// - `size` - The AES key size variant to use.
/// - `enc` - The content encryption algorithm to use.
///
/// ## Returns
///
/// An unencrypted `Jwe` with the AES Key Wrap family ready for encryption.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(encrypted) = jwe.new_aes_kw(jwa.Aes256, jwa.AesGcm(jwa.Aes256))
///   |> jwe.encrypt(key, <<"hello":utf8>>)
/// ```
pub fn new_aes_kw(
  size: jwa.AesKeySize,
  enc: jwa.Enc,
) -> Jwe(Unencrypted, AesKw, Built) {
  Jwe(
    header: JweHeader(
      alg: jwa.JweAesKeyWrap(jwa.AesKw, size),
      enc:,
      kid: None,
      typ: None,
      cty: None,
    ),
    aad: None,
    shared_unprotected: dict.new(),
    per_recipient_unprotected: dict.new(),
    alg_fields: NoAlgFields,
  )
}

/// Create a new unencrypted JWE for ChaCha20-Poly1305 Key Wrap encryption.
/// A random CEK is generated and wrapped using ChaCha20-Poly1305 or
/// XChaCha20-Poly1305 with the provided 32-byte symmetric key.
///
/// This is a non-standard extension (not defined in RFC 7518).
///
/// ## Parameters
///
/// - `variant` - The ChaCha20 Key Wrap variant (`C20PKw` or `XC20PKw`).
/// - `enc` - The content encryption algorithm to use.
///
/// ## Returns
///
/// An unencrypted `Jwe` with the ChaCha20 Key Wrap family ready for encryption.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(encrypted) = jwe.new_chacha20_kw(jwa.XC20PKw, jwa.AesGcm(jwa.Aes256))
///   |> jwe.encrypt(key, <<"hello":utf8>>)
/// ```
pub fn new_chacha20_kw(
  variant: jwa.ChaCha20Kw,
  enc: jwa.Enc,
) -> Jwe(Unencrypted, ChaCha20Kw, Built) {
  Jwe(
    header: JweHeader(
      alg: jwa.JweChaCha20KeyWrap(variant),
      enc:,
      kid: None,
      typ: None,
      cty: None,
    ),
    shared_unprotected: dict.new(),
    aad: None,
    per_recipient_unprotected: dict.new(),
    alg_fields: ChaCha20KwFields(kw_iv: None, kw_tag: None),
  )
}

/// Create a new unencrypted JWE for direct key encryption. The symmetric key
/// is used directly as the Content Encryption Key (CEK).
///
/// ## Parameters
///
/// - `enc` - The content encryption algorithm to use.
///
/// ## Returns
///
/// An unencrypted `Jwe` with the Direct family ready for encryption.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(encrypted) = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
///   |> jwe.encrypt(key, <<"hello":utf8>>)
/// ```
pub fn new_direct(enc: jwa.Enc) -> Jwe(Unencrypted, Direct, Built) {
  Jwe(
    header: JweHeader(alg: jwa.JweDirect, enc:, kid: None, typ: None, cty: None),
    aad: None,
    shared_unprotected: dict.new(),
    per_recipient_unprotected: dict.new(),
    alg_fields: NoAlgFields,
  )
}

/// Create a new unencrypted JWE for ECDH-ES key agreement. An ephemeral key
/// pair is generated during encryption for the key agreement.
///
/// ## Parameters
///
/// - `alg` - The ECDH-ES algorithm variant to use.
/// - `enc` - The content encryption algorithm to use.
///
/// ## Returns
///
/// An unencrypted `Jwe` with the ECDH-ES family ready for encryption.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(encrypted) = jwe.new_ecdh_es(jwa.EcdhEsDirect, jwa.AesGcm(jwa.Aes256))
///   |> jwe.encrypt(key, <<"hello":utf8>>)
/// ```
pub fn new_ecdh_es(
  alg: jwa.EcdhEsAlg,
  enc: jwa.Enc,
) -> Jwe(Unencrypted, EcdhEs, Built) {
  let alg_fields = case alg {
    jwa.EcdhEsChaCha20Kw(_) ->
      EcdhEsChaCha20KwFields(
        epk: None,
        apu: None,
        apv: None,
        kw_iv: None,
        kw_tag: None,
      )
    jwa.EcdhEsDirect | jwa.EcdhEsAesKw(_) ->
      EcdhEsFields(epk: None, apu: None, apv: None)
  }
  Jwe(
    header: JweHeader(
      alg: jwa.JweEcdhEs(alg),
      enc:,
      kid: None,
      typ: None,
      cty: None,
    ),
    aad: None,
    shared_unprotected: dict.new(),
    per_recipient_unprotected: dict.new(),
    alg_fields:,
  )
}

/// Create a new unencrypted JWE for PBES2 password-based encryption. The CEK
/// is derived from the password using PBKDF2.
///
/// ## Parameters
///
/// - `alg` - The PBES2 algorithm variant to use.
/// - `enc` - The content encryption algorithm to use.
///
/// ## Returns
///
/// An unencrypted `Jwe` with the PBES2 family ready for encryption.
/// Use `with_p2c` to override the default iteration count. The salt
/// is generated automatically.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(encrypted) = jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes128))
///   |> jwe.encrypt_with_password("secret", <<"hello":utf8>>)
/// ```
pub fn new_pbes2(
  alg: jwa.Pbes2Alg,
  enc: jwa.Enc,
) -> Jwe(Unencrypted, Pbes2, Built) {
  Jwe(
    header: JweHeader(
      alg: jwa.JwePbes2(alg),
      enc:,
      kid: None,
      typ: None,
      cty: None,
    ),
    aad: None,
    shared_unprotected: dict.new(),
    per_recipient_unprotected: dict.new(),
    alg_fields: Pbes2Fields(p2s: None, p2c: None),
  )
}

/// Create a new unencrypted JWE for RSA key encryption. A random CEK is
/// generated and encrypted with the RSA public key.
///
/// ## Parameters
///
/// - `alg` - The RSA key encryption algorithm variant to use.
/// - `enc` - The content encryption algorithm to use.
///
/// ## Returns
///
/// An unencrypted `Jwe` with the RSA family ready for encryption.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(encrypted) = jwe.new_rsa(jwa.RsaOaepSha256, jwa.AesGcm(jwa.Aes256))
///   |> jwe.encrypt(rsa_key, <<"hello":utf8>>)
/// ```
pub fn new_rsa(alg: jwa.RsaJweAlg, enc: jwa.Enc) -> Jwe(Unencrypted, Rsa, Built) {
  Jwe(
    header: JweHeader(
      alg: jwa.JweRsa(alg),
      enc:,
      kid: None,
      typ: None,
      cty: None,
    ),
    aad: None,
    shared_unprotected: dict.new(),
    per_recipient_unprotected: dict.new(),
    alg_fields: NoAlgFields,
  )
}

/// Create a password-based decryptor for PBES2 algorithms.
///
/// The decryptor pins the expected algorithm and encryption method.
/// Tokens with different algorithms will be rejected.
///
/// ## Parameters
///
/// - `alg` - The expected PBES2 key encryption algorithm.
/// - `enc` - The expected content encryption algorithm.
/// - `password` - The password used for key derivation.
///
/// ## Returns
///
/// A `Decryptor` that can be passed to `decrypt` to decrypt a PBES2-encrypted JWE.
///
/// ## Example
///
/// ```gleam
/// let decryptor = jwe.password_decryptor(
///   jwa.Pbes2Sha256Aes128Kw,
///   jwa.AesGcm(jwa.Aes128),
///   "super-secret",
/// )
/// let assert Ok(plaintext) = jwe.decrypt(decryptor, encrypted_jwe)
/// ```
pub fn password_decryptor(
  alg: jwa.Pbes2Alg,
  enc: jwa.Enc,
  password password: String,
) -> Decryptor {
  PasswordDecryptor(alg:, enc:, password:)
}

/// Set the Additional Authenticated Data (AAD) for JSON serialization.
///
/// AAD is only supported in JSON serialization (flattened and general formats).
/// Attempting to serialize to compact format with AAD set will return an error.
///
/// Per RFC 7516, AAD is included in the AEAD authentication but is not encrypted.
///
/// ## Parameters
///
/// - `jwe` - The unencrypted JWE to add AAD to.
/// - `aad` - The additional authenticated data.
///
/// ## Returns
///
/// The `Jwe` with AAD set.
pub fn with_aad(
  jwe: Jwe(Unencrypted, family, Built),
  aad: BitArray,
) -> Jwe(Unencrypted, family, Built) {
  let assert Jwe(..) = jwe
  Jwe(..jwe, aad: Some(aad))
}

/// Set the Agreement PartyUInfo (apu) for ECDH-ES algorithms.
///
/// ## Parameters
///
/// - `jwe` - The unencrypted ECDH-ES JWE.
/// - `apu` - The PartyUInfo value (typically an identifier for the sender).
///
/// ## Returns
///
/// The `Jwe` with the `apu` header set.
///
/// ## Example
///
/// ```gleam
/// let jwe = jwe.new_ecdh_es(jwa.EcdhEsDirect, jwa.AesGcm(jwa.Aes256))
///   |> jwe.with_apu(<<"Alice":utf8>>)
///   |> jwe.with_apv(<<"Bob":utf8>>)
/// let assert Ok(encrypted) = jwe
///   |> jwe.encrypt(key, <<"hello":utf8>>)
/// ```
pub fn with_apu(
  jwe: Jwe(Unencrypted, EcdhEs, Built),
  apu: BitArray,
) -> Jwe(Unencrypted, EcdhEs, Built) {
  let assert Jwe(..) = jwe
  let alg_fields = case jwe.alg_fields {
    EcdhEsFields(epk:, apv:, ..) -> EcdhEsFields(epk:, apu: Some(apu), apv:)
    EcdhEsChaCha20KwFields(epk:, apv:, kw_iv:, kw_tag:, ..) ->
      EcdhEsChaCha20KwFields(epk:, apu: Some(apu), apv:, kw_iv:, kw_tag:)
    NoAlgFields | Pbes2Fields(..) | AesGcmKwFields(..) | ChaCha20KwFields(..) ->
      panic as "unreachable: EcdhEs phantom type guarantees ECDH-ES alg_fields"
  }
  Jwe(..jwe, alg_fields:)
}

/// Set the Agreement PartyVInfo (apv) for ECDH-ES algorithms.
///
/// ## Parameters
///
/// - `jwe` - The unencrypted ECDH-ES JWE.
/// - `apv` - The PartyVInfo value (typically an identifier for the recipient).
///
/// ## Returns
///
/// The `Jwe` with the `apv` header set.
///
/// ## Example
///
/// ```gleam
/// let jwe = jwe.new_ecdh_es(jwa.EcdhEsDirect, jwa.AesGcm(jwa.Aes256))
///   |> jwe.with_apu(<<"Alice":utf8>>)
///   |> jwe.with_apv(<<"Bob":utf8>>)
/// let assert Ok(encrypted) = jwe
///   |> jwe.encrypt(key, <<"hello":utf8>>)
/// ```
pub fn with_apv(
  jwe: Jwe(Unencrypted, EcdhEs, Built),
  apv: BitArray,
) -> Jwe(Unencrypted, EcdhEs, Built) {
  let assert Jwe(..) = jwe
  let alg_fields = case jwe.alg_fields {
    EcdhEsFields(epk:, apu:, ..) -> EcdhEsFields(epk:, apu:, apv: Some(apv))
    EcdhEsChaCha20KwFields(epk:, apu:, kw_iv:, kw_tag:, ..) ->
      EcdhEsChaCha20KwFields(epk:, apu:, apv: Some(apv), kw_iv:, kw_tag:)
    NoAlgFields | Pbes2Fields(..) | AesGcmKwFields(..) | ChaCha20KwFields(..) ->
      panic as "unreachable: EcdhEs phantom type guarantees ECDH-ES alg_fields"
  }
  Jwe(..jwe, alg_fields:)
}

/// Set the content type (cty) header parameter.
///
/// ## Parameters
///
/// - `jwe` - The unencrypted JWE.
/// - `cty` - The content type string (e.g. `"JWT"`).
///
/// ## Returns
///
/// The `Jwe` with the `cty` header set.
pub fn with_cty(
  jwe: Jwe(Unencrypted, family, Built),
  cty: String,
) -> Jwe(Unencrypted, family, Built) {
  let assert Jwe(header:, ..) = jwe
  Jwe(..jwe, header: JweHeader(..header, cty: Some(cty)))
}

/// Set the key ID (kid) header parameter.
///
/// ## Parameters
///
/// - `jwe` - The unencrypted JWE.
/// - `kid` - The key identifier string.
///
/// ## Returns
///
/// The `Jwe` with the `kid` header set.
pub fn with_kid(
  jwe: Jwe(Unencrypted, family, Built),
  kid: String,
) -> Jwe(Unencrypted, family, Built) {
  let assert Jwe(header:, ..) = jwe
  Jwe(..jwe, header: JweHeader(..header, kid: Some(kid)))
}

/// Set the PBES2 iteration count (p2c) for password-based encryption.
///
/// This allows customizing the PBKDF2 iteration count. Production should use
/// a value tuned for the specific use case.
///
/// Returns an error if iterations is less than 1,000 or greater than
/// 10,000,000.
///
/// ## Parameters
///
/// - `jwe` - The unencrypted PBES2 JWE.
/// - `iterations` - The PBKDF2 iteration count (must be between 1,000 and 10,000,000).
///
/// ## Returns
///
/// `Ok(Jwe)` with the updated iteration count, or `Error(GoseError)` if
/// the iteration count is out of the allowed range.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(jwe) =
///   jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes128))
///   |> jwe.with_p2c(100_000)
/// ```
pub fn with_p2c(
  jwe: Jwe(Unencrypted, Pbes2, Built),
  iterations: Int,
) -> Result(Jwe(Unencrypted, Pbes2, Built), gose.GoseError) {
  use <- bool.guard(
    when: iterations < min_p2c || iterations > max_p2c,
    return: Error(gose.InvalidState(
      "p2c must be >= "
      <> int.to_string(min_p2c)
      <> " and <= "
      <> int.to_string(max_p2c),
    )),
  )
  let assert Jwe(alg_fields: Pbes2Fields(p2s:, ..), ..) = jwe
  Ok(Jwe(..jwe, alg_fields: Pbes2Fields(p2s:, p2c: Some(iterations))))
}

/// Encrypt a JWE using the appropriate key-based algorithm.
///
/// Dispatches to the correct key encryption method based on the algorithm
/// selected when the JWE was created. Supports direct, AES Key Wrap,
/// AES-GCM Key Wrap, RSA, and ECDH-ES algorithms.
///
/// For PBES2 password-based algorithms, use `encrypt_with_password` instead.
///
/// JWK metadata (`use`, `key_ops`) is enforced when present:
/// - Keys with `use=sig` are rejected
/// - Keys with `key_ops` that don't include `encrypt` or `wrapKey` are rejected
///
/// ## Parameters
///
/// - `jwe` - The unencrypted JWE to encrypt.
/// - `key` - The encryption key (type must match the algorithm).
/// - `plaintext` - The data to encrypt.
///
/// ## Returns
///
/// `Ok(Jwe(Encrypted, family, Built))` with the encrypted JWE, or
/// `Error(GoseError)` if the key is invalid, the algorithm is PBES2, or
/// encryption fails.
///
/// ## Example
///
/// ```gleam
/// let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
/// let assert Ok(encrypted) = jwe.new_direct(jwa.AesGcm(jwa.Aes256))
///   |> jwe.encrypt(key, <<"hello":utf8>>)
/// ```
pub fn encrypt(
  jwe: Jwe(Unencrypted, family, Built),
  key key: jwk.Jwk,
  plaintext plaintext: BitArray,
) -> Result(Jwe(Encrypted, family, Built), gose.GoseError) {
  case jwe.header.alg {
    jwa.JweDirect -> do_encrypt_direct(jwe, key, plaintext)
    jwa.JweAesKeyWrap(jwa.AesKw, _) -> do_encrypt_aes_kw(jwe, key, plaintext)
    jwa.JweAesKeyWrap(jwa.AesGcmKw, _) ->
      do_encrypt_aes_gcm_kw(jwe, key, plaintext)
    jwa.JweRsa(_) -> do_encrypt_rsa(jwe, key, plaintext)
    jwa.JweEcdhEs(_) -> do_encrypt_ecdh(jwe, key, plaintext)
    jwa.JweChaCha20KeyWrap(_) -> do_encrypt_chacha20_kw(jwe, key, plaintext)
    jwa.JwePbes2(_) ->
      Error(gose.InvalidState(
        "PBES2 algorithms require a password; use encrypt_with_password",
      ))
  }
}

/// Encrypt a JWE using a password (PBES2).
///
/// ## Parameters
///
/// - `jwe` - The unencrypted JWE to encrypt.
/// - `password` - The password used for key derivation via PBKDF2.
/// - `plaintext` - The data to encrypt.
///
/// ## Returns
///
/// `Ok(Jwe(Encrypted, Pbes2, Built))` with the encrypted JWE, or
/// `Error(GoseError)` if key derivation or encryption fails.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(encrypted) = jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes128))
///   |> jwe.encrypt_with_password("super-secret", <<"hello":utf8>>)
/// ```
pub fn encrypt_with_password(
  jwe: Jwe(Unencrypted, Pbes2, Built),
  password password: String,
  plaintext plaintext: BitArray,
) -> Result(Jwe(Encrypted, Pbes2, Built), gose.GoseError) {
  let assert Jwe(header:, alg_fields: Pbes2Fields(p2c: custom_p2c, ..), ..) =
    jwe

  let assert jwa.JwePbes2(pbes2_alg) = header.alg
  let #(hash_alg, kw_size, default_iterations) = resolve_pbes2_params(pbes2_alg)
  let kw_key_len = jwa.aes_key_size_in_bytes(kw_size)
  let iterations = option.unwrap(custom_p2c, default_iterations)

  let salt_input = crypto.random_bytes(16)
  let alg_str = jwa.jwe_alg_to_string(header.alg)
  let salt =
    bit_array.concat([bit_array.from_string(alg_str), <<0>>, salt_input])

  use kek <- result.try(
    crypto.pbkdf2(
      hash_alg,
      password: bit_array.from_string(password),
      salt:,
      iterations:,
      length: kw_key_len,
    )
    |> result.replace_error(gose.CryptoError("PBKDF2 key derivation failed")),
  )

  let cek = content_encryption.generate_cek(header.enc)
  use cipher <- result.try(content_encryption.aes_cipher(kw_size, kek))
  use encrypted_key <- result.try(
    block.wrap(cipher, cek)
    |> result.replace_error(gose.CryptoError("AES Key Wrap failed")),
  )

  let out_alg_fields = Pbes2Fields(p2s: Some(salt_input), p2c: Some(iterations))
  finalize_encryption(jwe, cek, encrypted_key, out_alg_fields, plaintext)
}

/// Add a shared unprotected header parameter.
///
/// **Security Warning:** Shared unprotected headers are NOT integrity protected.
/// They can be modified by an attacker without detection.
///
/// Returns an error if the name is a protected-only header (`alg`, `enc`,
/// `crit`, `zip`) which must be integrity protected.
///
/// Shared unprotected headers apply to all recipients in JSON serialization.
/// Compact serialization will return an error if unprotected headers are present.
///
/// If the same header name is set multiple times, the last value wins.
///
/// ## Parameters
///
/// - `jwe` - The unencrypted JWE to add the header to.
/// - `name` - The header parameter name.
/// - `value` - The header parameter value as JSON.
///
/// ## Returns
///
/// `Ok(Jwe)` with the added shared unprotected header, or
/// `Error(GoseError)` if the name is a protected-only header.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(jwe) =
///   jwe.new_direct(jwa.AesGcm(jwa.Aes256))
///   |> jwe.with_shared_unprotected("x-request-id", json.string("abc-123"))
/// ```
pub fn with_shared_unprotected(
  jwe: Jwe(Unencrypted, family, Built),
  name: String,
  value: json.Json,
) -> Result(Jwe(Unencrypted, family, Built), gose.GoseError) {
  use <- bool.guard(
    when: list.contains(protected_only_headers, name),
    return: Error(gose.InvalidState(
      "protected-only header cannot be in unprotected: " <> name,
    )),
  )
  let assert Jwe(shared_unprotected:, ..) = jwe
  Ok(
    Jwe(..jwe, shared_unprotected: dict.insert(shared_unprotected, name, value)),
  )
}

/// Set the type (typ) header parameter (e.g., "JWT").
///
/// ## Parameters
///
/// - `jwe` - The unencrypted JWE.
/// - `typ` - The type string (e.g. `"JWT"`).
///
/// ## Returns
///
/// The `Jwe` with the `typ` header set.
pub fn with_typ(
  jwe: Jwe(Unencrypted, family, Built),
  typ: String,
) -> Jwe(Unencrypted, family, Built) {
  let assert Jwe(header:, ..) = jwe
  Jwe(..jwe, header: JweHeader(..header, typ: Some(typ)))
}

/// Add a per-recipient unprotected header parameter.
///
/// **Security Warning:** Per-recipient unprotected headers are NOT integrity protected.
/// They can be modified by an attacker without detection.
///
/// Returns an error if the name is a protected-only header (`alg`, `enc`,
/// `crit`, `zip`) which must be integrity protected.
///
/// Per-recipient headers appear in JSON serialization only and apply to
/// the single recipient. Compact serialization will return an error if
/// unprotected headers are present.
///
/// If the same header name is set multiple times, the last value wins.
///
/// ## Parameters
///
/// - `jwe` - The unencrypted JWE to add the header to.
/// - `name` - The header parameter name.
/// - `value` - The header parameter value as JSON.
///
/// ## Returns
///
/// `Ok(Jwe)` with the added per-recipient unprotected header, or
/// `Error(GoseError)` if the name is a protected-only header.
pub fn with_unprotected(
  jwe: Jwe(Unencrypted, family, Built),
  name: String,
  value: json.Json,
) -> Result(Jwe(Unencrypted, family, Built), gose.GoseError) {
  use <- bool.guard(
    when: list.contains(protected_only_headers, name),
    return: Error(gose.InvalidState(
      "protected-only header cannot be in unprotected: " <> name,
    )),
  )
  let assert Jwe(per_recipient_unprotected:, ..) = jwe
  Ok(
    Jwe(
      ..jwe,
      per_recipient_unprotected: dict.insert(
        per_recipient_unprotected,
        name,
        value,
      ),
    ),
  )
}

/// Get the Additional Authenticated Data (AAD) from an encrypted JWE.
///
/// Returns `Ok(aad)` if AAD was set, `Error(Nil)` if not.
/// AAD is only present in JSON serialization; compact format never has AAD.
///
/// ## Parameters
///
/// - `jwe` - The encrypted JWE to read AAD from.
///
/// ## Returns
///
/// `Ok(BitArray)` with the AAD, or `Error(Nil)` if no AAD is present.
pub fn aad(jwe: Jwe(Encrypted, family, origin)) -> Result(BitArray, Nil) {
  let assert EncryptedJwe(aad:, ..) = jwe
  option.to_result(aad, Nil)
}

/// Get the key encryption algorithm (`alg`) from a JWE.
///
/// ## Parameters
///
/// - `jwe` - The JWE to read the algorithm from.
///
/// ## Returns
///
/// The `JweAlg` key encryption algorithm.
pub fn alg(jwe: Jwe(state, family, origin)) -> jwa.JweAlg {
  case jwe {
    Jwe(header:, ..) | EncryptedJwe(header:, ..) -> header.alg
  }
}

/// Get the content type (cty) from a JWE header.
///
/// ## Parameters
///
/// - `jwe` - The JWE to read the content type from.
///
/// ## Returns
///
/// `Ok(String)` with the content type, or `Error(Nil)` if not set.
pub fn cty(jwe: Jwe(state, family, origin)) -> Result(String, Nil) {
  case jwe {
    Jwe(header:, ..) | EncryptedJwe(header:, ..) ->
      option.to_result(header.cty, Nil)
  }
}

/// Decode the shared unprotected header using a custom decoder.
///
/// **Security Warning:** Shared unprotected headers are NOT integrity protected.
/// Values can be modified by an attacker without detection. Never trust
/// security-critical parameters from unprotected headers.
///
/// This function only works on parsed JWE instances. When building a JWE,
/// you already know what unprotected headers you set - use `has_shared_unprotected_header`
/// to check their presence.
///
/// Returns an error if no shared unprotected headers are present.
///
/// ## Parameters
///
/// - `jwe` - The parsed encrypted JWE to decode headers from.
/// - `decoder` - A decoder for the expected header structure.
///
/// ## Returns
///
/// `Ok(a)` with the decoded shared unprotected header value, or
/// `Error(GoseError)` if no shared unprotected headers are present or
/// decoding fails.
///
/// ## Example
///
/// ```gleam
/// let decoder = {
///   use id <- decode.field("x-request-id", decode.string)
///   decode.success(id)
/// }
/// let assert Ok(request_id) =
///   jwe.decode_shared_unprotected_header(parsed_jwe, decoder)
/// ```
pub fn decode_shared_unprotected_header(
  jwe: Jwe(Encrypted, family, Parsed),
  decoder: decode.Decoder(a),
) -> Result(a, gose.GoseError) {
  let assert EncryptedJwe(shared_unprotected_raw:, ..) = jwe
  case shared_unprotected_raw {
    Some(raw) ->
      decode.run(raw, decoder)
      |> result.replace_error(gose.ParseError(
        "failed to decode shared unprotected header",
      ))
    None -> Error(gose.ParseError("no shared unprotected headers present"))
  }
}

/// Decode the per-recipient unprotected header using a custom decoder.
///
/// **Security Warning:** Per-recipient unprotected headers are NOT integrity protected.
/// Values can be modified by an attacker without detection. Never trust
/// security-critical parameters from unprotected headers.
///
/// This function only works on parsed JWE instances. When building a JWE,
/// you already know what unprotected headers you set - use `has_unprotected_header`
/// to check their presence.
///
/// Returns an error if no per-recipient unprotected headers are present.
///
/// ## Parameters
///
/// - `jwe` - The parsed encrypted JWE to decode headers from.
/// - `decoder` - A decoder for the expected header structure.
///
/// ## Returns
///
/// `Ok(a)` with the decoded per-recipient unprotected header value, or
/// `Error(GoseError)` if no per-recipient unprotected headers are present
/// or decoding fails.
///
/// ## Example
///
/// ```gleam
/// let decoder = {
///   use id <- decode.field("x-recipient-id", decode.string)
///   decode.success(id)
/// }
/// let assert Ok(recipient_id) =
///   jwe.decode_unprotected_header(parsed_jwe, decoder)
/// ```
pub fn decode_unprotected_header(
  jwe: Jwe(Encrypted, family, Parsed),
  decoder: decode.Decoder(a),
) -> Result(a, gose.GoseError) {
  let assert EncryptedJwe(per_recipient_unprotected_raw:, ..) = jwe
  case per_recipient_unprotected_raw {
    Some(raw) ->
      decode.run(raw, decoder)
      |> result.replace_error(gose.ParseError(
        "failed to decode per-recipient unprotected header",
      ))
    None ->
      Error(gose.ParseError("no per-recipient unprotected headers present"))
  }
}

/// Get the content encryption algorithm (`enc`) from a JWE.
///
/// ## Parameters
///
/// - `jwe` - The JWE to read the encryption algorithm from.
///
/// ## Returns
///
/// The `Enc` content encryption algorithm.
pub fn enc(jwe: Jwe(state, family, origin)) -> jwa.Enc {
  case jwe {
    Jwe(header:, ..) | EncryptedJwe(header:, ..) -> header.enc
  }
}

/// Check if shared unprotected headers are present.
///
/// Returns True if the JWE was parsed from JSON with shared unprotected headers,
/// or if shared unprotected headers were added via `with_shared_unprotected`.
///
/// ## Parameters
///
/// - `jwe` - The encrypted JWE to check.
///
/// ## Returns
///
/// `True` if shared unprotected headers are present, `False` otherwise.
pub fn has_shared_unprotected_header(
  jwe: Jwe(Encrypted, family, origin),
) -> Bool {
  let assert EncryptedJwe(shared_unprotected:, shared_unprotected_raw:, ..) =
    jwe
  option.is_some(shared_unprotected_raw) || !dict.is_empty(shared_unprotected)
}

/// Check if per-recipient unprotected headers are present.
///
/// Returns True if the JWE was parsed from JSON with per-recipient unprotected headers,
/// or if per-recipient unprotected headers were added via `with_unprotected`.
///
/// ## Parameters
///
/// - `jwe` - The encrypted JWE to check.
///
/// ## Returns
///
/// `True` if per-recipient unprotected headers are present, `False` otherwise.
pub fn has_unprotected_header(jwe: Jwe(Encrypted, family, origin)) -> Bool {
  let assert EncryptedJwe(
    per_recipient_unprotected:,
    per_recipient_unprotected_raw:,
    ..,
  ) = jwe
  option.is_some(per_recipient_unprotected_raw)
  || !dict.is_empty(per_recipient_unprotected)
}

/// Get the key ID (kid) from a JWE header.
///
/// ## Parameters
///
/// - `jwe` - The JWE to read the key ID from.
///
/// ## Returns
///
/// `Ok(String)` with the key ID, or `Error(Nil)` if not set.
pub fn kid(jwe: Jwe(state, family, origin)) -> Result(String, Nil) {
  case jwe {
    Jwe(header:, ..) | EncryptedJwe(header:, ..) ->
      option.to_result(header.kid, Nil)
  }
}

/// Get the type (typ) from a JWE header.
///
/// ## Parameters
///
/// - `jwe` - The JWE to read the type from.
///
/// ## Returns
///
/// `Ok(String)` with the type, or `Error(Nil)` if not set.
pub fn typ(jwe: Jwe(state, family, origin)) -> Result(String, Nil) {
  case jwe {
    Jwe(header:, ..) | EncryptedJwe(header:, ..) ->
      option.to_result(header.typ, Nil)
  }
}

fn finalize_encryption(
  jwe: Jwe(Unencrypted, family, Built),
  cek: BitArray,
  encrypted_key: BitArray,
  alg_fields: AlgFields,
  plaintext: BitArray,
) -> Result(Jwe(Encrypted, family, Built), gose.GoseError) {
  let assert Jwe(
    header:,
    aad:,
    shared_unprotected:,
    per_recipient_unprotected:,
    ..,
  ) = jwe
  let iv = content_encryption.generate_iv(header.enc)
  let protected_json = header_to_json(header, alg_fields)
  let protected_b64 = utils.encode_base64_url(protected_json)
  let aead_aad = content_encryption.compute_aead_aad(protected_b64, aad)

  use #(ciphertext, tag) <- result.try(content_encryption.encrypt_content(
    header.enc,
    cek,
    iv,
    aead_aad,
    plaintext,
  ))

  Ok(EncryptedJwe(
    header:,
    protected_b64:,
    encrypted_key:,
    iv:,
    ciphertext:,
    tag:,
    alg_fields:,
    aad:,
    shared_unprotected:,
    shared_unprotected_raw: None,
    per_recipient_unprotected:,
    per_recipient_unprotected_raw: None,
  ))
}

fn do_encrypt_aes_gcm_kw(
  jwe: Jwe(Unencrypted, family, Built),
  key: jwk.Jwk,
  plaintext: BitArray,
) -> Result(Jwe(Encrypted, family, Built), gose.GoseError) {
  let assert Jwe(
    header:,
    alg_fields: AesGcmKwFields(kw_iv: custom_kw_iv, ..),
    ..,
  ) = jwe

  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(
    header.alg,
    key,
  ))
  let assert jwa.JweAesKeyWrap(_, aes_size) = header.alg
  use kek <- result.try(key_wrap.get_octet_key(
    key,
    jwa.aes_key_size_in_bytes(aes_size),
  ))

  let cek = content_encryption.generate_cek(header.enc)
  let kw_iv = case custom_kw_iv {
    Some(iv) -> iv
    None -> crypto.random_bytes(12)
  }

  use #(encrypted_cek, kw_tag) <- result.try(key_wrap.wrap_aes_gcm(
    kek,
    cek,
    kw_iv,
    aes_size,
  ))

  let out_alg_fields = AesGcmKwFields(kw_iv: Some(kw_iv), kw_tag: Some(kw_tag))
  finalize_encryption(jwe, cek, encrypted_cek, out_alg_fields, plaintext)
}

fn do_encrypt_chacha20_kw(
  jwe: Jwe(Unencrypted, family, Built),
  key: jwk.Jwk,
  plaintext: BitArray,
) -> Result(Jwe(Encrypted, family, Built), gose.GoseError) {
  let assert Jwe(header:, ..) = jwe

  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(
    header.alg,
    key,
  ))
  let assert jwa.JweChaCha20KeyWrap(variant) = header.alg
  use kek <- result.try(key_wrap.get_octet_key(key, 32))

  let cek = content_encryption.generate_cek(header.enc)
  let nonce_size = jwa.chacha20_kw_nonce_size(variant)
  let kw_iv = crypto.random_bytes(nonce_size)

  use #(encrypted_cek, kw_tag) <- result.try(key_wrap.wrap_chacha20_by_variant(
    kek,
    cek,
    kw_iv,
    variant,
  ))

  let out_alg_fields =
    ChaCha20KwFields(kw_iv: Some(kw_iv), kw_tag: Some(kw_tag))
  finalize_encryption(jwe, cek, encrypted_cek, out_alg_fields, plaintext)
}

fn do_encrypt_aes_kw(
  jwe: Jwe(Unencrypted, family, Built),
  key: jwk.Jwk,
  plaintext: BitArray,
) -> Result(Jwe(Encrypted, family, Built), gose.GoseError) {
  let assert Jwe(header:, ..) = jwe

  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(
    header.alg,
    key,
  ))
  let cek = content_encryption.generate_cek(header.enc)
  let assert jwa.JweAesKeyWrap(_, aes_size) = header.alg
  use encrypted_key <- result.try(key_wrap.wrap_aes_kw(key, cek, aes_size))

  finalize_encryption(jwe, cek, encrypted_key, NoAlgFields, plaintext)
}

fn do_encrypt_direct(
  jwe: Jwe(Unencrypted, family, Built),
  key: jwk.Jwk,
  plaintext: BitArray,
) -> Result(Jwe(Encrypted, family, Built), gose.GoseError) {
  let assert Jwe(header:, ..) = jwe

  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(
    header.alg,
    key,
  ))
  use cek <- result.try(key_wrap.unwrap_direct(key, header.enc))

  finalize_encryption(jwe, cek, <<>>, NoAlgFields, plaintext)
}

fn wrap_ecdh_by_alg(
  alg: jwa.EcdhEsAlg,
  enc: jwa.Enc,
  key: jwk.Jwk,
  apu: Option(BitArray),
  apv: Option(BitArray),
) -> Result(#(BitArray, BitArray, AlgFields), gose.GoseError) {
  case alg {
    jwa.EcdhEsDirect -> {
      use #(derived_cek, epk) <- result.try(key_wrap.wrap_ecdh_es_direct(
        key,
        enc,
        apu,
        apv,
      ))
      Ok(#(derived_cek, <<>>, EcdhEsFields(epk: Some(epk), apu:, apv:)))
    }
    jwa.EcdhEsAesKw(size) -> {
      let cek = content_encryption.generate_cek(enc)
      use #(wrapped, epk) <- result.try(key_wrap.wrap_ecdh_es_kw(
        key,
        cek,
        size,
        apu,
        apv,
      ))
      Ok(#(cek, wrapped, EcdhEsFields(epk: Some(epk), apu:, apv:)))
    }
    jwa.EcdhEsChaCha20Kw(variant) -> {
      let cek = content_encryption.generate_cek(enc)
      use #(encrypted_cek, epk, kw_iv, kw_tag) <- result.try(
        key_wrap.wrap_ecdh_es_chacha20_kw(key, cek, variant, apu, apv),
      )
      Ok(#(
        cek,
        encrypted_cek,
        EcdhEsChaCha20KwFields(
          epk: Some(epk),
          apu:,
          apv:,
          kw_iv: Some(kw_iv),
          kw_tag: Some(kw_tag),
        ),
      ))
    }
  }
}

fn extract_ecdh_apu_apv(
  alg_fields: AlgFields,
) -> #(Option(BitArray), Option(BitArray)) {
  case alg_fields {
    EcdhEsFields(apu:, apv:, ..) -> #(apu, apv)
    EcdhEsChaCha20KwFields(apu:, apv:, ..) -> #(apu, apv)
    NoAlgFields | Pbes2Fields(..) | AesGcmKwFields(..) | ChaCha20KwFields(..) ->
      panic as "extract_ecdh_apu_apv called with non-ECDH alg_fields"
  }
}

fn do_encrypt_ecdh(
  jwe: Jwe(Unencrypted, family, Built),
  key: jwk.Jwk,
  plaintext: BitArray,
) -> Result(Jwe(Encrypted, family, Built), gose.GoseError) {
  let assert Jwe(header:, ..) = jwe

  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(
    header.alg,
    key,
  ))

  let #(apu, apv) = extract_ecdh_apu_apv(jwe.alg_fields)
  use <- bool.guard(
    when: option.is_some(apu) && option.is_some(apv) && apu == apv,
    return: Error(gose.InvalidState("apu and apv must be distinct")),
  )

  let assert jwa.JweEcdhEs(ecdh_alg) = header.alg
  use #(cek, encrypted_key, out_alg_fields) <- result.try(wrap_ecdh_by_alg(
    ecdh_alg,
    header.enc,
    key,
    apu,
    apv,
  ))
  finalize_encryption(jwe, cek, encrypted_key, out_alg_fields, plaintext)
}

fn wrap_rsa_by_alg(
  alg: jwa.RsaJweAlg,
  key: jwk.Jwk,
  cek: BitArray,
) -> Result(BitArray, gose.GoseError) {
  case alg {
    jwa.RsaPkcs1v15 -> key_wrap.wrap_rsa_pkcs1v15(key, cek)
    jwa.RsaOaepSha1 -> key_wrap.wrap_rsa_oaep(key, cek, hash.Sha1)
    jwa.RsaOaepSha256 -> key_wrap.wrap_rsa_oaep(key, cek, hash.Sha256)
  }
}

fn do_encrypt_rsa(
  jwe: Jwe(Unencrypted, family, Built),
  key: jwk.Jwk,
  plaintext: BitArray,
) -> Result(Jwe(Encrypted, family, Built), gose.GoseError) {
  let assert Jwe(header:, ..) = jwe

  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(
    header.alg,
    key,
  ))
  let cek = content_encryption.generate_cek(header.enc)
  let assert jwa.JweRsa(rsa_alg) = header.alg
  use encrypted_key <- result.try(wrap_rsa_by_alg(rsa_alg, key, cek))

  finalize_encryption(jwe, cek, encrypted_key, NoAlgFields, plaintext)
}

fn unwrap_cek(
  header: JweHeader,
  alg_fields: AlgFields,
  key: jwk.Jwk,
  encrypted_key: BitArray,
) -> Result(BitArray, gose.GoseError) {
  case header.alg {
    jwa.JweDirect -> key_wrap.unwrap_direct(key, header.enc)
    jwa.JweAesKeyWrap(jwa.AesKw, aes_size) ->
      key_wrap.unwrap_aes_kw(key, encrypted_key, aes_size)
    jwa.JweAesKeyWrap(jwa.AesGcmKw, aes_size) -> {
      use #(kw_iv, kw_tag) <- result.try(require_aes_gcm_kw_fields(alg_fields))
      key_wrap.unwrap_aes_gcm_kw(key, encrypted_key, aes_size, kw_iv, kw_tag)
    }
    jwa.JweRsa(jwa.RsaPkcs1v15) ->
      Ok(key_wrap.unwrap_rsa_pkcs1v15_safe(key, encrypted_key, header.enc))
    jwa.JweRsa(jwa.RsaOaepSha1) ->
      key_wrap.unwrap_rsa_oaep(key, encrypted_key, hash.Sha1)
    jwa.JweRsa(jwa.RsaOaepSha256) ->
      key_wrap.unwrap_rsa_oaep(key, encrypted_key, hash.Sha256)
    jwa.JweChaCha20KeyWrap(variant) -> {
      use #(kw_iv, kw_tag) <- result.try(require_chacha20_kw_fields(alg_fields))
      key_wrap.unwrap_chacha20_kw(key, encrypted_key, variant, kw_iv, kw_tag)
    }
    jwa.JweEcdhEs(ecdh_alg) ->
      unwrap_cek_ecdh(ecdh_alg, alg_fields, key, encrypted_key, header.enc)
    jwa.JwePbes2(_) ->
      Error(gose.InvalidState("use password_decryptor for PBES2 algorithms"))
  }
}

fn unwrap_cek_ecdh(
  ecdh_alg: jwa.EcdhEsAlg,
  alg_fields: AlgFields,
  key: jwk.Jwk,
  encrypted_key: BitArray,
  enc: jwa.Enc,
) -> Result(BitArray, gose.GoseError) {
  case ecdh_alg {
    jwa.EcdhEsDirect -> {
      use #(epk, apu, apv) <- result.try(require_ecdh_es_fields(alg_fields))
      use epk_val <- result.try(option.to_result(
        epk,
        gose.InvalidState("missing epk in header"),
      ))
      key_wrap.unwrap_ecdh_es_direct(key, enc, epk_val, apu, apv)
    }
    jwa.EcdhEsAesKw(size) -> {
      use #(epk, apu, apv) <- result.try(require_ecdh_es_fields(alg_fields))
      use epk_val <- result.try(option.to_result(
        epk,
        gose.InvalidState("missing epk in header"),
      ))
      key_wrap.unwrap_ecdh_es_kw(key, encrypted_key, size, epk_val, apu, apv)
    }
    jwa.EcdhEsChaCha20Kw(variant) -> {
      use #(epk, apu, apv, kw_iv, kw_tag) <- result.try(
        require_ecdh_es_chacha20_kw_fields(alg_fields),
      )
      use epk_val <- result.try(option.to_result(
        epk,
        gose.InvalidState("missing epk in header"),
      ))
      use iv <- result.try(option.to_result(
        kw_iv,
        gose.ParseError("missing iv header for ECDH-ES+ChaCha20 Key Wrap"),
      ))
      use tag <- result.try(option.to_result(
        kw_tag,
        gose.ParseError("missing tag header for ECDH-ES+ChaCha20 Key Wrap"),
      ))
      key_wrap.unwrap_ecdh_es_chacha20_kw(
        key,
        encrypted_key,
        variant,
        epk_val,
        apu,
        apv,
        iv,
        tag,
      )
    }
  }
}

fn require_aes_gcm_kw_fields(
  alg_fields: AlgFields,
) -> Result(#(Option(BitArray), Option(BitArray)), gose.GoseError) {
  case alg_fields {
    AesGcmKwFields(kw_iv:, kw_tag:) -> Ok(#(kw_iv, kw_tag))
    NoAlgFields
    | EcdhEsFields(..)
    | Pbes2Fields(..)
    | ChaCha20KwFields(..)
    | EcdhEsChaCha20KwFields(..) ->
      Error(gose.InvalidState("expected AES-GCM key wrap fields"))
  }
}

fn require_chacha20_kw_fields(
  alg_fields: AlgFields,
) -> Result(#(Option(BitArray), Option(BitArray)), gose.GoseError) {
  case alg_fields {
    ChaCha20KwFields(kw_iv:, kw_tag:) -> Ok(#(kw_iv, kw_tag))
    NoAlgFields
    | EcdhEsFields(..)
    | Pbes2Fields(..)
    | AesGcmKwFields(..)
    | EcdhEsChaCha20KwFields(..) ->
      Error(gose.InvalidState("expected ChaCha20 key wrap fields"))
  }
}

fn require_ecdh_es_fields(
  alg_fields: AlgFields,
) -> Result(
  #(Option(key_wrap.EphemeralPublicKey), Option(BitArray), Option(BitArray)),
  gose.GoseError,
) {
  case alg_fields {
    EcdhEsFields(epk:, apu:, apv:) -> Ok(#(epk, apu, apv))
    NoAlgFields
    | Pbes2Fields(..)
    | AesGcmKwFields(..)
    | ChaCha20KwFields(..)
    | EcdhEsChaCha20KwFields(..) ->
      Error(gose.InvalidState("expected ECDH-ES fields"))
  }
}

fn require_ecdh_es_chacha20_kw_fields(
  alg_fields: AlgFields,
) -> Result(
  #(
    Option(key_wrap.EphemeralPublicKey),
    Option(BitArray),
    Option(BitArray),
    Option(BitArray),
    Option(BitArray),
  ),
  gose.GoseError,
) {
  case alg_fields {
    EcdhEsChaCha20KwFields(epk:, apu:, apv:, kw_iv:, kw_tag:) ->
      Ok(#(epk, apu, apv, kw_iv, kw_tag))
    NoAlgFields
    | EcdhEsFields(..)
    | Pbes2Fields(..)
    | AesGcmKwFields(..)
    | ChaCha20KwFields(..) ->
      Error(gose.InvalidState("expected ECDH-ES+ChaCha20 key wrap fields"))
  }
}

fn require_pbes2_fields(
  alg_fields: AlgFields,
) -> Result(#(Option(BitArray), Option(Int)), gose.GoseError) {
  case alg_fields {
    Pbes2Fields(p2s:, p2c:) -> Ok(#(p2s, p2c))
    NoAlgFields
    | EcdhEsFields(..)
    | AesGcmKwFields(..)
    | ChaCha20KwFields(..)
    | EcdhEsChaCha20KwFields(..) ->
      Error(gose.InvalidState("expected PBES2 fields"))
  }
}

fn decrypt_with_key(
  jwe: Jwe(Encrypted, family, origin),
  key: jwk.Jwk,
) -> Result(BitArray, gose.GoseError) {
  let assert EncryptedJwe(
    header:,
    protected_b64:,
    encrypted_key:,
    iv:,
    ciphertext:,
    tag:,
    alg_fields:,
    aad: user_aad,
    ..,
  ) = jwe

  use _ <- result.try(key_helpers.validate_key_use(
    key,
    key_helpers.ForDecryption,
  ))
  use _ <- result.try(key_helpers.validate_key_ops(
    key,
    key_helpers.ForDecryption,
  ))
  use _ <- result.try(key_helpers.validate_key_algorithm_jwe(key, header.alg))

  use cek <- result.try(unwrap_cek(header, alg_fields, key, encrypted_key))

  let aead_aad = content_encryption.compute_aead_aad(protected_b64, user_aad)
  content_encryption.decrypt_content(
    header.enc,
    cek,
    iv,
    aead_aad,
    ciphertext,
    tag,
  )
}

fn require_pbes2_alg(alg: jwa.JweAlg) -> Result(jwa.Pbes2Alg, gose.GoseError) {
  case alg {
    jwa.JwePbes2(pbes2_alg) -> Ok(pbes2_alg)
    jwa.JweDirect
    | jwa.JweAesKeyWrap(..)
    | jwa.JweChaCha20KeyWrap(..)
    | jwa.JweRsa(..)
    | jwa.JweEcdhEs(..) -> Error(gose.InvalidState("expected PBES2 algorithm"))
  }
}

fn resolve_pbes2_params(
  alg: jwa.Pbes2Alg,
) -> #(HashAlgorithm, jwa.AesKeySize, Int) {
  case alg {
    jwa.Pbes2Sha256Aes128Kw -> #(hash.Sha256, jwa.Aes128, 310_000)
    jwa.Pbes2Sha384Aes192Kw -> #(hash.Sha384, jwa.Aes192, 250_000)
    jwa.Pbes2Sha512Aes256Kw -> #(hash.Sha512, jwa.Aes256, 120_000)
  }
}

fn decrypt_with_password(
  jwe: Jwe(Encrypted, family, origin),
  password: String,
) -> Result(BitArray, gose.GoseError) {
  let assert EncryptedJwe(
    header:,
    protected_b64:,
    encrypted_key:,
    iv:,
    ciphertext:,
    tag:,
    alg_fields:,
    aad: user_aad,
    ..,
  ) = jwe

  use pbes2_alg <- result.try(require_pbes2_alg(header.alg))
  let #(hash_alg, kw_size, _) = resolve_pbes2_params(pbes2_alg)
  let kw_key_len = jwa.aes_key_size_in_bytes(kw_size)

  use #(p2s, p2c) <- result.try(require_pbes2_fields(alg_fields))
  use salt_input <- result.try(option.to_result(
    p2s,
    gose.ParseError("missing p2s in header"),
  ))
  use iterations <- result.try(option.to_result(
    p2c,
    gose.ParseError("missing p2c in header"),
  ))

  let alg_str = jwa.jwe_alg_to_string(header.alg)
  let salt =
    bit_array.concat([bit_array.from_string(alg_str), <<0>>, salt_input])

  use kek <- result.try(
    crypto.pbkdf2(
      hash_alg,
      password: bit_array.from_string(password),
      salt:,
      iterations:,
      length: kw_key_len,
    )
    |> result.replace_error(gose.CryptoError("PBKDF2 key derivation failed")),
  )

  use cipher <- result.try(content_encryption.aes_cipher(kw_size, kek))
  use cek <- result.try(
    block.unwrap(cipher, encrypted_key)
    |> result.replace_error(gose.CryptoError("AES Key Unwrap failed")),
  )

  let aead_aad = content_encryption.compute_aead_aad(protected_b64, user_aad)
  content_encryption.decrypt_content(
    header.enc,
    cek,
    iv,
    aead_aad,
    ciphertext,
    tag,
  )
}

/// Decrypt a JWE using a decryptor with algorithm pinning.
///
/// This is the recommended way to decrypt JWEs as it prevents algorithm
/// confusion attacks by validating that the token's algorithms match
/// the expected algorithms configured in the decryptor.
///
/// ## Parameters
///
/// - `decryptor` - A decryptor that pins the expected algorithms and provides keys or a password.
/// - `jwe` - The encrypted JWE to decrypt.
///
/// ## Returns
///
/// `Ok(BitArray)` with the decrypted plaintext, or `Error(GoseError)` if
/// algorithm validation fails, the key is wrong, or decryption fails.
///
/// ## Example
///
/// ```gleam
/// // Create a decryptor that only accepts A256GCM with direct encryption
/// let assert Ok(decryptor) = jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
///
/// // This will fail if the token uses a different algorithm
/// let assert Ok(plaintext) = jwe.decrypt(decryptor, jwe)
/// ```
pub fn decrypt(
  decryptor: Decryptor,
  jwe: Jwe(Encrypted, family, origin),
) -> Result(BitArray, gose.GoseError) {
  let assert EncryptedJwe(header:, ..) = jwe

  use _ <- result.try(require_matching_jwe_algorithms(
    decryptor,
    header.alg,
    header.enc,
  ))

  case decryptor {
    KeyDecryptor(keys:, ..) -> decrypt_with_keys(jwe, keys, decrypt_with_key)
    PasswordDecryptor(password:, ..) -> decrypt_with_password(jwe, password)
  }
}

fn require_matching_jwe_algorithms(
  decryptor: Decryptor,
  actual_alg: jwa.JweAlg,
  actual_enc: jwa.Enc,
) -> Result(Nil, gose.GoseError) {
  let #(expected_alg, expected_enc) = case decryptor {
    KeyDecryptor(alg:, enc:, ..) -> #(alg, enc)
    PasswordDecryptor(alg:, enc:, ..) -> #(jwa.JwePbes2(alg), enc)
  }

  use <- bool.guard(
    when: expected_alg != actual_alg,
    return: Error(gose.InvalidState(
      "algorithm mismatch: expected "
      <> jwa.jwe_alg_to_string(expected_alg)
      <> ", got "
      <> jwa.jwe_alg_to_string(actual_alg),
    )),
  )
  use <- bool.guard(
    when: expected_enc != actual_enc,
    return: Error(gose.InvalidState(
      "encryption mismatch: expected "
      <> jwa.enc_to_string(expected_enc)
      <> ", got "
      <> jwa.enc_to_string(actual_enc),
    )),
  )

  Ok(Nil)
}

fn decrypt_with_keys(
  jwe: Jwe(Encrypted, family, origin),
  keys: List(jwk.Jwk),
  decrypt_fn: fn(Jwe(Encrypted, family, origin), jwk.Jwk) ->
    Result(BitArray, gose.GoseError),
) -> Result(BitArray, gose.GoseError) {
  let jwe_kid = kid(jwe) |> result.unwrap("")

  let ordered_keys = case jwe_kid {
    "" -> keys
    target_kid -> {
      let #(matching, others) =
        list.partition(keys, fn(key) { jwk.kid(key) == Ok(target_kid) })
      list.append(matching, others)
    }
  }

  try_keys(
    ordered_keys,
    jwe,
    decrypt_fn,
    Error(gose.InvalidState("no keys provided")),
  )
}

fn try_keys(
  keys: List(jwk.Jwk),
  jwe: Jwe(Encrypted, family, origin),
  decrypt_fn: fn(Jwe(Encrypted, family, origin), jwk.Jwk) ->
    Result(BitArray, gose.GoseError),
  last_error: Result(BitArray, gose.GoseError),
) -> Result(BitArray, gose.GoseError) {
  case keys {
    [] -> last_error
    [key, ..rest] ->
      case decrypt_fn(jwe, key) {
        Ok(plaintext) -> Ok(plaintext)
        Error(e) -> try_keys(rest, jwe, decrypt_fn, Error(e))
      }
  }
}

fn header_to_json(header: JweHeader, alg_fields: AlgFields) -> BitArray {
  let alg_field = #("alg", json.string(jwa.jwe_alg_to_string(header.alg)))
  let enc_field = #("enc", json.string(jwa.enc_to_string(header.enc)))

  let optional_fields =
    [
      option.map(header.kid, fn(k) { #("kid", json.string(k)) }),
      option.map(header.typ, fn(t) { #("typ", json.string(t)) }),
      option.map(header.cty, fn(c) { #("cty", json.string(c)) }),
      ..alg_fields_to_json(alg_fields)
    ]
    |> list.filter_map(option.to_result(_, Nil))

  let fields = [alg_field, enc_field, ..optional_fields]
  json.object(fields)
  |> json.to_string
  |> bit_array.from_string
}

fn alg_fields_to_json(
  alg_fields: AlgFields,
) -> List(Option(#(String, json.Json))) {
  case alg_fields {
    NoAlgFields -> []
    EcdhEsFields(epk:, apu:, apv:) -> [
      option.map(epk, epk_to_json_field),
      option.map(apu, fn(a) {
        #("apu", json.string(utils.encode_base64_url(a)))
      }),
      option.map(apv, fn(a) {
        #("apv", json.string(utils.encode_base64_url(a)))
      }),
    ]
    Pbes2Fields(p2s:, p2c:) -> [
      option.map(p2s, fn(s) {
        #("p2s", json.string(utils.encode_base64_url(s)))
      }),
      option.map(p2c, fn(c) { #("p2c", json.int(c)) }),
    ]
    AesGcmKwFields(kw_iv:, kw_tag:) -> [
      option.map(kw_iv, fn(iv) {
        #("iv", json.string(utils.encode_base64_url(iv)))
      }),
      option.map(kw_tag, fn(t) {
        #("tag", json.string(utils.encode_base64_url(t)))
      }),
    ]
    ChaCha20KwFields(kw_iv:, kw_tag:) -> [
      option.map(kw_iv, fn(iv) {
        #("iv", json.string(utils.encode_base64_url(iv)))
      }),
      option.map(kw_tag, fn(t) {
        #("tag", json.string(utils.encode_base64_url(t)))
      }),
    ]
    EcdhEsChaCha20KwFields(epk:, apu:, apv:, kw_iv:, kw_tag:) -> [
      option.map(epk, epk_to_json_field),
      option.map(apu, fn(a) {
        #("apu", json.string(utils.encode_base64_url(a)))
      }),
      option.map(apv, fn(a) {
        #("apv", json.string(utils.encode_base64_url(a)))
      }),
      option.map(kw_iv, fn(iv) {
        #("iv", json.string(utils.encode_base64_url(iv)))
      }),
      option.map(kw_tag, fn(t) {
        #("tag", json.string(utils.encode_base64_url(t)))
      }),
    ]
  }
}

fn epk_to_json_field(epk: key_wrap.EphemeralPublicKey) -> #(String, json.Json) {
  case epk {
    key_wrap.EcEphemeralKey(curve:, x:, y:) -> #(
      "epk",
      json.object([
        #("kty", json.string("EC")),
        #("crv", json.string(utils.ec_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x))),
        #("y", json.string(utils.encode_base64_url(y))),
      ]),
    )
    key_wrap.XdhEphemeralKey(curve:, x:) -> #(
      "epk",
      json.object([
        #("kty", json.string("OKP")),
        #("crv", json.string(utils.xdh_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x))),
      ]),
    )
  }
}

/// Serialize an encrypted JWE to compact format.
///
/// Format: `{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}`
///
/// Returns an error if AAD is set, since compact format does not support AAD.
/// Use `serialize_json_flattened` or `serialize_json_general` for JWEs with AAD.
///
/// ## Parameters
///
/// - `jwe` - The encrypted JWE to serialize.
///
/// ## Returns
///
/// `Ok(String)` with the JWE in compact serialization format, or
/// `Error(GoseError)` if AAD or unprotected headers are present.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(token) = jwe.serialize_compact(encrypted)
/// // -> "eyJhbGci...ciphertext...tag"
/// ```
pub fn serialize_compact(
  jwe: Jwe(Encrypted, family, Built),
) -> Result(String, gose.GoseError) {
  let assert EncryptedJwe(
    protected_b64:,
    encrypted_key:,
    iv:,
    ciphertext:,
    tag:,
    aad:,
    shared_unprotected:,
    per_recipient_unprotected:,
    ..,
  ) = jwe
  use <- bool.guard(
    when: option.is_some(aad),
    return: Error(gose.InvalidState(
      "cannot serialize to compact format: AAD is only supported in JSON serialization",
    )),
  )
  use <- bool.guard(
    when: !dict.is_empty(shared_unprotected)
      || !dict.is_empty(per_recipient_unprotected),
    return: Error(gose.InvalidState(
      "cannot serialize to compact format: unprotected headers are only supported in JSON serialization",
    )),
  )
  let ek_b64 = utils.encode_base64_url(encrypted_key)
  let iv_b64 = utils.encode_base64_url(iv)
  let ct_b64 = utils.encode_base64_url(ciphertext)
  let tag_b64 = utils.encode_base64_url(tag)
  Ok(
    protected_b64
    <> "."
    <> ek_b64
    <> "."
    <> iv_b64
    <> "."
    <> ct_b64
    <> "."
    <> tag_b64,
  )
}

/// Parse a JWE from compact format.
///
/// Returns an encrypted JWE that can be decrypted.
/// Uses Nil family since algorithm family isn't known at compile time.
///
/// ## Parameters
///
/// - `token` - The compact-serialized JWE string to parse.
///
/// ## Returns
///
/// `Ok(Jwe(Encrypted, Nil, Parsed))` with the parsed encrypted JWE, or
/// `Error(GoseError)` if the token is malformed or contains invalid data.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(parsed) = jwe.parse_compact(token)
/// let assert Ok(decryptor) = jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
/// let assert Ok(plaintext) = jwe.decrypt(decryptor, parsed)
/// ```
pub fn parse_compact(
  token: String,
) -> Result(Jwe(Encrypted, Nil, Parsed), gose.GoseError) {
  case string.split(token, ".") {
    [protected_b64, ek_b64, iv_b64, ct_b64, tag_b64] -> {
      use ParsedHeader(header:, alg_fields:) <- result.try(
        parse_protected_header(protected_b64),
      )
      use encrypted_key <- result.try(utils.decode_base64_url(
        ek_b64,
        "encrypted_key",
      ))
      use _ <- result.try(validate_encrypted_key_for_algorithm(
        header.alg,
        encrypted_key,
      ))
      use iv <- result.try(utils.decode_base64_url(iv_b64, "iv"))
      use ciphertext <- result.try(utils.decode_base64_url(ct_b64, "ciphertext"))
      use tag <- result.try(utils.decode_base64_url(tag_b64, "tag"))
      use _ <- result.try(content_encryption.validate_iv_tag_sizes(
        header.enc,
        iv,
        tag,
      ))
      Ok(EncryptedJwe(
        header:,
        protected_b64:,
        encrypted_key:,
        iv:,
        ciphertext:,
        tag:,
        alg_fields:,
        aad: None,
        shared_unprotected: dict.new(),
        shared_unprotected_raw: None,
        per_recipient_unprotected: dict.new(),
        per_recipient_unprotected_raw: None,
      ))
    }
    _ ->
      Error(gose.ParseError("invalid compact serialization: expected 5 parts"))
  }
}

fn parse_protected_header(b64: String) -> Result(ParsedHeader, gose.GoseError) {
  use header_bits <- result.try(utils.decode_base64_url(b64, "header"))
  parse_header_json(header_bits)
}

fn parse_header_json(
  json_bits: BitArray,
) -> Result(ParsedHeader, gose.GoseError) {
  let epk_decoder = {
    use kty <- decode.field("kty", decode.string)
    use crv <- decode.field("crv", decode.string)
    use x <- decode.field("x", decode.string)
    use y <- decode.optional_field("y", None, decode.optional(decode.string))
    decode.success(#(kty, crv, x, y))
  }

  let decoder = {
    use alg <- decode.field("alg", decode.string)
    use enc <- decode.field("enc", decode.string)
    use kid <- decode.optional_field(
      "kid",
      None,
      decode.optional(decode.string),
    )
    use typ <- decode.optional_field(
      "typ",
      None,
      decode.optional(decode.string),
    )
    use cty <- decode.optional_field(
      "cty",
      None,
      decode.optional(decode.string),
    )
    use epk_raw <- decode.optional_field(
      "epk",
      None,
      decode.optional(epk_decoder),
    )
    use apu <- decode.optional_field(
      "apu",
      None,
      decode.optional(decode.string),
    )
    use apv <- decode.optional_field(
      "apv",
      None,
      decode.optional(decode.string),
    )
    use p2s <- decode.optional_field(
      "p2s",
      None,
      decode.optional(decode.string),
    )
    use p2c <- decode.optional_field("p2c", None, decode.optional(decode.int))
    use kw_iv <- decode.optional_field(
      "iv",
      None,
      decode.optional(decode.string),
    )
    use kw_tag <- decode.optional_field(
      "tag",
      None,
      decode.optional(decode.string),
    )
    use crit <- decode.optional_field(
      "crit",
      None,
      decode.optional(decode.list(decode.string)),
    )
    use zip <- decode.optional_field(
      "zip",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(
      alg,
      enc,
      kid,
      typ,
      cty,
      epk_raw,
      apu,
      apv,
      p2s,
      p2c,
      kw_iv,
      kw_tag,
      crit,
      zip,
    ))
  }

  use
    #(
      alg_str,
      enc_str,
      kid,
      typ,
      cty,
      epk_raw,
      apu_b64,
      apv_b64,
      p2s_b64,
      p2c,
      kw_iv_b64,
      kw_tag_b64,
      crit,
      zip,
    )
  <- result.try(
    json.parse_bits(json_bits, decoder)
    |> result.replace_error(gose.ParseError("invalid header JSON")),
  )

  use _ <- result.try(validate_crit(crit))
  use <- bool.guard(
    when: option.is_some(zip),
    return: Error(gose.ParseError("unsupported header: zip")),
  )
  let p2c_out_of_range = case p2c {
    Some(iterations) -> iterations < min_p2c || iterations > max_p2c
    None -> False
  }
  use <- bool.guard(
    when: p2c_out_of_range,
    return: Error(gose.ParseError(
      "p2c must be >= "
      <> int.to_string(min_p2c)
      <> " and <= "
      <> int.to_string(max_p2c),
    )),
  )

  use alg <- result.try(jwa.jwe_alg_from_string(alg_str))
  use enc <- result.try(jwa.enc_from_string(enc_str))
  use epk <- result.try(parse_optional_epk(epk_raw))
  use apu <- result.try(parse_optional_base64(apu_b64, "apu"))
  use apv <- result.try(parse_optional_base64(apv_b64, "apv"))
  use p2s <- result.try(parse_optional_base64(p2s_b64, "p2s"))
  use kw_iv <- result.try(parse_optional_base64(kw_iv_b64, "iv"))
  use kw_tag <- result.try(parse_optional_base64(kw_tag_b64, "tag"))
  use alg_fields <- result.try(build_parsed_alg_fields(
    alg,
    epk,
    apu,
    apv,
    p2s,
    p2c,
    kw_iv,
    kw_tag,
  ))

  let header = JweHeader(alg:, enc:, kid:, typ:, cty:)
  Ok(ParsedHeader(header:, alg_fields:))
}

fn validate_crit(crit: Option(List(String))) -> Result(Nil, gose.GoseError) {
  case crit {
    None -> Ok(Nil)
    Some(extensions) ->
      utils.validate_crit_headers(extensions, standard_headers, [])
  }
}

fn build_parsed_alg_fields(
  alg: jwa.JweAlg,
  epk: Option(key_wrap.EphemeralPublicKey),
  apu: Option(BitArray),
  apv: Option(BitArray),
  p2s: Option(BitArray),
  p2c: Option(Int),
  kw_iv: Option(BitArray),
  kw_tag: Option(BitArray),
) -> Result(AlgFields, gose.GoseError) {
  let alg_str = jwa.jwe_alg_to_string(alg)
  case alg {
    jwa.JweChaCha20KeyWrap(_) -> {
      use _ <- result.try(
        reject_disallowed_headers(alg_str, [
          #(option.is_some(epk), "epk"),
          #(option.is_some(apu), "apu"),
          #(option.is_some(apv), "apv"),
          #(option.is_some(p2s), "p2s"),
          #(option.is_some(p2c), "p2c"),
        ]),
      )
      Ok(ChaCha20KwFields(kw_iv:, kw_tag:))
    }
    jwa.JweEcdhEs(jwa.EcdhEsChaCha20Kw(_)) -> {
      use _ <- result.try(
        reject_disallowed_headers(alg_str, [
          #(option.is_some(p2s), "p2s"),
          #(option.is_some(p2c), "p2c"),
        ]),
      )
      case option.is_some(apu) && option.is_some(apv) && apu == apv {
        True -> Error(gose.ParseError("apu and apv must be distinct"))
        False -> Ok(EcdhEsChaCha20KwFields(epk:, apu:, apv:, kw_iv:, kw_tag:))
      }
    }
    jwa.JweEcdhEs(_) -> {
      use _ <- result.try(
        reject_disallowed_headers(alg_str, [
          #(option.is_some(p2s), "p2s"),
          #(option.is_some(p2c), "p2c"),
        ]),
      )
      case option.is_some(apu) && option.is_some(apv) && apu == apv {
        True -> Error(gose.ParseError("apu and apv must be distinct"))
        False -> Ok(EcdhEsFields(epk:, apu:, apv:))
      }
    }
    jwa.JwePbes2(_) -> {
      use _ <- result.try(
        reject_disallowed_headers(alg_str, [
          #(option.is_some(epk), "epk"),
          #(option.is_some(apu), "apu"),
          #(option.is_some(apv), "apv"),
        ]),
      )
      let p2s_too_short = case p2s {
        Some(salt) -> bit_array.byte_size(salt) < 8
        None -> False
      }
      use <- bool.guard(
        when: p2s_too_short,
        return: Error(gose.ParseError("p2s must be at least 8 bytes")),
      )
      Ok(Pbes2Fields(p2s:, p2c:))
    }
    jwa.JweAesKeyWrap(jwa.AesGcmKw, _) -> {
      use _ <- result.try(
        reject_disallowed_headers(alg_str, [
          #(option.is_some(epk), "epk"),
          #(option.is_some(apu), "apu"),
          #(option.is_some(apv), "apv"),
          #(option.is_some(p2s), "p2s"),
          #(option.is_some(p2c), "p2c"),
        ]),
      )
      Ok(AesGcmKwFields(kw_iv:, kw_tag:))
    }
    jwa.JweDirect | jwa.JweAesKeyWrap(jwa.AesKw, _) | jwa.JweRsa(_) -> {
      use _ <- result.try(
        reject_disallowed_headers(alg_str, [
          #(option.is_some(epk), "epk"),
          #(option.is_some(apu), "apu"),
          #(option.is_some(apv), "apv"),
          #(option.is_some(p2s), "p2s"),
          #(option.is_some(p2c), "p2c"),
          #(option.is_some(kw_iv), "iv"),
          #(option.is_some(kw_tag), "tag"),
        ]),
      )
      Ok(NoAlgFields)
    }
  }
}

fn reject_disallowed_headers(
  alg_str: String,
  checks: List(#(Bool, String)),
) -> Result(Nil, gose.GoseError) {
  case checks {
    [] -> Ok(Nil)
    [#(True, name), ..] ->
      Error(gose.ParseError(name <> " header not allowed for " <> alg_str))
    [#(False, _), ..rest] -> reject_disallowed_headers(alg_str, rest)
  }
}

fn validate_encrypted_key_for_algorithm(
  alg: jwa.JweAlg,
  encrypted_key: BitArray,
) -> Result(Nil, gose.GoseError) {
  let is_direct = alg == jwa.JweDirect || alg == jwa.JweEcdhEs(jwa.EcdhEsDirect)
  let key_size = bit_array.byte_size(encrypted_key)

  case is_direct, key_size {
    True, 0 -> Ok(Nil)
    True, _ ->
      Error(gose.ParseError(
        "encrypted_key must be empty for " <> jwa.jwe_alg_to_string(alg),
      ))
    False, 0 ->
      Error(gose.ParseError(
        "encrypted_key required for " <> jwa.jwe_alg_to_string(alg),
      ))
    False, _ -> Ok(Nil)
  }
}

/// Parse an unprotected header from a decode.Dynamic value.
/// Returns a tuple of (raw dynamic for decoder, header names for disjointness validation).
/// The dict is not populated — parsed values are accessed via decoders on the raw dynamic.
fn parse_unprotected_header(
  raw: Option(decode.Dynamic),
) -> Result(#(Option(decode.Dynamic), List(String)), gose.GoseError) {
  case raw {
    None -> Ok(#(None, []))
    Some(dyn) -> {
      use unprotected_dict <- result.try(
        decode.run(dyn, decode.dict(decode.string, decode.dynamic))
        |> result.replace_error(gose.ParseError(
          "unprotected header must be a JSON object",
        )),
      )
      let names = dict.keys(unprotected_dict)
      use _ <- result.try(validate_no_protected_only_headers(names))
      Ok(#(Some(dyn), names))
    }
  }
}

/// Validate that no protected-only headers appear in unprotected.
fn validate_no_protected_only_headers(
  names: List(String),
) -> Result(Nil, gose.GoseError) {
  let violations = list.filter(names, list.contains(protected_only_headers, _))
  case list.is_empty(violations) {
    True -> Ok(Nil)
    False ->
      Error(gose.ParseError(
        "protected-only headers in unprotected: "
        <> string.join(violations, ", "),
      ))
  }
}

fn present_field_names(fields: List(#(Bool, String))) -> List(String) {
  list.filter_map(fields, fn(field) {
    case field {
      #(True, name) -> Ok(name)
      #(False, _) -> Error(Nil)
    }
  })
}

/// Validate that protected and unprotected headers have disjoint parameter names.
/// Per RFC 7516, the same parameter MUST NOT appear in both protected and unprotected.
fn validate_jwe_header_disjointness(
  header: JweHeader,
  alg_fields: AlgFields,
  shared_unprotected_names: List(String),
  per_recipient_unprotected_names: List(String),
) -> Result(Nil, gose.GoseError) {
  let alg_specific_names = case alg_fields {
    EcdhEsFields(epk:, apu:, apv:) ->
      present_field_names([
        #(option.is_some(epk), "epk"),
        #(option.is_some(apu), "apu"),
        #(option.is_some(apv), "apv"),
      ])
    Pbes2Fields(p2s:, p2c:) ->
      present_field_names([
        #(option.is_some(p2s), "p2s"),
        #(option.is_some(p2c), "p2c"),
      ])
    AesGcmKwFields(kw_iv:, kw_tag:) ->
      present_field_names([
        #(option.is_some(kw_iv), "iv"),
        #(option.is_some(kw_tag), "tag"),
      ])
    ChaCha20KwFields(kw_iv:, kw_tag:) ->
      present_field_names([
        #(option.is_some(kw_iv), "iv"),
        #(option.is_some(kw_tag), "tag"),
      ])
    EcdhEsChaCha20KwFields(epk:, apu:, apv:, kw_iv:, kw_tag:) ->
      present_field_names([
        #(option.is_some(epk), "epk"),
        #(option.is_some(apu), "apu"),
        #(option.is_some(apv), "apv"),
        #(option.is_some(kw_iv), "iv"),
        #(option.is_some(kw_tag), "tag"),
      ])
    NoAlgFields -> []
  }

  let protected_names =
    list.flatten([
      ["alg", "enc"],
      present_field_names([
        #(option.is_some(header.kid), "kid"),
        #(option.is_some(header.typ), "typ"),
        #(option.is_some(header.cty), "cty"),
      ]),
      alg_specific_names,
    ])

  let protected_set = set.from_list(protected_names)
  let shared_names = shared_unprotected_names
  let per_recipient_names = per_recipient_unprotected_names

  let shared_overlap = list.filter(shared_names, set.contains(protected_set, _))
  use <- bool.guard(
    when: !list.is_empty(shared_overlap),
    return: Error(gose.ParseError(
      "header parameter appears in both protected and shared unprotected: "
      <> string.join(shared_overlap, ", "),
    )),
  )

  let per_recipient_overlap =
    list.filter(per_recipient_names, set.contains(protected_set, _))
  use <- bool.guard(
    when: !list.is_empty(per_recipient_overlap),
    return: Error(gose.ParseError(
      "header parameter appears in both protected and per-recipient unprotected: "
      <> string.join(per_recipient_overlap, ", "),
    )),
  )

  let shared_set = set.from_list(shared_names)
  let shared_per_recipient_overlap =
    list.filter(per_recipient_names, set.contains(shared_set, _))
  use <- bool.guard(
    when: !list.is_empty(shared_per_recipient_overlap),
    return: Error(gose.ParseError(
      "header parameter appears in both shared and per-recipient unprotected: "
      <> string.join(shared_per_recipient_overlap, ", "),
    )),
  )

  Ok(Nil)
}

fn parse_optional_epk(
  epk_raw: Option(#(String, String, String, Option(String))),
) -> Result(Option(key_wrap.EphemeralPublicKey), gose.GoseError) {
  case epk_raw {
    None -> Ok(None)
    Some(#(kty, crv, x_b64, y_opt)) -> {
      use x <- result.try(
        bit_array.base64_url_decode(x_b64)
        |> result.replace_error(gose.ParseError("invalid epk x base64")),
      )
      case kty {
        "EC" -> {
          use y_b64 <- result.try(option.to_result(
            y_opt,
            gose.ParseError("EC epk requires y coordinate"),
          ))
          use y <- result.try(
            bit_array.base64_url_decode(y_b64)
            |> result.replace_error(gose.ParseError("invalid epk y base64")),
          )
          use curve <- result.try(utils.ec_curve_from_string(crv))
          Ok(Some(key_wrap.EcEphemeralKey(curve:, x:, y:)))
        }
        "OKP" -> {
          use curve <- result.try(utils.xdh_curve_from_string(crv))
          Ok(Some(key_wrap.XdhEphemeralKey(curve:, x:)))
        }
        _ -> Error(gose.ParseError("unsupported epk kty: " <> kty))
      }
    }
  }
}

fn parse_optional_base64(
  opt: Option(String),
  name: String,
) -> Result(Option(BitArray), gose.GoseError) {
  case opt {
    None -> Ok(None)
    Some(b64) -> {
      use decoded <- result.try(
        bit_array.base64_url_decode(b64)
        |> result.replace_error(gose.ParseError("invalid " <> name <> " base64")),
      )
      Ok(Some(decoded))
    }
  }
}

/// Serialize an encrypted JWE to JSON Flattened format.
///
/// Format: `{"protected":"...","encrypted_key":"...","iv":"...","ciphertext":"...","tag":"..."}`
///
/// **Note:** This implementation supports a single recipient only.
/// For Direct or ECDH-ES algorithms, the encrypted_key field is omitted.
/// When AAD is present, includes the `aad` field.
/// When unprotected headers are present, includes the `unprotected` and/or `header` fields.
///
/// ## Parameters
///
/// - `jwe` - The encrypted JWE to serialize.
///
/// ## Returns
///
/// The JWE as a `json.Json` value in Flattened JSON Serialization format.
pub fn serialize_json_flattened(jwe: Jwe(Encrypted, family, Built)) -> json.Json {
  let assert EncryptedJwe(
    protected_b64:,
    encrypted_key:,
    iv:,
    ciphertext:,
    tag:,
    aad:,
    shared_unprotected:,
    per_recipient_unprotected:,
    ..,
  ) = jwe

  let ek_b64 = utils.encode_base64_url(encrypted_key)
  let iv_b64 = utils.encode_base64_url(iv)
  let ct_b64 = utils.encode_base64_url(ciphertext)
  let tag_b64 = utils.encode_base64_url(tag)

  let base_fields = case bit_array.byte_size(encrypted_key) {
    0 -> [
      #("protected", json.string(protected_b64)),
      #("iv", json.string(iv_b64)),
      #("ciphertext", json.string(ct_b64)),
      #("tag", json.string(tag_b64)),
    ]
    _ -> [
      #("protected", json.string(protected_b64)),
      #("encrypted_key", json.string(ek_b64)),
      #("iv", json.string(iv_b64)),
      #("ciphertext", json.string(ct_b64)),
      #("tag", json.string(tag_b64)),
    ]
  }

  let fields_with_header = case dict.is_empty(per_recipient_unprotected) {
    True -> base_fields
    False -> [
      #("header", json.object(dict.to_list(per_recipient_unprotected))),
      ..base_fields
    ]
  }

  fields_with_header
  |> append_optional_jwe_fields(shared_unprotected, aad)
  |> json.object
}

/// Serialize an encrypted JWE to JSON General format.
///
/// Format: `{"protected":"...","recipients":[{"encrypted_key":"..."}],"iv":"...","ciphertext":"...","tag":"..."}`
///
/// **Note:** This implementation supports a single recipient only. Multiple recipients
/// are not supported per RFC 7516 General Serialization.
/// For Direct or ECDH-ES algorithms, the encrypted_key field is omitted.
/// When AAD is present, includes the `aad` field.
/// When unprotected headers are present, includes the `unprotected` field and/or
/// the `header` field in the recipient object.
///
/// ## Parameters
///
/// - `jwe` - The encrypted JWE to serialize.
///
/// ## Returns
///
/// The JWE as a `json.Json` value in General JSON Serialization format.
pub fn serialize_json_general(jwe: Jwe(Encrypted, family, Built)) -> json.Json {
  let assert EncryptedJwe(
    protected_b64:,
    encrypted_key:,
    iv:,
    ciphertext:,
    tag:,
    aad:,
    shared_unprotected:,
    per_recipient_unprotected:,
    ..,
  ) = jwe

  let ek_b64 = utils.encode_base64_url(encrypted_key)
  let iv_b64 = utils.encode_base64_url(iv)
  let ct_b64 = utils.encode_base64_url(ciphertext)
  let tag_b64 = utils.encode_base64_url(tag)

  let recipient_fields = case bit_array.byte_size(encrypted_key) {
    0 -> []
    _ -> [#("encrypted_key", json.string(ek_b64))]
  }
  let recipient_with_header = case dict.is_empty(per_recipient_unprotected) {
    True -> recipient_fields
    False -> [
      #("header", json.object(dict.to_list(per_recipient_unprotected))),
      ..recipient_fields
    ]
  }
  let recipient = json.object(recipient_with_header)

  [
    #("protected", json.string(protected_b64)),
    #("iv", json.string(iv_b64)),
    #("ciphertext", json.string(ct_b64)),
    #("tag", json.string(tag_b64)),
    #("recipients", json.preprocessed_array([recipient])),
  ]
  |> append_optional_jwe_fields(shared_unprotected, aad)
  |> json.object
}

fn append_optional_jwe_fields(
  fields: List(#(String, json.Json)),
  shared_unprotected: dict.Dict(String, json.Json),
  aad: Option(BitArray),
) -> List(#(String, json.Json)) {
  let fields = case dict.is_empty(shared_unprotected) {
    True -> fields
    False -> [
      #("unprotected", json.object(dict.to_list(shared_unprotected))),
      ..fields
    ]
  }
  case aad {
    Some(aad) -> {
      let aad_b64 = utils.encode_base64_url(aad)
      [#("aad", json.string(aad_b64)), ..fields]
    }
    None -> fields
  }
}

/// Parse a JWE from JSON format (supports both General and Flattened).
///
/// ## Parameters
///
/// - `json_str` - The JSON string to parse.
///
/// ## Returns
///
/// `Ok(Jwe(Encrypted, Nil, Parsed))` with the parsed encrypted JWE, or
/// `Error(GoseError)` if the JSON is malformed or contains invalid data.
pub fn parse_json(
  json_str: String,
) -> Result(Jwe(Encrypted, Nil, Parsed), gose.GoseError) {
  let format_detector = {
    use _ <- decode.field("recipients", decode.list(decode.dynamic))
    decode.success(True)
  }
  let is_general_format = json.parse(json_str, format_detector) |> result.is_ok
  case is_general_format {
    True -> parse_json_general(json_str)
    False -> parse_json_flattened(json_str)
  }
}

fn decode_base64_url_or_empty(
  opt: Option(String),
  name: String,
) -> Result(BitArray, gose.GoseError) {
  case opt {
    Some(b64) -> utils.decode_base64_url(b64, name)
    None -> Ok(<<>>)
  }
}

fn decode_optional_base64_url(
  opt: Option(String),
  name: String,
) -> Result(Option(BitArray), gose.GoseError) {
  case opt {
    Some(b64) -> utils.decode_base64_url(b64, name) |> result.map(Some)
    None -> Ok(None)
  }
}

fn parse_json_flattened(
  json_str: String,
) -> Result(Jwe(Encrypted, Nil, Parsed), gose.GoseError) {
  let decoder = {
    use protected <- decode.field("protected", decode.string)
    use encrypted_key <- decode.optional_field(
      "encrypted_key",
      None,
      decode.optional(decode.string),
    )
    use iv <- decode.field("iv", decode.string)
    use ciphertext <- decode.field("ciphertext", decode.string)
    use tag <- decode.field("tag", decode.string)
    use header_raw <- decode.optional_field(
      "header",
      None,
      decode.optional(decode.dynamic),
    )
    use aad_b64 <- decode.optional_field(
      "aad",
      None,
      decode.optional(decode.string),
    )
    use unprotected_raw <- decode.optional_field(
      "unprotected",
      None,
      decode.optional(decode.dynamic),
    )
    decode.success(#(
      protected,
      encrypted_key,
      iv,
      ciphertext,
      tag,
      header_raw,
      aad_b64,
      unprotected_raw,
    ))
  }

  use
    #(
      protected_b64,
      ek_opt,
      iv_b64,
      ct_b64,
      tag_b64,
      header_raw,
      aad_b64_opt,
      unprotected_raw,
    )
  <- result.try(
    json.parse(json_str, decoder)
    |> result.replace_error(gose.ParseError("invalid JWE JSON (flattened)")),
  )

  use ParsedHeader(header:, alg_fields:) <- result.try(parse_protected_header(
    protected_b64,
  ))

  use #(shared_unprotected_raw, shared_names) <- result.try(
    parse_unprotected_header(unprotected_raw),
  )
  use #(per_recipient_unprotected_raw, per_recipient_names) <- result.try(
    parse_unprotected_header(header_raw),
  )
  use _ <- result.try(validate_jwe_header_disjointness(
    header,
    alg_fields,
    shared_names,
    per_recipient_names,
  ))

  use encrypted_key <- result.try(decode_base64_url_or_empty(
    ek_opt,
    "encrypted_key",
  ))
  use _ <- result.try(validate_encrypted_key_for_algorithm(
    header.alg,
    encrypted_key,
  ))
  use iv <- result.try(utils.decode_base64_url(iv_b64, "iv"))
  use ciphertext <- result.try(utils.decode_base64_url(ct_b64, "ciphertext"))
  use tag <- result.try(utils.decode_base64_url(tag_b64, "tag"))
  use _ <- result.try(content_encryption.validate_iv_tag_sizes(
    header.enc,
    iv,
    tag,
  ))
  use user_aad <- result.try(decode_optional_base64_url(aad_b64_opt, "aad"))

  Ok(EncryptedJwe(
    header:,
    protected_b64:,
    encrypted_key:,
    iv:,
    ciphertext:,
    tag:,
    alg_fields:,
    aad: user_aad,
    shared_unprotected: dict.new(),
    shared_unprotected_raw:,
    per_recipient_unprotected: dict.new(),
    per_recipient_unprotected_raw:,
  ))
}

fn parse_json_general(
  json_str: String,
) -> Result(Jwe(Encrypted, Nil, Parsed), gose.GoseError) {
  let recipient_decoder = {
    use encrypted_key <- decode.optional_field(
      "encrypted_key",
      None,
      decode.optional(decode.string),
    )
    use header_raw <- decode.optional_field(
      "header",
      None,
      decode.optional(decode.dynamic),
    )
    decode.success(#(encrypted_key, header_raw))
  }

  let decoder = {
    use protected <- decode.field("protected", decode.string)
    use recipients <- decode.field("recipients", decode.list(recipient_decoder))
    use iv <- decode.field("iv", decode.string)
    use ciphertext <- decode.field("ciphertext", decode.string)
    use tag <- decode.field("tag", decode.string)
    use aad_b64 <- decode.optional_field(
      "aad",
      None,
      decode.optional(decode.string),
    )
    use unprotected_raw <- decode.optional_field(
      "unprotected",
      None,
      decode.optional(decode.dynamic),
    )
    decode.success(#(
      protected,
      recipients,
      iv,
      ciphertext,
      tag,
      aad_b64,
      unprotected_raw,
    ))
  }

  use
    #(
      protected_b64,
      recipients,
      iv_b64,
      ct_b64,
      tag_b64,
      aad_b64_opt,
      unprotected_raw,
    )
  <- result.try(
    json.parse(json_str, decoder)
    |> result.replace_error(gose.ParseError("invalid JWE JSON (general)")),
  )

  use #(shared_unprotected_raw, shared_names) <- result.try(
    parse_unprotected_header(unprotected_raw),
  )

  case recipients {
    [#(ek_opt, header_raw)] -> {
      use ParsedHeader(header:, alg_fields:) <- result.try(
        parse_protected_header(protected_b64),
      )

      use #(per_recipient_unprotected_raw, per_recipient_names) <- result.try(
        parse_unprotected_header(header_raw),
      )
      use _ <- result.try(validate_jwe_header_disjointness(
        header,
        alg_fields,
        shared_names,
        per_recipient_names,
      ))

      use encrypted_key <- result.try(decode_base64_url_or_empty(
        ek_opt,
        "encrypted_key",
      ))
      use _ <- result.try(validate_encrypted_key_for_algorithm(
        header.alg,
        encrypted_key,
      ))
      use iv <- result.try(utils.decode_base64_url(iv_b64, "iv"))
      use ciphertext <- result.try(utils.decode_base64_url(ct_b64, "ciphertext"))
      use tag <- result.try(utils.decode_base64_url(tag_b64, "tag"))
      use _ <- result.try(content_encryption.validate_iv_tag_sizes(
        header.enc,
        iv,
        tag,
      ))
      use aad <- result.try(decode_optional_base64_url(aad_b64_opt, "aad"))

      Ok(EncryptedJwe(
        header:,
        protected_b64:,
        encrypted_key:,
        iv:,
        ciphertext:,
        tag:,
        alg_fields:,
        aad:,
        shared_unprotected: dict.new(),
        shared_unprotected_raw:,
        per_recipient_unprotected: dict.new(),
        per_recipient_unprotected_raw:,
      ))
    }
    [_, _, ..] ->
      Error(gose.ParseError(
        "JWE JSON (general) has multiple recipients (not supported)",
      ))
    [] -> Error(gose.ParseError("JWE JSON (general) has no recipients"))
  }
}

fn apply_optional(
  jwe: Jwe(Unencrypted, family, Built),
  value: Option(a),
  setter: fn(Jwe(Unencrypted, family, Built), a) ->
    Jwe(Unencrypted, family, Built),
) -> Jwe(Unencrypted, family, Built) {
  case value {
    Some(v) -> setter(jwe, v)
    None -> jwe
  }
}

fn apply_headers(
  jwe: Jwe(Unencrypted, family, Built),
  kid: Option(String),
  typ: Option(String),
  cty: Option(String),
) -> Jwe(Unencrypted, family, Built) {
  jwe
  |> apply_optional(kid, with_kid)
  |> apply_optional(typ, with_typ)
  |> apply_optional(cty, with_cty)
}

fn encrypt_and_serialize(
  unencrypted: Jwe(Unencrypted, family, Built),
  alg: jwa.JweAlg,
  key: jwk.Jwk,
  plaintext: BitArray,
) -> Result(#(String, jwa.JweAlg), gose.GoseError) {
  use encrypted <- result.try(encrypt(unencrypted, key, plaintext))
  use token <- result.try(serialize_compact(encrypted))
  Ok(#(token, alg))
}

@internal
pub fn encrypt_to_compact(
  alg: jwa.JweAlg,
  enc: jwa.Enc,
  plaintext: BitArray,
  key: jwk.Jwk,
  kid: Option(String),
  typ: Option(String),
  cty: Option(String),
) -> Result(#(String, jwa.JweAlg), gose.GoseError) {
  case alg {
    jwa.JweDirect ->
      encrypt_and_serialize(
        apply_headers(new_direct(enc), kid, typ, cty),
        alg,
        key,
        plaintext,
      )

    jwa.JweAesKeyWrap(jwa.AesKw, size) ->
      encrypt_and_serialize(
        apply_headers(new_aes_kw(size, enc), kid, typ, cty),
        alg,
        key,
        plaintext,
      )

    jwa.JweAesKeyWrap(jwa.AesGcmKw, size) ->
      encrypt_and_serialize(
        apply_headers(new_aes_gcm_kw(size, enc), kid, typ, cty),
        alg,
        key,
        plaintext,
      )

    jwa.JweRsa(rsa_alg) ->
      encrypt_and_serialize(
        apply_headers(new_rsa(rsa_alg, enc), kid, typ, cty),
        alg,
        key,
        plaintext,
      )

    jwa.JweEcdhEs(ecdh_alg) ->
      encrypt_and_serialize(
        apply_headers(new_ecdh_es(ecdh_alg, enc), kid, typ, cty),
        alg,
        key,
        plaintext,
      )

    jwa.JweChaCha20KeyWrap(variant) ->
      encrypt_and_serialize(
        apply_headers(new_chacha20_kw(variant, enc), kid, typ, cty),
        alg,
        key,
        plaintext,
      )

    jwa.JwePbes2(_) ->
      Error(gose.InvalidState("PBES2 algorithms require a password, not a key"))
  }
}
