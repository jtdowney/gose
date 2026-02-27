//// JSON Web Algorithms (JWA) - [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html)
////
//// This module defines the cryptographic algorithms used for signing (JWS)
//// and encryption (JWE) operations.

import gose

/// AES key sizes.
pub type AesKeySize {
  /// 128-bit AES key
  Aes128
  /// 192-bit AES key
  Aes192
  /// 256-bit AES key
  Aes256
}

/// AES key wrapping modes.
pub type AesKwMode {
  /// AES Key Wrap (RFC 3394)
  AesKw
  /// AES-GCM Key Wrap
  AesGcmKw
}

/// ChaCha20-Poly1305 key wrapping variants.
pub type ChaCha20Kw {
  /// ChaCha20-Poly1305 Key Wrap (12-byte nonce)
  C20PKw
  /// XChaCha20-Poly1305 Key Wrap (24-byte nonce)
  XC20PKw
}

/// HMAC signing algorithm variants.
pub type HmacAlg {
  /// HMAC using SHA-256
  HmacSha256
  /// HMAC using SHA-384
  HmacSha384
  /// HMAC using SHA-512
  HmacSha512
}

/// RSA PKCS#1 v1.5 signing algorithm variants.
pub type RsaPkcs1Alg {
  /// RSA PKCSv1.5 using SHA-256
  RsaPkcs1Sha256
  /// RSA PKCSv1.5 using SHA-384
  RsaPkcs1Sha384
  /// RSA PKCSv1.5 using SHA-512
  RsaPkcs1Sha512
}

/// RSA-PSS signing algorithm variants.
pub type RsaPssAlg {
  /// RSA-PSS using SHA-256 (RSASSA-PSS)
  RsaPssSha256
  /// RSA-PSS using SHA-384 (RSASSA-PSS)
  RsaPssSha384
  /// RSA-PSS using SHA-512 (RSASSA-PSS)
  RsaPssSha512
}

/// ECDSA signing algorithm variants.
pub type EcdsaAlg {
  /// ECDSA using P-256 and SHA-256
  EcdsaP256
  /// ECDSA using P-384 and SHA-384
  EcdsaP384
  /// ECDSA using P-521 and SHA-512
  EcdsaP521
  /// ECDSA using secp256k1 and SHA-256 (RFC 8812)
  EcdsaSecp256k1
}

/// JWS signing algorithms.
pub type JwsAlg {
  /// HMAC-based signing
  JwsHmac(HmacAlg)
  /// RSA PKCS#1 v1.5 signing
  JwsRsaPkcs1(RsaPkcs1Alg)
  /// RSA-PSS signing
  JwsRsaPss(RsaPssAlg)
  /// ECDSA signing
  JwsEcdsa(EcdsaAlg)
  /// EdDSA (Ed25519 or Ed448, curve determined by key)
  JwsEddsa
}

/// RSA JWE key encryption algorithm variants.
pub type RsaJweAlg {
  /// RSAES PKCS1 v1.5 key encryption.
  ///
  /// **Security Warning:** Vulnerable to padding oracle attacks (Bleichenbacher).
  /// Use only for interoperability with legacy systems that require RSA1_5.
  /// Prefer `RsaOaepSha1` or `RsaOaepSha256` for new applications.
  ///
  /// **Note:** Decryption may fail on Node.js 20.x (CVE-2023-46809).
  RsaPkcs1v15
  /// RSAES OAEP using default parameters
  RsaOaepSha1
  /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
  RsaOaepSha256
}

/// ECDH-ES key agreement algorithm variants.
pub type EcdhEsAlg {
  /// ECDH-ES using Concat KDF (direct key agreement)
  EcdhEsDirect
  /// ECDH-ES using Concat KDF and AES Key Wrap
  EcdhEsAesKw(AesKeySize)
  /// ECDH-ES using Concat KDF and ChaCha20-Poly1305 Key Wrap
  EcdhEsChaCha20Kw(ChaCha20Kw)
}

/// PBES2 key encryption algorithm variants.
pub type Pbes2Alg {
  /// PBES2 with HMAC-SHA-256 and A128KW wrapping
  Pbes2Sha256Aes128Kw
  /// PBES2 with HMAC-SHA-384 and A192KW wrapping
  Pbes2Sha384Aes192Kw
  /// PBES2 with HMAC-SHA-512 and A256KW wrapping
  Pbes2Sha512Aes256Kw
}

/// JWE key encryption algorithms.
pub type JweAlg {
  /// Direct use of a shared symmetric key
  JweDirect
  /// AES Key Wrap (standard or GCM mode)
  JweAesKeyWrap(AesKwMode, AesKeySize)
  /// ChaCha20-Poly1305 Key Wrap
  JweChaCha20KeyWrap(ChaCha20Kw)
  /// RSA key encryption
  JweRsa(RsaJweAlg)
  /// ECDH-ES key agreement
  JweEcdhEs(EcdhEsAlg)
  /// PBES2 password-based encryption
  JwePbes2(Pbes2Alg)
}

/// JWE content encryption algorithms.
pub type Enc {
  /// AES-GCM content encryption
  AesGcm(AesKeySize)
  /// AES-CBC with HMAC composite AEAD (CEK is double the AES key size)
  AesCbcHmac(AesKeySize)
  /// ChaCha20-Poly1305
  ChaCha20Poly1305
  /// XChaCha20-Poly1305
  XChaCha20Poly1305
}

/// Convert a JWS algorithm to its RFC string representation.
///
/// ## Parameters
///
/// - `alg` - The JWS algorithm variant to convert.
///
/// ## Returns
///
/// The RFC 7518 string identifier (e.g. `"HS256"`, `"EdDSA"`).
pub fn jws_alg_to_string(alg: JwsAlg) -> String {
  case alg {
    JwsHmac(HmacSha256) -> "HS256"
    JwsHmac(HmacSha384) -> "HS384"
    JwsHmac(HmacSha512) -> "HS512"
    JwsRsaPkcs1(RsaPkcs1Sha256) -> "RS256"
    JwsRsaPkcs1(RsaPkcs1Sha384) -> "RS384"
    JwsRsaPkcs1(RsaPkcs1Sha512) -> "RS512"
    JwsRsaPss(RsaPssSha256) -> "PS256"
    JwsRsaPss(RsaPssSha384) -> "PS384"
    JwsRsaPss(RsaPssSha512) -> "PS512"
    JwsEcdsa(EcdsaP256) -> "ES256"
    JwsEcdsa(EcdsaP384) -> "ES384"
    JwsEcdsa(EcdsaP521) -> "ES512"
    JwsEcdsa(EcdsaSecp256k1) -> "ES256K"
    JwsEddsa -> "EdDSA"
  }
}

/// Parse a JWS algorithm from its RFC string representation.
///
/// ## Parameters
///
/// - `alg` - The RFC 7518 string identifier (e.g. `"HS256"`, `"EdDSA"`).
///
/// ## Returns
///
/// `Ok(JwsAlg)` with the parsed algorithm variant, or `Error(ParseError)`
/// if the string is not a recognized JWS algorithm.
pub fn jws_alg_from_string(alg: String) -> Result(JwsAlg, gose.GoseError) {
  case alg {
    "HS256" -> Ok(JwsHmac(HmacSha256))
    "HS384" -> Ok(JwsHmac(HmacSha384))
    "HS512" -> Ok(JwsHmac(HmacSha512))
    "RS256" -> Ok(JwsRsaPkcs1(RsaPkcs1Sha256))
    "RS384" -> Ok(JwsRsaPkcs1(RsaPkcs1Sha384))
    "RS512" -> Ok(JwsRsaPkcs1(RsaPkcs1Sha512))
    "PS256" -> Ok(JwsRsaPss(RsaPssSha256))
    "PS384" -> Ok(JwsRsaPss(RsaPssSha384))
    "PS512" -> Ok(JwsRsaPss(RsaPssSha512))
    "ES256" -> Ok(JwsEcdsa(EcdsaP256))
    "ES384" -> Ok(JwsEcdsa(EcdsaP384))
    "ES512" -> Ok(JwsEcdsa(EcdsaP521))
    "ES256K" -> Ok(JwsEcdsa(EcdsaSecp256k1))
    "EdDSA" -> Ok(JwsEddsa)
    _ -> Error(gose.ParseError("unknown JWS algorithm: " <> alg))
  }
}

/// Convert a JWE key encryption algorithm to its RFC string representation.
///
/// ## Parameters
///
/// - `alg` - The JWE key encryption algorithm variant to convert.
///
/// ## Returns
///
/// The RFC 7518 string identifier (e.g. `"dir"`, `"RSA-OAEP-256"`).
pub fn jwe_alg_to_string(alg: JweAlg) -> String {
  case alg {
    JweDirect -> "dir"
    JweAesKeyWrap(AesKw, Aes128) -> "A128KW"
    JweAesKeyWrap(AesKw, Aes192) -> "A192KW"
    JweAesKeyWrap(AesKw, Aes256) -> "A256KW"
    JweAesKeyWrap(AesGcmKw, Aes128) -> "A128GCMKW"
    JweAesKeyWrap(AesGcmKw, Aes192) -> "A192GCMKW"
    JweAesKeyWrap(AesGcmKw, Aes256) -> "A256GCMKW"
    JweRsa(RsaPkcs1v15) -> "RSA1_5"
    JweRsa(RsaOaepSha1) -> "RSA-OAEP"
    JweRsa(RsaOaepSha256) -> "RSA-OAEP-256"
    JweEcdhEs(EcdhEsDirect) -> "ECDH-ES"
    JweEcdhEs(EcdhEsAesKw(Aes128)) -> "ECDH-ES+A128KW"
    JweEcdhEs(EcdhEsAesKw(Aes192)) -> "ECDH-ES+A192KW"
    JweEcdhEs(EcdhEsAesKw(Aes256)) -> "ECDH-ES+A256KW"
    JweEcdhEs(EcdhEsChaCha20Kw(C20PKw)) -> "ECDH-ES+C20PKW"
    JweEcdhEs(EcdhEsChaCha20Kw(XC20PKw)) -> "ECDH-ES+XC20PKW"
    JweChaCha20KeyWrap(C20PKw) -> "C20PKW"
    JweChaCha20KeyWrap(XC20PKw) -> "XC20PKW"
    JwePbes2(Pbes2Sha256Aes128Kw) -> "PBES2-HS256+A128KW"
    JwePbes2(Pbes2Sha384Aes192Kw) -> "PBES2-HS384+A192KW"
    JwePbes2(Pbes2Sha512Aes256Kw) -> "PBES2-HS512+A256KW"
  }
}

/// Parse a JWE key encryption algorithm from its RFC string representation.
///
/// ## Parameters
///
/// - `alg` - The RFC 7518 string identifier (e.g. `"dir"`, `"RSA-OAEP"`).
///
/// ## Returns
///
/// `Ok(JweAlg)` with the parsed algorithm variant, or `Error(ParseError)`
/// if the string is not a recognized JWE algorithm.
pub fn jwe_alg_from_string(alg: String) -> Result(JweAlg, gose.GoseError) {
  case alg {
    "dir" -> Ok(JweDirect)
    "A128KW" -> Ok(JweAesKeyWrap(AesKw, Aes128))
    "A192KW" -> Ok(JweAesKeyWrap(AesKw, Aes192))
    "A256KW" -> Ok(JweAesKeyWrap(AesKw, Aes256))
    "A128GCMKW" -> Ok(JweAesKeyWrap(AesGcmKw, Aes128))
    "A192GCMKW" -> Ok(JweAesKeyWrap(AesGcmKw, Aes192))
    "A256GCMKW" -> Ok(JweAesKeyWrap(AesGcmKw, Aes256))
    "RSA1_5" -> Ok(JweRsa(RsaPkcs1v15))
    "RSA-OAEP" -> Ok(JweRsa(RsaOaepSha1))
    "RSA-OAEP-256" -> Ok(JweRsa(RsaOaepSha256))
    "ECDH-ES" -> Ok(JweEcdhEs(EcdhEsDirect))
    "ECDH-ES+A128KW" -> Ok(JweEcdhEs(EcdhEsAesKw(Aes128)))
    "ECDH-ES+A192KW" -> Ok(JweEcdhEs(EcdhEsAesKw(Aes192)))
    "ECDH-ES+A256KW" -> Ok(JweEcdhEs(EcdhEsAesKw(Aes256)))
    "ECDH-ES+C20PKW" -> Ok(JweEcdhEs(EcdhEsChaCha20Kw(C20PKw)))
    "ECDH-ES+XC20PKW" -> Ok(JweEcdhEs(EcdhEsChaCha20Kw(XC20PKw)))
    "C20PKW" -> Ok(JweChaCha20KeyWrap(C20PKw))
    "XC20PKW" -> Ok(JweChaCha20KeyWrap(XC20PKw))
    "PBES2-HS256+A128KW" -> Ok(JwePbes2(Pbes2Sha256Aes128Kw))
    "PBES2-HS384+A192KW" -> Ok(JwePbes2(Pbes2Sha384Aes192Kw))
    "PBES2-HS512+A256KW" -> Ok(JwePbes2(Pbes2Sha512Aes256Kw))
    _ -> Error(gose.ParseError("unknown JWE algorithm: " <> alg))
  }
}

/// Convert a content encryption algorithm to its RFC string representation.
///
/// ## Parameters
///
/// - `alg` - The content encryption algorithm variant to convert.
///
/// ## Returns
///
/// The RFC 7518 string identifier (e.g. `"A256GCM"`, `"C20P"`).
pub fn enc_to_string(alg: Enc) -> String {
  case alg {
    AesGcm(Aes128) -> "A128GCM"
    AesGcm(Aes192) -> "A192GCM"
    AesGcm(Aes256) -> "A256GCM"
    AesCbcHmac(Aes128) -> "A128CBC-HS256"
    AesCbcHmac(Aes192) -> "A192CBC-HS384"
    AesCbcHmac(Aes256) -> "A256CBC-HS512"
    ChaCha20Poly1305 -> "C20P"
    XChaCha20Poly1305 -> "XC20P"
  }
}

/// Parse a content encryption algorithm from its RFC string representation.
///
/// ## Parameters
///
/// - `alg` - The RFC 7518 string identifier (e.g. `"A256GCM"`, `"C20P"`).
///
/// ## Returns
///
/// `Ok(Enc)` with the parsed encryption algorithm variant, or
/// `Error(ParseError)` if the string is not a recognized encryption algorithm.
pub fn enc_from_string(alg: String) -> Result(Enc, gose.GoseError) {
  case alg {
    "A128GCM" -> Ok(AesGcm(Aes128))
    "A192GCM" -> Ok(AesGcm(Aes192))
    "A256GCM" -> Ok(AesGcm(Aes256))
    "A128CBC-HS256" -> Ok(AesCbcHmac(Aes128))
    "A192CBC-HS384" -> Ok(AesCbcHmac(Aes192))
    "A256CBC-HS512" -> Ok(AesCbcHmac(Aes256))
    "C20P" -> Ok(ChaCha20Poly1305)
    "XC20P" -> Ok(XChaCha20Poly1305)
    _ -> Error(gose.ParseError("unknown content encryption algorithm: " <> alg))
  }
}

/// Returns the key size in bytes for an AES key size variant.
///
/// ## Parameters
///
/// - `size` - The AES key size variant to query.
///
/// ## Returns
///
/// The key size in bytes (16, 24, or 32).
pub fn aes_key_size_in_bytes(size: AesKeySize) -> Int {
  case size {
    Aes128 -> 16
    Aes192 -> 24
    Aes256 -> 32
  }
}

/// Returns the recommended symmetric key size in bytes for an HMAC algorithm.
///
/// ## Parameters
///
/// - `alg` - The HMAC algorithm variant to query.
///
/// ## Returns
///
/// The key size in bytes (32, 48, or 64).
pub fn hmac_alg_octet_key_size(alg: HmacAlg) -> Int {
  case alg {
    HmacSha256 -> 32
    HmacSha384 -> 48
    HmacSha512 -> 64
  }
}

/// Returns the content encryption key (CEK) size in bytes for a content
/// encryption algorithm.
///
/// ## Parameters
///
/// - `enc` - The content encryption algorithm to query.
///
/// ## Returns
///
/// The key size in bytes. Every `Enc` variant has a defined key size.
/// For `AesCbcHmac`, the CEK is double the AES key size because
/// it is split into separate HMAC and AES-CBC keys.
pub fn enc_octet_key_size(enc: Enc) -> Int {
  case enc {
    AesGcm(size) -> aes_key_size_in_bytes(size)
    AesCbcHmac(size) -> aes_key_size_in_bytes(size) * 2
    ChaCha20Poly1305 -> 32
    XChaCha20Poly1305 -> 32
  }
}

/// Returns the nonce size in bytes for a ChaCha20 key wrapping variant.
///
/// ## Parameters
///
/// - `variant` - The ChaCha20 key wrapping variant (`C20PKw` or `XC20PKw`).
///
/// ## Returns
///
/// The nonce size in bytes (12 for C20PKW, 24 for XC20PKW).
pub fn chacha20_kw_nonce_size(variant: ChaCha20Kw) -> Int {
  case variant {
    C20PKw -> 12
    XC20PKw -> 24
  }
}
