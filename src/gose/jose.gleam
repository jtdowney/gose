//// JOSE algorithm string mapping ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html)).
////
//// Maps between `gose` algorithm types and JOSE string identifiers.

import gose

/// Convert a signing algorithm to its JOSE string representation.
pub fn signing_alg_to_string(alg: gose.SigningAlg) -> String {
  case alg {
    gose.Mac(gose.Hmac(gose.HmacSha256)) -> "HS256"
    gose.Mac(gose.Hmac(gose.HmacSha384)) -> "HS384"
    gose.Mac(gose.Hmac(gose.HmacSha512)) -> "HS512"
    gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha256)) -> "RS256"
    gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha384)) -> "RS384"
    gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha512)) -> "RS512"
    gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha256)) -> "PS256"
    gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha384)) -> "PS384"
    gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha512)) -> "PS512"
    gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)) -> "ES256"
    gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP384)) -> "ES384"
    gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP521)) -> "ES512"
    gose.DigitalSignature(gose.Ecdsa(gose.EcdsaSecp256k1)) -> "ES256K"
    gose.DigitalSignature(gose.Eddsa) -> "EdDSA"
  }
}

/// Parse a signing algorithm from its JOSE string representation.
pub fn signing_alg_from_string(
  alg: String,
) -> Result(gose.SigningAlg, gose.GoseError) {
  case alg {
    "HS256" -> Ok(gose.Mac(gose.Hmac(gose.HmacSha256)))
    "HS384" -> Ok(gose.Mac(gose.Hmac(gose.HmacSha384)))
    "HS512" -> Ok(gose.Mac(gose.Hmac(gose.HmacSha512)))
    "RS256" -> Ok(gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha256)))
    "RS384" -> Ok(gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha384)))
    "RS512" -> Ok(gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha512)))
    "PS256" -> Ok(gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha256)))
    "PS384" -> Ok(gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha384)))
    "PS512" -> Ok(gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha512)))
    "ES256" -> Ok(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)))
    "ES384" -> Ok(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP384)))
    "ES512" -> Ok(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP521)))
    "ES256K" -> Ok(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaSecp256k1)))
    "EdDSA" -> Ok(gose.DigitalSignature(gose.Eddsa))
    _ -> Error(gose.ParseError("unknown JWS algorithm: " <> alg))
  }
}

/// Convert a key encryption algorithm to its JOSE string representation.
pub fn key_encryption_alg_to_string(alg: gose.KeyEncryptionAlg) -> String {
  case alg {
    gose.Direct -> "dir"
    gose.AesKeyWrap(gose.AesKw, gose.Aes128) -> "A128KW"
    gose.AesKeyWrap(gose.AesKw, gose.Aes192) -> "A192KW"
    gose.AesKeyWrap(gose.AesKw, gose.Aes256) -> "A256KW"
    gose.AesKeyWrap(gose.AesGcmKw, gose.Aes128) -> "A128GCMKW"
    gose.AesKeyWrap(gose.AesGcmKw, gose.Aes192) -> "A192GCMKW"
    gose.AesKeyWrap(gose.AesGcmKw, gose.Aes256) -> "A256GCMKW"
    gose.RsaEncryption(gose.RsaPkcs1v15) -> "RSA1_5"
    gose.RsaEncryption(gose.RsaOaepSha1) -> "RSA-OAEP"
    gose.RsaEncryption(gose.RsaOaepSha256) -> "RSA-OAEP-256"
    gose.EcdhEs(gose.EcdhEsDirect) -> "ECDH-ES"
    gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128)) -> "ECDH-ES+A128KW"
    gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes192)) -> "ECDH-ES+A192KW"
    gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes256)) -> "ECDH-ES+A256KW"
    gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.C20PKw)) -> "ECDH-ES+C20PKW"
    gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.XC20PKw)) -> "ECDH-ES+XC20PKW"
    gose.ChaCha20KeyWrap(gose.C20PKw) -> "C20PKW"
    gose.ChaCha20KeyWrap(gose.XC20PKw) -> "XC20PKW"
    gose.Pbes2(gose.Pbes2Sha256Aes128Kw) -> "PBES2-HS256+A128KW"
    gose.Pbes2(gose.Pbes2Sha384Aes192Kw) -> "PBES2-HS384+A192KW"
    gose.Pbes2(gose.Pbes2Sha512Aes256Kw) -> "PBES2-HS512+A256KW"
  }
}

/// Parse a key encryption algorithm from its JOSE string representation.
pub fn key_encryption_alg_from_string(
  alg: String,
) -> Result(gose.KeyEncryptionAlg, gose.GoseError) {
  case alg {
    "dir" -> Ok(gose.Direct)
    "A128KW" -> Ok(gose.AesKeyWrap(gose.AesKw, gose.Aes128))
    "A192KW" -> Ok(gose.AesKeyWrap(gose.AesKw, gose.Aes192))
    "A256KW" -> Ok(gose.AesKeyWrap(gose.AesKw, gose.Aes256))
    "A128GCMKW" -> Ok(gose.AesKeyWrap(gose.AesGcmKw, gose.Aes128))
    "A192GCMKW" -> Ok(gose.AesKeyWrap(gose.AesGcmKw, gose.Aes192))
    "A256GCMKW" -> Ok(gose.AesKeyWrap(gose.AesGcmKw, gose.Aes256))
    "RSA1_5" -> Ok(gose.RsaEncryption(gose.RsaPkcs1v15))
    "RSA-OAEP" -> Ok(gose.RsaEncryption(gose.RsaOaepSha1))
    "RSA-OAEP-256" -> Ok(gose.RsaEncryption(gose.RsaOaepSha256))
    "ECDH-ES" -> Ok(gose.EcdhEs(gose.EcdhEsDirect))
    "ECDH-ES+A128KW" -> Ok(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128)))
    "ECDH-ES+A192KW" -> Ok(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes192)))
    "ECDH-ES+A256KW" -> Ok(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes256)))
    "ECDH-ES+C20PKW" -> Ok(gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.C20PKw)))
    "ECDH-ES+XC20PKW" -> Ok(gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.XC20PKw)))
    "C20PKW" -> Ok(gose.ChaCha20KeyWrap(gose.C20PKw))
    "XC20PKW" -> Ok(gose.ChaCha20KeyWrap(gose.XC20PKw))
    "PBES2-HS256+A128KW" -> Ok(gose.Pbes2(gose.Pbes2Sha256Aes128Kw))
    "PBES2-HS384+A192KW" -> Ok(gose.Pbes2(gose.Pbes2Sha384Aes192Kw))
    "PBES2-HS512+A256KW" -> Ok(gose.Pbes2(gose.Pbes2Sha512Aes256Kw))
    _ -> Error(gose.ParseError("unknown JWE algorithm: " <> alg))
  }
}

/// Convert a content encryption algorithm to its JOSE string representation.
pub fn content_alg_to_string(alg: gose.ContentAlg) -> String {
  case alg {
    gose.AesGcm(gose.Aes128) -> "A128GCM"
    gose.AesGcm(gose.Aes192) -> "A192GCM"
    gose.AesGcm(gose.Aes256) -> "A256GCM"
    gose.AesCbcHmac(gose.Aes128) -> "A128CBC-HS256"
    gose.AesCbcHmac(gose.Aes192) -> "A192CBC-HS384"
    gose.AesCbcHmac(gose.Aes256) -> "A256CBC-HS512"
    gose.ChaCha20Poly1305 -> "C20P"
    gose.XChaCha20Poly1305 -> "XC20P"
  }
}

/// Parse a content encryption algorithm from its JOSE string representation.
pub fn content_alg_from_string(
  alg: String,
) -> Result(gose.ContentAlg, gose.GoseError) {
  case alg {
    "A128GCM" -> Ok(gose.AesGcm(gose.Aes128))
    "A192GCM" -> Ok(gose.AesGcm(gose.Aes192))
    "A256GCM" -> Ok(gose.AesGcm(gose.Aes256))
    "A128CBC-HS256" -> Ok(gose.AesCbcHmac(gose.Aes128))
    "A192CBC-HS384" -> Ok(gose.AesCbcHmac(gose.Aes192))
    "A256CBC-HS512" -> Ok(gose.AesCbcHmac(gose.Aes256))
    "C20P" -> Ok(gose.ChaCha20Poly1305)
    "XC20P" -> Ok(gose.XChaCha20Poly1305)
    _ -> Error(gose.ParseError("unknown content encryption algorithm: " <> alg))
  }
}
