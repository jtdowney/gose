//// JOSE algorithm string mapping ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html)).
////
//// Maps between `gose/algorithm` types and JOSE string identifiers.

import gose
import gose/algorithm

/// Convert a signing algorithm to its JOSE string representation.
pub fn signing_alg_to_string(alg: algorithm.SigningAlg) -> String {
  case alg {
    algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)) -> "HS256"
    algorithm.Mac(algorithm.Hmac(algorithm.HmacSha384)) -> "HS384"
    algorithm.Mac(algorithm.Hmac(algorithm.HmacSha512)) -> "HS512"
    algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256)) ->
      "RS256"
    algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha384)) ->
      "RS384"
    algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha512)) ->
      "RS512"
    algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha256)) ->
      "PS256"
    algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha384)) ->
      "PS384"
    algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha512)) ->
      "PS512"
    algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)) -> "ES256"
    algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP384)) -> "ES384"
    algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP521)) -> "ES512"
    algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaSecp256k1)) ->
      "ES256K"
    algorithm.DigitalSignature(algorithm.Eddsa) -> "EdDSA"
  }
}

/// Parse a signing algorithm from its JOSE string representation.
pub fn signing_alg_from_string(
  alg: String,
) -> Result(algorithm.SigningAlg, gose.GoseError) {
  case alg {
    "HS256" -> Ok(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)))
    "HS384" -> Ok(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha384)))
    "HS512" -> Ok(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha512)))
    "RS256" ->
      Ok(
        algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256)),
      )
    "RS384" ->
      Ok(
        algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha384)),
      )
    "RS512" ->
      Ok(
        algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha512)),
      )
    "PS256" ->
      Ok(algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha256)))
    "PS384" ->
      Ok(algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha384)))
    "PS512" ->
      Ok(algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha512)))
    "ES256" ->
      Ok(algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)))
    "ES384" ->
      Ok(algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP384)))
    "ES512" ->
      Ok(algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP521)))
    "ES256K" ->
      Ok(algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaSecp256k1)))
    "EdDSA" -> Ok(algorithm.DigitalSignature(algorithm.Eddsa))
    _ -> Error(gose.ParseError("unknown JWS algorithm: " <> alg))
  }
}

/// Convert a key encryption algorithm to its JOSE string representation.
pub fn key_encryption_alg_to_string(alg: algorithm.KeyEncryptionAlg) -> String {
  case alg {
    algorithm.Direct -> "dir"
    algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes128) -> "A128KW"
    algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes192) -> "A192KW"
    algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes256) -> "A256KW"
    algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes128) -> "A128GCMKW"
    algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes192) -> "A192GCMKW"
    algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes256) -> "A256GCMKW"
    algorithm.RsaEncryption(algorithm.RsaPkcs1v15) -> "RSA1_5"
    algorithm.RsaEncryption(algorithm.RsaOaepSha1) -> "RSA-OAEP"
    algorithm.RsaEncryption(algorithm.RsaOaepSha256) -> "RSA-OAEP-256"
    algorithm.EcdhEs(algorithm.EcdhEsDirect) -> "ECDH-ES"
    algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes128)) ->
      "ECDH-ES+A128KW"
    algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes192)) ->
      "ECDH-ES+A192KW"
    algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes256)) ->
      "ECDH-ES+A256KW"
    algorithm.EcdhEs(algorithm.EcdhEsChaCha20Kw(algorithm.C20PKw)) ->
      "ECDH-ES+C20PKW"
    algorithm.EcdhEs(algorithm.EcdhEsChaCha20Kw(algorithm.XC20PKw)) ->
      "ECDH-ES+XC20PKW"
    algorithm.ChaCha20KeyWrap(algorithm.C20PKw) -> "C20PKW"
    algorithm.ChaCha20KeyWrap(algorithm.XC20PKw) -> "XC20PKW"
    algorithm.Pbes2(algorithm.Pbes2Sha256Aes128Kw) -> "PBES2-HS256+A128KW"
    algorithm.Pbes2(algorithm.Pbes2Sha384Aes192Kw) -> "PBES2-HS384+A192KW"
    algorithm.Pbes2(algorithm.Pbes2Sha512Aes256Kw) -> "PBES2-HS512+A256KW"
  }
}

/// Parse a key encryption algorithm from its JOSE string representation.
pub fn key_encryption_alg_from_string(
  alg: String,
) -> Result(algorithm.KeyEncryptionAlg, gose.GoseError) {
  case alg {
    "dir" -> Ok(algorithm.Direct)
    "A128KW" -> Ok(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes128))
    "A192KW" -> Ok(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes192))
    "A256KW" -> Ok(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes256))
    "A128GCMKW" ->
      Ok(algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes128))
    "A192GCMKW" ->
      Ok(algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes192))
    "A256GCMKW" ->
      Ok(algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes256))
    "RSA1_5" -> Ok(algorithm.RsaEncryption(algorithm.RsaPkcs1v15))
    "RSA-OAEP" -> Ok(algorithm.RsaEncryption(algorithm.RsaOaepSha1))
    "RSA-OAEP-256" -> Ok(algorithm.RsaEncryption(algorithm.RsaOaepSha256))
    "ECDH-ES" -> Ok(algorithm.EcdhEs(algorithm.EcdhEsDirect))
    "ECDH-ES+A128KW" ->
      Ok(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes128)))
    "ECDH-ES+A192KW" ->
      Ok(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes192)))
    "ECDH-ES+A256KW" ->
      Ok(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes256)))
    "ECDH-ES+C20PKW" ->
      Ok(algorithm.EcdhEs(algorithm.EcdhEsChaCha20Kw(algorithm.C20PKw)))
    "ECDH-ES+XC20PKW" ->
      Ok(algorithm.EcdhEs(algorithm.EcdhEsChaCha20Kw(algorithm.XC20PKw)))
    "C20PKW" -> Ok(algorithm.ChaCha20KeyWrap(algorithm.C20PKw))
    "XC20PKW" -> Ok(algorithm.ChaCha20KeyWrap(algorithm.XC20PKw))
    "PBES2-HS256+A128KW" -> Ok(algorithm.Pbes2(algorithm.Pbes2Sha256Aes128Kw))
    "PBES2-HS384+A192KW" -> Ok(algorithm.Pbes2(algorithm.Pbes2Sha384Aes192Kw))
    "PBES2-HS512+A256KW" -> Ok(algorithm.Pbes2(algorithm.Pbes2Sha512Aes256Kw))
    _ -> Error(gose.ParseError("unknown JWE algorithm: " <> alg))
  }
}

/// Convert a content encryption algorithm to its JOSE string representation.
pub fn content_alg_to_string(alg: algorithm.ContentAlg) -> String {
  case alg {
    algorithm.AesGcm(algorithm.Aes128) -> "A128GCM"
    algorithm.AesGcm(algorithm.Aes192) -> "A192GCM"
    algorithm.AesGcm(algorithm.Aes256) -> "A256GCM"
    algorithm.AesCbcHmac(algorithm.Aes128) -> "A128CBC-HS256"
    algorithm.AesCbcHmac(algorithm.Aes192) -> "A192CBC-HS384"
    algorithm.AesCbcHmac(algorithm.Aes256) -> "A256CBC-HS512"
    algorithm.ChaCha20Poly1305 -> "C20P"
    algorithm.XChaCha20Poly1305 -> "XC20P"
  }
}

/// Parse a content encryption algorithm from its JOSE string representation.
pub fn content_alg_from_string(
  alg: String,
) -> Result(algorithm.ContentAlg, gose.GoseError) {
  case alg {
    "A128GCM" -> Ok(algorithm.AesGcm(algorithm.Aes128))
    "A192GCM" -> Ok(algorithm.AesGcm(algorithm.Aes192))
    "A256GCM" -> Ok(algorithm.AesGcm(algorithm.Aes256))
    "A128CBC-HS256" -> Ok(algorithm.AesCbcHmac(algorithm.Aes128))
    "A192CBC-HS384" -> Ok(algorithm.AesCbcHmac(algorithm.Aes192))
    "A256CBC-HS512" -> Ok(algorithm.AesCbcHmac(algorithm.Aes256))
    "C20P" -> Ok(algorithm.ChaCha20Poly1305)
    "XC20P" -> Ok(algorithm.XChaCha20Poly1305)
    _ -> Error(gose.ParseError("unknown content encryption algorithm: " <> alg))
  }
}
