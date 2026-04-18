//// COSE algorithm integer ID mapping ([RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html)).
////
//// Maps between `gose/algorithm` types and COSE integer identifiers.

import gleam/int
import gleam/string
import gose
import gose/algorithm

/// Convert a signature algorithm to its COSE integer identifier.
pub fn signature_alg_to_int(alg: algorithm.DigitalSignatureAlg) -> Int {
  case alg {
    algorithm.Ecdsa(algorithm.EcdsaP256) -> -7
    algorithm.Ecdsa(algorithm.EcdsaP384) -> -35
    algorithm.Ecdsa(algorithm.EcdsaP521) -> -36
    algorithm.Ecdsa(algorithm.EcdsaSecp256k1) -> -47
    algorithm.Eddsa -> -8
    algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256) -> -257
    algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha384) -> -258
    algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha512) -> -259
    algorithm.RsaPss(algorithm.RsaPssSha256) -> -37
    algorithm.RsaPss(algorithm.RsaPssSha384) -> -38
    algorithm.RsaPss(algorithm.RsaPssSha512) -> -39
  }
}

/// Parse a signature algorithm from its COSE integer identifier.
pub fn signature_alg_from_int(
  id: Int,
) -> Result(algorithm.DigitalSignatureAlg, gose.GoseError) {
  case id {
    -257 -> Ok(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256))
    -258 -> Ok(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha384))
    -259 -> Ok(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha512))
    -35 -> Ok(algorithm.Ecdsa(algorithm.EcdsaP384))
    -36 -> Ok(algorithm.Ecdsa(algorithm.EcdsaP521))
    -37 -> Ok(algorithm.RsaPss(algorithm.RsaPssSha256))
    -38 -> Ok(algorithm.RsaPss(algorithm.RsaPssSha384))
    -39 -> Ok(algorithm.RsaPss(algorithm.RsaPssSha512))
    -47 -> Ok(algorithm.Ecdsa(algorithm.EcdsaSecp256k1))
    -7 -> Ok(algorithm.Ecdsa(algorithm.EcdsaP256))
    -8 -> Ok(algorithm.Eddsa)
    _ ->
      Error(gose.ParseError(
        "unknown COSE signature algorithm: " <> int.to_string(id),
      ))
  }
}

/// Convert a MAC algorithm to its COSE integer identifier.
pub fn mac_alg_to_int(alg: algorithm.MacAlg) -> Int {
  case alg {
    algorithm.Hmac(algorithm.HmacSha256) -> 5
    algorithm.Hmac(algorithm.HmacSha384) -> 6
    algorithm.Hmac(algorithm.HmacSha512) -> 7
  }
}

/// Parse a MAC algorithm from its COSE integer identifier.
pub fn mac_alg_from_int(id: Int) -> Result(algorithm.MacAlg, gose.GoseError) {
  case id {
    5 -> Ok(algorithm.Hmac(algorithm.HmacSha256))
    6 -> Ok(algorithm.Hmac(algorithm.HmacSha384))
    7 -> Ok(algorithm.Hmac(algorithm.HmacSha512))
    _ ->
      Error(gose.ParseError("unknown COSE MAC algorithm: " <> int.to_string(id)))
  }
}

/// Convert a signing algorithm to its COSE integer identifier.
pub fn signing_alg_to_int(alg: algorithm.SigningAlg) -> Int {
  case alg {
    algorithm.DigitalSignature(sig_alg) -> signature_alg_to_int(sig_alg)
    algorithm.Mac(mac_alg) -> mac_alg_to_int(mac_alg)
  }
}

/// Parse a signing algorithm from its COSE integer identifier.
pub fn signing_alg_from_int(
  id: Int,
) -> Result(algorithm.SigningAlg, gose.GoseError) {
  case signature_alg_from_int(id) {
    Ok(alg) -> Ok(algorithm.DigitalSignature(alg))
    Error(_) ->
      case mac_alg_from_int(id) {
        Ok(alg) -> Ok(algorithm.Mac(alg))
        Error(_) ->
          Error(gose.ParseError(
            "unknown COSE signing algorithm: " <> int.to_string(id),
          ))
      }
  }
}

/// Convert a key encryption algorithm to its COSE integer identifier.
///
/// Some key encryption algorithms are JOSE-only and have no COSE
/// identifier, in which case this returns an error.
pub fn key_encryption_alg_to_int(
  alg: algorithm.KeyEncryptionAlg,
) -> Result(Int, gose.GoseError) {
  case alg {
    algorithm.Direct -> Ok(-6)
    algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes128) -> Ok(-3)
    algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes192) -> Ok(-4)
    algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes256) -> Ok(-5)
    algorithm.EcdhEs(algorithm.EcdhEsDirect) -> Ok(-25)
    algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes128)) -> Ok(-29)
    algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes192)) -> Ok(-30)
    algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes256)) -> Ok(-31)
    algorithm.RsaEncryption(algorithm.RsaOaepSha1) -> Ok(-40)
    algorithm.RsaEncryption(algorithm.RsaOaepSha256) -> Ok(-41)
    algorithm.AesKeyWrap(algorithm.AesGcmKw, _)
    | algorithm.ChaCha20KeyWrap(_)
    | algorithm.RsaEncryption(algorithm.RsaPkcs1v15)
    | algorithm.EcdhEs(algorithm.EcdhEsChaCha20Kw(_))
    | algorithm.Pbes2(_) ->
      Error(gose.InvalidState(
        "no COSE identifier for algorithm: " <> string.inspect(alg),
      ))
  }
}

/// Parse a key encryption algorithm from its COSE integer identifier.
///
/// Both ECDH-ES+HKDF-256 (-25) and ECDH-ES+HKDF-512 (-26) map to
/// `EcdhEs(EcdhEsDirect)` because the shared algorithm type does not
/// distinguish the HKDF variant. The HKDF variant is preserved at the
/// `cose/encrypt` layer via `EcdhEsDirectVariant`. Use
/// `new_ecdh_es_direct_recipient` and `ecdh_es_direct_decryptor` for
/// HKDF-512 support.
pub fn key_encryption_alg_from_int(
  id: Int,
) -> Result(algorithm.KeyEncryptionAlg, gose.GoseError) {
  case id {
    -25 | -26 -> Ok(algorithm.EcdhEs(algorithm.EcdhEsDirect))
    -29 -> Ok(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes128)))
    -3 -> Ok(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes128))
    -30 -> Ok(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes192)))
    -31 -> Ok(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes256)))
    -4 -> Ok(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes192))
    -5 -> Ok(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes256))
    -6 -> Ok(algorithm.Direct)
    -40 -> Ok(algorithm.RsaEncryption(algorithm.RsaOaepSha1))
    -41 -> Ok(algorithm.RsaEncryption(algorithm.RsaOaepSha256))
    _ ->
      Error(gose.ParseError(
        "unknown COSE key encryption algorithm: " <> int.to_string(id),
      ))
  }
}

/// Convert a content encryption algorithm to its COSE integer identifier.
///
/// Some content encryption algorithms are JOSE-only and have no COSE
/// identifier, in which case this returns an error.
pub fn content_alg_to_int(
  alg: algorithm.ContentAlg,
) -> Result(Int, gose.GoseError) {
  case alg {
    algorithm.AesGcm(algorithm.Aes128) -> Ok(1)
    algorithm.AesGcm(algorithm.Aes192) -> Ok(2)
    algorithm.AesGcm(algorithm.Aes256) -> Ok(3)
    algorithm.ChaCha20Poly1305 -> Ok(24)
    algorithm.AesCbcHmac(_) | algorithm.XChaCha20Poly1305 ->
      Error(gose.InvalidState(
        "no COSE identifier for algorithm: " <> string.inspect(alg),
      ))
  }
}

/// Parse a content encryption algorithm from its COSE integer identifier.
pub fn content_alg_from_int(
  id: Int,
) -> Result(algorithm.ContentAlg, gose.GoseError) {
  case id {
    1 -> Ok(algorithm.AesGcm(algorithm.Aes128))
    2 -> Ok(algorithm.AesGcm(algorithm.Aes192))
    3 -> Ok(algorithm.AesGcm(algorithm.Aes256))
    24 -> Ok(algorithm.ChaCha20Poly1305)
    _ ->
      Error(gose.ParseError(
        "unknown COSE content encryption algorithm: " <> int.to_string(id),
      ))
  }
}
