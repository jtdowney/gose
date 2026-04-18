import gose
import gose/algorithm
import gose/cose/algorithm as cose_algorithm
import gose/test_helpers/generators
import qcheck

pub fn signing_alg_roundtrip_test() {
  use alg <- qcheck.given(generators.bare_jws_alg_generator())
  let id = cose_algorithm.signing_alg_to_int(alg)
  assert cose_algorithm.signing_alg_from_int(id) == Ok(alg)
}

pub fn signing_alg_from_cose_unknown_returns_error_test() {
  assert cose_algorithm.signing_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE signing algorithm: 999"))
}

pub fn signing_alg_from_cose_zero_returns_error_test() {
  assert cose_algorithm.signing_alg_from_int(0)
    == Error(gose.ParseError("unknown COSE signing algorithm: 0"))
}

pub fn key_encryption_alg_roundtrip_test() {
  let gen = cose_key_encryption_alg_generator()
  use alg <- qcheck.given(gen)
  let assert Ok(id) = cose_algorithm.key_encryption_alg_to_int(alg)
  assert cose_algorithm.key_encryption_alg_from_int(id) == Ok(alg)
}

pub fn key_encryption_alg_to_cose_direct_spot_check_test() {
  assert cose_algorithm.key_encryption_alg_to_int(algorithm.Direct) == Ok(-6)
}

pub fn key_encryption_alg_from_cose_ecdh_es_direct_hkdf512_test() {
  assert cose_algorithm.key_encryption_alg_from_int(-26)
    == Ok(algorithm.EcdhEs(algorithm.EcdhEsDirect))
}

pub fn key_encryption_alg_from_cose_unknown_returns_error_test() {
  assert cose_algorithm.key_encryption_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE key encryption algorithm: 999"))
}

pub fn key_encryption_alg_to_cose_aes_gcm_kw_returns_error_test() {
  assert cose_algorithm.key_encryption_alg_to_int(algorithm.AesKeyWrap(
      algorithm.AesGcmKw,
      algorithm.Aes128,
    ))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: AesKeyWrap(AesGcmKw, Aes128)",
    ))
}

pub fn key_encryption_alg_to_cose_chacha20_kw_returns_error_test() {
  assert cose_algorithm.key_encryption_alg_to_int(algorithm.ChaCha20KeyWrap(
      algorithm.C20PKw,
    ))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: ChaCha20KeyWrap(C20PKw)",
    ))
}

pub fn key_encryption_alg_to_cose_ecdh_es_chacha20_kw_returns_error_test() {
  assert cose_algorithm.key_encryption_alg_to_int(
      algorithm.EcdhEs(algorithm.EcdhEsChaCha20Kw(algorithm.C20PKw)),
    )
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: EcdhEs(EcdhEsChaCha20Kw(C20PKw))",
    ))
}

pub fn key_encryption_alg_to_cose_rsa_pkcs1v15_returns_error_test() {
  assert cose_algorithm.key_encryption_alg_to_int(algorithm.RsaEncryption(
      algorithm.RsaPkcs1v15,
    ))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: RsaEncryption(RsaPkcs1v15)",
    ))
}

pub fn key_encryption_alg_to_cose_pbes2_returns_error_test() {
  assert cose_algorithm.key_encryption_alg_to_int(algorithm.Pbes2(
      algorithm.Pbes2Sha256Aes128Kw,
    ))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: Pbes2(Pbes2Sha256Aes128Kw)",
    ))
}

pub fn content_alg_roundtrip_test() {
  let gen = cose_content_alg_generator()
  use alg <- qcheck.given(gen)
  let assert Ok(id) = cose_algorithm.content_alg_to_int(alg)
  assert cose_algorithm.content_alg_from_int(id) == Ok(alg)
}

pub fn content_alg_from_cose_unknown_returns_error_test() {
  assert cose_algorithm.content_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE content encryption algorithm: 999"))
}

pub fn content_alg_to_cose_aes_cbc_hmac_returns_error_test() {
  assert cose_algorithm.content_alg_to_int(algorithm.AesCbcHmac(
      algorithm.Aes128,
    ))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: AesCbcHmac(Aes128)",
    ))
}

pub fn content_alg_to_cose_xchacha20_poly1305_returns_error_test() {
  assert cose_algorithm.content_alg_to_int(algorithm.XChaCha20Poly1305)
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: XChaCha20Poly1305",
    ))
}

pub fn signature_alg_roundtrip_test() {
  let gen = cose_signature_alg_generator()
  use alg <- qcheck.given(gen)
  let id = cose_algorithm.signature_alg_to_int(alg)
  assert cose_algorithm.signature_alg_from_int(id) == Ok(alg)
}

pub fn signature_alg_to_cose_es256_spot_check_test() {
  assert cose_algorithm.signature_alg_to_int(algorithm.Ecdsa(
      algorithm.EcdsaP256,
    ))
    == -7
}

pub fn signature_alg_from_cose_unknown_returns_error_test() {
  assert cose_algorithm.signature_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE signature algorithm: 999"))
}

pub fn mac_alg_roundtrip_test() {
  let gen = cose_mac_alg_generator()
  use alg <- qcheck.given(gen)
  let id = cose_algorithm.mac_alg_to_int(alg)
  assert cose_algorithm.mac_alg_from_int(id) == Ok(alg)
}

pub fn mac_alg_from_cose_unknown_returns_error_test() {
  assert cose_algorithm.mac_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE MAC algorithm: 999"))
}

fn cose_key_encryption_alg_generator() -> qcheck.Generator(
  algorithm.KeyEncryptionAlg,
) {
  qcheck.from_generators(qcheck.return(algorithm.Direct), [
    qcheck.return(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes128)),
    qcheck.return(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes192)),
    qcheck.return(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes256)),
    qcheck.return(algorithm.EcdhEs(algorithm.EcdhEsDirect)),
    qcheck.return(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes128))),
    qcheck.return(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes192))),
    qcheck.return(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes256))),
    qcheck.return(algorithm.RsaEncryption(algorithm.RsaOaepSha1)),
    qcheck.return(algorithm.RsaEncryption(algorithm.RsaOaepSha256)),
  ])
}

fn cose_content_alg_generator() -> qcheck.Generator(algorithm.ContentAlg) {
  qcheck.from_generators(qcheck.return(algorithm.AesGcm(algorithm.Aes128)), [
    qcheck.return(algorithm.AesGcm(algorithm.Aes192)),
    qcheck.return(algorithm.AesGcm(algorithm.Aes256)),
    qcheck.return(algorithm.ChaCha20Poly1305),
  ])
}

fn cose_signature_alg_generator() -> qcheck.Generator(
  algorithm.DigitalSignatureAlg,
) {
  qcheck.from_generators(qcheck.return(algorithm.Ecdsa(algorithm.EcdsaP256)), [
    qcheck.return(algorithm.Ecdsa(algorithm.EcdsaP384)),
    qcheck.return(algorithm.Ecdsa(algorithm.EcdsaP521)),
    qcheck.return(algorithm.Ecdsa(algorithm.EcdsaSecp256k1)),
    qcheck.return(algorithm.Eddsa),
    qcheck.return(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256)),
    qcheck.return(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha384)),
    qcheck.return(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha512)),
    qcheck.return(algorithm.RsaPss(algorithm.RsaPssSha256)),
    qcheck.return(algorithm.RsaPss(algorithm.RsaPssSha384)),
    qcheck.return(algorithm.RsaPss(algorithm.RsaPssSha512)),
  ])
}

fn cose_mac_alg_generator() -> qcheck.Generator(algorithm.MacAlg) {
  qcheck.from_generators(qcheck.return(algorithm.Hmac(algorithm.HmacSha256)), [
    qcheck.return(algorithm.Hmac(algorithm.HmacSha384)),
    qcheck.return(algorithm.Hmac(algorithm.HmacSha512)),
  ])
}
