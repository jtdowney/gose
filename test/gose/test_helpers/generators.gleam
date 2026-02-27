import gose/jwa
import gose/jwk
import gose/test_helpers/fixtures
import kryptos/ec
import kryptos/eddsa
import kryptos/xdh
import qcheck

pub fn bare_jws_alg_generator() -> qcheck.Generator(jwa.JwsAlg) {
  qcheck.from_generators(qcheck.return(jwa.JwsHmac(jwa.HmacSha256)), [
    qcheck.return(jwa.JwsHmac(jwa.HmacSha384)),
    qcheck.return(jwa.JwsHmac(jwa.HmacSha512)),
    qcheck.return(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256)),
    qcheck.return(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha384)),
    qcheck.return(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha512)),
    qcheck.return(jwa.JwsRsaPss(jwa.RsaPssSha256)),
    qcheck.return(jwa.JwsRsaPss(jwa.RsaPssSha384)),
    qcheck.return(jwa.JwsRsaPss(jwa.RsaPssSha512)),
    qcheck.return(jwa.JwsEcdsa(jwa.EcdsaP256)),
    qcheck.return(jwa.JwsEcdsa(jwa.EcdsaP384)),
    qcheck.return(jwa.JwsEcdsa(jwa.EcdsaP521)),
    qcheck.return(jwa.JwsEcdsa(jwa.EcdsaSecp256k1)),
    qcheck.return(jwa.JwsEddsa),
  ])
}

pub fn bare_jwe_alg_generator() -> qcheck.Generator(jwa.JweAlg) {
  qcheck.from_generators(qcheck.return(jwa.JweDirect), [
    qcheck.return(jwa.JweAesKeyWrap(jwa.AesKw, jwa.Aes128)),
    qcheck.return(jwa.JweAesKeyWrap(jwa.AesKw, jwa.Aes192)),
    qcheck.return(jwa.JweAesKeyWrap(jwa.AesKw, jwa.Aes256)),
    qcheck.return(jwa.JweAesKeyWrap(jwa.AesGcmKw, jwa.Aes128)),
    qcheck.return(jwa.JweAesKeyWrap(jwa.AesGcmKw, jwa.Aes192)),
    qcheck.return(jwa.JweAesKeyWrap(jwa.AesGcmKw, jwa.Aes256)),
    qcheck.return(jwa.JweRsa(jwa.RsaPkcs1v15)),
    qcheck.return(jwa.JweRsa(jwa.RsaOaepSha1)),
    qcheck.return(jwa.JweRsa(jwa.RsaOaepSha256)),
    qcheck.return(jwa.JweEcdhEs(jwa.EcdhEsDirect)),
    qcheck.return(jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes128))),
    qcheck.return(jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes192))),
    qcheck.return(jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes256))),
    qcheck.return(jwa.JwePbes2(jwa.Pbes2Sha256Aes128Kw)),
    qcheck.return(jwa.JwePbes2(jwa.Pbes2Sha384Aes192Kw)),
    qcheck.return(jwa.JwePbes2(jwa.Pbes2Sha512Aes256Kw)),
    qcheck.return(jwa.JweChaCha20KeyWrap(jwa.C20PKw)),
    qcheck.return(jwa.JweChaCha20KeyWrap(jwa.XC20PKw)),
    qcheck.return(jwa.JweEcdhEs(jwa.EcdhEsChaCha20Kw(jwa.C20PKw))),
    qcheck.return(jwa.JweEcdhEs(jwa.EcdhEsChaCha20Kw(jwa.XC20PKw))),
  ])
}

pub type JwsAlgWithKey {
  JwsAlgWithKey(alg: jwa.JwsAlg, key: jwk.Jwk)
}

pub type HmacKeys {
  HmacKeys(hs256: jwk.Jwk, hs384: jwk.Jwk, hs512: jwk.Jwk)
}

pub fn generate_hmac_keys() -> HmacKeys {
  let hs256 = jwk.generate_hmac_key(jwa.HmacSha256)
  let hs384 = jwk.generate_hmac_key(jwa.HmacSha384)
  let hs512 = jwk.generate_hmac_key(jwa.HmacSha512)
  HmacKeys(hs256, hs384, hs512)
}

pub fn jws_hmac_alg_generator(keys: HmacKeys) -> qcheck.Generator(JwsAlgWithKey) {
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(jwa.JwsHmac(jwa.HmacSha256), keys.hs256)),
    [
      qcheck.return(JwsAlgWithKey(jwa.JwsHmac(jwa.HmacSha384), keys.hs384)),
      qcheck.return(JwsAlgWithKey(jwa.JwsHmac(jwa.HmacSha512), keys.hs512)),
    ],
  )
}

pub fn jws_rsa_alg_generator() -> qcheck.Generator(JwsAlgWithKey) {
  let key = fixtures.rsa_private_key()
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256), key)),
    [
      qcheck.return(JwsAlgWithKey(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha384), key)),
      qcheck.return(JwsAlgWithKey(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha512), key)),
      qcheck.return(JwsAlgWithKey(jwa.JwsRsaPss(jwa.RsaPssSha256), key)),
      qcheck.return(JwsAlgWithKey(jwa.JwsRsaPss(jwa.RsaPssSha384), key)),
      qcheck.return(JwsAlgWithKey(jwa.JwsRsaPss(jwa.RsaPssSha512), key)),
    ],
  )
}

pub fn jws_ecdsa_alg_generator() -> qcheck.Generator(JwsAlgWithKey) {
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(
      jwa.JwsEcdsa(jwa.EcdsaP256),
      fixtures.ec_p256_key(),
    )),
    [
      qcheck.return(JwsAlgWithKey(
        jwa.JwsEcdsa(jwa.EcdsaP384),
        fixtures.ec_p384_key(),
      )),
      qcheck.return(JwsAlgWithKey(
        jwa.JwsEcdsa(jwa.EcdsaP521),
        fixtures.ec_p521_key(),
      )),
      qcheck.return(JwsAlgWithKey(
        jwa.JwsEcdsa(jwa.EcdsaSecp256k1),
        fixtures.ec_secp256k1_key(),
      )),
    ],
  )
}

pub fn jws_eddsa_alg_generator() -> qcheck.Generator(JwsAlgWithKey) {
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(jwa.JwsEddsa, fixtures.ed25519_key())),
    [
      qcheck.return(JwsAlgWithKey(jwa.JwsEddsa, fixtures.ed448_key())),
    ],
  )
}

pub fn jws_alg_generator(hmac_keys: HmacKeys) -> qcheck.Generator(JwsAlgWithKey) {
  qcheck.from_generators(jws_hmac_alg_generator(hmac_keys), [
    jws_rsa_alg_generator(),
    jws_ecdsa_alg_generator(),
    jws_eddsa_alg_generator(),
  ])
}

pub fn jwe_enc_generator() -> qcheck.Generator(jwa.Enc) {
  qcheck.from_generators(qcheck.return(jwa.AesGcm(jwa.Aes128)), [
    qcheck.return(jwa.AesGcm(jwa.Aes192)),
    qcheck.return(jwa.AesGcm(jwa.Aes256)),
    qcheck.return(jwa.AesCbcHmac(jwa.Aes128)),
    qcheck.return(jwa.AesCbcHmac(jwa.Aes192)),
    qcheck.return(jwa.AesCbcHmac(jwa.Aes256)),
    qcheck.return(jwa.ChaCha20Poly1305),
    qcheck.return(jwa.XChaCha20Poly1305),
  ])
}

pub type JweDirectEncWithKey {
  JweDirectEncWithKey(enc: jwa.Enc, key: jwk.Jwk)
}

fn jwe_direct_enc_with_key(
  enc: jwa.Enc,
) -> qcheck.Generator(JweDirectEncWithKey) {
  let key = jwk.generate_enc_key(enc)
  qcheck.return(JweDirectEncWithKey(enc, key))
}

pub fn jwe_direct_generator() -> qcheck.Generator(JweDirectEncWithKey) {
  qcheck.from_generators(jwe_direct_enc_with_key(jwa.AesGcm(jwa.Aes128)), [
    jwe_direct_enc_with_key(jwa.AesGcm(jwa.Aes192)),
    jwe_direct_enc_with_key(jwa.AesGcm(jwa.Aes256)),
    jwe_direct_enc_with_key(jwa.AesCbcHmac(jwa.Aes128)),
    jwe_direct_enc_with_key(jwa.AesCbcHmac(jwa.Aes192)),
    jwe_direct_enc_with_key(jwa.AesCbcHmac(jwa.Aes256)),
    jwe_direct_enc_with_key(jwa.ChaCha20Poly1305),
    jwe_direct_enc_with_key(jwa.XChaCha20Poly1305),
  ])
}

pub type JweAesKwWithKey {
  JweAesKwWithKey(size: jwa.AesKeySize, enc: jwa.Enc, key: jwk.Jwk)
}

fn jwe_aes_kw_with_key(
  size: jwa.AesKeySize,
  enc: jwa.Enc,
) -> qcheck.Generator(JweAesKwWithKey) {
  let key = jwk.generate_aes_kw_key(size)
  qcheck.return(JweAesKwWithKey(size, enc, key))
}

pub fn jwe_aes_kw_generator() -> qcheck.Generator(JweAesKwWithKey) {
  qcheck.from_generators(
    jwe_aes_kw_with_key(jwa.Aes128, jwa.AesGcm(jwa.Aes128)),
    [
      jwe_aes_kw_with_key(jwa.Aes128, jwa.AesGcm(jwa.Aes192)),
      jwe_aes_kw_with_key(jwa.Aes128, jwa.AesGcm(jwa.Aes256)),
      jwe_aes_kw_with_key(jwa.Aes128, jwa.AesCbcHmac(jwa.Aes128)),
      jwe_aes_kw_with_key(jwa.Aes128, jwa.AesCbcHmac(jwa.Aes192)),
      jwe_aes_kw_with_key(jwa.Aes128, jwa.AesCbcHmac(jwa.Aes256)),
      jwe_aes_kw_with_key(jwa.Aes192, jwa.AesGcm(jwa.Aes128)),
      jwe_aes_kw_with_key(jwa.Aes192, jwa.AesGcm(jwa.Aes192)),
      jwe_aes_kw_with_key(jwa.Aes192, jwa.AesGcm(jwa.Aes256)),
      jwe_aes_kw_with_key(jwa.Aes192, jwa.AesCbcHmac(jwa.Aes128)),
      jwe_aes_kw_with_key(jwa.Aes192, jwa.AesCbcHmac(jwa.Aes192)),
      jwe_aes_kw_with_key(jwa.Aes192, jwa.AesCbcHmac(jwa.Aes256)),
      jwe_aes_kw_with_key(jwa.Aes256, jwa.AesGcm(jwa.Aes128)),
      jwe_aes_kw_with_key(jwa.Aes256, jwa.AesGcm(jwa.Aes192)),
      jwe_aes_kw_with_key(jwa.Aes256, jwa.AesGcm(jwa.Aes256)),
      jwe_aes_kw_with_key(jwa.Aes256, jwa.AesCbcHmac(jwa.Aes128)),
      jwe_aes_kw_with_key(jwa.Aes256, jwa.AesCbcHmac(jwa.Aes192)),
      jwe_aes_kw_with_key(jwa.Aes256, jwa.AesCbcHmac(jwa.Aes256)),
    ],
  )
}

pub type JweAesGcmKwWithKey {
  JweAesGcmKwWithKey(size: jwa.AesKeySize, enc: jwa.Enc, key: jwk.Jwk)
}

fn jwe_aes_gcm_kw_with_key(
  size: jwa.AesKeySize,
  enc: jwa.Enc,
) -> qcheck.Generator(JweAesGcmKwWithKey) {
  let key = jwk.generate_aes_kw_key(size)
  qcheck.return(JweAesGcmKwWithKey(size, enc, key))
}

pub fn jwe_aes_gcm_kw_generator() -> qcheck.Generator(JweAesGcmKwWithKey) {
  qcheck.from_generators(
    jwe_aes_gcm_kw_with_key(jwa.Aes128, jwa.AesGcm(jwa.Aes128)),
    [
      jwe_aes_gcm_kw_with_key(jwa.Aes128, jwa.AesGcm(jwa.Aes192)),
      jwe_aes_gcm_kw_with_key(jwa.Aes128, jwa.AesGcm(jwa.Aes256)),
      jwe_aes_gcm_kw_with_key(jwa.Aes128, jwa.AesCbcHmac(jwa.Aes128)),
      jwe_aes_gcm_kw_with_key(jwa.Aes128, jwa.AesCbcHmac(jwa.Aes192)),
      jwe_aes_gcm_kw_with_key(jwa.Aes128, jwa.AesCbcHmac(jwa.Aes256)),
      jwe_aes_gcm_kw_with_key(jwa.Aes192, jwa.AesGcm(jwa.Aes128)),
      jwe_aes_gcm_kw_with_key(jwa.Aes192, jwa.AesGcm(jwa.Aes192)),
      jwe_aes_gcm_kw_with_key(jwa.Aes192, jwa.AesGcm(jwa.Aes256)),
      jwe_aes_gcm_kw_with_key(jwa.Aes192, jwa.AesCbcHmac(jwa.Aes128)),
      jwe_aes_gcm_kw_with_key(jwa.Aes192, jwa.AesCbcHmac(jwa.Aes192)),
      jwe_aes_gcm_kw_with_key(jwa.Aes192, jwa.AesCbcHmac(jwa.Aes256)),
      jwe_aes_gcm_kw_with_key(jwa.Aes256, jwa.AesGcm(jwa.Aes128)),
      jwe_aes_gcm_kw_with_key(jwa.Aes256, jwa.AesGcm(jwa.Aes192)),
      jwe_aes_gcm_kw_with_key(jwa.Aes256, jwa.AesGcm(jwa.Aes256)),
      jwe_aes_gcm_kw_with_key(jwa.Aes256, jwa.AesCbcHmac(jwa.Aes128)),
      jwe_aes_gcm_kw_with_key(jwa.Aes256, jwa.AesCbcHmac(jwa.Aes192)),
      jwe_aes_gcm_kw_with_key(jwa.Aes256, jwa.AesCbcHmac(jwa.Aes256)),
    ],
  )
}

pub type JweChaCha20KwWithKey {
  JweChaCha20KwWithKey(variant: jwa.ChaCha20Kw, enc: jwa.Enc, key: jwk.Jwk)
}

fn jwe_chacha20_kw_with_key(
  variant: jwa.ChaCha20Kw,
  enc: jwa.Enc,
) -> qcheck.Generator(JweChaCha20KwWithKey) {
  let key = jwk.generate_chacha20_kw_key()
  qcheck.return(JweChaCha20KwWithKey(variant, enc, key))
}

pub fn jwe_chacha20_kw_generator() -> qcheck.Generator(JweChaCha20KwWithKey) {
  qcheck.from_generators(
    jwe_chacha20_kw_with_key(jwa.C20PKw, jwa.AesGcm(jwa.Aes128)),
    [
      jwe_chacha20_kw_with_key(jwa.C20PKw, jwa.AesGcm(jwa.Aes256)),
      jwe_chacha20_kw_with_key(jwa.C20PKw, jwa.ChaCha20Poly1305),
      jwe_chacha20_kw_with_key(jwa.C20PKw, jwa.XChaCha20Poly1305),
      jwe_chacha20_kw_with_key(jwa.XC20PKw, jwa.AesGcm(jwa.Aes128)),
      jwe_chacha20_kw_with_key(jwa.XC20PKw, jwa.AesGcm(jwa.Aes256)),
      jwe_chacha20_kw_with_key(jwa.XC20PKw, jwa.ChaCha20Poly1305),
      jwe_chacha20_kw_with_key(jwa.XC20PKw, jwa.XChaCha20Poly1305),
    ],
  )
}

pub fn jwe_rsa_alg_generator() -> qcheck.Generator(jwa.RsaJweAlg) {
  qcheck.from_generators(qcheck.return(jwa.RsaOaepSha1), [
    qcheck.return(jwa.RsaOaepSha256),
    qcheck.return(jwa.RsaPkcs1v15),
  ])
}

pub type JweEcdhEsWithKey {
  JweEcdhEsWithKey(alg: jwa.EcdhEsAlg, key: jwk.Jwk)
}

pub fn jwe_ecdh_es_generator(
  ec_p256_key: jwk.Jwk,
  ec_p384_key: jwk.Jwk,
  ec_p521_key: jwk.Jwk,
  x25519_key: jwk.Jwk,
  x448_key: jwk.Jwk,
) -> qcheck.Generator(JweEcdhEsWithKey) {
  qcheck.from_generators(
    qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsDirect, ec_p256_key)),
    [
      qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsDirect, ec_p384_key)),
      qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsDirect, ec_p521_key)),
      qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsDirect, x25519_key)),
      qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsDirect, x448_key)),
      qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsAesKw(jwa.Aes128), ec_p256_key)),
      qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsAesKw(jwa.Aes192), ec_p521_key)),
      qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsAesKw(jwa.Aes256), ec_p384_key)),
      qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsAesKw(jwa.Aes128), x25519_key)),
      qcheck.return(JweEcdhEsWithKey(jwa.EcdhEsAesKw(jwa.Aes256), x448_key)),
      qcheck.return(JweEcdhEsWithKey(
        jwa.EcdhEsChaCha20Kw(jwa.C20PKw),
        ec_p256_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        jwa.EcdhEsChaCha20Kw(jwa.XC20PKw),
        ec_p384_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        jwa.EcdhEsChaCha20Kw(jwa.C20PKw),
        x25519_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        jwa.EcdhEsChaCha20Kw(jwa.XC20PKw),
        x448_key,
      )),
    ],
  )
}

pub fn jwe_pbes2_alg_generator() -> qcheck.Generator(jwa.Pbes2Alg) {
  qcheck.from_generators(qcheck.return(jwa.Pbes2Sha256Aes128Kw), [
    qcheck.return(jwa.Pbes2Sha384Aes192Kw),
    qcheck.return(jwa.Pbes2Sha512Aes256Kw),
  ])
}

pub type Pbes2Variant {
  Pbes2Variant(alg: jwa.Pbes2Alg, enc: jwa.Enc)
}

pub fn pbes2_variant_generator() -> qcheck.Generator(Pbes2Variant) {
  qcheck.from_generators(
    qcheck.return(Pbes2Variant(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes128))),
    [
      qcheck.return(Pbes2Variant(
        jwa.Pbes2Sha384Aes192Kw,
        jwa.AesGcm(jwa.Aes192),
      )),
      qcheck.return(Pbes2Variant(
        jwa.Pbes2Sha512Aes256Kw,
        jwa.AesGcm(jwa.Aes256),
      )),
    ],
  )
}

pub type AesKeyWrapVariant {
  AesKeyWrapVariant(size: jwa.AesKeySize, enc: jwa.Enc)
}

pub fn aes_kw_variant_generator() -> qcheck.Generator(AesKeyWrapVariant) {
  qcheck.from_generators(
    qcheck.return(AesKeyWrapVariant(jwa.Aes128, jwa.AesGcm(jwa.Aes128))),
    [
      qcheck.return(AesKeyWrapVariant(jwa.Aes192, jwa.AesGcm(jwa.Aes192))),
      qcheck.return(AesKeyWrapVariant(jwa.Aes256, jwa.AesGcm(jwa.Aes256))),
    ],
  )
}

pub fn aes_gcm_kw_variant_generator() -> qcheck.Generator(AesKeyWrapVariant) {
  qcheck.from_generators(
    qcheck.return(AesKeyWrapVariant(jwa.Aes128, jwa.AesGcm(jwa.Aes128))),
    [
      qcheck.return(AesKeyWrapVariant(jwa.Aes192, jwa.AesGcm(jwa.Aes192))),
      qcheck.return(AesKeyWrapVariant(jwa.Aes256, jwa.AesGcm(jwa.Aes256))),
    ],
  )
}

pub type RsaVariant {
  RsaVariant(alg: jwa.RsaJweAlg, enc: jwa.Enc)
}

pub fn rsa_variant_generator() -> qcheck.Generator(RsaVariant) {
  qcheck.from_generators(
    qcheck.return(RsaVariant(jwa.RsaOaepSha1, jwa.AesGcm(jwa.Aes256))),
    [
      qcheck.return(RsaVariant(jwa.RsaOaepSha256, jwa.AesGcm(jwa.Aes128))),
      qcheck.return(RsaVariant(jwa.RsaPkcs1v15, jwa.AesGcm(jwa.Aes256))),
    ],
  )
}

pub type EcdhVariant {
  EcdhVariant(alg: jwa.EcdhEsAlg, enc: jwa.Enc)
}

pub fn ecdh_variant_generator() -> qcheck.Generator(EcdhVariant) {
  qcheck.from_generators(
    qcheck.return(EcdhVariant(jwa.EcdhEsDirect, jwa.AesGcm(jwa.Aes256))),
    [
      qcheck.return(EcdhVariant(
        jwa.EcdhEsAesKw(jwa.Aes128),
        jwa.AesGcm(jwa.Aes128),
      )),
      qcheck.return(EcdhVariant(
        jwa.EcdhEsAesKw(jwa.Aes256),
        jwa.AesGcm(jwa.Aes256),
      )),
    ],
  )
}

pub type JweAlgEncWithKey {
  JweAlgEncWithKey(alg: jwa.JweAlg, enc: jwa.Enc, key: jwk.Jwk)
}

pub fn jwe_key_alg_enc_generator() -> qcheck.Generator(JweAlgEncWithKey) {
  let ec_p256_key = fixtures.ec_p256_key()
  let x25519_key = fixtures.x25519_key()

  qcheck.from_generators(
    qcheck.map(jwe_direct_generator(), fn(d) {
      JweAlgEncWithKey(jwa.JweDirect, d.enc, d.key)
    }),
    [
      qcheck.map(jwe_aes_kw_generator(), fn(a) {
        JweAlgEncWithKey(jwa.JweAesKeyWrap(jwa.AesKw, a.size), a.enc, a.key)
      }),
      qcheck.map(jwe_aes_gcm_kw_generator(), fn(a) {
        JweAlgEncWithKey(jwa.JweAesKeyWrap(jwa.AesGcmKw, a.size), a.enc, a.key)
      }),
      qcheck.map(jwe_chacha20_kw_generator(), fn(c) {
        JweAlgEncWithKey(jwa.JweChaCha20KeyWrap(c.variant), c.enc, c.key)
      }),
      qcheck.return(JweAlgEncWithKey(
        jwa.JweRsa(jwa.RsaOaepSha256),
        jwa.AesGcm(jwa.Aes256),
        fixtures.rsa_private_key(),
      )),
      qcheck.return(JweAlgEncWithKey(
        jwa.JweEcdhEs(jwa.EcdhEsDirect),
        jwa.AesGcm(jwa.Aes256),
        ec_p256_key,
      )),
      qcheck.return(JweAlgEncWithKey(
        jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes128)),
        jwa.AesGcm(jwa.Aes128),
        x25519_key,
      )),
    ],
  )
}

pub type EcCurveWithKey {
  EcCurveWithKey(curve: ec.Curve, key: jwk.Jwk)
}

pub fn ec_curve_with_key_generator() -> qcheck.Generator(EcCurveWithKey) {
  let p256_key = jwk.generate_ec(ec.P256)
  let p384_key = jwk.generate_ec(ec.P384)
  let p521_key = jwk.generate_ec(ec.P521)
  let secp256k1_key = jwk.generate_ec(ec.Secp256k1)

  qcheck.from_generators(qcheck.return(EcCurveWithKey(ec.P256, p256_key)), [
    qcheck.return(EcCurveWithKey(ec.P384, p384_key)),
    qcheck.return(EcCurveWithKey(ec.P521, p521_key)),
    qcheck.return(EcCurveWithKey(ec.Secp256k1, secp256k1_key)),
  ])
}

pub fn key_op_generator() -> qcheck.Generator(jwk.KeyOp) {
  qcheck.from_generators(qcheck.return(jwk.Sign), [
    qcheck.return(jwk.Verify),
    qcheck.return(jwk.Encrypt),
    qcheck.return(jwk.Decrypt),
    qcheck.return(jwk.WrapKey),
    qcheck.return(jwk.UnwrapKey),
    qcheck.return(jwk.DeriveKey),
    qcheck.return(jwk.DeriveBits),
  ])
}

pub fn alg_generator() -> qcheck.Generator(jwk.Alg) {
  qcheck.from_generators(qcheck.map(bare_jws_alg_generator(), jwk.Jws), [
    qcheck.map(bare_jwe_alg_generator(), jwk.Jwe),
  ])
}

pub fn ec_curve_generator() -> qcheck.Generator(ec.Curve) {
  qcheck.from_generators(qcheck.return(ec.P256), [
    qcheck.return(ec.P384),
    qcheck.return(ec.P521),
    qcheck.return(ec.Secp256k1),
  ])
}

pub fn eddsa_curve_generator() -> qcheck.Generator(eddsa.Curve) {
  qcheck.from_generators(qcheck.return(eddsa.Ed25519), [
    qcheck.return(eddsa.Ed448),
  ])
}

pub fn xdh_curve_generator() -> qcheck.Generator(xdh.Curve) {
  qcheck.from_generators(qcheck.return(xdh.X25519), [qcheck.return(xdh.X448)])
}
