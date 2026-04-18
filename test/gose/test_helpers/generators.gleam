import gleam/list
import gose
import gose/test_helpers/fixtures
import kryptos/ec
import kryptos/eddsa
import kryptos/xdh
import qcheck

pub fn bare_jws_alg_generator() -> qcheck.Generator(gose.SigningAlg) {
  qcheck.from_generators(qcheck.return(gose.Mac(gose.Hmac(gose.HmacSha256))), [
    qcheck.return(gose.Mac(gose.Hmac(gose.HmacSha384))),
    qcheck.return(gose.Mac(gose.Hmac(gose.HmacSha512))),
    qcheck.return(gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha256))),
    qcheck.return(gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha384))),
    qcheck.return(gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha512))),
    qcheck.return(gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha256))),
    qcheck.return(gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha384))),
    qcheck.return(gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha512))),
    qcheck.return(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256))),
    qcheck.return(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP384))),
    qcheck.return(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP521))),
    qcheck.return(gose.DigitalSignature(gose.Ecdsa(gose.EcdsaSecp256k1))),
    qcheck.return(gose.DigitalSignature(gose.Eddsa)),
  ])
}

pub fn bare_jwe_alg_generator() -> qcheck.Generator(gose.KeyEncryptionAlg) {
  qcheck.from_generators(qcheck.return(gose.Direct), [
    qcheck.return(gose.AesKeyWrap(gose.AesKw, gose.Aes128)),
    qcheck.return(gose.AesKeyWrap(gose.AesKw, gose.Aes192)),
    qcheck.return(gose.AesKeyWrap(gose.AesKw, gose.Aes256)),
    qcheck.return(gose.AesKeyWrap(gose.AesGcmKw, gose.Aes128)),
    qcheck.return(gose.AesKeyWrap(gose.AesGcmKw, gose.Aes192)),
    qcheck.return(gose.AesKeyWrap(gose.AesGcmKw, gose.Aes256)),
    qcheck.return(gose.RsaEncryption(gose.RsaPkcs1v15)),
    qcheck.return(gose.RsaEncryption(gose.RsaOaepSha1)),
    qcheck.return(gose.RsaEncryption(gose.RsaOaepSha256)),
    qcheck.return(gose.EcdhEs(gose.EcdhEsDirect)),
    qcheck.return(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128))),
    qcheck.return(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes192))),
    qcheck.return(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes256))),
    qcheck.return(gose.Pbes2(gose.Pbes2Sha256Aes128Kw)),
    qcheck.return(gose.Pbes2(gose.Pbes2Sha384Aes192Kw)),
    qcheck.return(gose.Pbes2(gose.Pbes2Sha512Aes256Kw)),
    qcheck.return(gose.ChaCha20KeyWrap(gose.C20PKw)),
    qcheck.return(gose.ChaCha20KeyWrap(gose.XC20PKw)),
    qcheck.return(gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.C20PKw))),
    qcheck.return(gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.XC20PKw))),
  ])
}

pub type JwsAlgWithKey(kid) {
  JwsAlgWithKey(alg: gose.SigningAlg, key: gose.Key(kid))
}

pub type HmacKeys(kid) {
  HmacKeys(hs256: gose.Key(kid), hs384: gose.Key(kid), hs512: gose.Key(kid))
}

pub fn generate_hmac_keys() -> HmacKeys(kid) {
  let hs256 = gose.generate_hmac_key(gose.HmacSha256)
  let hs384 = gose.generate_hmac_key(gose.HmacSha384)
  let hs512 = gose.generate_hmac_key(gose.HmacSha512)
  HmacKeys(hs256, hs384, hs512)
}

pub fn jws_hmac_alg_generator(
  keys: HmacKeys(kid),
) -> qcheck.Generator(JwsAlgWithKey(kid)) {
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(
      gose.Mac(gose.Hmac(gose.HmacSha256)),
      keys.hs256,
    )),
    [
      qcheck.return(JwsAlgWithKey(
        gose.Mac(gose.Hmac(gose.HmacSha384)),
        keys.hs384,
      )),
      qcheck.return(JwsAlgWithKey(
        gose.Mac(gose.Hmac(gose.HmacSha512)),
        keys.hs512,
      )),
    ],
  )
}

pub fn jws_rsa_alg_generator() -> qcheck.Generator(JwsAlgWithKey(kid)) {
  let key = fixtures.rsa_private_key()
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(
      gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha256)),
      key,
    )),
    [
      qcheck.return(JwsAlgWithKey(
        gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha384)),
        key,
      )),
      qcheck.return(JwsAlgWithKey(
        gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha512)),
        key,
      )),
      qcheck.return(JwsAlgWithKey(
        gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha256)),
        key,
      )),
      qcheck.return(JwsAlgWithKey(
        gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha384)),
        key,
      )),
      qcheck.return(JwsAlgWithKey(
        gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha512)),
        key,
      )),
    ],
  )
}

pub fn jws_ecdsa_alg_generator() -> qcheck.Generator(JwsAlgWithKey(kid)) {
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(
      gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)),
      fixtures.ec_p256_key(),
    )),
    [
      qcheck.return(JwsAlgWithKey(
        gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP384)),
        fixtures.ec_p384_key(),
      )),
      qcheck.return(JwsAlgWithKey(
        gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP521)),
        fixtures.ec_p521_key(),
      )),
      qcheck.return(JwsAlgWithKey(
        gose.DigitalSignature(gose.Ecdsa(gose.EcdsaSecp256k1)),
        fixtures.ec_secp256k1_key(),
      )),
    ],
  )
}

pub fn jws_eddsa_alg_generator() -> qcheck.Generator(JwsAlgWithKey(kid)) {
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(
      gose.DigitalSignature(gose.Eddsa),
      fixtures.ed25519_key(),
    )),
    [
      qcheck.return(JwsAlgWithKey(
        gose.DigitalSignature(gose.Eddsa),
        fixtures.ed448_key(),
      )),
    ],
  )
}

pub fn jws_alg_generator(
  hmac_keys: HmacKeys(kid),
) -> qcheck.Generator(JwsAlgWithKey(kid)) {
  qcheck.from_generators(jws_hmac_alg_generator(hmac_keys), [
    jws_rsa_alg_generator(),
    jws_ecdsa_alg_generator(),
    jws_eddsa_alg_generator(),
  ])
}

pub fn jwe_enc_generator() -> qcheck.Generator(gose.ContentAlg) {
  qcheck.from_generators(qcheck.return(gose.AesGcm(gose.Aes128)), [
    qcheck.return(gose.AesGcm(gose.Aes192)),
    qcheck.return(gose.AesGcm(gose.Aes256)),
    qcheck.return(gose.AesCbcHmac(gose.Aes128)),
    qcheck.return(gose.AesCbcHmac(gose.Aes192)),
    qcheck.return(gose.AesCbcHmac(gose.Aes256)),
    qcheck.return(gose.ChaCha20Poly1305),
    qcheck.return(gose.XChaCha20Poly1305),
  ])
}

pub type JweDirectEncWithKey(kid) {
  JweDirectEncWithKey(enc: gose.ContentAlg, key: gose.Key(kid))
}

fn jwe_direct_enc_with_key(
  enc: gose.ContentAlg,
) -> qcheck.Generator(JweDirectEncWithKey(kid)) {
  let key = gose.generate_enc_key(enc)
  qcheck.return(JweDirectEncWithKey(enc, key))
}

pub fn jwe_direct_generator() -> qcheck.Generator(JweDirectEncWithKey(kid)) {
  qcheck.from_generators(jwe_direct_enc_with_key(gose.AesGcm(gose.Aes128)), [
    jwe_direct_enc_with_key(gose.AesGcm(gose.Aes192)),
    jwe_direct_enc_with_key(gose.AesGcm(gose.Aes256)),
    jwe_direct_enc_with_key(gose.AesCbcHmac(gose.Aes128)),
    jwe_direct_enc_with_key(gose.AesCbcHmac(gose.Aes192)),
    jwe_direct_enc_with_key(gose.AesCbcHmac(gose.Aes256)),
    jwe_direct_enc_with_key(gose.ChaCha20Poly1305),
    jwe_direct_enc_with_key(gose.XChaCha20Poly1305),
  ])
}

fn aes_size_enc_combinations() -> List(#(gose.AesKeySize, gose.ContentAlg)) {
  let sizes = [gose.Aes128, gose.Aes192, gose.Aes256]
  let encs = [
    gose.AesGcm(gose.Aes128),
    gose.AesGcm(gose.Aes192),
    gose.AesGcm(gose.Aes256),
    gose.AesCbcHmac(gose.Aes128),
    gose.AesCbcHmac(gose.Aes192),
    gose.AesCbcHmac(gose.Aes256),
  ]
  list.flat_map(sizes, fn(size) { list.map(encs, fn(enc) { #(size, enc) }) })
}

pub type JweAesKwWithKey(kid) {
  JweAesKwWithKey(
    size: gose.AesKeySize,
    enc: gose.ContentAlg,
    key: gose.Key(kid),
  )
}

fn jwe_aes_kw_with_key(
  size: gose.AesKeySize,
  enc: gose.ContentAlg,
) -> qcheck.Generator(JweAesKwWithKey(kid)) {
  let key = gose.generate_aes_kw_key(size)
  qcheck.return(JweAesKwWithKey(size, enc, key))
}

pub fn jwe_aes_kw_generator() -> qcheck.Generator(JweAesKwWithKey(kid)) {
  let generators =
    list.map(aes_size_enc_combinations(), fn(pair) {
      jwe_aes_kw_with_key(pair.0, pair.1)
    })
  let assert [first, ..rest] = generators
  qcheck.from_generators(first, rest)
}

pub type JweAesGcmKwWithKey(kid) {
  JweAesGcmKwWithKey(
    size: gose.AesKeySize,
    enc: gose.ContentAlg,
    key: gose.Key(kid),
  )
}

fn jwe_aes_gcm_kw_with_key(
  size: gose.AesKeySize,
  enc: gose.ContentAlg,
) -> qcheck.Generator(JweAesGcmKwWithKey(kid)) {
  let key = gose.generate_aes_kw_key(size)
  qcheck.return(JweAesGcmKwWithKey(size, enc, key))
}

pub fn jwe_aes_gcm_kw_generator() -> qcheck.Generator(JweAesGcmKwWithKey(kid)) {
  let generators =
    list.map(aes_size_enc_combinations(), fn(pair) {
      jwe_aes_gcm_kw_with_key(pair.0, pair.1)
    })
  let assert [first, ..rest] = generators
  qcheck.from_generators(first, rest)
}

pub type JweChaCha20KwWithKey(kid) {
  JweChaCha20KwWithKey(
    variant: gose.ChaCha20Kw,
    enc: gose.ContentAlg,
    key: gose.Key(kid),
  )
}

fn jwe_chacha20_kw_with_key(
  variant: gose.ChaCha20Kw,
  enc: gose.ContentAlg,
) -> qcheck.Generator(JweChaCha20KwWithKey(kid)) {
  let key = gose.generate_chacha20_kw_key()
  qcheck.return(JweChaCha20KwWithKey(variant, enc, key))
}

pub fn jwe_chacha20_kw_generator() -> qcheck.Generator(
  JweChaCha20KwWithKey(kid),
) {
  qcheck.from_generators(
    jwe_chacha20_kw_with_key(gose.C20PKw, gose.AesGcm(gose.Aes128)),
    [
      jwe_chacha20_kw_with_key(gose.C20PKw, gose.AesGcm(gose.Aes256)),
      jwe_chacha20_kw_with_key(gose.C20PKw, gose.ChaCha20Poly1305),
      jwe_chacha20_kw_with_key(gose.C20PKw, gose.XChaCha20Poly1305),
      jwe_chacha20_kw_with_key(gose.XC20PKw, gose.AesGcm(gose.Aes128)),
      jwe_chacha20_kw_with_key(gose.XC20PKw, gose.AesGcm(gose.Aes256)),
      jwe_chacha20_kw_with_key(gose.XC20PKw, gose.ChaCha20Poly1305),
      jwe_chacha20_kw_with_key(gose.XC20PKw, gose.XChaCha20Poly1305),
    ],
  )
}

pub fn jwe_rsa_alg_generator() -> qcheck.Generator(gose.RsaEncryptionAlg) {
  qcheck.from_generators(qcheck.return(gose.RsaOaepSha1), [
    qcheck.return(gose.RsaOaepSha256),
    qcheck.return(gose.RsaPkcs1v15),
  ])
}

pub type JweEcdhEsWithKey(kid) {
  JweEcdhEsWithKey(alg: gose.EcdhEsAlg, key: gose.Key(kid))
}

pub fn jwe_ecdh_es_generator(
  ec_p256_key: gose.Key(kid),
  ec_p384_key: gose.Key(kid),
  ec_p521_key: gose.Key(kid),
  x25519_key: gose.Key(kid),
  x448_key: gose.Key(kid),
) -> qcheck.Generator(JweEcdhEsWithKey(kid)) {
  qcheck.from_generators(
    qcheck.return(JweEcdhEsWithKey(gose.EcdhEsDirect, ec_p256_key)),
    [
      qcheck.return(JweEcdhEsWithKey(gose.EcdhEsDirect, ec_p384_key)),
      qcheck.return(JweEcdhEsWithKey(gose.EcdhEsDirect, ec_p521_key)),
      qcheck.return(JweEcdhEsWithKey(gose.EcdhEsDirect, x25519_key)),
      qcheck.return(JweEcdhEsWithKey(gose.EcdhEsDirect, x448_key)),
      qcheck.return(JweEcdhEsWithKey(gose.EcdhEsAesKw(gose.Aes128), ec_p256_key)),
      qcheck.return(JweEcdhEsWithKey(gose.EcdhEsAesKw(gose.Aes192), ec_p521_key)),
      qcheck.return(JweEcdhEsWithKey(gose.EcdhEsAesKw(gose.Aes256), ec_p384_key)),
      qcheck.return(JweEcdhEsWithKey(gose.EcdhEsAesKw(gose.Aes128), x25519_key)),
      qcheck.return(JweEcdhEsWithKey(gose.EcdhEsAesKw(gose.Aes256), x448_key)),
      qcheck.return(JweEcdhEsWithKey(
        gose.EcdhEsChaCha20Kw(gose.C20PKw),
        ec_p256_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        gose.EcdhEsChaCha20Kw(gose.XC20PKw),
        ec_p384_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        gose.EcdhEsChaCha20Kw(gose.C20PKw),
        x25519_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        gose.EcdhEsChaCha20Kw(gose.XC20PKw),
        x448_key,
      )),
    ],
  )
}

pub fn jwe_pbes2_alg_generator() -> qcheck.Generator(gose.Pbes2Alg) {
  qcheck.from_generators(qcheck.return(gose.Pbes2Sha256Aes128Kw), [
    qcheck.return(gose.Pbes2Sha384Aes192Kw),
    qcheck.return(gose.Pbes2Sha512Aes256Kw),
  ])
}

pub type Pbes2Variant {
  Pbes2Variant(alg: gose.Pbes2Alg, enc: gose.ContentAlg)
}

pub fn pbes2_variant_generator() -> qcheck.Generator(Pbes2Variant) {
  qcheck.from_generators(
    qcheck.return(Pbes2Variant(
      gose.Pbes2Sha256Aes128Kw,
      gose.AesGcm(gose.Aes128),
    )),
    [
      qcheck.return(Pbes2Variant(
        gose.Pbes2Sha384Aes192Kw,
        gose.AesGcm(gose.Aes192),
      )),
      qcheck.return(Pbes2Variant(
        gose.Pbes2Sha512Aes256Kw,
        gose.AesGcm(gose.Aes256),
      )),
    ],
  )
}

pub type AesKeyWrapVariant {
  AesKeyWrapVariant(size: gose.AesKeySize, enc: gose.ContentAlg)
}

pub fn aes_kw_variant_generator() -> qcheck.Generator(AesKeyWrapVariant) {
  qcheck.from_generators(
    qcheck.return(AesKeyWrapVariant(gose.Aes128, gose.AesGcm(gose.Aes128))),
    [
      qcheck.return(AesKeyWrapVariant(gose.Aes192, gose.AesGcm(gose.Aes192))),
      qcheck.return(AesKeyWrapVariant(gose.Aes256, gose.AesGcm(gose.Aes256))),
    ],
  )
}

pub type RsaVariant {
  RsaVariant(alg: gose.RsaEncryptionAlg, enc: gose.ContentAlg)
}

pub fn rsa_variant_generator() -> qcheck.Generator(RsaVariant) {
  qcheck.from_generators(
    qcheck.return(RsaVariant(gose.RsaOaepSha1, gose.AesGcm(gose.Aes256))),
    [
      qcheck.return(RsaVariant(gose.RsaOaepSha256, gose.AesGcm(gose.Aes128))),
      qcheck.return(RsaVariant(gose.RsaPkcs1v15, gose.AesGcm(gose.Aes256))),
    ],
  )
}

pub type EcdhVariant {
  EcdhVariant(alg: gose.EcdhEsAlg, enc: gose.ContentAlg)
}

pub fn ecdh_variant_generator() -> qcheck.Generator(EcdhVariant) {
  qcheck.from_generators(
    qcheck.return(EcdhVariant(gose.EcdhEsDirect, gose.AesGcm(gose.Aes256))),
    [
      qcheck.return(EcdhVariant(
        gose.EcdhEsAesKw(gose.Aes128),
        gose.AesGcm(gose.Aes128),
      )),
      qcheck.return(EcdhVariant(
        gose.EcdhEsAesKw(gose.Aes256),
        gose.AesGcm(gose.Aes256),
      )),
    ],
  )
}

pub type JweAlgEncWithKey(kid) {
  JweAlgEncWithKey(
    alg: gose.KeyEncryptionAlg,
    enc: gose.ContentAlg,
    key: gose.Key(kid),
  )
}

pub fn jwe_key_alg_enc_generator() -> qcheck.Generator(JweAlgEncWithKey(kid)) {
  let ec_p256_key = fixtures.ec_p256_key()
  let x25519_key = fixtures.x25519_key()

  qcheck.from_generators(
    qcheck.map(jwe_direct_generator(), fn(d) {
      JweAlgEncWithKey(gose.Direct, d.enc, d.key)
    }),
    [
      qcheck.map(jwe_aes_kw_generator(), fn(a) {
        JweAlgEncWithKey(gose.AesKeyWrap(gose.AesKw, a.size), a.enc, a.key)
      }),
      qcheck.map(jwe_aes_gcm_kw_generator(), fn(a) {
        JweAlgEncWithKey(gose.AesKeyWrap(gose.AesGcmKw, a.size), a.enc, a.key)
      }),
      qcheck.map(jwe_chacha20_kw_generator(), fn(c) {
        JweAlgEncWithKey(gose.ChaCha20KeyWrap(c.variant), c.enc, c.key)
      }),
      qcheck.return(JweAlgEncWithKey(
        gose.RsaEncryption(gose.RsaOaepSha256),
        gose.AesGcm(gose.Aes256),
        fixtures.rsa_private_key(),
      )),
      qcheck.return(JweAlgEncWithKey(
        gose.EcdhEs(gose.EcdhEsDirect),
        gose.AesGcm(gose.Aes256),
        ec_p256_key,
      )),
      qcheck.return(JweAlgEncWithKey(
        gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128)),
        gose.AesGcm(gose.Aes128),
        x25519_key,
      )),
    ],
  )
}

pub type EcCurveWithKey(kid) {
  EcCurveWithKey(curve: ec.Curve, key: gose.Key(kid))
}

pub fn ec_curve_with_key_generator() -> qcheck.Generator(EcCurveWithKey(kid)) {
  let p256_key = gose.generate_ec(ec.P256)
  let p384_key = gose.generate_ec(ec.P384)
  let p521_key = gose.generate_ec(ec.P521)
  let secp256k1_key = gose.generate_ec(ec.Secp256k1)

  qcheck.from_generators(qcheck.return(EcCurveWithKey(ec.P256, p256_key)), [
    qcheck.return(EcCurveWithKey(ec.P384, p384_key)),
    qcheck.return(EcCurveWithKey(ec.P521, p521_key)),
    qcheck.return(EcCurveWithKey(ec.Secp256k1, secp256k1_key)),
  ])
}

pub fn key_op_generator() -> qcheck.Generator(gose.KeyOp) {
  qcheck.from_generators(qcheck.return(gose.Sign), [
    qcheck.return(gose.Verify),
    qcheck.return(gose.Encrypt),
    qcheck.return(gose.Decrypt),
    qcheck.return(gose.WrapKey),
    qcheck.return(gose.UnwrapKey),
    qcheck.return(gose.DeriveKey),
    qcheck.return(gose.DeriveBits),
  ])
}

pub fn alg_generator() -> qcheck.Generator(gose.Alg) {
  qcheck.from_generators(qcheck.map(bare_jws_alg_generator(), gose.SigningAlg), [
    qcheck.map(bare_jwe_alg_generator(), gose.KeyEncryptionAlg),
    qcheck.map(jwe_enc_generator(), gose.ContentAlg),
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
