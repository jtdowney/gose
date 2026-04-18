import gleam/list
import gose/algorithm
import gose/key
import gose/test_helpers/fixtures
import kryptos/ec
import kryptos/eddsa
import kryptos/xdh
import qcheck

pub fn bare_jws_alg_generator() -> qcheck.Generator(algorithm.SigningAlg) {
  qcheck.from_generators(
    qcheck.return(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256))),
    [
      qcheck.return(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha384))),
      qcheck.return(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha512))),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256)),
      ),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha384)),
      ),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha512)),
      ),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha256)),
      ),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha384)),
      ),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha512)),
      ),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      ),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP384)),
      ),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP521)),
      ),
      qcheck.return(
        algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaSecp256k1)),
      ),
      qcheck.return(algorithm.DigitalSignature(algorithm.Eddsa)),
    ],
  )
}

pub fn bare_jwe_alg_generator() -> qcheck.Generator(algorithm.KeyEncryptionAlg) {
  qcheck.from_generators(qcheck.return(algorithm.Direct), [
    qcheck.return(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes128)),
    qcheck.return(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes192)),
    qcheck.return(algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes256)),
    qcheck.return(algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes128)),
    qcheck.return(algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes192)),
    qcheck.return(algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes256)),
    qcheck.return(algorithm.RsaEncryption(algorithm.RsaPkcs1v15)),
    qcheck.return(algorithm.RsaEncryption(algorithm.RsaOaepSha1)),
    qcheck.return(algorithm.RsaEncryption(algorithm.RsaOaepSha256)),
    qcheck.return(algorithm.EcdhEs(algorithm.EcdhEsDirect)),
    qcheck.return(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes128))),
    qcheck.return(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes192))),
    qcheck.return(algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes256))),
    qcheck.return(algorithm.Pbes2(algorithm.Pbes2Sha256Aes128Kw)),
    qcheck.return(algorithm.Pbes2(algorithm.Pbes2Sha384Aes192Kw)),
    qcheck.return(algorithm.Pbes2(algorithm.Pbes2Sha512Aes256Kw)),
    qcheck.return(algorithm.ChaCha20KeyWrap(algorithm.C20PKw)),
    qcheck.return(algorithm.ChaCha20KeyWrap(algorithm.XC20PKw)),
    qcheck.return(
      algorithm.EcdhEs(algorithm.EcdhEsChaCha20Kw(algorithm.C20PKw)),
    ),
    qcheck.return(
      algorithm.EcdhEs(algorithm.EcdhEsChaCha20Kw(algorithm.XC20PKw)),
    ),
  ])
}

pub type JwsAlgWithKey(kid) {
  JwsAlgWithKey(alg: algorithm.SigningAlg, key: key.Key(kid))
}

pub type HmacKeys(kid) {
  HmacKeys(hs256: key.Key(kid), hs384: key.Key(kid), hs512: key.Key(kid))
}

pub fn generate_hmac_keys() -> HmacKeys(kid) {
  let hs256 = key.generate_hmac_key(algorithm.HmacSha256)
  let hs384 = key.generate_hmac_key(algorithm.HmacSha384)
  let hs512 = key.generate_hmac_key(algorithm.HmacSha512)
  HmacKeys(hs256, hs384, hs512)
}

pub fn jws_hmac_alg_generator(
  keys: HmacKeys(kid),
) -> qcheck.Generator(JwsAlgWithKey(kid)) {
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      keys.hs256,
    )),
    [
      qcheck.return(JwsAlgWithKey(
        algorithm.Mac(algorithm.Hmac(algorithm.HmacSha384)),
        keys.hs384,
      )),
      qcheck.return(JwsAlgWithKey(
        algorithm.Mac(algorithm.Hmac(algorithm.HmacSha512)),
        keys.hs512,
      )),
    ],
  )
}

pub fn jws_rsa_alg_generator() -> qcheck.Generator(JwsAlgWithKey(kid)) {
  let key = fixtures.rsa_private_key()
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(
      algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256)),
      key,
    )),
    [
      qcheck.return(JwsAlgWithKey(
        algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha384)),
        key,
      )),
      qcheck.return(JwsAlgWithKey(
        algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha512)),
        key,
      )),
      qcheck.return(JwsAlgWithKey(
        algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha256)),
        key,
      )),
      qcheck.return(JwsAlgWithKey(
        algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha384)),
        key,
      )),
      qcheck.return(JwsAlgWithKey(
        algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha512)),
        key,
      )),
    ],
  )
}

pub fn jws_ecdsa_alg_generator() -> qcheck.Generator(JwsAlgWithKey(kid)) {
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      fixtures.ec_p256_key(),
    )),
    [
      qcheck.return(JwsAlgWithKey(
        algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP384)),
        fixtures.ec_p384_key(),
      )),
      qcheck.return(JwsAlgWithKey(
        algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP521)),
        fixtures.ec_p521_key(),
      )),
      qcheck.return(JwsAlgWithKey(
        algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaSecp256k1)),
        fixtures.ec_secp256k1_key(),
      )),
    ],
  )
}

pub fn jws_eddsa_alg_generator() -> qcheck.Generator(JwsAlgWithKey(kid)) {
  qcheck.from_generators(
    qcheck.return(JwsAlgWithKey(
      algorithm.DigitalSignature(algorithm.Eddsa),
      fixtures.ed25519_key(),
    )),
    [
      qcheck.return(JwsAlgWithKey(
        algorithm.DigitalSignature(algorithm.Eddsa),
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

pub fn jwe_enc_generator() -> qcheck.Generator(algorithm.ContentAlg) {
  qcheck.from_generators(qcheck.return(algorithm.AesGcm(algorithm.Aes128)), [
    qcheck.return(algorithm.AesGcm(algorithm.Aes192)),
    qcheck.return(algorithm.AesGcm(algorithm.Aes256)),
    qcheck.return(algorithm.AesCbcHmac(algorithm.Aes128)),
    qcheck.return(algorithm.AesCbcHmac(algorithm.Aes192)),
    qcheck.return(algorithm.AesCbcHmac(algorithm.Aes256)),
    qcheck.return(algorithm.ChaCha20Poly1305),
    qcheck.return(algorithm.XChaCha20Poly1305),
  ])
}

pub type JweDirectEncWithKey(kid) {
  JweDirectEncWithKey(enc: algorithm.ContentAlg, key: key.Key(kid))
}

fn jwe_direct_enc_with_key(
  enc: algorithm.ContentAlg,
) -> qcheck.Generator(JweDirectEncWithKey(kid)) {
  let key = key.generate_enc_key(enc)
  qcheck.return(JweDirectEncWithKey(enc, key))
}

pub fn jwe_direct_generator() -> qcheck.Generator(JweDirectEncWithKey(kid)) {
  qcheck.from_generators(
    jwe_direct_enc_with_key(algorithm.AesGcm(algorithm.Aes128)),
    [
      jwe_direct_enc_with_key(algorithm.AesGcm(algorithm.Aes192)),
      jwe_direct_enc_with_key(algorithm.AesGcm(algorithm.Aes256)),
      jwe_direct_enc_with_key(algorithm.AesCbcHmac(algorithm.Aes128)),
      jwe_direct_enc_with_key(algorithm.AesCbcHmac(algorithm.Aes192)),
      jwe_direct_enc_with_key(algorithm.AesCbcHmac(algorithm.Aes256)),
      jwe_direct_enc_with_key(algorithm.ChaCha20Poly1305),
      jwe_direct_enc_with_key(algorithm.XChaCha20Poly1305),
    ],
  )
}

fn aes_size_enc_combinations() -> List(
  #(algorithm.AesKeySize, algorithm.ContentAlg),
) {
  let sizes = [algorithm.Aes128, algorithm.Aes192, algorithm.Aes256]
  let encs = [
    algorithm.AesGcm(algorithm.Aes128),
    algorithm.AesGcm(algorithm.Aes192),
    algorithm.AesGcm(algorithm.Aes256),
    algorithm.AesCbcHmac(algorithm.Aes128),
    algorithm.AesCbcHmac(algorithm.Aes192),
    algorithm.AesCbcHmac(algorithm.Aes256),
  ]
  list.flat_map(sizes, fn(size) { list.map(encs, fn(enc) { #(size, enc) }) })
}

pub type JweAesKwWithKey(kid) {
  JweAesKwWithKey(
    size: algorithm.AesKeySize,
    enc: algorithm.ContentAlg,
    key: key.Key(kid),
  )
}

fn jwe_aes_kw_with_key(
  size: algorithm.AesKeySize,
  enc: algorithm.ContentAlg,
) -> qcheck.Generator(JweAesKwWithKey(kid)) {
  let key = key.generate_aes_kw_key(size)
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
    size: algorithm.AesKeySize,
    enc: algorithm.ContentAlg,
    key: key.Key(kid),
  )
}

fn jwe_aes_gcm_kw_with_key(
  size: algorithm.AesKeySize,
  enc: algorithm.ContentAlg,
) -> qcheck.Generator(JweAesGcmKwWithKey(kid)) {
  let key = key.generate_aes_kw_key(size)
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
    variant: algorithm.ChaCha20Kw,
    enc: algorithm.ContentAlg,
    key: key.Key(kid),
  )
}

fn jwe_chacha20_kw_with_key(
  variant: algorithm.ChaCha20Kw,
  enc: algorithm.ContentAlg,
) -> qcheck.Generator(JweChaCha20KwWithKey(kid)) {
  let key = key.generate_chacha20_kw_key()
  qcheck.return(JweChaCha20KwWithKey(variant, enc, key))
}

pub fn jwe_chacha20_kw_generator() -> qcheck.Generator(
  JweChaCha20KwWithKey(kid),
) {
  qcheck.from_generators(
    jwe_chacha20_kw_with_key(
      algorithm.C20PKw,
      algorithm.AesGcm(algorithm.Aes128),
    ),
    [
      jwe_chacha20_kw_with_key(
        algorithm.C20PKw,
        algorithm.AesGcm(algorithm.Aes256),
      ),
      jwe_chacha20_kw_with_key(algorithm.C20PKw, algorithm.ChaCha20Poly1305),
      jwe_chacha20_kw_with_key(algorithm.C20PKw, algorithm.XChaCha20Poly1305),
      jwe_chacha20_kw_with_key(
        algorithm.XC20PKw,
        algorithm.AesGcm(algorithm.Aes128),
      ),
      jwe_chacha20_kw_with_key(
        algorithm.XC20PKw,
        algorithm.AesGcm(algorithm.Aes256),
      ),
      jwe_chacha20_kw_with_key(algorithm.XC20PKw, algorithm.ChaCha20Poly1305),
      jwe_chacha20_kw_with_key(algorithm.XC20PKw, algorithm.XChaCha20Poly1305),
    ],
  )
}

pub fn jwe_rsa_alg_generator() -> qcheck.Generator(algorithm.RsaEncryptionAlg) {
  qcheck.from_generators(qcheck.return(algorithm.RsaOaepSha1), [
    qcheck.return(algorithm.RsaOaepSha256),
    qcheck.return(algorithm.RsaPkcs1v15),
  ])
}

pub type JweEcdhEsWithKey(kid) {
  JweEcdhEsWithKey(alg: algorithm.EcdhEsAlg, key: key.Key(kid))
}

pub fn jwe_ecdh_es_generator(
  ec_p256_key: key.Key(kid),
  ec_p384_key: key.Key(kid),
  ec_p521_key: key.Key(kid),
  x25519_key: key.Key(kid),
  x448_key: key.Key(kid),
) -> qcheck.Generator(JweEcdhEsWithKey(kid)) {
  qcheck.from_generators(
    qcheck.return(JweEcdhEsWithKey(algorithm.EcdhEsDirect, ec_p256_key)),
    [
      qcheck.return(JweEcdhEsWithKey(algorithm.EcdhEsDirect, ec_p384_key)),
      qcheck.return(JweEcdhEsWithKey(algorithm.EcdhEsDirect, ec_p521_key)),
      qcheck.return(JweEcdhEsWithKey(algorithm.EcdhEsDirect, x25519_key)),
      qcheck.return(JweEcdhEsWithKey(algorithm.EcdhEsDirect, x448_key)),
      qcheck.return(JweEcdhEsWithKey(
        algorithm.EcdhEsAesKw(algorithm.Aes128),
        ec_p256_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        algorithm.EcdhEsAesKw(algorithm.Aes192),
        ec_p521_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        algorithm.EcdhEsAesKw(algorithm.Aes256),
        ec_p384_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        algorithm.EcdhEsAesKw(algorithm.Aes128),
        x25519_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        algorithm.EcdhEsAesKw(algorithm.Aes256),
        x448_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        algorithm.EcdhEsChaCha20Kw(algorithm.C20PKw),
        ec_p256_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        algorithm.EcdhEsChaCha20Kw(algorithm.XC20PKw),
        ec_p384_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        algorithm.EcdhEsChaCha20Kw(algorithm.C20PKw),
        x25519_key,
      )),
      qcheck.return(JweEcdhEsWithKey(
        algorithm.EcdhEsChaCha20Kw(algorithm.XC20PKw),
        x448_key,
      )),
    ],
  )
}

pub fn jwe_pbes2_alg_generator() -> qcheck.Generator(algorithm.Pbes2Alg) {
  qcheck.from_generators(qcheck.return(algorithm.Pbes2Sha256Aes128Kw), [
    qcheck.return(algorithm.Pbes2Sha384Aes192Kw),
    qcheck.return(algorithm.Pbes2Sha512Aes256Kw),
  ])
}

pub type Pbes2Variant {
  Pbes2Variant(alg: algorithm.Pbes2Alg, enc: algorithm.ContentAlg)
}

pub fn pbes2_variant_generator() -> qcheck.Generator(Pbes2Variant) {
  qcheck.from_generators(
    qcheck.return(Pbes2Variant(
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes128),
    )),
    [
      qcheck.return(Pbes2Variant(
        algorithm.Pbes2Sha384Aes192Kw,
        algorithm.AesGcm(algorithm.Aes192),
      )),
      qcheck.return(Pbes2Variant(
        algorithm.Pbes2Sha512Aes256Kw,
        algorithm.AesGcm(algorithm.Aes256),
      )),
    ],
  )
}

pub type AesKeyWrapVariant {
  AesKeyWrapVariant(size: algorithm.AesKeySize, enc: algorithm.ContentAlg)
}

pub fn aes_kw_variant_generator() -> qcheck.Generator(AesKeyWrapVariant) {
  qcheck.from_generators(
    qcheck.return(AesKeyWrapVariant(
      algorithm.Aes128,
      algorithm.AesGcm(algorithm.Aes128),
    )),
    [
      qcheck.return(AesKeyWrapVariant(
        algorithm.Aes192,
        algorithm.AesGcm(algorithm.Aes192),
      )),
      qcheck.return(AesKeyWrapVariant(
        algorithm.Aes256,
        algorithm.AesGcm(algorithm.Aes256),
      )),
    ],
  )
}

pub type RsaVariant {
  RsaVariant(alg: algorithm.RsaEncryptionAlg, enc: algorithm.ContentAlg)
}

pub fn rsa_variant_generator() -> qcheck.Generator(RsaVariant) {
  qcheck.from_generators(
    qcheck.return(RsaVariant(
      algorithm.RsaOaepSha1,
      algorithm.AesGcm(algorithm.Aes256),
    )),
    [
      qcheck.return(RsaVariant(
        algorithm.RsaOaepSha256,
        algorithm.AesGcm(algorithm.Aes128),
      )),
      qcheck.return(RsaVariant(
        algorithm.RsaPkcs1v15,
        algorithm.AesGcm(algorithm.Aes256),
      )),
    ],
  )
}

pub type EcdhVariant {
  EcdhVariant(alg: algorithm.EcdhEsAlg, enc: algorithm.ContentAlg)
}

pub fn ecdh_variant_generator() -> qcheck.Generator(EcdhVariant) {
  qcheck.from_generators(
    qcheck.return(EcdhVariant(
      algorithm.EcdhEsDirect,
      algorithm.AesGcm(algorithm.Aes256),
    )),
    [
      qcheck.return(EcdhVariant(
        algorithm.EcdhEsAesKw(algorithm.Aes128),
        algorithm.AesGcm(algorithm.Aes128),
      )),
      qcheck.return(EcdhVariant(
        algorithm.EcdhEsAesKw(algorithm.Aes256),
        algorithm.AesGcm(algorithm.Aes256),
      )),
    ],
  )
}

pub type JweAlgEncWithKey(kid) {
  JweAlgEncWithKey(
    alg: algorithm.KeyEncryptionAlg,
    enc: algorithm.ContentAlg,
    key: key.Key(kid),
  )
}

pub fn jwe_key_alg_enc_generator() -> qcheck.Generator(JweAlgEncWithKey(kid)) {
  let ec_p256_key = fixtures.ec_p256_key()
  let x25519_key = fixtures.x25519_key()

  qcheck.from_generators(
    qcheck.map(jwe_direct_generator(), fn(d) {
      JweAlgEncWithKey(algorithm.Direct, d.enc, d.key)
    }),
    [
      qcheck.map(jwe_aes_kw_generator(), fn(a) {
        JweAlgEncWithKey(
          algorithm.AesKeyWrap(algorithm.AesKw, a.size),
          a.enc,
          a.key,
        )
      }),
      qcheck.map(jwe_aes_gcm_kw_generator(), fn(a) {
        JweAlgEncWithKey(
          algorithm.AesKeyWrap(algorithm.AesGcmKw, a.size),
          a.enc,
          a.key,
        )
      }),
      qcheck.map(jwe_chacha20_kw_generator(), fn(c) {
        JweAlgEncWithKey(algorithm.ChaCha20KeyWrap(c.variant), c.enc, c.key)
      }),
      qcheck.return(JweAlgEncWithKey(
        algorithm.RsaEncryption(algorithm.RsaOaepSha256),
        algorithm.AesGcm(algorithm.Aes256),
        fixtures.rsa_private_key(),
      )),
      qcheck.return(JweAlgEncWithKey(
        algorithm.EcdhEs(algorithm.EcdhEsDirect),
        algorithm.AesGcm(algorithm.Aes256),
        ec_p256_key,
      )),
      qcheck.return(JweAlgEncWithKey(
        algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes128)),
        algorithm.AesGcm(algorithm.Aes128),
        x25519_key,
      )),
    ],
  )
}

pub type EcCurveWithKey(kid) {
  EcCurveWithKey(curve: ec.Curve, key: key.Key(kid))
}

pub fn ec_curve_with_key_generator() -> qcheck.Generator(EcCurveWithKey(kid)) {
  let p256_key = key.generate_ec(ec.P256)
  let p384_key = key.generate_ec(ec.P384)
  let p521_key = key.generate_ec(ec.P521)
  let secp256k1_key = key.generate_ec(ec.Secp256k1)

  qcheck.from_generators(qcheck.return(EcCurveWithKey(ec.P256, p256_key)), [
    qcheck.return(EcCurveWithKey(ec.P384, p384_key)),
    qcheck.return(EcCurveWithKey(ec.P521, p521_key)),
    qcheck.return(EcCurveWithKey(ec.Secp256k1, secp256k1_key)),
  ])
}

pub fn key_op_generator() -> qcheck.Generator(key.KeyOp) {
  qcheck.from_generators(qcheck.return(key.Sign), [
    qcheck.return(key.Verify),
    qcheck.return(key.Encrypt),
    qcheck.return(key.Decrypt),
    qcheck.return(key.WrapKey),
    qcheck.return(key.UnwrapKey),
    qcheck.return(key.DeriveKey),
    qcheck.return(key.DeriveBits),
  ])
}

pub fn alg_generator() -> qcheck.Generator(key.Alg) {
  qcheck.from_generators(qcheck.map(bare_jws_alg_generator(), key.SigningAlg), [
    qcheck.map(bare_jwe_alg_generator(), key.KeyEncryptionAlg),
    qcheck.map(jwe_enc_generator(), key.ContentAlg),
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
