//// Deprecated: use the `gose` module instead.
////
//// Re-exports the key API from `gose` for the v2.x migration window.
//// The module will be removed in v3.0. New code should import `gose`
//// directly.
////
//// Constructors of `KeyUse`, `KeyOp`, `Alg`, and `KeyType` are not
//// re-exported (Gleam type aliases re-export the type but not its
//// constructors). Callers that reference those constructors must
//// update to `gose.Signing`, `gose.SigningAlg(_)`, and so on. See
//// `docs/MIGRATION.md` for the full list.

import gose
import kryptos/ec
import kryptos/eddsa
import kryptos/rsa
import kryptos/xdh

@deprecated("use gose.Key")
pub type Key(kid) =
  gose.Key(kid)

@deprecated("use gose.KeyUse (constructors must be re-imported: gose.Signing, gose.Encrypting)")
pub type KeyUse =
  gose.KeyUse

@deprecated("use gose.KeyOp (constructors must be re-imported)")
pub type KeyOp =
  gose.KeyOp

@deprecated("use gose.Alg (constructors must be re-imported: gose.SigningAlg, gose.KeyEncryptionAlg, gose.ContentAlg)")
pub type Alg =
  gose.Alg

@deprecated("use gose.KeyType")
pub type KeyType =
  gose.KeyType

@deprecated("use gose.from_der")
pub fn from_der(der: BitArray) -> Result(gose.Key(kid), gose.GoseError) {
  gose.from_der(der)
}

@deprecated("use gose.from_pem")
pub fn from_pem(pem: String) -> Result(gose.Key(kid), gose.GoseError) {
  gose.from_pem(pem)
}

@deprecated("use gose.from_octet_bits")
pub fn from_octet_bits(
  secret: BitArray,
) -> Result(gose.Key(kid), gose.GoseError) {
  gose.from_octet_bits(secret)
}

@deprecated("use gose.from_eddsa_bits")
pub fn from_eddsa_bits(
  curve: eddsa.Curve,
  private_bits private_bits: BitArray,
) -> Result(gose.Key(kid), gose.GoseError) {
  gose.from_eddsa_bits(curve, private_bits:)
}

@deprecated("use gose.from_eddsa_public_bits")
pub fn from_eddsa_public_bits(
  curve: eddsa.Curve,
  public_bits public_bits: BitArray,
) -> Result(gose.Key(kid), gose.GoseError) {
  gose.from_eddsa_public_bits(curve, public_bits:)
}

@deprecated("use gose.from_xdh_bits")
pub fn from_xdh_bits(
  curve: xdh.Curve,
  private_bits private_bits: BitArray,
) -> Result(gose.Key(kid), gose.GoseError) {
  gose.from_xdh_bits(curve, private_bits:)
}

@deprecated("use gose.from_xdh_public_bits")
pub fn from_xdh_public_bits(
  curve: xdh.Curve,
  public_bits public_bits: BitArray,
) -> Result(gose.Key(kid), gose.GoseError) {
  gose.from_xdh_public_bits(curve, public_bits:)
}

@deprecated("use gose.ec_public_key_from_coordinates")
pub fn ec_public_key_from_coordinates(
  curve: ec.Curve,
  x x: BitArray,
  y y: BitArray,
) -> Result(gose.Key(kid), gose.GoseError) {
  gose.ec_public_key_from_coordinates(curve, x:, y:)
}

@deprecated("use gose.generate_ec")
pub fn generate_ec(curve: ec.Curve) -> gose.Key(kid) {
  gose.generate_ec(curve)
}

@deprecated("use gose.generate_eddsa")
pub fn generate_eddsa(curve: eddsa.Curve) -> gose.Key(kid) {
  gose.generate_eddsa(curve)
}

@deprecated("use gose.generate_hmac_key")
pub fn generate_hmac_key(alg: gose.HmacAlg) -> gose.Key(kid) {
  gose.generate_hmac_key(alg)
}

@deprecated("use gose.generate_enc_key")
pub fn generate_enc_key(enc: gose.ContentAlg) -> gose.Key(kid) {
  gose.generate_enc_key(enc)
}

@deprecated("use gose.generate_aes_kw_key")
pub fn generate_aes_kw_key(size: gose.AesKeySize) -> gose.Key(kid) {
  gose.generate_aes_kw_key(size)
}

@deprecated("use gose.generate_chacha20_kw_key")
pub fn generate_chacha20_kw_key() -> gose.Key(kid) {
  gose.generate_chacha20_kw_key()
}

@deprecated("use gose.generate_rsa")
pub fn generate_rsa(bits: Int) -> Result(gose.Key(kid), gose.GoseError) {
  gose.generate_rsa(bits)
}

@deprecated("use gose.generate_xdh")
pub fn generate_xdh(curve: xdh.Curve) -> gose.Key(kid) {
  gose.generate_xdh(curve)
}

@deprecated("use gose.with_alg")
pub fn with_alg(key: gose.Key(kid), alg: gose.Alg) -> gose.Key(kid) {
  gose.with_alg(key, alg)
}

@deprecated("use gose.with_key_ops")
pub fn with_key_ops(
  key: gose.Key(kid),
  ops: List(gose.KeyOp),
) -> Result(gose.Key(kid), gose.GoseError) {
  gose.with_key_ops(key, ops)
}

@deprecated("use gose.with_key_use")
pub fn with_key_use(
  key: gose.Key(kid),
  use_: gose.KeyUse,
) -> Result(gose.Key(kid), gose.GoseError) {
  gose.with_key_use(key, use_)
}

@deprecated("use gose.with_kid")
pub fn with_kid(key: gose.Key(a), kid: String) -> gose.Key(String) {
  gose.with_kid(key, kid)
}

@deprecated("use gose.with_kid_bits")
pub fn with_kid_bits(key: gose.Key(a), kid: BitArray) -> gose.Key(BitArray) {
  gose.with_kid_bits(key, kid)
}

@deprecated("use gose.alg")
pub fn alg(key: gose.Key(kid)) -> Result(gose.Alg, Nil) {
  gose.alg(key)
}

@deprecated("use gose.ec_curve")
pub fn ec_curve(key: gose.Key(kid)) -> Result(ec.Curve, gose.GoseError) {
  gose.ec_curve(key)
}

@deprecated("use gose.ec_public_key")
pub fn ec_public_key(
  key: gose.Key(kid),
) -> Result(ec.PublicKey, gose.GoseError) {
  gose.ec_public_key(key)
}

@deprecated("use gose.ec_public_key_coordinates")
pub fn ec_public_key_coordinates(
  key: gose.Key(kid),
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  gose.ec_public_key_coordinates(key)
}

@deprecated("use gose.eddsa_curve")
pub fn eddsa_curve(key: gose.Key(kid)) -> Result(eddsa.Curve, gose.GoseError) {
  gose.eddsa_curve(key)
}

@deprecated("use gose.eddsa_public_key")
pub fn eddsa_public_key(
  key: gose.Key(kid),
) -> Result(eddsa.PublicKey, gose.GoseError) {
  gose.eddsa_public_key(key)
}

@deprecated("use gose.key_ops")
pub fn key_ops(key: gose.Key(kid)) -> Result(List(gose.KeyOp), Nil) {
  gose.key_ops(key)
}

@deprecated("use gose.key_type")
pub fn key_type(key: gose.Key(kid)) -> gose.KeyType {
  gose.key_type(key)
}

@deprecated("use gose.key_use")
pub fn key_use(key: gose.Key(kid)) -> Result(gose.KeyUse, Nil) {
  gose.key_use(key)
}

@deprecated("use gose.kid")
pub fn kid(key: gose.Key(kid)) -> Result(kid, Nil) {
  gose.kid(key)
}

@deprecated("use gose.octet_key_size")
pub fn octet_key_size(key: gose.Key(kid)) -> Result(Int, gose.GoseError) {
  gose.octet_key_size(key)
}

@deprecated("use gose.rsa_public_key")
pub fn rsa_public_key(
  key: gose.Key(kid),
) -> Result(rsa.PublicKey, gose.GoseError) {
  gose.rsa_public_key(key)
}

@deprecated("use gose.xdh_curve")
pub fn xdh_curve(key: gose.Key(kid)) -> Result(xdh.Curve, gose.GoseError) {
  gose.xdh_curve(key)
}

@deprecated("use gose.xdh_public_key")
pub fn xdh_public_key(
  key: gose.Key(kid),
) -> Result(xdh.PublicKey, gose.GoseError) {
  gose.xdh_public_key(key)
}

@deprecated("use gose.public_key")
pub fn public_key(key: gose.Key(kid)) -> Result(gose.Key(kid), gose.GoseError) {
  gose.public_key(key)
}

@deprecated("use gose.to_der")
pub fn to_der(key: gose.Key(kid)) -> Result(BitArray, gose.GoseError) {
  gose.to_der(key)
}

@deprecated("use gose.to_octet_bits")
pub fn to_octet_bits(key: gose.Key(kid)) -> Result(BitArray, gose.GoseError) {
  gose.to_octet_bits(key)
}

@deprecated("use gose.to_pem")
pub fn to_pem(key: gose.Key(kid)) -> Result(String, gose.GoseError) {
  gose.to_pem(key)
}
