//// Deprecated: use the `gose` module instead.
////
//// This module re-exports the algorithm types from `gose` for the v2.x
//// migration window. It will be removed in v3.0. New code should import
//// `gose` directly.
////
//// The constructors of every type are not re-exported here (Gleam type
//// aliases do not re-export constructors). Callers that pattern-match on
//// these types must update to `gose.Aes128`, `gose.HmacSha256`, etc.

import gose

@deprecated("use gose.AesKeySize")
pub type AesKeySize =
  gose.AesKeySize

@deprecated("use gose.AesKwMode")
pub type AesKwMode =
  gose.AesKwMode

@deprecated("use gose.ChaCha20Kw")
pub type ChaCha20Kw =
  gose.ChaCha20Kw

@deprecated("use gose.HmacAlg")
pub type HmacAlg =
  gose.HmacAlg

@deprecated("use gose.RsaPkcs1Alg")
pub type RsaPkcs1Alg =
  gose.RsaPkcs1Alg

@deprecated("use gose.RsaPssAlg")
pub type RsaPssAlg =
  gose.RsaPssAlg

@deprecated("use gose.EcdsaAlg")
pub type EcdsaAlg =
  gose.EcdsaAlg

@deprecated("use gose.DigitalSignatureAlg")
pub type DigitalSignatureAlg =
  gose.DigitalSignatureAlg

@deprecated("use gose.MacAlg")
pub type MacAlg =
  gose.MacAlg

@deprecated("use gose.SigningAlg")
pub type SigningAlg =
  gose.SigningAlg

@deprecated("use gose.RsaEncryptionAlg")
pub type RsaEncryptionAlg =
  gose.RsaEncryptionAlg

@deprecated("use gose.EcdhEsAlg")
pub type EcdhEsAlg =
  gose.EcdhEsAlg

@deprecated("use gose.Pbes2Alg")
pub type Pbes2Alg =
  gose.Pbes2Alg

@deprecated("use gose.KeyEncryptionAlg")
pub type KeyEncryptionAlg =
  gose.KeyEncryptionAlg

@deprecated("use gose.ContentAlg")
pub type ContentAlg =
  gose.ContentAlg
