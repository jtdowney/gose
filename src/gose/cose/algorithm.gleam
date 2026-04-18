//// Deprecated: use the `gose/cose` module instead.
////
//// This module re-exports the COSE algorithm integer-conversion functions
//// from `gose/cose` for the v2.x migration window. It will be removed in
//// v3.0. New code should import `gose/cose` directly.

import gose
import gose/cose

@deprecated("use gose/cose.signature_alg_to_int")
pub fn signature_alg_to_int(alg: gose.DigitalSignatureAlg) -> Int {
  cose.signature_alg_to_int(alg)
}

@deprecated("use gose/cose.signature_alg_from_int")
pub fn signature_alg_from_int(
  id: Int,
) -> Result(gose.DigitalSignatureAlg, gose.GoseError) {
  cose.signature_alg_from_int(id)
}

@deprecated("use gose/cose.mac_alg_to_int")
pub fn mac_alg_to_int(alg: gose.MacAlg) -> Int {
  cose.mac_alg_to_int(alg)
}

@deprecated("use gose/cose.mac_alg_from_int")
pub fn mac_alg_from_int(id: Int) -> Result(gose.MacAlg, gose.GoseError) {
  cose.mac_alg_from_int(id)
}

@deprecated("use gose/cose.signing_alg_to_int")
pub fn signing_alg_to_int(alg: gose.SigningAlg) -> Int {
  cose.signing_alg_to_int(alg)
}

@deprecated("use gose/cose.signing_alg_from_int")
pub fn signing_alg_from_int(id: Int) -> Result(gose.SigningAlg, gose.GoseError) {
  cose.signing_alg_from_int(id)
}

@deprecated("use gose/cose.key_encryption_alg_to_int")
pub fn key_encryption_alg_to_int(
  alg: gose.KeyEncryptionAlg,
) -> Result(Int, gose.GoseError) {
  cose.key_encryption_alg_to_int(alg)
}

@deprecated("use gose/cose.key_encryption_alg_from_int")
pub fn key_encryption_alg_from_int(
  id: Int,
) -> Result(gose.KeyEncryptionAlg, gose.GoseError) {
  cose.key_encryption_alg_from_int(id)
}

@deprecated("use gose/cose.content_alg_to_int")
pub fn content_alg_to_int(alg: gose.ContentAlg) -> Result(Int, gose.GoseError) {
  cose.content_alg_to_int(alg)
}

@deprecated("use gose/cose.content_alg_from_int")
pub fn content_alg_from_int(id: Int) -> Result(gose.ContentAlg, gose.GoseError) {
  cose.content_alg_from_int(id)
}
