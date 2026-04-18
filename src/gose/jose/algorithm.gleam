//// Deprecated: use the `gose/jose` module instead.
////
//// This module re-exports the JOSE algorithm string-conversion functions
//// from `gose/jose` for the v2.x migration window. It will be removed in
//// v3.0. New code should import `gose/jose` directly.

import gose
import gose/jose

@deprecated("use gose/jose.signing_alg_to_string")
pub fn signing_alg_to_string(alg: gose.SigningAlg) -> String {
  jose.signing_alg_to_string(alg)
}

@deprecated("use gose/jose.signing_alg_from_string")
pub fn signing_alg_from_string(
  alg: String,
) -> Result(gose.SigningAlg, gose.GoseError) {
  jose.signing_alg_from_string(alg)
}

@deprecated("use gose/jose.key_encryption_alg_to_string")
pub fn key_encryption_alg_to_string(alg: gose.KeyEncryptionAlg) -> String {
  jose.key_encryption_alg_to_string(alg)
}

@deprecated("use gose/jose.key_encryption_alg_from_string")
pub fn key_encryption_alg_from_string(
  alg: String,
) -> Result(gose.KeyEncryptionAlg, gose.GoseError) {
  jose.key_encryption_alg_from_string(alg)
}

@deprecated("use gose/jose.content_alg_to_string")
pub fn content_alg_to_string(alg: gose.ContentAlg) -> String {
  jose.content_alg_to_string(alg)
}

@deprecated("use gose/jose.content_alg_from_string")
pub fn content_alg_from_string(
  alg: String,
) -> Result(gose.ContentAlg, gose.GoseError) {
  jose.content_alg_from_string(alg)
}
