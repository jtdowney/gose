//// Encrypted CWT with decrypt-then-validate workflow for encrypted CWT tokens.
////
//// An encrypted CWT is a CWT (signed COSE_Sign1 containing claims) that is
//// then encrypted with COSE_Encrypt0. The workflow to consume one is:
//// 1. Decrypt the outer Encrypt0 layer to get the inner signed CWT bytes
//// 2. Verify the Sign1 signature and validate the CWT claims
////
//// ## Example
////
//// ```gleam
//// import gleam/time/duration
//// import gleam/time/timestamp
//// import gose
//// import gose/cose/cwt
//// import gose/cose/encrypt0
//// import gose/cose/encrypted_cwt
//// import kryptos/ec
////
//// let signing_key = gose.generate_ec(ec.P256)
//// let encryption_key = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
//// let now = timestamp.system_time()
//// let exp = timestamp.add(now, duration.hours(1))
////
//// let claims = cwt.new()
////   |> cwt.with_subject("user123")
////   |> cwt.with_expiration(exp)
////
//// let assert Ok(signed) =
////   cwt.sign(claims, alg: gose.Ecdsa(gose.EcdsaP256), key: signing_key)
//// let assert Ok(encrypted) =
////   encrypted_cwt.encrypt(signed, enc: gose.AesGcm(gose.Aes128), key: encryption_key)
////
//// let assert Ok(verifier) =
////   cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
//// let assert Ok(decryptor) =
////   encrypt0.decryptor(gose.AesGcm(gose.Aes128), key: encryption_key)
//// let assert Ok(verified) =
////   encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)
//// ```

import gleam/result
import gleam/time/timestamp.{type Timestamp}
import gose
import gose/cose/cwt
import gose/cose/encrypt0

/// Encrypt a signed CWT with COSE_Encrypt0.
pub fn encrypt(
  signed_cwt: BitArray,
  enc content_alg: gose.ContentAlg,
  key encryption_key: gose.Key(BitArray),
) -> Result(BitArray, cwt.CwtError) {
  use message <- result.try(
    encrypt0.new(content_alg) |> result.map_error(map_gose_error),
  )
  encrypt0.encrypt(message, encryption_key, signed_cwt)
  |> result.map(encrypt0.serialize)
  |> result.map_error(map_gose_error)
}

/// Decrypt an encrypted CWT and validate its claims.
pub fn decrypt_and_validate(
  token: BitArray,
  decryptor decryptor: encrypt0.Decryptor,
  verifier verifier: cwt.Verifier,
  now now: Timestamp,
) -> Result(cwt.Cwt(cwt.Verified), cwt.CwtError) {
  use parsed <- result.try(
    encrypt0.parse(token) |> result.map_error(map_gose_error),
  )
  use inner_bytes <- result.try(
    encrypt0.decrypt(decryptor, parsed)
    |> result.map_error(fn(err) {
      cwt.DecryptionFailed(gose.error_message(err))
    }),
  )
  cwt.verify_and_validate(verifier, token: inner_bytes, now:)
}

fn map_gose_error(err: gose.GoseError) -> cwt.CwtError {
  cwt.CoseError(err)
}
