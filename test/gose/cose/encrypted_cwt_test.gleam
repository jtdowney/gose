import gleam/option
import gleam/time/duration
import gleam/time/timestamp
import gose
import gose/cose/cwt
import gose/cose/encrypt0
import gose/cose/encrypted_cwt
import gose/test_helpers/fixtures

fn fixed_timestamp() {
  timestamp.from_unix_seconds(1_700_000_000)
}

pub fn full_roundtrip_test() {
  let signing_key = fixtures.ec_p256_key()
  let enc_alg = gose.AesGcm(gose.Aes128)
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_issuer("my-app")
    |> cwt.with_expiration(exp)

  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)

  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Ok(verified) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)

  let verified_claims = cwt.verified_claims(verified)
  assert cwt.subject(verified_claims) == Ok("user123")
  assert cwt.issuer(verified_claims) == Ok("my-app")
  assert cwt.expiration(verified_claims) == Ok(exp)
}

pub fn wrong_decryption_key_test() {
  let signing_key = fixtures.ec_p256_key()
  let enc_alg = gose.AesGcm(gose.Aes128)
  let encryption_key = gose.generate_enc_key(enc_alg)
  let wrong_key = gose.generate_enc_key(enc_alg)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_expiration(exp)

  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)

  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: wrong_key)
  let assert Error(cwt.DecryptionFailed(_)) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)
}

pub fn expired_token_inside_encryption_test() {
  let signing_key = fixtures.ec_p256_key()
  let enc_alg = gose.AesGcm(gose.Aes128)
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = fixed_timestamp()
  let past = timestamp.add(now, duration.hours(-1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_expiration(past)

  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)

  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Error(cwt.TokenExpired(_)) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)
}

pub fn issuer_validation_through_encryption_test() {
  let signing_key = fixtures.ec_p256_key()
  let enc_alg = gose.AesGcm(gose.Aes128)
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_issuer("my-app")
    |> cwt.with_expiration(exp)

  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)

  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let verifier = cwt.with_issuer_validation(verifier, "wrong-issuer")
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Error(cwt.IssuerMismatch(
    expected: "wrong-issuer",
    actual: option.Some("my-app"),
  )) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)
}

pub fn chacha20_poly1305_encryption_roundtrip_test() {
  let signing_key = fixtures.ec_p256_key()
  let enc_alg = gose.ChaCha20Poly1305
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_issuer("my-app")
    |> cwt.with_expiration(exp)

  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)

  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Ok(verified) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)

  let verified_claims = cwt.verified_claims(verified)
  assert cwt.subject(verified_claims) == Ok("user123")
  assert cwt.issuer(verified_claims) == Ok("my-app")
}

pub fn aes256gcm_encryption_roundtrip_test() {
  let signing_key = fixtures.ec_p256_key()
  let enc_alg = gose.AesGcm(gose.Aes256)
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user456")
    |> cwt.with_expiration(exp)

  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)

  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Ok(verified) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)

  assert cwt.subject(cwt.verified_claims(verified)) == Ok("user456")
}

pub fn not_before_validation_through_encryption_test() {
  let signing_key = fixtures.ec_p256_key()
  let enc_alg = gose.AesGcm(gose.Aes128)
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = fixed_timestamp()
  let future_nbf = timestamp.add(now, duration.hours(1))
  let exp = timestamp.add(now, duration.hours(2))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_not_before(future_nbf)
    |> cwt.with_expiration(exp)

  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)

  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Error(cwt.TokenNotYetValid(_)) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)
}

pub fn audience_validation_through_encryption_test() {
  let signing_key = fixtures.ec_p256_key()
  let enc_alg = gose.AesGcm(gose.Aes128)
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_audience("my-audience")
    |> cwt.with_expiration(exp)

  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)

  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let verifier = cwt.with_audience_validation(verifier, "wrong-audience")
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Error(cwt.AudienceMismatch(
    expected: "wrong-audience",
    actual: option.Some(["my-audience"]),
  )) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)
}
