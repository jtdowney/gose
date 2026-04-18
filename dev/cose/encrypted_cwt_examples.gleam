import gleam/bit_array
import gleam/io
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import gose
import gose/cose/cwt
import gose/cose/encrypt0
import gose/cose/encrypted_cwt
import kryptos/ec

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("Encrypted CWT (Sign-then-Encrypt) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  aes_gcm_roundtrip()
  chacha20_roundtrip()
  validation_through_encryption()

  io.println(string.repeat("=", 60))
  io.println("All Encrypted CWT examples completed!")
  io.println(string.repeat("=", 60))
}

fn aes_gcm_roundtrip() {
  io.println("--- Full Roundtrip (ES256 + AES-128-GCM) ---")

  let signing_key = gose.generate_ec(ec.P256)
  let enc_alg = gose.AesGcm(gose.Aes128)
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_issuer("auth-service")
    |> cwt.with_subject("user-42")
    |> cwt.with_expiration(exp)

  // Sign
  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)

  // Encrypt
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)
  io.println("Encrypted CWT (base64):")
  io.println(bit_array.base64_encode(encrypted, True))

  // Decrypt and verify
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Ok(verified) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)

  let verified_claims = cwt.verified_claims(verified)
  let assert Ok(sub) = cwt.subject(verified_claims)
  io.println("Decrypted and verified, subject: " <> sub)
  io.println("")
}

fn chacha20_roundtrip() {
  io.println("--- ChaCha20-Poly1305 Encryption ---")

  let signing_key = gose.generate_ec(ec.P256)
  let enc_alg = gose.ChaCha20Poly1305
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("device-001")
    |> cwt.with_issuer("iot-gateway")
    |> cwt.with_expiration(exp)

  // Sign
  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)

  // Encrypt
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)
  io.println("ChaCha20 encrypted CWT (base64):")
  io.println(bit_array.base64_encode(encrypted, True))

  // Decrypt and verify
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Ok(verified) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)

  let assert Ok(sub) = cwt.subject(cwt.verified_claims(verified))
  io.println("Decrypted and verified, subject: " <> sub)
  io.println("")
}

fn validation_through_encryption() {
  io.println("--- Issuer Validation Through Encryption ---")

  let signing_key = gose.generate_ec(ec.P256)
  let enc_alg = gose.AesGcm(gose.Aes256)
  let encryption_key = gose.generate_enc_key(enc_alg)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_issuer("trusted-issuer")
    |> cwt.with_subject("user-99")
    |> cwt.with_expiration(exp)

  // Sign
  let assert Ok(signed) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)

  // Encrypt
  let assert Ok(encrypted) =
    encrypted_cwt.encrypt(signed, enc_alg, encryption_key)

  // Decrypt and verify
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let verifier = cwt.with_issuer_validation(verifier, "trusted-issuer")
  let assert Ok(decryptor) = encrypt0.decryptor(enc_alg, key: encryption_key)
  let assert Ok(verified) =
    encrypted_cwt.decrypt_and_validate(encrypted, decryptor:, verifier:, now:)

  let assert Ok(iss) = cwt.issuer(cwt.verified_claims(verified))
  io.println("Issuer validated through encryption: " <> iss)
  io.println("")
}
