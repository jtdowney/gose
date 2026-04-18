import gleam/bit_array
import gleam/io
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import gose
import gose/cbor
import gose/cose/cwt
import kryptos/ec

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("CWT (CBOR Web Token) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  sign_and_verify()
  ecdsa_signed()
  validation_options()
  custom_claims()

  io.println(string.repeat("=", 60))
  io.println("All CWT examples completed!")
  io.println(string.repeat("=", 60))
}

fn sign_and_verify() {
  io.println("--- Sign and Verify (ES256) ---")

  let signing_key = gose.generate_ec(ec.P256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_issuer("example-app")
    |> cwt.with_subject("user-42")
    |> cwt.with_audience("api.example.com")
    |> cwt.with_expiration(exp)
    |> cwt.with_issued_at(now)

  // Sign
  let assert Ok(token) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  io.println("Signed CWT (base64):")
  io.println(bit_array.base64_encode(token, True))

  // Verify
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)

  let verified_claims = cwt.verified_claims(verified)
  let assert Ok(iss) = cwt.issuer(verified_claims)
  let assert Ok(sub) = cwt.subject(verified_claims)
  io.println("Issuer: " <> iss)
  io.println("Subject: " <> sub)
  io.println("")
}

fn ecdsa_signed() {
  io.println("--- ECDSA-Signed CWT (ES384) ---")

  let signing_key = gose.generate_ec(ec.P384)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_subject("service-account")
    |> cwt.with_expiration(exp)

  // Sign
  let assert Ok(token) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP384), signing_key)
  io.println("ECDSA-signed CWT (base64):")
  io.println(bit_array.base64_encode(token, True))

  // Verify
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP384), keys: [signing_key])
  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)
  let assert Ok(sub) = cwt.subject(cwt.verified_claims(verified))
  io.println("Subject: " <> sub)
  io.println("")
}

fn validation_options() {
  io.println("--- Validation Options ---")

  let signing_key = gose.generate_ec(ec.P256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    cwt.new()
    |> cwt.with_issuer("trusted-issuer")
    |> cwt.with_audience("my-service")
    |> cwt.with_expiration(exp)

  // Sign
  let assert Ok(token) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)

  // Verify
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let verifier =
    verifier
    |> cwt.with_issuer_validation("trusted-issuer")
    |> cwt.with_audience_validation("my-service")
    |> cwt.with_clock_skew(120)

  let assert Ok(_verified) = cwt.verify_and_validate(verifier, token, now)
  io.println("Token verified with issuer, audience, and clock skew validation")
  io.println("")
}

fn custom_claims() {
  io.println("--- Custom Claims ---")

  let signing_key = gose.generate_ec(ec.P256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let base_claims =
    cwt.new()
    |> cwt.with_expiration(exp)
  let assert Ok(claims) =
    cwt.with_custom_claim(base_claims, cbor.Text("role"), cbor.Text("admin"))
  let assert Ok(claims) =
    cwt.with_custom_claim(claims, cbor.Int(100), cbor.Int(42))

  // Sign
  let assert Ok(token) =
    cwt.sign(claims, gose.Ecdsa(gose.EcdsaP256), signing_key)
  io.println("CWT with custom claims (base64):")
  io.println(bit_array.base64_encode(token, True))

  // Verify
  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(verified) = cwt.verify_and_validate(verifier, token, now)

  let verified_claims = cwt.verified_claims(verified)
  let assert Ok(cbor.Text(role)) =
    cwt.custom_claim(verified_claims, cbor.Text("role"))
  let assert Ok(cbor.Int(num)) =
    cwt.custom_claim(verified_claims, cbor.Int(100))
  io.println("Custom claim 'role': " <> role)
  io.println("Custom claim 100: " <> string.inspect(num))
  io.println("")
}
