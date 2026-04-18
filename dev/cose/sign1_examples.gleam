import gleam/bit_array
import gleam/io
import gleam/string
import gose
import gose/cose/sign1
import kryptos/ec
import kryptos/eddsa

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("COSE_Sign1 (Single-Signer Signatures) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  ecdsa_signing()
  eddsa_signing()
  aad()
  detached_payload()

  io.println(string.repeat("=", 60))
  io.println("All COSE_Sign1 examples completed!")
  io.println(string.repeat("=", 60))
}

fn ecdsa_signing() {
  io.println("--- ECDSA Signing (ES256) ---")

  let signing_key = gose.generate_ec(ec.P256)
  let payload = <<"Hello, COSE!":utf8>>

  // Sign
  let assert Ok(signed) =
    sign1.new(gose.Ecdsa(gose.EcdsaP256))
    |> sign1.sign(signing_key, payload)

  let data = sign1.serialize(signed)
  io.println("Serialized COSE_Sign1 (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Verify
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(verifier) =
    sign1.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(Nil) = sign1.verify(verifier, parsed)
  io.println("Signature verified successfully")
  io.println("")
}

fn eddsa_signing() {
  io.println("--- EdDSA Signing (Ed25519) ---")

  let signing_key = gose.generate_eddsa(eddsa.Ed25519)
  let payload = <<"EdDSA signed message":utf8>>

  // Sign
  let assert Ok(signed) =
    sign1.new(gose.Eddsa)
    |> sign1.sign(signing_key, payload)

  let data = sign1.serialize_tagged(signed)
  io.println("Tagged COSE_Sign1 (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Verify
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(verifier) = sign1.verifier(gose.Eddsa, keys: [signing_key])
  let assert Ok(Nil) = sign1.verify(verifier, parsed)
  io.println("Signature verified")
  io.println("")
}

fn aad() {
  io.println("--- External AAD ---")

  let signing_key = gose.generate_ec(ec.P256)
  let payload = <<"Protected payload":utf8>>
  let aad = <<"protocol-header-v1":utf8>>

  // Sign
  let assert Ok(signed) =
    sign1.new(gose.Ecdsa(gose.EcdsaP256))
    |> sign1.with_aad(aad:)
    |> sign1.sign(signing_key, payload)

  let data = sign1.serialize(signed)
  io.println("COSE_Sign1 with external AAD (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Verify
  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(verifier) =
    sign1.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(Nil) = sign1.verify_with_aad(verifier, parsed, aad)
  io.println("Verified with matching external AAD")
  io.println("")
}

fn detached_payload() {
  io.println("--- Detached Payload ---")

  let signing_key = gose.generate_ec(ec.P256)
  let payload = <<"detached COSE_Sign1 payload":utf8>>

  let assert Ok(signed) =
    sign1.new(gose.Ecdsa(gose.EcdsaP256))
    |> sign1.with_detached
    |> sign1.sign(signing_key, payload)

  let data = sign1.serialize(signed)
  io.println("COSE_Sign1 without embedded payload (base64):")
  io.println(bit_array.base64_encode(data, True))

  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(verifier) =
    sign1.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(Nil) = sign1.verify_detached(verifier, parsed, payload)
  io.println("Verified with externally provided payload")
  io.println("")
}
