import gleam/bit_array
import gleam/io
import gleam/string
import gose/algorithm
import gose/cose/sign
import gose/key
import kryptos/ec
import kryptos/eddsa

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("COSE_Sign (Multi-Signer Signatures) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  single_signer()
  multi_signer()
  aad()

  io.println(string.repeat("=", 60))
  io.println("All COSE_Sign examples completed!")
  io.println(string.repeat("=", 60))
}

fn single_signer() {
  io.println("--- Single Signer (ES256) ---")

  let payload = <<"Hello, COSE_Sign!":utf8>>
  let signing_key = key.generate_ec(ec.P256)

  // Sign
  let assert Ok(body) =
    sign.new(payload:)
    |> sign.sign(algorithm.Ecdsa(algorithm.EcdsaP256), key: signing_key)
  let signed = sign.assemble(body)

  let data = sign.serialize(signed)
  io.println("Serialized COSE_Sign (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Verify
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(verifier) =
    sign.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [signing_key])
  let assert Ok(Nil) = sign.verify(verifier, parsed)
  io.println("Signature verified successfully")
  io.println("")
}

fn multi_signer() {
  io.println("--- Multi-Signer (ES256 + EdDSA) ---")

  let payload = <<"Multi-signed message":utf8>>
  let ec_key = key.generate_ec(ec.P256)
  let ed_key = key.generate_eddsa(eddsa.Ed25519)

  // Sign
  let assert Ok(body) =
    sign.new(payload:)
    |> sign.sign(algorithm.Ecdsa(algorithm.EcdsaP256), key: ec_key)
  let assert Ok(body) = sign.sign(body, algorithm.Eddsa, key: ed_key)
  let signed = sign.assemble(body)

  let data = sign.serialize_tagged(signed)
  io.println("Tagged COSE_Sign with 2 signers (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Verify
  let assert Ok(parsed) = sign.parse(data)

  let assert Ok(verifier) =
    sign.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [ec_key])
  let assert Ok(Nil) = sign.verify(verifier, parsed)
  io.println("ECDSA signer verified")

  let assert Ok(verifier) = sign.verifier(algorithm.Eddsa, keys: [ed_key])
  let assert Ok(Nil) = sign.verify(verifier, parsed)
  io.println("EdDSA signer verified")
  io.println("")
}

fn aad() {
  io.println("--- External AAD ---")

  let payload = <<"Protected payload":utf8>>
  let aad = <<"protocol-header-v1":utf8>>
  let signing_key = key.generate_ec(ec.P256)

  // Sign
  let assert Ok(body) =
    sign.new(payload:)
    |> sign.with_aad(aad:)
    |> sign.sign(algorithm.Ecdsa(algorithm.EcdsaP256), key: signing_key)
  let signed = sign.assemble(body)

  let data = sign.serialize(signed)
  io.println("COSE_Sign with external AAD (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Verify
  let assert Ok(parsed) = sign.parse(data)
  let assert Ok(verifier) =
    sign.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [signing_key])
  let assert Ok(Nil) = sign.verify_with_aad(verifier, message: parsed, aad:)
  io.println("Verified with matching external AAD")
  io.println("")
}
