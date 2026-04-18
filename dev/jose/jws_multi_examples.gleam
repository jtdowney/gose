import gleam/bit_array
import gleam/io
import gleam/json
import gleam/string
import gose/algorithm
import gose/jose/jws_multi
import gose/key
import kryptos/ec
import kryptos/eddsa

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("JWS Multi-Signer Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  two_signers()
  single_signer_json()

  io.println(string.repeat("=", 60))
  io.println("All JWS multi-signer examples completed!")
  io.println(string.repeat("=", 60))
}

fn two_signers() {
  io.println("--- Two Signers (ES256 + EdDSA) ---")

  let ec_key = key.generate_ec(ec.P256)
  let ed_key = key.generate_eddsa(eddsa.Ed25519)
  let payload = <<"multi-signed payload":utf8>>

  let assert Ok(body) =
    jws_multi.new(payload:)
    |> jws_multi.sign(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      key: ec_key,
    )
  let assert Ok(body) =
    body
    |> jws_multi.sign(algorithm.DigitalSignature(algorithm.Eddsa), key: ed_key)

  let message = jws_multi.assemble(body)

  let json_str =
    jws_multi.serialize_json(message)
    |> json.to_string

  io.println("Serialized JWS JSON:")
  io.println(json_str)

  let assert Ok(parsed) = jws_multi.parse_json(json_str)

  let assert Ok(ec_verifier) =
    jws_multi.verifier(
      algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256)),
      keys: [ec_key],
    )
  let assert Ok(Nil) = jws_multi.verify(ec_verifier, parsed)
  io.println("ES256 signature verified")

  let assert Ok(ed_verifier) =
    jws_multi.verifier(algorithm.DigitalSignature(algorithm.Eddsa), keys: [
      ed_key,
    ])
  let assert Ok(Nil) = jws_multi.verify(ed_verifier, parsed)
  io.println("EdDSA signature verified")

  let recovered = jws_multi.payload(parsed)
  let assert Ok(text) = bit_array.to_string(recovered)
  io.println("Payload: " <> text)
  io.println("")
}

fn single_signer_json() {
  io.println("--- Single Signer JSON Serialization (HS256) ---")

  let hmac_key = key.generate_hmac_key(algorithm.HmacSha256)
  let payload = <<"hmac json":utf8>>

  let assert Ok(body) =
    jws_multi.new(payload:)
    |> jws_multi.sign(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      key: hmac_key,
    )
  let message = jws_multi.assemble(body)

  let json_str = jws_multi.serialize_json(message) |> json.to_string
  io.println("JWS JSON: " <> json_str)

  let assert Ok(parsed) = jws_multi.parse_json(json_str)
  let assert Ok(verifier) =
    jws_multi.verifier(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      keys: [hmac_key],
    )
  let assert Ok(Nil) = jws_multi.verify(verifier, parsed)
  io.println("HMAC signature verified")
  io.println("")
}
