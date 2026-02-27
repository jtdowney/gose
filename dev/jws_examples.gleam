import gleam/io
import gleam/json
import gleam/result
import gleam/string
import gose/jwa
import gose/jwk
import gose/jws
import kryptos/ec
import kryptos/eddsa

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("JWS (JSON Web Signature) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  hmac_signing()
  rsa_signing()
  ecdsa_signing()
  eddsa_signing()
  detached_payload()
  json_serialization()

  io.println(string.repeat("=", 60))
  io.println("All JWS examples completed!")
  io.println(string.repeat("=", 60))
}

fn hmac_signing() {
  io.println("--- HMAC Signing (HS256) ---")

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"Hello, JOSE!":utf8>>

  let assert Ok(token) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, payload)
    |> result.try(jws.serialize_compact)

  io.println("Signed JWS (compact):")
  io.println(token)

  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  let assert Ok(True) = jws.verify(verifier, parsed)
  io.println("Signature verified successfully")
  io.println("")
}

fn rsa_signing() {
  io.println("--- RSA Signing (RS256) ---")

  let assert Ok(key) = jwk.generate_rsa(2048)
  let payload = <<"RSA signed message":utf8>>

  let assert Ok(token) =
    jws.new(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256))
    |> jws.with_kid("rsa-key-001")
    |> jws.sign(key, payload)
    |> result.try(jws.serialize_compact)

  io.println("Signed JWS with kid header:")
  io.println(token)

  let assert Ok(pub_key) = jwk.public_key(key)
  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) =
    jws.verifier(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256), [pub_key])
  let assert Ok(True) = jws.verify(verifier, parsed)
  io.println("Verified with public key")
  io.println("")
}

fn ecdsa_signing() {
  io.println("--- ECDSA Signing (ES256) ---")

  let key = jwk.generate_ec(ec.P256)
  let payload = <<"ECDSA signed message":utf8>>

  let assert Ok(token) =
    jws.new(jwa.JwsEcdsa(jwa.EcdsaP256))
    |> jws.sign(key, payload)
    |> result.try(jws.serialize_compact)

  io.println("Signed JWS (ES256):")
  io.println(token)

  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) = jws.verifier(jwa.JwsEcdsa(jwa.EcdsaP256), [key])
  let assert Ok(True) = jws.verify(verifier, parsed)
  io.println("Signature verified")
  io.println("")
}

fn eddsa_signing() {
  io.println("--- EdDSA Signing (Ed25519) ---")

  let key = jwk.generate_eddsa(eddsa.Ed25519)
  let payload = <<"EdDSA signed message":utf8>>

  let assert Ok(token) =
    jws.new(jwa.JwsEddsa)
    |> jws.sign(key, payload)
    |> result.try(jws.serialize_compact)

  io.println("Signed JWS (EdDSA):")
  io.println(token)

  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) = jws.verifier(jwa.JwsEddsa, [key])
  let assert Ok(True) = jws.verify(verifier, parsed)
  io.println("Signature verified")
  io.println("")
}

fn detached_payload() {
  io.println("--- Detached Payload ---")

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"This payload is transmitted separately":utf8>>

  let assert Ok(token) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.with_detached()
    |> jws.sign(key, payload)
    |> result.try(jws.serialize_compact)

  io.println("JWS with detached payload (note empty middle section):")
  io.println(token)

  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  let assert Ok(True) = jws.verify_detached(verifier, parsed, payload)
  io.println("Verified with externally provided payload")
  io.println("")
}

fn json_serialization() {
  io.println("--- JSON Serialization ---")

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let payload = <<"JSON serialized JWS":utf8>>

  let assert Ok(signed) =
    jws.new(jwa.JwsHmac(jwa.HmacSha256))
    |> jws.sign(key, payload)

  io.println("Flattened JSON:")
  let flattened =
    jws.serialize_json_flattened(signed)
    |> json.to_string
  io.println(flattened)

  io.println("")
  io.println("General JSON:")
  let general =
    jws.serialize_json_general(signed)
    |> json.to_string
  io.println(general)

  let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
  let assert Ok(parsed_flat) = jws.parse_json(flattened)
  let assert Ok(True) = jws.verify(verifier, parsed_flat)
  let assert Ok(parsed_gen) = jws.parse_json(general)
  let assert Ok(True) = jws.verify(verifier, parsed_gen)
  io.println("")
  io.println("Both formats parsed and verified")
  io.println("")
}
