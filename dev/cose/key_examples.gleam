import gleam/bit_array
import gleam/io
import gleam/string
import gose
import gose/cose
import kryptos/ec
import kryptos/eddsa

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("COSE_Key (Key Serialization) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  ec_key_roundtrip()
  eddsa_key_roundtrip()
  symmetric_key_roundtrip()
  public_key_only()

  io.println(string.repeat("=", 60))
  io.println("All COSE_Key examples completed!")
  io.println(string.repeat("=", 60))
}

fn ec_key_roundtrip() {
  io.println("--- EC P-256 Key Roundtrip ---")

  let ec_key = gose.generate_ec(ec.P256)

  let assert Ok(cbor_bytes) = cose.key_to_cbor(ec_key)
  io.println("EC key as CBOR (base64):")
  io.println(bit_array.base64_encode(cbor_bytes, True))

  let assert Ok(decoded) = cose.key_from_cbor(cbor_bytes)
  io.println("Key type: " <> string.inspect(gose.key_type(decoded)))
  io.println("Roundtrip successful")
  io.println("")
}

fn eddsa_key_roundtrip() {
  io.println("--- EdDSA Ed25519 Key Roundtrip ---")

  let eddsa_key = gose.generate_eddsa(eddsa.Ed25519)

  let assert Ok(cbor_bytes) = cose.key_to_cbor(eddsa_key)
  io.println("EdDSA key as CBOR (base64):")
  io.println(bit_array.base64_encode(cbor_bytes, True))

  let assert Ok(decoded) = cose.key_from_cbor(cbor_bytes)
  io.println("Key type: " <> string.inspect(gose.key_type(decoded)))
  io.println("Roundtrip successful")
  io.println("")
}

fn symmetric_key_roundtrip() {
  io.println("--- Symmetric Key Roundtrip ---")

  let hmac_key = gose.generate_hmac_key(gose.HmacSha256)

  let assert Ok(cbor_bytes) = cose.key_to_cbor(hmac_key)
  io.println("Symmetric key as CBOR (base64):")
  io.println(bit_array.base64_encode(cbor_bytes, True))

  let assert Ok(decoded) = cose.key_from_cbor(cbor_bytes)
  io.println("Key type: " <> string.inspect(gose.key_type(decoded)))
  io.println("Roundtrip successful")
  io.println("")
}

fn public_key_only() {
  io.println("--- Public Key Only ---")

  let ec_key = gose.generate_ec(ec.P256)
  let assert Ok(pub_key) = gose.public_key(ec_key)

  let assert Ok(cbor_bytes) = cose.key_to_cbor(pub_key)
  io.println("EC public key as CBOR (base64):")
  io.println(bit_array.base64_encode(cbor_bytes, True))

  let assert Ok(decoded) = cose.key_from_cbor(cbor_bytes)
  io.println("Key type: " <> string.inspect(gose.key_type(decoded)))
  io.println("Roundtrip successful")
  io.println("")
}
