import gleam/bit_array
import gleam/io
import gleam/string
import gose/algorithm
import gose/cose/key as cose_key
import gose/key
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

  let ec_key = key.generate_ec(ec.P256)

  // Serialize
  let assert Ok(cbor_bytes) = cose_key.to_cbor(ec_key)
  io.println("EC key as CBOR (base64):")
  io.println(bit_array.base64_encode(cbor_bytes, True))

  // Parse
  let assert Ok(decoded) = cose_key.from_cbor(cbor_bytes)
  io.println("Key type: " <> string.inspect(key.key_type(decoded)))
  io.println("Roundtrip successful")
  io.println("")
}

fn eddsa_key_roundtrip() {
  io.println("--- EdDSA Ed25519 Key Roundtrip ---")

  let eddsa_key = key.generate_eddsa(eddsa.Ed25519)

  // Serialize
  let assert Ok(cbor_bytes) = cose_key.to_cbor(eddsa_key)
  io.println("EdDSA key as CBOR (base64):")
  io.println(bit_array.base64_encode(cbor_bytes, True))

  // Parse
  let assert Ok(decoded) = cose_key.from_cbor(cbor_bytes)
  io.println("Key type: " <> string.inspect(key.key_type(decoded)))
  io.println("Roundtrip successful")
  io.println("")
}

fn symmetric_key_roundtrip() {
  io.println("--- Symmetric Key Roundtrip ---")

  let hmac_key = key.generate_hmac_key(algorithm.HmacSha256)

  // Serialize
  let assert Ok(cbor_bytes) = cose_key.to_cbor(hmac_key)
  io.println("Symmetric key as CBOR (base64):")
  io.println(bit_array.base64_encode(cbor_bytes, True))

  // Parse
  let assert Ok(decoded) = cose_key.from_cbor(cbor_bytes)
  io.println("Key type: " <> string.inspect(key.key_type(decoded)))
  io.println("Roundtrip successful")
  io.println("")
}

fn public_key_only() {
  io.println("--- Public Key Only ---")

  let ec_key = key.generate_ec(ec.P256)
  let assert Ok(pub_key) = key.public_key(ec_key)

  // Serialize
  let assert Ok(cbor_bytes) = cose_key.to_cbor(pub_key)
  io.println("EC public key as CBOR (base64):")
  io.println(bit_array.base64_encode(cbor_bytes, True))

  // Parse
  let assert Ok(decoded) = cose_key.from_cbor(cbor_bytes)
  io.println("Key type: " <> string.inspect(key.key_type(decoded)))
  io.println("Roundtrip successful")
  io.println("")
}
