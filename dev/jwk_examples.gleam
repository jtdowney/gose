import gleam/bit_array
import gleam/int
import gleam/io
import gleam/json
import gleam/result
import gleam/string
import gose/encrypted_jwk
import gose/jwa
import gose/jwe
import gose/jwk
import kryptos/ec
import kryptos/eddsa
import kryptos/xdh

fn ec_curve_name(curve: ec.Curve) -> String {
  case curve {
    ec.P256 -> "P-256"
    ec.P384 -> "P-384"
    ec.P521 -> "P-521"
    ec.Secp256k1 -> "secp256k1"
  }
}

fn eddsa_curve_name(curve: eddsa.Curve) -> String {
  case curve {
    eddsa.Ed25519 -> "Ed25519"
    eddsa.Ed448 -> "Ed448"
  }
}

fn xdh_curve_name(curve: xdh.Curve) -> String {
  case curve {
    xdh.X25519 -> "X25519"
    xdh.X448 -> "X448"
  }
}

fn key_type_name(key_type: jwk.KeyType) -> String {
  case key_type {
    jwk.OctKeyType -> "oct"
    jwk.RsaKeyType -> "RSA"
    jwk.EcKeyType -> "EC"
    jwk.OkpKeyType -> "OKP"
  }
}

fn key_use_name(use_value: jwk.KeyUse) -> String {
  case use_value {
    jwk.Signing -> "sig"
    jwk.Encrypting -> "enc"
  }
}

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("JWK (JSON Web Key) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  generate_symmetric_key()
  generate_rsa_key()
  generate_ec_key()
  generate_eddsa_key()
  generate_xdh_key()
  add_metadata()
  algorithm_metadata()
  json_serialization()
  pem_serialization()
  raw_bits_roundtrip()
  key_type_inspection()
  ec_coordinates()
  component_extraction()
  extract_public_key()
  encrypted_jwk_export()

  io.println(string.repeat("=", 60))
  io.println("All JWK examples completed!")
  io.println(string.repeat("=", 60))
}

fn generate_symmetric_key() {
  io.println("--- Generate Symmetric Key (256-bit) ---")

  let _key = jwk.generate_hmac_key(jwa.HmacSha256)
  io.println("Generated 32-byte symmetric key for HMAC signing")
  io.println("Key type: oct")
  io.println("")
}

fn generate_rsa_key() {
  io.println("--- Generate RSA Key Pair (2048-bit) ---")

  let assert Ok(key) = jwk.generate_rsa(2048)
  io.println("Generated 2048-bit RSA key pair")
  io.println("Key type: RSA")

  let _pub_key = jwk.public_key(key)
  io.println("Extracted public key successfully")
  io.println("")
}

fn generate_ec_key() {
  io.println("--- Generate EC Key Pair (P-256) ---")

  let key = jwk.generate_ec(ec.P256)
  io.println("Generated P-256 EC key pair")
  io.println("Key type: EC")

  let assert Ok(curve) = jwk.ec_curve(key)
  io.println("Curve: " <> ec_curve_name(curve))
  io.println("")
}

fn generate_eddsa_key() {
  io.println("--- Generate EdDSA Key Pair (Ed25519) ---")

  let key = jwk.generate_eddsa(eddsa.Ed25519)
  io.println("Generated Ed25519 key pair")
  io.println("Key type: OKP")

  let assert Ok(curve) = jwk.eddsa_curve(key)
  io.println("Curve: " <> eddsa_curve_name(curve))
  io.println("")
}

fn add_metadata() {
  io.println("--- Add Key Metadata ---")

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let key_with_kid = jwk.with_kid(key, "my-signing-key-001")
  let assert Ok(key_with_use) = jwk.with_key_use(key_with_kid, jwk.Signing)
  let assert Ok(key_with_ops) =
    jwk.with_key_ops(key_with_use, [jwk.Sign, jwk.Verify])

  let assert Ok(kid_value) = jwk.kid(key_with_ops)
  io.println("Key ID (kid): " <> kid_value)

  let assert Ok(use_value) = jwk.key_use(key_with_ops)
  io.println("Key Use: " <> key_use_name(use_value))
  io.println("Key Ops: [sign, verify]")
  io.println("")
}

fn json_serialization() {
  io.println("--- JSON Serialization ---")

  let key = jwk.generate_ec(ec.P256)
  let key_with_kid = jwk.with_kid(key, "ec-key-001")

  let json_val = jwk.to_json(key_with_kid)
  let json_str = json.to_string(json_val)
  io.println("Serialized EC key to JSON:")
  io.println(json_str)

  let assert Ok(parsed_key) = jwk.from_json(json_str)
  let assert Ok(parsed_kid) = jwk.kid(parsed_key)
  io.println("Parsed key ID: " <> parsed_kid)
  io.println("")
}

fn extract_public_key() {
  io.println("--- Extract Public Key ---")

  let private_key = jwk.generate_ec(ec.P256)
  let private_key = jwk.with_kid(private_key, "my-ec-key")

  let assert Ok(public_key) = jwk.public_key(private_key)

  let pub_json = jwk.to_json(public_key)
  let json_str = json.to_string(pub_json)
  io.println("Public key (no 'd' parameter):")
  io.println(json_str)
  io.println("")
}

fn generate_xdh_key() {
  io.println("--- Generate XDH Key Pair (X25519) ---")

  let key = jwk.generate_xdh(xdh.X25519)
  io.println("Generated X25519 key pair for key agreement")
  io.println("Key type: OKP")

  let assert Ok(curve) = jwk.xdh_curve(key)
  io.println("Curve: " <> xdh_curve_name(curve))

  let json_val = jwk.to_json(key)
  io.println("XDH JWK: " <> json.to_string(json_val))
  io.println("")
}

fn raw_bits_roundtrip() {
  io.println("--- Raw Bits Round-Trip ---")

  let secret = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(oct_key) = jwk.from_octet_bits(secret)
  let assert Ok(extracted) = jwk.to_octet_bits(oct_key)
  io.println(
    "Octet key round-trip: "
    <> int.to_string(bit_array.byte_size(extracted))
    <> " bytes",
  )

  let eddsa_key = jwk.generate_eddsa(eddsa.Ed25519)
  let assert Ok(private_bits) = jwk.to_octet_bits(eddsa_key)
  let assert Ok(restored_key) = jwk.from_eddsa_bits(eddsa.Ed25519, private_bits)
  io.println(
    "EdDSA private key round-trip: "
    <> int.to_string(bit_array.byte_size(private_bits))
    <> " bytes",
  )

  let assert Ok(eddsa_pub) = jwk.public_key(eddsa_key)
  let assert Ok(pub_bits) = jwk.to_octet_bits(eddsa_pub)
  let assert Ok(_restored_pub) =
    jwk.from_eddsa_public_bits(eddsa.Ed25519, pub_bits)
  io.println(
    "EdDSA public key round-trip: "
    <> int.to_string(bit_array.byte_size(pub_bits))
    <> " bytes",
  )

  let restored_json = jwk.to_json(restored_key)
  io.println("Restored EdDSA key JSON: " <> json.to_string(restored_json))
  io.println("")
}

fn pem_serialization() {
  io.println("--- PEM Serialization ---")

  let ec_key = jwk.generate_ec(ec.P256)
  let assert Ok(pem_str) = jwk.to_pem(ec_key)
  io.println("EC private key PEM (first 64 chars):")
  io.println(string.slice(pem_str, 0, 64) <> "...")

  let assert Ok(parsed_key) = jwk.from_pem(pem_str)
  let assert Ok(parsed_curve) = jwk.ec_curve(parsed_key)
  io.println("Parsed key curve: " <> ec_curve_name(parsed_curve))

  let eddsa_key = jwk.generate_eddsa(eddsa.Ed25519)
  let assert Ok(eddsa_pem) = jwk.to_pem(eddsa_key)
  let assert Ok(_eddsa_parsed) = jwk.from_pem(eddsa_pem)
  io.println("EdDSA PEM round-trip successful")
  io.println("")
}

fn key_type_inspection() {
  io.println("--- Key Type Inspection ---")

  let oct_key = jwk.generate_hmac_key(jwa.HmacSha256)
  io.println("Octet key type: " <> key_type_name(jwk.key_type(oct_key)))

  let assert Ok(size) = jwk.octet_key_size(oct_key)
  io.println("Octet key size: " <> int.to_string(size) <> " bytes")

  let assert Ok(rsa_key) = jwk.generate_rsa(2048)
  io.println("RSA key type: " <> key_type_name(jwk.key_type(rsa_key)))

  let eddsa_key = jwk.generate_eddsa(eddsa.Ed25519)
  io.println("EdDSA key type: " <> key_type_name(jwk.key_type(eddsa_key)))
  io.println("")
}

fn algorithm_metadata() {
  io.println("--- Algorithm Metadata ---")

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(alg) = jwk.alg_from_string("HS256")
  let key_with_alg = jwk.with_alg(key, alg)

  let assert Ok(retrieved_alg) = jwk.alg(key_with_alg)
  let alg_str = jwk.alg_to_string(retrieved_alg)
  io.println("Algorithm set on key: " <> alg_str)

  let json_val = jwk.to_json(key_with_alg)
  io.println("Key with algorithm: " <> json.to_string(json_val))

  let assert Ok(jwe_alg) = jwk.alg_from_string("RSA-OAEP")
  io.println("Parsed JWE algorithm: " <> jwk.alg_to_string(jwe_alg))
  io.println("")
}

fn ec_coordinates() {
  io.println("--- EC Coordinate Operations ---")

  let ec_key = jwk.generate_ec(ec.P256)
  let assert Ok(#(x, y)) = jwk.ec_public_key_coordinates(ec_key)
  io.println(
    "EC P-256 coordinates extracted: x="
    <> int.to_string(bit_array.byte_size(x))
    <> " bytes, y="
    <> int.to_string(bit_array.byte_size(y))
    <> " bytes",
  )

  let assert Ok(reconstructed) =
    jwk.ec_public_key_from_coordinates(ec.P256, x, y)
  let recon_json = jwk.to_json(reconstructed)
  io.println("Reconstructed EC public key from coordinates:")
  io.println(json.to_string(recon_json))
  io.println("")
}

fn component_extraction() {
  io.println("--- Component Extraction ---")

  let assert Ok(rsa_key) = jwk.generate_rsa(2048)
  let assert Ok(_rsa_pub) = jwk.rsa_public_key(rsa_key)
  io.println("Extracted RSA public key component (kryptos type)")

  let ec_key = jwk.generate_ec(ec.P384)
  let assert Ok(_ec_pub) = jwk.ec_public_key(ec_key)
  io.println("Extracted EC public key component (kryptos type)")

  let eddsa_key = jwk.generate_eddsa(eddsa.Ed25519)
  let assert Ok(_eddsa_pub) = jwk.eddsa_public_key(eddsa_key)
  io.println("Extracted EdDSA public key component (kryptos type)")

  let xdh_key = jwk.generate_xdh(xdh.X25519)
  let assert Ok(_xdh_pub) = jwk.xdh_public_key(xdh_key)
  io.println("Extracted XDH public key component (kryptos type)")

  io.println("All kryptos types can be used directly with kryptos APIs")
  io.println("")
}

fn encrypted_jwk_export() {
  io.println("--- Encrypted JWK Export ---")

  let key = jwk.generate_ec(ec.P256)
  let key = jwk.with_kid(key, "my-signing-key")
  let assert Ok(key) = jwk.with_key_use(key, jwk.Signing)

  io.println("Generated P-256 EC key for signing")

  let key_json = jwk.to_json(key)
  let plaintext = bit_array.from_string(json.to_string(key_json))

  let assert Ok(encrypted) =
    jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes256))
    |> jwe.with_cty("jwk+json")
    |> jwe.with_p2c(1000)
    |> result.try(jwe.encrypt_with_password(_, "my-secure-password", plaintext))
    |> result.try(jwe.serialize_compact)

  io.println("Encrypted JWK with PBES2-HS256+A128KW / AES-256-GCM:")
  io.println(string.slice(encrypted, 0, 80) <> "...")

  let decryptor =
    jwe.password_decryptor(
      jwa.Pbes2Sha256Aes128Kw,
      jwa.AesGcm(jwa.Aes256),
      "my-secure-password",
    )
  let assert Ok(recovered) = encrypted_jwk.decrypt(decryptor, encrypted)

  let assert Ok(recovered_kid) = jwk.kid(recovered)
  io.println("Recovered key ID: " <> recovered_kid)

  let assert Ok(recovered_use) = jwk.key_use(recovered)
  io.println("Recovered key use: " <> key_use_name(recovered_use))

  io.println("")
  io.println("Using symmetric key encryption (AES-256-GCM direct):")

  let wrap_key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let assert Ok(encrypted_sym) =
    encrypted_jwk.encrypt_with_key(
      key,
      jwa.JweDirect,
      jwa.AesGcm(jwa.Aes256),
      wrap_key,
    )

  io.println("Encrypted: " <> string.slice(encrypted_sym, 0, 80) <> "...")

  let assert Ok(sym_decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [wrap_key])
  let assert Ok(_recovered_sym) =
    encrypted_jwk.decrypt(sym_decryptor, encrypted_sym)

  io.println("Successfully decrypted with symmetric key")
  io.println("")
}
