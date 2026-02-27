import gleam/bit_array
import gleam/io
import gleam/json
import gleam/result
import gleam/string
import gose/jwa
import gose/jwe
import gose/jwk
import kryptos/ec
import kryptos/xdh

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("JWE (JSON Web Encryption) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  direct_encryption()
  xchacha20_poly1305_encryption()
  aes_key_wrap()
  aes_gcm_key_wrap()
  rsa_oaep_encryption()
  ecdh_es_direct()
  ecdh_es_with_key_wrap()
  password_based_encryption()
  additional_authenticated_data()

  io.println(string.repeat("=", 60))
  io.println("All JWE examples completed!")
  io.println(string.repeat("=", 60))
}

fn direct_encryption() {
  io.println("--- Direct Symmetric Encryption (dir + A256GCM) ---")

  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"Secret message using direct encryption":utf8>>

  let assert Ok(token) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, plaintext)
    |> result.try(jwe.serialize_compact)

  io.println("Encrypted JWE (compact):")
  io.println(token)

  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  let assert Ok(message) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> message)
  io.println("")
}

fn xchacha20_poly1305_encryption() {
  io.println("--- XChaCha20-Poly1305 Encryption (dir + XC20P) ---")

  let key = jwk.generate_enc_key(jwa.XChaCha20Poly1305)
  let plaintext = <<"Secret message using XChaCha20-Poly1305":utf8>>

  let assert Ok(token) =
    jwe.new_direct(jwa.XChaCha20Poly1305)
    |> jwe.encrypt(key, plaintext)
    |> result.try(jwe.serialize_compact)

  io.println("Encrypted JWE (compact):")
  io.println(token)

  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.XChaCha20Poly1305, [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  let assert Ok(message) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> message)
  io.println("")
}

fn aes_key_wrap() {
  io.println("--- AES Key Wrap (A256KW + A256GCM) ---")

  let key = jwk.generate_aes_kw_key(jwa.Aes256)
  let plaintext = <<"Message encrypted with AES Key Wrap":utf8>>

  let assert Ok(token) =
    jwe.new_aes_kw(jwa.Aes256, jwa.AesGcm(jwa.Aes256))
    |> jwe.with_kid("aes-kw-key")
    |> jwe.encrypt(key, plaintext)
    |> result.try(jwe.serialize_compact)

  io.println("Encrypted JWE with AES Key Wrap:")
  io.println(token)

  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweAesKeyWrap(jwa.AesKw, jwa.Aes256),
      jwa.AesGcm(jwa.Aes256),
      [
        key,
      ],
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  let assert Ok(message) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> message)
  io.println("")
}

fn aes_gcm_key_wrap() {
  io.println("--- AES-GCM Key Wrap (A256GCMKW + A256GCM) ---")

  let key = jwk.generate_aes_kw_key(jwa.Aes256)
  let plaintext = <<"Message encrypted with AES-GCM Key Wrap":utf8>>

  let assert Ok(token) =
    jwe.new_aes_gcm_kw(jwa.Aes256, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, plaintext)
    |> result.try(jwe.serialize_compact)

  io.println("Encrypted JWE with AES-GCM Key Wrap:")
  io.println(token)

  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweAesKeyWrap(jwa.AesGcmKw, jwa.Aes256),
      jwa.AesGcm(jwa.Aes256),
      [key],
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  let assert Ok(message) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> message)
  io.println("")
}

fn rsa_oaep_encryption() {
  io.println("--- RSA-OAEP Encryption (RSA-OAEP-256 + A256GCM) ---")

  let assert Ok(key) = jwk.generate_rsa(2048)
  let plaintext = <<"RSA-OAEP encrypted message":utf8>>

  let assert Ok(token) =
    jwe.new_rsa(jwa.RsaOaepSha256, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, plaintext)
    |> result.try(jwe.serialize_compact)

  io.println("Encrypted JWE with RSA-OAEP-256:")
  io.println(token)

  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweRsa(jwa.RsaOaepSha256), jwa.AesGcm(jwa.Aes256), [
      key,
    ])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  let assert Ok(message) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> message)
  io.println("")
}

fn ecdh_es_direct() {
  io.println("--- ECDH-ES Direct Key Agreement (P-256) ---")

  let key = jwk.generate_ec(ec.P256)
  let plaintext = <<"ECDH-ES direct encrypted message":utf8>>

  let assert Ok(token) =
    jwe.new_ecdh_es(jwa.EcdhEsDirect, jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, plaintext)
    |> result.try(jwe.serialize_compact)

  io.println("Encrypted JWE with ECDH-ES:")
  io.println(token)

  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweEcdhEs(jwa.EcdhEsDirect), jwa.AesGcm(jwa.Aes256), [
      key,
    ])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  let assert Ok(message) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> message)
  io.println("")
}

fn ecdh_es_with_key_wrap() {
  io.println("--- ECDH-ES with Key Wrap (X25519 + A256KW) ---")

  let key = jwk.generate_xdh(xdh.X25519)
  let plaintext = <<"ECDH-ES+A256KW encrypted with X25519":utf8>>

  let assert Ok(token) =
    jwe.new_ecdh_es(jwa.EcdhEsAesKw(jwa.Aes256), jwa.AesGcm(jwa.Aes256))
    |> jwe.with_apu(<<"Alice":utf8>>)
    |> jwe.with_apv(<<"Bob":utf8>>)
    |> jwe.encrypt(key, plaintext)
    |> result.try(jwe.serialize_compact)

  io.println("Encrypted JWE with ECDH-ES+A256KW (with apu/apv):")
  io.println(token)

  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes256)),
      jwa.AesGcm(jwa.Aes256),
      [key],
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  let assert Ok(message) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> message)
  io.println("")
}

fn password_based_encryption() {
  io.println("--- Password-Based Encryption (PBES2-HS256+A128KW) ---")

  let password = "correct-horse-battery-staple"
  let plaintext = <<"Password-encrypted secret":utf8>>

  let assert Ok(token) =
    jwe.new_pbes2(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes128))
    |> jwe.with_p2c(1000)
    |> result.try(jwe.encrypt_with_password(_, password, plaintext))
    |> result.try(jwe.serialize_compact)

  io.println("Encrypted JWE with PBES2 (1000 iterations for demo):")
  io.println(token)

  let assert Ok(parsed) = jwe.parse_compact(token)
  let decryptor =
    jwe.password_decryptor(
      jwa.Pbes2Sha256Aes128Kw,
      jwa.AesGcm(jwa.Aes128),
      password,
    )
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  let assert Ok(message) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> message)
  io.println("")
}

fn additional_authenticated_data() {
  io.println("--- Additional Authenticated Data (AAD) ---")

  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"Secret with authenticated context":utf8>>
  let context = <<"request-id:12345,timestamp:2026-01-28":utf8>>

  // Create JWE with AAD - context is authenticated but not encrypted
  let assert Ok(token) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.with_aad(context)
    |> jwe.encrypt(key, plaintext)
    // AAD requires JSON serialization (compact format doesn't support it)
    |> result.map(jwe.serialize_json_flattened)
    |> result.map(json.to_string)

  io.println("Encrypted JWE with AAD (JSON flattened):")
  io.println(token)

  // Parse and decrypt - AAD integrity is verified during decryption
  let assert Ok(parsed) = jwe.parse_json(token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  let assert Ok(message) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> message)

  // Access the AAD from the parsed JWE
  let assert Ok(recovered_aad) = jwe.aad(parsed)
  let assert Ok(aad_str) = bit_array.to_string(recovered_aad)
  io.println("AAD: " <> aad_str)
  io.println("")
}
