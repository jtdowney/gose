import gleam/bit_array
import gleam/io
import gleam/string
import gose/algorithm
import gose/cose/encrypt0
import gose/key

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("COSE_Encrypt0 (Symmetric Encryption) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  aes128_gcm()
  aes256_gcm()
  chacha20_poly1305()
  serialize_and_parse()
  aad()

  io.println(string.repeat("=", 60))
  io.println("All COSE_Encrypt0 examples completed!")
  io.println(string.repeat("=", 60))
}

fn aes128_gcm() {
  io.println("--- AES-128-GCM ---")

  let alg = algorithm.AesGcm(algorithm.Aes128)
  let encryption_key = key.generate_enc_key(alg)
  let plaintext = <<"Hello, COSE encryption!":utf8>>

  // Encrypt
  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) =
    encrypt0.encrypt(message, encryption_key, plaintext)

  let data = encrypt0.serialize(encrypted)
  io.println("Encrypted COSE_Encrypt0 (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Decrypt
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: encryption_key)
  let assert Ok(decrypted) = encrypt0.decrypt(decryptor, parsed)
  let assert Ok(text) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> text)
  io.println("")
}

fn aes256_gcm() {
  io.println("--- AES-256-GCM ---")

  let alg = algorithm.AesGcm(algorithm.Aes256)
  let encryption_key = key.generate_enc_key(alg)
  let plaintext = <<"AES-256 encrypted message":utf8>>

  // Encrypt
  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) =
    encrypt0.encrypt(message, encryption_key, plaintext)

  let data = encrypt0.serialize(encrypted)
  io.println("Encrypted (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Decrypt
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: encryption_key)
  let assert Ok(decrypted) = encrypt0.decrypt(decryptor, parsed)
  let assert Ok(text) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> text)
  io.println("")
}

fn chacha20_poly1305() {
  io.println("--- ChaCha20-Poly1305 ---")

  let alg = algorithm.ChaCha20Poly1305
  let encryption_key = key.generate_enc_key(alg)
  let plaintext = <<"ChaCha20 encrypted message":utf8>>

  // Encrypt
  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) =
    encrypt0.encrypt(message, encryption_key, plaintext)

  let data = encrypt0.serialize(encrypted)
  io.println("Encrypted (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Decrypt
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: encryption_key)
  let assert Ok(decrypted) = encrypt0.decrypt(decryptor, parsed)
  let assert Ok(text) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> text)
  io.println("")
}

fn serialize_and_parse() {
  io.println("--- Tagged Serialization Roundtrip ---")

  let alg = algorithm.AesGcm(algorithm.Aes128)
  let encryption_key = key.generate_enc_key(alg)
  let plaintext = <<"Tagged serialization test":utf8>>

  // Encrypt
  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) =
    encrypt0.encrypt(message, encryption_key, plaintext)

  let data = encrypt0.serialize_tagged(encrypted)
  io.println("Tagged COSE_Encrypt0 (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Decrypt
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: encryption_key)
  let assert Ok(decrypted) = encrypt0.decrypt(decryptor, parsed)
  let assert Ok(text) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> text)
  io.println("")
}

fn aad() {
  io.println("--- External AAD ---")

  let alg = algorithm.AesGcm(algorithm.Aes256)
  let encryption_key = key.generate_enc_key(alg)
  let plaintext = <<"Payload with AAD":utf8>>
  let aad = <<"additional-context":utf8>>

  // Encrypt
  let assert Ok(message) = encrypt0.new(alg)
  let assert Ok(encrypted) =
    message
    |> encrypt0.with_aad(aad:)
    |> encrypt0.encrypt(encryption_key, plaintext)

  let data = encrypt0.serialize(encrypted)
  io.println("Encrypted with AAD (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Decrypt
  let assert Ok(parsed) = encrypt0.parse(data)
  let assert Ok(decryptor) = encrypt0.decryptor(alg, key: encryption_key)
  let assert Ok(decrypted) =
    encrypt0.decrypt_with_aad(decryptor, message: parsed, aad:)
  let assert Ok(text) = bit_array.to_string(decrypted)
  io.println("Decrypted: " <> text)
  io.println("")
}
