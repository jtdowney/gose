import gleam/bit_array
import gleam/io
import gleam/string
import gose/algorithm
import gose/cose/encrypt
import gose/key
import kryptos/ec
import kryptos/xdh

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("COSE_Encrypt (Multi-Recipient Encryption) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  direct_encryption()
  aes_key_wrap()
  ecdh_es_direct()
  multi_recipient()

  io.println(string.repeat("=", 60))
  io.println("All COSE_Encrypt examples completed!")
  io.println(string.repeat("=", 60))
}

fn direct_encryption() {
  io.println("--- Direct Symmetric Encryption ---")

  let content_alg = algorithm.AesGcm(algorithm.Aes256)
  let k = key.generate_enc_key(content_alg)
  let plaintext = <<"direct COSE_Encrypt":utf8>>

  // Encrypt
  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_direct_recipient(key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  io.println("Serialized COSE_Encrypt (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Decrypt
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(dec) =
    encrypt.decryptor(algorithm.Direct, content_alg, keys: [k])
  let assert Ok(pt) = encrypt.decrypt(dec, parsed)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("Decrypted: " <> text)
  io.println("")
}

fn aes_key_wrap() {
  io.println("--- AES Key Wrap (A128KW + A256GCM) ---")

  let content_alg = algorithm.AesGcm(algorithm.Aes256)
  let kw_alg = algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes128)
  let k = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes128))
  let plaintext = <<"aes key wrapped":utf8>>

  // Encrypt
  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) = encrypt.new_aes_kw_recipient(algorithm.Aes128, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize_tagged(encrypted)
  io.println("Tagged COSE_Encrypt (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Decrypt
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(dec) = encrypt.decryptor(kw_alg, content_alg, keys: [k])
  let assert Ok(pt) = encrypt.decrypt(dec, parsed)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("Decrypted: " <> text)
  io.println("")
}

fn ecdh_es_direct() {
  io.println("--- ECDH-ES Direct Key Agreement (P-256) ---")

  let content_alg = algorithm.AesGcm(algorithm.Aes256)
  let k = key.generate_ec(ec.P256)
  let plaintext = <<"ecdh-es direct agreement":utf8>>

  // Encrypt
  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(r) =
    encrypt.new_ecdh_es_direct_recipient(encrypt.EcdhEsHkdf256, key: k)
  let message = encrypt.add_recipient(message, r)
  let assert Ok(encrypted) = encrypt.encrypt(message, plaintext:)

  let data = encrypt.serialize(encrypted)
  io.println("Serialized COSE_Encrypt (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Decrypt
  let assert Ok(parsed) = encrypt.parse(data)
  let assert Ok(dec) =
    encrypt.ecdh_es_direct_decryptor(encrypt.EcdhEsHkdf256, content_alg, keys: [
      k,
    ])
  let assert Ok(pt) = encrypt.decrypt(dec, parsed)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("Decrypted: " <> text)
  io.println("")
}

fn multi_recipient() {
  io.println("--- Multi-Recipient (AES-KW + ECDH-ES+A128KW) ---")

  let content_alg = algorithm.AesGcm(algorithm.Aes256)
  let aes_key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes128))
  let ec_key = key.generate_xdh(xdh.X25519)
  let plaintext = <<"shared across recipients":utf8>>

  // Encrypt
  let assert Ok(message) = encrypt.new(content_alg)
  let assert Ok(aes_r) =
    encrypt.new_aes_kw_recipient(algorithm.Aes128, key: aes_key)
  let assert Ok(ec_r) =
    encrypt.new_ecdh_es_aes_kw_recipient(algorithm.Aes128, key: ec_key)
  let message =
    message
    |> encrypt.add_recipient(aes_r)
    |> encrypt.add_recipient(ec_r)
  let assert Ok(encrypted) =
    message
    |> encrypt.with_aad(aad: <<"ctx":utf8>>)
    |> encrypt.encrypt(plaintext:)

  let data = encrypt.serialize(encrypted)
  io.println("Serialized COSE_Encrypt (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Decrypt
  let assert Ok(parsed) = encrypt.parse(data)

  let assert Ok(dec) =
    encrypt.decryptor(
      algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes128),
      content_alg,
      keys: [aes_key],
    )
  let assert Ok(pt) =
    encrypt.decrypt_with_aad(dec, message: parsed, aad: <<"ctx":utf8>>)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("AES-KW recipient decrypted: " <> text)

  let assert Ok(dec) =
    encrypt.decryptor(
      algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes128)),
      content_alg,
      keys: [ec_key],
    )
  let assert Ok(pt) =
    encrypt.decrypt_with_aad(dec, message: parsed, aad: <<"ctx":utf8>>)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("ECDH-ES+A128KW recipient decrypted: " <> text)
  io.println("")
}
