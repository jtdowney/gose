import gleam/bit_array
import gleam/io
import gleam/json
import gleam/string
import gose
import gose/jose/jwe_multi
import kryptos/ec
import kryptos/xdh

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("JWE Multi-Recipient Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  two_aes_kw_recipients()
  ecdh_es_aes_kw_recipient()
  mixed_recipients()

  io.println(string.repeat("=", 60))
  io.println("All JWE multi-recipient examples completed!")
  io.println(string.repeat("=", 60))
}

fn two_aes_kw_recipients() {
  io.println("--- Two AES Key Wrap Recipients ---")

  let k1 = gose.generate_aes_kw_key(gose.Aes256)
  let k2 = gose.generate_aes_kw_key(gose.Aes128)
  let enc = gose.AesGcm(gose.Aes256)
  let plaintext = <<"shared secret for two recipients":utf8>>

  // Encrypt
  let message = jwe_multi.new(enc)
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.AesKeyWrap(gose.AesKw, gose.Aes256),
      key: k1,
    )
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.AesKeyWrap(gose.AesKw, gose.Aes128),
      key: k2,
    )
  let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)

  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  io.println("JWE JSON:" <> "\n" <> json_str)

  // Decrypt
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)

  let assert Ok(dec) =
    jwe_multi.decryptor(
      gose.AesKeyWrap(gose.AesKw, gose.Aes256),
      enc,
      keys: [k1],
    )
  let assert Ok(pt) = jwe_multi.decrypt(dec, parsed)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("Recipient 1 decrypted: " <> text)

  let assert Ok(dec) =
    jwe_multi.decryptor(
      gose.AesKeyWrap(gose.AesKw, gose.Aes128),
      enc,
      keys: [k2],
    )
  let assert Ok(pt) = jwe_multi.decrypt(dec, parsed)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("Recipient 2 decrypted: " <> text)
  io.println("")
}

fn ecdh_es_aes_kw_recipient() {
  io.println("--- ECDH-ES+A256KW Recipient (P-256) ---")

  let ec_key = gose.generate_ec(ec.P256)
  let enc = gose.AesGcm(gose.Aes256)
  let alg = gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes256))
  let plaintext = <<"ecdh-es key agreement with AES key wrap":utf8>>

  // Encrypt
  let message = jwe_multi.new(enc)
  let assert Ok(message) = jwe_multi.add_recipient(message, alg, key: ec_key)
  let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)

  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  io.println("JWE JSON:" <> "\n" <> json_str)

  // Decrypt
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)
  let assert Ok(dec) = jwe_multi.decryptor(alg, enc, keys: [ec_key])
  let assert Ok(pt) = jwe_multi.decrypt(dec, parsed)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("Decrypted: " <> text)
  io.println("")
}

fn mixed_recipients() {
  io.println("--- Mixed Recipients (AES-KW + ECDH-ES+C20PKW) ---")

  let aes_key = gose.generate_aes_kw_key(gose.Aes256)
  let xdh_key = gose.generate_xdh(xdh.X25519)
  let enc = gose.AesGcm(gose.Aes256)
  let plaintext = <<"mixed algorithm recipients":utf8>>

  // Encrypt
  let message = jwe_multi.new(enc)
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.AesKeyWrap(gose.AesKw, gose.Aes256),
      key: aes_key,
    )
  let assert Ok(message) =
    jwe_multi.add_recipient(
      message,
      gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.C20PKw)),
      key: xdh_key,
    )
  let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)
  let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
  io.println("JWE JSON:" <> "\n" <> json_str)

  // Decrypt
  let assert Ok(parsed) = jwe_multi.parse_json(json_str)

  let assert Ok(dec) =
    jwe_multi.decryptor(
      gose.AesKeyWrap(gose.AesKw, gose.Aes256),
      enc,
      keys: [aes_key],
    )
  let assert Ok(pt) = jwe_multi.decrypt(dec, parsed)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("AES-KW recipient decrypted: " <> text)

  let assert Ok(dec) =
    jwe_multi.decryptor(
      gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.C20PKw)),
      enc,
      keys: [xdh_key],
    )
  let assert Ok(pt) = jwe_multi.decrypt(dec, parsed)
  let assert Ok(text) = bit_array.to_string(pt)
  io.println("ECDH-ES+C20PKW recipient decrypted: " <> text)
  io.println("")
}
