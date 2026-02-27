//// Content encryption and decryption for JWE payloads using AES-GCM,
//// AES-CBC-HMAC, ChaCha20-Poly1305, and XChaCha20-Poly1305.

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import gose
import gose/internal/utils
import gose/jwa
import kryptos/aead
import kryptos/block
import kryptos/crypto
import kryptos/hash.{type HashAlgorithm}

pub fn iv_size(enc: jwa.Enc) -> Int {
  case enc {
    jwa.AesGcm(_) -> 12
    jwa.AesCbcHmac(_) -> 16
    jwa.ChaCha20Poly1305 -> 12
    jwa.XChaCha20Poly1305 -> 24
  }
}

pub fn tag_size(enc: jwa.Enc) -> Int {
  case enc {
    jwa.AesGcm(_) -> 16
    jwa.AesCbcHmac(size) -> jwa.aes_key_size_in_bytes(size)
    jwa.ChaCha20Poly1305 | jwa.XChaCha20Poly1305 -> 16
  }
}

pub fn validate_iv_tag_sizes(
  enc: jwa.Enc,
  iv: BitArray,
  tag: BitArray,
) -> Result(Nil, gose.GoseError) {
  let expected_iv = iv_size(enc)
  let actual_iv = bit_array.byte_size(iv)
  use <- bool.guard(
    when: actual_iv != expected_iv,
    return: Error(gose.ParseError(
      "invalid IV length: expected "
      <> int.to_string(expected_iv)
      <> " bytes, got "
      <> int.to_string(actual_iv),
    )),
  )

  let expected_tag = tag_size(enc)
  let actual_tag = bit_array.byte_size(tag)
  use <- bool.guard(
    when: actual_tag != expected_tag,
    return: Error(gose.ParseError(
      "invalid tag length: expected "
      <> int.to_string(expected_tag)
      <> " bytes, got "
      <> int.to_string(actual_tag),
    )),
  )

  Ok(Nil)
}

pub fn generate_cek(enc: jwa.Enc) -> BitArray {
  crypto.random_bytes(jwa.enc_octet_key_size(enc))
}

pub fn generate_iv(enc: jwa.Enc) -> BitArray {
  crypto.random_bytes(iv_size(enc))
}

pub fn compute_aead_aad(
  protected_b64: String,
  user_aad: Option(BitArray),
) -> BitArray {
  case user_aad {
    None -> bit_array.from_string(protected_b64)
    Some(aad) -> {
      let aad_b64 = utils.encode_base64_url(aad)
      bit_array.concat([
        bit_array.from_string(protected_b64),
        <<".":utf8>>,
        bit_array.from_string(aad_b64),
      ])
    }
  }
}

pub fn aes_block_for_size(
  size: jwa.AesKeySize,
) -> fn(BitArray) -> Result(block.BlockCipher, Nil) {
  case size {
    jwa.Aes128 -> block.aes_128
    jwa.Aes192 -> block.aes_192
    jwa.Aes256 -> block.aes_256
  }
}

pub fn hash_for_aes_size(size: jwa.AesKeySize) -> HashAlgorithm {
  case size {
    jwa.Aes128 -> hash.Sha256
    jwa.Aes192 -> hash.Sha384
    jwa.Aes256 -> hash.Sha512
  }
}

pub fn encrypt_content(
  enc: jwa.Enc,
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  plaintext: BitArray,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  case enc {
    jwa.AesGcm(size) ->
      encrypt_aes_gcm(cek, iv, aad, plaintext, aes_block_for_size(size))
    jwa.AesCbcHmac(size) ->
      encrypt_aes_cbc_hmac(
        cek,
        iv,
        aad,
        plaintext,
        hash_for_aes_size(size),
        size,
      )
    jwa.ChaCha20Poly1305 -> encrypt_chacha20(cek, iv, aad, plaintext)
    jwa.XChaCha20Poly1305 -> encrypt_xchacha20(cek, iv, aad, plaintext)
  }
}

pub fn decrypt_content(
  enc: jwa.Enc,
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  case enc {
    jwa.AesGcm(size) ->
      decrypt_aes_gcm(cek, iv, aad, ciphertext, tag, aes_block_for_size(size))
    jwa.AesCbcHmac(size) ->
      decrypt_aes_cbc_hmac(
        cek,
        iv,
        aad,
        ciphertext,
        tag,
        hash_for_aes_size(size),
        size,
      )
    jwa.ChaCha20Poly1305 -> decrypt_chacha20(cek, iv, aad, ciphertext, tag)
    jwa.XChaCha20Poly1305 -> decrypt_xchacha20(cek, iv, aad, ciphertext, tag)
  }
}

fn encrypt_aes_gcm(
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  plaintext: BitArray,
  cipher_fn: fn(BitArray) -> Result(block.BlockCipher, Nil),
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  use cipher <- result.try(
    cipher_fn(cek)
    |> result.replace_error(gose.CryptoError("invalid CEK size for AES-GCM")),
  )
  let ctx = aead.gcm(cipher)
  aead.seal_with_aad(ctx, nonce: iv, plaintext:, additional_data: aad)
  |> result.replace_error(gose.CryptoError("AES-GCM encryption failed"))
}

fn decrypt_aes_gcm(
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
  cipher_fn: fn(BitArray) -> Result(block.BlockCipher, Nil),
) -> Result(BitArray, gose.GoseError) {
  use cipher <- result.try(
    cipher_fn(cek)
    |> result.replace_error(gose.CryptoError("invalid CEK size for AES-GCM")),
  )
  let ctx = aead.gcm(cipher)
  aead.open_with_aad(ctx, nonce: iv, tag:, ciphertext:, additional_data: aad)
  |> result.replace_error(gose.CryptoError("AES-GCM decryption failed"))
}

fn encrypt_chacha20(
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  plaintext: BitArray,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  use ctx <- result.try(
    aead.chacha20_poly1305(cek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for ChaCha20-Poly1305",
    )),
  )
  aead.seal_with_aad(ctx, nonce: iv, plaintext:, additional_data: aad)
  |> result.replace_error(gose.CryptoError(
    "ChaCha20-Poly1305 encryption failed",
  ))
}

fn decrypt_chacha20(
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use ctx <- result.try(
    aead.chacha20_poly1305(cek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for ChaCha20-Poly1305",
    )),
  )
  aead.open_with_aad(ctx, nonce: iv, tag:, ciphertext:, additional_data: aad)
  |> result.replace_error(gose.CryptoError(
    "ChaCha20-Poly1305 decryption failed",
  ))
}

fn encrypt_xchacha20(
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  plaintext: BitArray,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  use ctx <- result.try(
    aead.xchacha20_poly1305(cek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for XChaCha20-Poly1305",
    )),
  )
  aead.seal_with_aad(ctx, nonce: iv, plaintext:, additional_data: aad)
  |> result.replace_error(gose.CryptoError(
    "XChaCha20-Poly1305 encryption failed",
  ))
}

fn decrypt_xchacha20(
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use ctx <- result.try(
    aead.xchacha20_poly1305(cek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for XChaCha20-Poly1305",
    )),
  )
  aead.open_with_aad(ctx, nonce: iv, tag:, ciphertext:, additional_data: aad)
  |> result.replace_error(gose.CryptoError(
    "XChaCha20-Poly1305 decryption failed",
  ))
}

pub fn aes_cipher(
  size: jwa.AesKeySize,
  key: BitArray,
) -> Result(block.BlockCipher, gose.GoseError) {
  let cipher = case size {
    jwa.Aes128 -> block.aes_128(key)
    jwa.Aes192 -> block.aes_192(key)
    jwa.Aes256 -> block.aes_256(key)
  }
  cipher
  |> result.replace_error(gose.CryptoError("failed to create AES cipher"))
}

fn split_cek(
  cek: BitArray,
  key_size: Int,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  case cek {
    <<mk:bytes-size(key_size), ek:bytes-size(key_size)>> -> Ok(#(mk, ek))
    _ ->
      Error(gose.CryptoError(
        "invalid CEK size for AES-CBC-HMAC: expected "
        <> int.to_string(key_size * 2)
        <> " bytes, got "
        <> int.to_string(bit_array.byte_size(cek)),
      ))
  }
}

fn encrypt_aes_cbc_hmac(
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  plaintext: BitArray,
  hash_alg: HashAlgorithm,
  size: jwa.AesKeySize,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  let half = jwa.aes_key_size_in_bytes(size)
  use #(mac_key, enc_key) <- result.try(split_cek(cek, half))

  use cipher <- result.try(aes_cipher(size, enc_key))
  use ctx <- result.try(
    block.cbc(cipher, iv:)
    |> result.replace_error(gose.CryptoError("invalid IV for AES-CBC")),
  )
  use ciphertext <- result.try(
    block.encrypt(ctx, plaintext)
    |> result.replace_error(gose.CryptoError("AES-CBC encryption failed")),
  )

  let aad_len = bit_array.byte_size(aad)
  let al = <<{ aad_len * 8 }:size(64)>>
  let mac_input = bit_array.concat([aad, iv, ciphertext, al])

  use full_mac <- result.try(
    crypto.hmac(hash_alg, key: mac_key, data: mac_input)
    |> result.replace_error(gose.CryptoError("HMAC computation failed")),
  )

  let tag_size = bit_array.byte_size(full_mac) / 2
  case bit_array.slice(full_mac, 0, tag_size) {
    Ok(tag) -> Ok(#(ciphertext, tag))
    Error(_) -> Error(gose.CryptoError("tag extraction failed"))
  }
}

fn decrypt_aes_cbc_hmac(
  cek: BitArray,
  iv: BitArray,
  aad: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
  hash_alg: HashAlgorithm,
  size: jwa.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  let half = jwa.aes_key_size_in_bytes(size)
  use #(mac_key, enc_key) <- result.try(split_cek(cek, half))

  let aad_len = bit_array.byte_size(aad)
  let al = <<{ aad_len * 8 }:size(64)>>
  let mac_input = bit_array.concat([aad, iv, ciphertext, al])

  use full_mac <- result.try(
    crypto.hmac(hash_alg, key: mac_key, data: mac_input)
    |> result.replace_error(gose.CryptoError("HMAC computation failed")),
  )

  let tag_size = bit_array.byte_size(full_mac) / 2
  use expected_tag <- result.try(
    bit_array.slice(full_mac, 0, tag_size)
    |> result.replace_error(gose.CryptoError("tag extraction failed")),
  )

  use <- bool.guard(
    when: !crypto.constant_time_equal(tag, expected_tag),
    return: Error(gose.CryptoError("authentication tag mismatch")),
  )

  use cipher <- result.try(aes_cipher(size, enc_key))
  case block.cbc(cipher, iv:) {
    Ok(ctx) ->
      block.decrypt(ctx, ciphertext)
      |> result.replace_error(gose.CryptoError("AES-CBC decryption failed"))
    Error(_) -> Error(gose.CryptoError("invalid IV for AES-CBC"))
  }
}
