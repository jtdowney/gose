//// Key wrapping and unwrapping operations for all JWE key management algorithms
//// (direct, AES-KW, AES-GCM-KW, ChaCha20-KW, RSA, ECDH-ES, and PBES2).

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/option.{type Option}
import gleam/result
import gleam/string
import gose
import gose/internal/content_encryption
import gose/internal/key_extract
import kryptos/aead
import kryptos/block
import kryptos/crypto
import kryptos/ec
import kryptos/ecdh
import kryptos/hash
import kryptos/rsa
import kryptos/xdh

pub type EphemeralPublicKey {
  EcEphemeralKey(curve: ec.Curve, x: BitArray, y: BitArray)
  XdhEphemeralKey(curve: xdh.Curve, x: BitArray)
}

pub fn wrap_aes_kw(
  key: gose.Key(kid),
  cek cek: BitArray,
  size size: gose.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  use secret <- result.try(get_octet_key(key, gose.aes_key_size(size)))
  use cipher <- result.try(content_encryption.aes_cipher(size, secret))
  block.wrap(cipher, cek)
  |> result.replace_error(gose.CryptoError("AES Key Wrap failed"))
}

pub fn unwrap_aes_kw(
  key: gose.Key(kid),
  encrypted_key encrypted_key: BitArray,
  size size: gose.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  use secret <- result.try(get_octet_key(key, gose.aes_key_size(size)))
  use cipher <- result.try(content_encryption.aes_cipher(size, secret))
  block.unwrap(cipher, encrypted_key)
  |> result.replace_error(gose.CryptoError("AES Key Unwrap failed"))
}

pub fn get_octet_key(
  key: gose.Key(kid),
  expected_size expected_size: Int,
) -> Result(BitArray, gose.GoseError) {
  use secret <- result.try(
    gose.material_octet_secret(gose.material(key))
    |> result.replace_error(gose.InvalidState("expected octet key")),
  )

  let actual_size = bit_array.byte_size(secret)
  use <- bool.guard(
    when: actual_size != expected_size,
    return: Error(gose.InvalidState(
      "expected "
      <> int.to_string(expected_size)
      <> "-byte key, got "
      <> int.to_string(actual_size),
    )),
  )

  Ok(secret)
}

pub fn wrap_aes_gcm(
  kek: BitArray,
  cek cek: BitArray,
  iv iv: BitArray,
  size size: gose.AesKeySize,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  let ctx = aead.gcm(cipher)
  aead.seal(ctx, nonce: iv, plaintext: cek)
  |> result.replace_error(gose.CryptoError("AES-GCM Key Wrap failed"))
}

pub fn unwrap_aes_gcm(
  kek: BitArray,
  encrypted_cek encrypted_cek: BitArray,
  iv iv: BitArray,
  tag tag: BitArray,
  size size: gose.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  let ctx = aead.gcm(cipher)
  aead.open(ctx, nonce: iv, tag:, ciphertext: encrypted_cek)
  |> result.replace_error(gose.CryptoError("AES-GCM Key Unwrap failed"))
}

pub fn unwrap_aes_gcm_kw(
  key: gose.Key(kid),
  encrypted_cek encrypted_cek: BitArray,
  size size: gose.AesKeySize,
  kw_iv kw_iv: Option(BitArray),
  kw_tag kw_tag: Option(BitArray),
) -> Result(BitArray, gose.GoseError) {
  use iv <- result.try(option.to_result(
    kw_iv,
    gose.ParseError("missing iv header for AES-GCM Key Wrap"),
  ))
  use tag <- result.try(option.to_result(
    kw_tag,
    gose.ParseError("missing tag header for AES-GCM Key Wrap"),
  ))

  use kek <- result.try(get_octet_key(key, gose.aes_key_size(size)))
  unwrap_aes_gcm(kek, encrypted_cek:, iv:, tag:, size:)
}

fn chacha20_variant_params(
  variant: gose.ChaCha20Kw,
) -> #(fn(BitArray) -> Result(aead.AeadContext, Nil), String) {
  case variant {
    gose.C20PKw -> #(aead.chacha20_poly1305, "ChaCha20-Poly1305")
    gose.XC20PKw -> #(aead.xchacha20_poly1305, "XChaCha20-Poly1305")
  }
}

fn wrap_chacha20_variant(
  kek kek: BitArray,
  cek cek: BitArray,
  nonce nonce: BitArray,
  using cipher_fn: fn(BitArray) -> Result(aead.AeadContext, Nil),
  variant variant_name: String,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  use ctx <- result.try(
    cipher_fn(kek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for " <> variant_name <> " Key Wrap",
    )),
  )
  aead.seal(ctx, nonce:, plaintext: cek)
  |> result.replace_error(gose.CryptoError(variant_name <> " Key Wrap failed"))
}

fn unwrap_chacha20_variant(
  kek kek: BitArray,
  encrypted_cek encrypted_cek: BitArray,
  nonce nonce: BitArray,
  tag tag: BitArray,
  using cipher_fn: fn(BitArray) -> Result(aead.AeadContext, Nil),
  variant variant_name: String,
) -> Result(BitArray, gose.GoseError) {
  use ctx <- result.try(
    cipher_fn(kek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for " <> variant_name <> " Key Unwrap",
    )),
  )
  aead.open(ctx, nonce:, tag:, ciphertext: encrypted_cek)
  |> result.replace_error(gose.CryptoError(variant_name <> " Key Unwrap failed"))
}

pub fn wrap_chacha20_by_variant(
  kek: BitArray,
  cek cek: BitArray,
  nonce nonce: BitArray,
  variant variant: gose.ChaCha20Kw,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  let #(cipher_fn, variant_name) = chacha20_variant_params(variant)
  wrap_chacha20_variant(
    kek:,
    cek:,
    nonce:,
    using: cipher_fn,
    variant: variant_name,
  )
}

pub fn unwrap_chacha20_by_variant(
  kek: BitArray,
  encrypted_cek encrypted_cek: BitArray,
  nonce nonce: BitArray,
  tag tag: BitArray,
  variant variant: gose.ChaCha20Kw,
) -> Result(BitArray, gose.GoseError) {
  let #(cipher_fn, variant_name) = chacha20_variant_params(variant)
  unwrap_chacha20_variant(
    kek:,
    encrypted_cek:,
    nonce:,
    tag:,
    using: cipher_fn,
    variant: variant_name,
  )
}

pub fn unwrap_chacha20_kw(
  key: gose.Key(kid),
  encrypted_cek encrypted_cek: BitArray,
  variant variant: gose.ChaCha20Kw,
  kw_iv kw_iv: Option(BitArray),
  kw_tag kw_tag: Option(BitArray),
) -> Result(BitArray, gose.GoseError) {
  use iv <- result.try(option.to_result(
    kw_iv,
    gose.ParseError("missing iv header for ChaCha20 Key Wrap"),
  ))
  use tag <- result.try(option.to_result(
    kw_tag,
    gose.ParseError("missing tag header for ChaCha20 Key Wrap"),
  ))

  use kek <- result.try(get_octet_key(key, 32))
  unwrap_chacha20_by_variant(kek, encrypted_cek:, nonce: iv, tag:, variant:)
}

pub fn wrap_ecdh_es_chacha20_kw(
  key: gose.Key(kid),
  cek cek: BitArray,
  variant variant: gose.ChaCha20Kw,
  alg_id alg_id: String,
  apu apu: Option(BitArray),
  apv apv: Option(BitArray),
) -> Result(#(BitArray, EphemeralPublicKey, BitArray, BitArray), gose.GoseError) {
  use #(shared_secret, epk) <- result.try(compute_ecdh_shared_secret(key))
  use kek <- result.try(derive_ecdh_key(
    shared_secret,
    alg_id:,
    apu:,
    apv:,
    length: 32,
  ))

  let nonce_size = gose.chacha20_kw_nonce_size(variant)
  let nonce = crypto.random_bytes(nonce_size)
  use #(encrypted_cek, kw_tag) <- result.try(wrap_chacha20_by_variant(
    kek,
    cek:,
    nonce:,
    variant:,
  ))
  Ok(#(encrypted_cek, epk, nonce, kw_tag))
}

pub fn unwrap_ecdh_es_chacha20_kw(
  key: gose.Key(kid),
  encrypted_key encrypted_key: BitArray,
  variant variant: gose.ChaCha20Kw,
  alg_id alg_id: String,
  epk epk: EphemeralPublicKey,
  apu apu: Option(BitArray),
  apv apv: Option(BitArray),
  kw_iv kw_iv: BitArray,
  kw_tag kw_tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use shared_secret <- result.try(compute_ecdh_shared_secret_with_epk(key, epk))
  use kek <- result.try(derive_ecdh_key(
    shared_secret,
    alg_id:,
    apu:,
    apv:,
    length: 32,
  ))
  unwrap_chacha20_by_variant(
    kek,
    encrypted_cek: encrypted_key,
    nonce: kw_iv,
    tag: kw_tag,
    variant:,
  )
}

pub fn wrap_rsa_oaep(
  key: gose.Key(kid),
  cek cek: BitArray,
  hash_alg hash_alg: hash.HashAlgorithm,
) -> Result(BitArray, gose.GoseError) {
  use public <- result.try(
    key_extract.rsa_public_key(gose.material(key))
    |> result.replace_error(gose.InvalidState(
      "RSA encryption requires an RSA key",
    )),
  )
  let padding = rsa.Oaep(hash: hash_alg, label: <<>>)
  rsa.encrypt(public, cek, padding)
  |> result.replace_error(gose.CryptoError("RSA-OAEP encryption failed"))
}

pub fn unwrap_rsa_oaep(
  key: gose.Key(kid),
  encrypted_key encrypted_key: BitArray,
  hash_alg hash_alg: hash.HashAlgorithm,
) -> Result(BitArray, gose.GoseError) {
  use private <- result.try(
    key_extract.rsa_private_key(gose.material(key))
    |> result.replace_error(gose.InvalidState(
      "RSA decryption requires an RSA private key",
    )),
  )
  let padding = rsa.Oaep(hash: hash_alg, label: <<>>)
  rsa.decrypt(private, encrypted_key, padding)
  |> result.replace_error(gose.CryptoError("RSA-OAEP decryption failed"))
}

pub fn wrap_rsa_pkcs1v15(
  key: gose.Key(kid),
  cek: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use public <- result.try(
    key_extract.rsa_public_key(gose.material(key))
    |> result.replace_error(gose.InvalidState(
      "RSA encryption requires an RSA key",
    )),
  )
  rsa.encrypt(public, cek, rsa.EncryptPkcs1v15)
  |> result.replace_error(gose.CryptoError("RSA PKCS1v15 encryption failed"))
}

pub fn unwrap_rsa_pkcs1v15_safe(
  key: gose.Key(kid),
  encrypted_key encrypted_key: BitArray,
  enc enc: gose.ContentAlg,
) -> Result(BitArray, gose.GoseError) {
  use private <- result.try(
    key_extract.rsa_private_key(gose.material(key))
    |> result.replace_error(gose.InvalidState(
      "RSA decryption requires an RSA private key",
    )),
  )
  let expected_size = gose.content_alg_key_size(enc)
  let random_cek = content_encryption.generate_cek(enc)
  let cek =
    rsa.decrypt(private, encrypted_key, rsa.EncryptPkcs1v15)
    |> result.try(validate_decrypted_size(_, expected_size))
    |> result.unwrap(random_cek)
  Ok(cek)
}

fn validate_decrypted_size(
  decrypted: BitArray,
  expected_size expected_size: Int,
) -> Result(BitArray, Nil) {
  case bit_array.byte_size(decrypted) == expected_size {
    True -> Ok(decrypted)
    False -> Error(Nil)
  }
}

pub fn unwrap_direct(
  key: gose.Key(kid),
  enc: gose.ContentAlg,
) -> Result(BitArray, gose.GoseError) {
  use secret <- result.try(
    gose.material_octet_secret(gose.material(key))
    |> result.replace_error(gose.InvalidState(
      "direct encryption requires an octet key",
    )),
  )

  let expected_size = gose.content_alg_key_size(enc)
  let actual_size = bit_array.byte_size(secret)
  case actual_size == expected_size {
    True -> Ok(secret)
    False ->
      Error(gose.InvalidState(
        "direct encryption requires "
        <> int.to_string(expected_size)
        <> "-byte key for "
        <> string.inspect(enc)
        <> ", got "
        <> int.to_string(actual_size),
      ))
  }
}

pub fn wrap_ecdh_es_direct(
  key: gose.Key(kid),
  enc enc: gose.ContentAlg,
  alg_id alg_id: String,
  apu apu: Option(BitArray),
  apv apv: Option(BitArray),
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  let key_len = gose.content_alg_key_size(enc)
  use #(shared_secret, epk) <- result.try(compute_ecdh_shared_secret(key))
  derive_ecdh_key(shared_secret, alg_id:, apu:, apv:, length: key_len)
  |> result.map(fn(cek) { #(cek, epk) })
}

pub fn unwrap_ecdh_es_direct(
  key: gose.Key(kid),
  enc enc: gose.ContentAlg,
  alg_id alg_id: String,
  epk epk: EphemeralPublicKey,
  apu apu: Option(BitArray),
  apv apv: Option(BitArray),
) -> Result(BitArray, gose.GoseError) {
  let key_len = gose.content_alg_key_size(enc)
  use shared_secret <- result.try(compute_ecdh_shared_secret_with_epk(key, epk))
  derive_ecdh_key(shared_secret, alg_id:, apu:, apv:, length: key_len)
}

pub fn wrap_ecdh_es_kw(
  key: gose.Key(kid),
  cek cek: BitArray,
  size size: gose.AesKeySize,
  alg_id alg_id: String,
  apu apu: Option(BitArray),
  apv apv: Option(BitArray),
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  use #(shared_secret, epk) <- result.try(compute_ecdh_shared_secret(key))
  let kw_key_len = gose.aes_key_size(size)
  use kek <- result.try(derive_ecdh_key(
    shared_secret,
    alg_id:,
    apu:,
    apv:,
    length: kw_key_len,
  ))

  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  block.wrap(cipher, cek)
  |> result.replace_error(gose.CryptoError("AES Key Wrap failed"))
  |> result.map(fn(wrapped) { #(wrapped, epk) })
}

pub fn unwrap_ecdh_es_kw(
  key: gose.Key(kid),
  encrypted_key encrypted_key: BitArray,
  size size: gose.AesKeySize,
  alg_id alg_id: String,
  epk epk: EphemeralPublicKey,
  apu apu: Option(BitArray),
  apv apv: Option(BitArray),
) -> Result(BitArray, gose.GoseError) {
  use shared_secret <- result.try(compute_ecdh_shared_secret_with_epk(key, epk))
  let kw_key_len = gose.aes_key_size(size)
  use kek <- result.try(derive_ecdh_key(
    shared_secret,
    alg_id:,
    apu:,
    apv:,
    length: kw_key_len,
  ))

  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  block.unwrap(cipher, encrypted_key)
  |> result.replace_error(gose.CryptoError("AES Key Unwrap failed"))
}

pub fn compute_ecdh_shared_secret(
  key: gose.Key(kid),
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  let mat = gose.material(key)
  compute_ec_shared_secret(mat)
  |> result.lazy_or(fn() { compute_xdh_shared_secret(mat) })
  |> result.replace_error(gose.InvalidState("ECDH-ES requires an EC or XDH key"))
}

fn compute_ec_shared_secret(
  mat: gose.KeyMaterial,
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  use ec_mat <- result.try(gose.material_ec(mat))
  let #(peer_public, curve) = case ec_mat {
    gose.EcPrivate(public:, curve:, ..) -> #(public, curve)
    gose.EcPublic(key: public, curve:) -> #(public, curve)
  }
  let #(ephemeral_private, ephemeral_public) = ec.generate_key_pair(curve)
  use shared <- result.try(
    ecdh.compute_shared_secret(ephemeral_private, peer_public)
    |> result.replace_error(gose.CryptoError("ECDH key agreement failed")),
  )
  gose.ec_raw_coordinates(ephemeral_public, curve:)
  |> result.map(fn(coords) {
    let #(x, y) = coords
    #(shared, EcEphemeralKey(curve:, x:, y:))
  })
}

fn compute_xdh_shared_secret(
  mat: gose.KeyMaterial,
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  use xdh_mat <- result.try(gose.material_xdh(mat))
  let #(peer_public, curve) = case xdh_mat {
    gose.XdhPrivate(public:, curve:, ..) -> #(public, curve)
    gose.XdhPublic(key: public, curve:) -> #(public, curve)
  }
  let #(ephemeral_private, ephemeral_public) = xdh.generate_key_pair(curve)
  use shared <- result.try(
    xdh.compute_shared_secret(ephemeral_private, peer_public)
    |> result.replace_error(gose.CryptoError("XDH key agreement failed")),
  )
  let x = xdh.public_key_to_bytes(ephemeral_public)
  Ok(#(shared, XdhEphemeralKey(curve:, x:)))
}

pub fn compute_ecdh_shared_secret_with_epk(
  key: gose.Key(kid),
  epk epk: EphemeralPublicKey,
) -> Result(BitArray, gose.GoseError) {
  let mat = gose.material(key)
  case epk {
    EcEphemeralKey(curve: epk_curve, x:, y:) -> {
      let key_error =
        gose.InvalidState("key type does not match ephemeral key type")
      use ec_mat <- result.try(
        gose.material_ec(mat) |> result.replace_error(key_error),
      )
      case ec_mat {
        gose.EcPrivate(key: private, curve:, ..) -> {
          use <- bool.guard(
            when: curve != epk_curve,
            return: Error(gose.InvalidState("ephemeral key curve mismatch")),
          )
          use epk_public <- result.try(gose.ec_public_key_from_raw_coordinates(
            curve,
            x:,
            y:,
          ))
          ecdh.compute_shared_secret(private, epk_public)
          |> result.replace_error(gose.CryptoError("ECDH key agreement failed"))
        }
        gose.EcPublic(..) -> Error(key_error)
      }
    }
    XdhEphemeralKey(curve: epk_curve, x:) -> {
      let key_error =
        gose.InvalidState("key type does not match ephemeral key type")
      use xdh_mat <- result.try(
        gose.material_xdh(mat) |> result.replace_error(key_error),
      )
      case xdh_mat {
        gose.XdhPrivate(key: private, curve:, ..) -> {
          use <- bool.guard(
            when: curve != epk_curve,
            return: Error(gose.InvalidState("ephemeral key curve mismatch")),
          )
          use epk_public <- result.try(
            xdh.public_key_from_bytes(curve, x)
            |> result.replace_error(gose.ParseError(
              "invalid ephemeral public key",
            )),
          )
          xdh.compute_shared_secret(private, epk_public)
          |> result.replace_error(gose.CryptoError("XDH key agreement failed"))
        }
        gose.XdhPublic(..) -> Error(key_error)
      }
    }
  }
}

pub fn derive_ecdh_key(
  secret: BitArray,
  alg_id alg_id: String,
  apu apu: Option(BitArray),
  apv apv: Option(BitArray),
  length length: Int,
) -> Result(BitArray, gose.GoseError) {
  let alg_bits = bit_array.from_string(alg_id)
  let alg_len = bit_array.byte_size(alg_bits)
  let algorithm_id = <<alg_len:32, alg_bits:bits>>

  let apu_bits = option.unwrap(apu, <<>>)
  let apu_len = bit_array.byte_size(apu_bits)
  let party_u_info = <<apu_len:32, apu_bits:bits>>

  let apv_bits = option.unwrap(apv, <<>>)
  let apv_len = bit_array.byte_size(apv_bits)
  let party_v_info = <<apv_len:32, apv_bits:bits>>

  let supp_pub_info = <<{ length * 8 }:32>>

  let info =
    bit_array.concat([algorithm_id, party_u_info, party_v_info, supp_pub_info])

  crypto.concat_kdf(hash.Sha256, secret:, info:, length:)
  |> result.replace_error(gose.CryptoError("ECDH key derivation failed"))
}
