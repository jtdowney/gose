//// Key wrapping and unwrapping operations for all JWE key management algorithms
//// (direct, AES-KW, AES-GCM-KW, ChaCha20-KW, RSA, ECDH-ES, and PBES2).

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/option.{type Option}
import gleam/result
import gose
import gose/internal/jwe/content_encryption
import gose/internal/utils
import gose/jwa
import gose/jwk
import kryptos/aead
import kryptos/block
import kryptos/crypto
import kryptos/ec
import kryptos/ecdh
import kryptos/hash
import kryptos/rsa
import kryptos/xdh

@internal
pub type EphemeralPublicKey {
  EcEphemeralKey(curve: ec.Curve, x: BitArray, y: BitArray)
  XdhEphemeralKey(curve: xdh.Curve, x: BitArray)
}

pub fn wrap_aes_kw(
  key: jwk.Jwk,
  cek: BitArray,
  size: jwa.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  use secret <- result.try(get_octet_key(key, jwa.aes_key_size_in_bytes(size)))
  use cipher <- result.try(content_encryption.aes_cipher(size, secret))
  block.wrap(cipher, cek)
  |> result.replace_error(gose.CryptoError("AES Key Wrap failed"))
}

pub fn unwrap_aes_kw(
  key: jwk.Jwk,
  encrypted_key: BitArray,
  size: jwa.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  use secret <- result.try(get_octet_key(key, jwa.aes_key_size_in_bytes(size)))
  use cipher <- result.try(content_encryption.aes_cipher(size, secret))
  block.unwrap(cipher, encrypted_key)
  |> result.replace_error(gose.CryptoError("AES Key Unwrap failed"))
}

pub fn get_octet_key(
  key: jwk.Jwk,
  expected_size: Int,
) -> Result(BitArray, gose.GoseError) {
  use secret <- result.try(
    jwk.material_octet_secret(jwk.material(key))
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
  cek: BitArray,
  iv: BitArray,
  size: jwa.AesKeySize,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  let ctx = aead.gcm(cipher)
  aead.seal(ctx, nonce: iv, plaintext: cek)
  |> result.replace_error(gose.CryptoError("AES-GCM Key Wrap failed"))
}

pub fn unwrap_aes_gcm(
  kek: BitArray,
  encrypted_cek: BitArray,
  iv: BitArray,
  tag: BitArray,
  size: jwa.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  let ctx = aead.gcm(cipher)
  aead.open(ctx, nonce: iv, tag:, ciphertext: encrypted_cek)
  |> result.replace_error(gose.CryptoError("AES-GCM Key Unwrap failed"))
}

pub fn unwrap_aes_gcm_kw(
  key: jwk.Jwk,
  encrypted_cek: BitArray,
  size: jwa.AesKeySize,
  kw_iv: Option(BitArray),
  kw_tag: Option(BitArray),
) -> Result(BitArray, gose.GoseError) {
  use iv <- result.try(option.to_result(
    kw_iv,
    gose.ParseError("missing iv header for AES-GCM Key Wrap"),
  ))
  use tag <- result.try(option.to_result(
    kw_tag,
    gose.ParseError("missing tag header for AES-GCM Key Wrap"),
  ))

  use kek <- result.try(get_octet_key(key, jwa.aes_key_size_in_bytes(size)))
  unwrap_aes_gcm(kek, encrypted_cek, iv, tag, size)
}

pub fn wrap_chacha20(
  kek: BitArray,
  cek: BitArray,
  nonce: BitArray,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  use ctx <- result.try(
    aead.chacha20_poly1305(kek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for ChaCha20-Poly1305 Key Wrap",
    )),
  )
  aead.seal(ctx, nonce:, plaintext: cek)
  |> result.replace_error(gose.CryptoError("ChaCha20-Poly1305 Key Wrap failed"))
}

pub fn unwrap_chacha20(
  kek: BitArray,
  encrypted_cek: BitArray,
  nonce: BitArray,
  tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use ctx <- result.try(
    aead.chacha20_poly1305(kek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for ChaCha20-Poly1305 Key Unwrap",
    )),
  )
  aead.open(ctx, nonce:, tag:, ciphertext: encrypted_cek)
  |> result.replace_error(gose.CryptoError(
    "ChaCha20-Poly1305 Key Unwrap failed",
  ))
}

pub fn wrap_xchacha20(
  kek: BitArray,
  cek: BitArray,
  nonce: BitArray,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  use ctx <- result.try(
    aead.xchacha20_poly1305(kek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for XChaCha20-Poly1305 Key Wrap",
    )),
  )
  aead.seal(ctx, nonce:, plaintext: cek)
  |> result.replace_error(gose.CryptoError("XChaCha20-Poly1305 Key Wrap failed"))
}

pub fn unwrap_xchacha20(
  kek: BitArray,
  encrypted_cek: BitArray,
  nonce: BitArray,
  tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use ctx <- result.try(
    aead.xchacha20_poly1305(kek)
    |> result.replace_error(gose.CryptoError(
      "invalid key size for XChaCha20-Poly1305 Key Unwrap",
    )),
  )
  aead.open(ctx, nonce:, tag:, ciphertext: encrypted_cek)
  |> result.replace_error(gose.CryptoError(
    "XChaCha20-Poly1305 Key Unwrap failed",
  ))
}

pub fn wrap_chacha20_by_variant(
  kek: BitArray,
  cek: BitArray,
  nonce: BitArray,
  variant: jwa.ChaCha20Kw,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  case variant {
    jwa.C20PKw -> wrap_chacha20(kek, cek, nonce)
    jwa.XC20PKw -> wrap_xchacha20(kek, cek, nonce)
  }
}

pub fn unwrap_chacha20_by_variant(
  kek: BitArray,
  encrypted_cek: BitArray,
  nonce: BitArray,
  tag: BitArray,
  variant: jwa.ChaCha20Kw,
) -> Result(BitArray, gose.GoseError) {
  case variant {
    jwa.C20PKw -> unwrap_chacha20(kek, encrypted_cek, nonce, tag)
    jwa.XC20PKw -> unwrap_xchacha20(kek, encrypted_cek, nonce, tag)
  }
}

pub fn unwrap_chacha20_kw(
  key: jwk.Jwk,
  encrypted_cek: BitArray,
  variant: jwa.ChaCha20Kw,
  kw_iv: Option(BitArray),
  kw_tag: Option(BitArray),
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
  unwrap_chacha20_by_variant(kek, encrypted_cek, iv, tag, variant)
}

pub fn wrap_ecdh_es_chacha20_kw(
  key: jwk.Jwk,
  cek: BitArray,
  variant: jwa.ChaCha20Kw,
  apu: Option(BitArray),
  apv: Option(BitArray),
) -> Result(#(BitArray, EphemeralPublicKey, BitArray, BitArray), gose.GoseError) {
  use #(shared_secret, epk) <- result.try(compute_ecdh_shared_secret(key))
  let alg_id =
    jwa.jwe_alg_to_string(jwa.JweEcdhEs(jwa.EcdhEsChaCha20Kw(variant)))
  use kek <- result.try(derive_ecdh_key(shared_secret, alg_id, apu, apv, 32))

  let nonce_size = jwa.chacha20_kw_nonce_size(variant)
  let nonce = crypto.random_bytes(nonce_size)
  use #(encrypted_cek, kw_tag) <- result.try(wrap_chacha20_by_variant(
    kek,
    cek,
    nonce,
    variant,
  ))
  Ok(#(encrypted_cek, epk, nonce, kw_tag))
}

pub fn unwrap_ecdh_es_chacha20_kw(
  key: jwk.Jwk,
  encrypted_key: BitArray,
  variant: jwa.ChaCha20Kw,
  epk: EphemeralPublicKey,
  apu: Option(BitArray),
  apv: Option(BitArray),
  kw_iv: BitArray,
  kw_tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use shared_secret <- result.try(compute_ecdh_shared_secret_with_epk(key, epk))
  let alg_id =
    jwa.jwe_alg_to_string(jwa.JweEcdhEs(jwa.EcdhEsChaCha20Kw(variant)))
  use kek <- result.try(derive_ecdh_key(shared_secret, alg_id, apu, apv, 32))
  unwrap_chacha20_by_variant(kek, encrypted_key, kw_iv, kw_tag, variant)
}

pub fn wrap_rsa_oaep(
  key: jwk.Jwk,
  cek: BitArray,
  hash_alg: hash.HashAlgorithm,
) -> Result(BitArray, gose.GoseError) {
  use public <- result.try(rsa_public_key(key))
  let padding = rsa.Oaep(hash: hash_alg, label: <<>>)
  rsa.encrypt(public, cek, padding)
  |> result.replace_error(gose.CryptoError("RSA-OAEP encryption failed"))
}

pub fn unwrap_rsa_oaep(
  key: jwk.Jwk,
  encrypted_key: BitArray,
  hash_alg: hash.HashAlgorithm,
) -> Result(BitArray, gose.GoseError) {
  use private <- result.try(rsa_private_key(key))
  let padding = rsa.Oaep(hash: hash_alg, label: <<>>)
  rsa.decrypt(private, encrypted_key, padding)
  |> result.replace_error(gose.CryptoError("RSA-OAEP decryption failed"))
}

pub fn wrap_rsa_pkcs1v15(
  key: jwk.Jwk,
  cek: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use public <- result.try(rsa_public_key(key))
  rsa.encrypt(public, cek, rsa.EncryptPkcs1v15)
  |> result.replace_error(gose.CryptoError("RSA PKCS1v15 encryption failed"))
}

pub fn unwrap_rsa_pkcs1v15_safe(
  key: jwk.Jwk,
  encrypted_key: BitArray,
  enc: jwa.Enc,
) -> BitArray {
  let expected_size = jwa.enc_octet_key_size(enc)
  let random_cek = content_encryption.generate_cek(enc)

  key
  |> rsa_private_key
  |> result.replace_error(Nil)
  |> result.try(rsa.decrypt(_, encrypted_key, rsa.EncryptPkcs1v15))
  |> result.try(validate_decrypted_size(_, expected_size))
  |> result.unwrap(random_cek)
}

pub fn validate_decrypted_size(
  decrypted: BitArray,
  expected_size: Int,
) -> Result(BitArray, Nil) {
  case bit_array.byte_size(decrypted) == expected_size {
    True -> Ok(decrypted)
    False -> Error(Nil)
  }
}

pub fn rsa_public_key(key: jwk.Jwk) -> Result(rsa.PublicKey, gose.GoseError) {
  use rsa_mat <- result.try(
    jwk.material_rsa(jwk.material(key))
    |> result.replace_error(gose.InvalidState(
      "RSA encryption requires an RSA key",
    )),
  )
  case rsa_mat {
    jwk.RsaPrivate(public:, ..) -> Ok(public)
    jwk.RsaPublic(key: public) -> Ok(public)
  }
}

pub fn rsa_private_key(key: jwk.Jwk) -> Result(rsa.PrivateKey, gose.GoseError) {
  let error = gose.InvalidState("RSA decryption requires an RSA private key")
  use rsa_mat <- result.try(
    jwk.material_rsa(jwk.material(key)) |> result.replace_error(error),
  )
  case rsa_mat {
    jwk.RsaPrivate(key: private, ..) -> Ok(private)
    jwk.RsaPublic(..) -> Error(error)
  }
}

pub fn unwrap_direct(
  key: jwk.Jwk,
  enc: jwa.Enc,
) -> Result(BitArray, gose.GoseError) {
  use secret <- result.try(
    jwk.material_octet_secret(jwk.material(key))
    |> result.replace_error(gose.InvalidState(
      "direct encryption requires an octet key",
    )),
  )

  let expected_size = jwa.enc_octet_key_size(enc)
  let actual_size = bit_array.byte_size(secret)
  case actual_size == expected_size {
    True -> Ok(secret)
    False ->
      Error(gose.InvalidState(
        "direct encryption requires "
        <> int.to_string(expected_size)
        <> "-byte key for "
        <> jwa.enc_to_string(enc)
        <> ", got "
        <> int.to_string(actual_size),
      ))
  }
}

pub fn wrap_ecdh_es_direct(
  key: jwk.Jwk,
  enc: jwa.Enc,
  apu: Option(BitArray),
  apv: Option(BitArray),
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  let key_len = jwa.enc_octet_key_size(enc)
  use #(shared_secret, epk) <- result.try(compute_ecdh_shared_secret(key))
  let alg_id = jwa.enc_to_string(enc)
  derive_ecdh_key(shared_secret, alg_id, apu, apv, key_len)
  |> result.map(fn(cek) { #(cek, epk) })
}

pub fn unwrap_ecdh_es_direct(
  key: jwk.Jwk,
  enc: jwa.Enc,
  epk: EphemeralPublicKey,
  apu: Option(BitArray),
  apv: Option(BitArray),
) -> Result(BitArray, gose.GoseError) {
  let key_len = jwa.enc_octet_key_size(enc)
  use shared_secret <- result.try(compute_ecdh_shared_secret_with_epk(key, epk))
  let alg_id = jwa.enc_to_string(enc)
  derive_ecdh_key(shared_secret, alg_id, apu, apv, key_len)
}

pub fn wrap_ecdh_es_kw(
  key: jwk.Jwk,
  cek: BitArray,
  size: jwa.AesKeySize,
  apu: Option(BitArray),
  apv: Option(BitArray),
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  use #(shared_secret, epk) <- result.try(compute_ecdh_shared_secret(key))
  let alg_id = jwa.jwe_alg_to_string(jwa.JweEcdhEs(jwa.EcdhEsAesKw(size)))
  let kw_key_len = jwa.aes_key_size_in_bytes(size)
  use kek <- result.try(derive_ecdh_key(
    shared_secret,
    alg_id,
    apu,
    apv,
    kw_key_len,
  ))

  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  block.wrap(cipher, cek)
  |> result.replace_error(gose.CryptoError("AES Key Wrap failed"))
  |> result.map(fn(wrapped) { #(wrapped, epk) })
}

pub fn unwrap_ecdh_es_kw(
  key: jwk.Jwk,
  encrypted_key: BitArray,
  size: jwa.AesKeySize,
  epk: EphemeralPublicKey,
  apu: Option(BitArray),
  apv: Option(BitArray),
) -> Result(BitArray, gose.GoseError) {
  use shared_secret <- result.try(compute_ecdh_shared_secret_with_epk(key, epk))
  let alg_id = jwa.jwe_alg_to_string(jwa.JweEcdhEs(jwa.EcdhEsAesKw(size)))
  let kw_key_len = jwa.aes_key_size_in_bytes(size)
  use kek <- result.try(derive_ecdh_key(
    shared_secret,
    alg_id,
    apu,
    apv,
    kw_key_len,
  ))

  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  block.unwrap(cipher, encrypted_key)
  |> result.replace_error(gose.CryptoError("AES Key Unwrap failed"))
}

pub fn compute_ecdh_shared_secret(
  key: jwk.Jwk,
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  let mat = jwk.material(key)
  compute_ec_shared_secret(mat)
  |> result.lazy_or(fn() { compute_xdh_shared_secret(mat) })
  |> result.replace_error(gose.InvalidState("ECDH-ES requires an EC or XDH key"))
}

fn compute_ec_shared_secret(
  mat: jwk.KeyMaterial,
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  use ec_mat <- result.try(jwk.material_ec(mat))
  let #(peer_public, curve) = case ec_mat {
    jwk.EcPrivate(public:, curve:, ..) -> #(public, curve)
    jwk.EcPublic(key: public, curve:) -> #(public, curve)
  }
  let #(ephemeral_private, ephemeral_public) = ec.generate_key_pair(curve)
  use shared <- result.try(
    ecdh.compute_shared_secret(ephemeral_private, peer_public)
    |> result.replace_error(gose.CryptoError("ECDH key agreement failed")),
  )
  utils.ec_public_key_coordinates(ephemeral_public, curve)
  |> result.map(fn(coords) {
    let #(x, y) = coords
    #(shared, EcEphemeralKey(curve:, x:, y:))
  })
}

fn compute_xdh_shared_secret(
  mat: jwk.KeyMaterial,
) -> Result(#(BitArray, EphemeralPublicKey), gose.GoseError) {
  use xdh_mat <- result.try(jwk.material_xdh(mat))
  let #(peer_public, curve) = case xdh_mat {
    jwk.XdhPrivate(public:, curve:, ..) -> #(public, curve)
    jwk.XdhPublic(key: public, curve:) -> #(public, curve)
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
  key: jwk.Jwk,
  epk: EphemeralPublicKey,
) -> Result(BitArray, gose.GoseError) {
  let mat = jwk.material(key)
  case epk {
    EcEphemeralKey(curve: epk_curve, x:, y:) -> {
      let key_error =
        gose.InvalidState("key type does not match ephemeral key type")
      use ec_mat <- result.try(
        jwk.material_ec(mat) |> result.replace_error(key_error),
      )
      case ec_mat {
        jwk.EcPrivate(key: private, curve:, ..) -> {
          use <- bool.guard(
            when: curve != epk_curve,
            return: Error(gose.InvalidState("ephemeral key curve mismatch")),
          )
          use epk_public <- result.try(utils.ec_public_key_from_coordinates(
            curve,
            x,
            y,
          ))
          ecdh.compute_shared_secret(private, epk_public)
          |> result.replace_error(gose.CryptoError("ECDH key agreement failed"))
        }
        jwk.EcPublic(..) -> Error(key_error)
      }
    }
    XdhEphemeralKey(curve: epk_curve, x:) -> {
      let key_error =
        gose.InvalidState("key type does not match ephemeral key type")
      use xdh_mat <- result.try(
        jwk.material_xdh(mat) |> result.replace_error(key_error),
      )
      case xdh_mat {
        jwk.XdhPrivate(key: private, curve:, ..) -> {
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
        jwk.XdhPublic(..) -> Error(key_error)
      }
    }
  }
}

pub fn derive_ecdh_key(
  secret: BitArray,
  alg_id: String,
  apu: Option(BitArray),
  apv: Option(BitArray),
  length: Int,
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
