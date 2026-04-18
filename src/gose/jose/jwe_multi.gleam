//// JWE JSON Serialization for multi-recipient encryption and decryption
//// ([RFC 7516 Section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1)).
////
//// ## Example
////
//// ```gleam
//// import gleam/json
//// import gose
//// import gose/jose/jwe_multi
////
//// let k1 = gose.generate_aes_kw_key(gose.Aes256)
//// let k2 = gose.generate_aes_kw_key(gose.Aes128)
//// let plaintext = <<"hello":utf8>>
////
//// let message = jwe_multi.new(gose.AesGcm(gose.Aes256))
//// let assert Ok(message) =
////   jwe_multi.add_recipient(
////     message,
////     gose.AesKeyWrap(gose.AesKw, gose.Aes256),
////     key: k1,
////   )
//// let assert Ok(message) =
////   jwe_multi.add_recipient(
////     message,
////     gose.AesKeyWrap(gose.AesKw, gose.Aes128),
////     key: k2,
////   )
//// let assert Ok(encrypted) = jwe_multi.encrypt(message, plaintext:)
////
//// let json_str = jwe_multi.serialize_json(encrypted) |> json.to_string
//// let assert Ok(parsed) = jwe_multi.parse_json(json_str)
//// let assert Ok(dec) =
////   jwe_multi.decryptor(
////     gose.AesKeyWrap(gose.AesKw, gose.Aes256),
////     gose.AesGcm(gose.Aes256),
////     keys: [k1],
////   )
//// let assert Ok(plaintext) = jwe_multi.decrypt(dec, parsed)
//// ```
////
//// ## Rejected Algorithms
////
//// `Direct` and `EcdhEs(EcdhEsDirect)` are rejected because they derive
//// the CEK directly rather than wrapping it, making multi-recipient
//// impossible. `Pbes2` is also excluded (requires a password, not a key).
////
//// ## Algorithm Pinning
////
//// Each decryptor is pinned to expected key encryption and content encryption
//// algorithms. Mismatches are rejected.

import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gose
import gose/internal/content_encryption
import gose/internal/key_encryption
import gose/internal/key_helpers
import gose/internal/utils
import gose/jose
import kryptos/crypto
import kryptos/hash

type PendingRecipient {
  PendingRecipient(alg: gose.KeyEncryptionAlg, key: gose.Key(String))
}

type EncryptedRecipient {
  SimpleRecipient(alg_str: String, encrypted_key: BitArray)
  EcdhEsRecipient(
    alg_str: String,
    encrypted_key: BitArray,
    epk: key_encryption.EphemeralPublicKey,
    apu: Option(BitArray),
    apv: Option(BitArray),
  )
  KwWithIvTagRecipient(
    alg_str: String,
    encrypted_key: BitArray,
    kw_iv: BitArray,
    kw_tag: BitArray,
  )
  EcdhEsKwWithIvTagRecipient(
    alg_str: String,
    encrypted_key: BitArray,
    epk: key_encryption.EphemeralPublicKey,
    apu: Option(BitArray),
    apv: Option(BitArray),
    kw_iv: BitArray,
    kw_tag: BitArray,
  )
}

/// A multi-recipient JWE message parameterized by encryption state.
pub opaque type MultiJwe(state) {
  UnencryptedMultiJwe(enc: gose.ContentAlg, recipients: List(PendingRecipient))
  EncryptedMultiJwe(
    enc: gose.ContentAlg,
    protected_b64: String,
    recipients: List(EncryptedRecipient),
    iv: BitArray,
    ciphertext: BitArray,
    tag: BitArray,
  )
}

/// Phantom type for unencrypted JWE.
pub type Unencrypted

/// Phantom type for encrypted JWE.
pub type Encrypted

/// A decryptor pinned to expected algorithms and keys.
pub opaque type Decryptor {
  Decryptor(
    key_alg: gose.KeyEncryptionAlg,
    content_alg: gose.ContentAlg,
    keys: List(gose.Key(String)),
  )
}

/// Create a new multi-recipient JWE with the given content encryption algorithm.
pub fn new(enc: gose.ContentAlg) -> MultiJwe(Unencrypted) {
  UnencryptedMultiJwe(enc:, recipients: [])
}

/// Add a recipient with the given key encryption algorithm and key.
pub fn add_recipient(
  message: MultiJwe(Unencrypted),
  alg: gose.KeyEncryptionAlg,
  key key: gose.Key(String),
) -> Result(MultiJwe(Unencrypted), gose.GoseError) {
  let assert UnencryptedMultiJwe(enc:, recipients:) = message
  use <- reject_direct_algorithms(alg)
  use <- reject_pbes2_algorithms(alg)
  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(alg, key))
  let recipient = PendingRecipient(alg:, key:)
  Ok(UnencryptedMultiJwe(enc:, recipients: [recipient, ..recipients]))
}

/// Encrypt the plaintext for all recipients.
pub fn encrypt(
  message: MultiJwe(Unencrypted),
  plaintext plaintext: BitArray,
) -> Result(MultiJwe(Encrypted), gose.GoseError) {
  let assert UnencryptedMultiJwe(enc:, recipients:) = message
  use <- bool.guard(
    when: list.is_empty(recipients),
    return: Error(gose.InvalidState("at least one recipient required")),
  )
  let recipients = list.reverse(recipients)

  let cek = content_encryption.generate_cek(enc)
  use encrypted_recipients <- result.try(
    list.try_map(recipients, wrap_cek_for_recipient(_, cek)),
  )

  let protected_json = enc_header_json(enc)
  let protected_b64 = utils.encode_base64_url(protected_json)
  let iv = content_encryption.generate_iv(enc)
  let aead_aad = content_encryption.build_jwe_aad(protected_b64, option.None)

  use #(ciphertext, tag) <- result.try(content_encryption.encrypt_content(
    enc,
    cek:,
    iv:,
    aad: aead_aad,
    plaintext:,
  ))

  Ok(EncryptedMultiJwe(
    enc:,
    protected_b64:,
    recipients: encrypted_recipients,
    iv:,
    ciphertext:,
    tag:,
  ))
}

/// Serialize as JWE JSON General Serialization.
pub fn serialize_json(message: MultiJwe(Encrypted)) -> json.Json {
  let assert EncryptedMultiJwe(
    protected_b64:,
    recipients:,
    iv:,
    ciphertext:,
    tag:,
    ..,
  ) = message

  let recipient_objects = list.map(recipients, recipient_to_json)

  json.object([
    #("protected", json.string(protected_b64)),
    #("recipients", json.preprocessed_array(recipient_objects)),
    #("iv", json.string(utils.encode_base64_url(iv))),
    #("ciphertext", json.string(utils.encode_base64_url(ciphertext))),
    #("tag", json.string(utils.encode_base64_url(tag))),
  ])
}

/// Parse a JWE from JSON General Serialization format.
pub fn parse_json(
  json_str: String,
) -> Result(MultiJwe(Encrypted), gose.GoseError) {
  let recipient_decoder = {
    use header <- decode.field("header", decode.dynamic)
    use encrypted_key <- decode.optional_field(
      "encrypted_key",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(#(header, encrypted_key))
  }
  let decoder = {
    use protected <- decode.field("protected", decode.string)
    use recipients <- decode.field("recipients", decode.list(recipient_decoder))
    use iv <- decode.field("iv", decode.string)
    use ciphertext <- decode.field("ciphertext", decode.string)
    use tag <- decode.field("tag", decode.string)
    decode.success(#(protected, recipients, iv, ciphertext, tag))
  }

  use #(protected_b64, raw_recipients, iv_b64, ct_b64, tag_b64) <- result.try(
    json.parse(json_str, decoder)
    |> result.replace_error(gose.ParseError("invalid JWE JSON")),
  )

  use enc <- result.try(parse_enc_from_protected(protected_b64))
  use recipients <- result.try(list.try_map(raw_recipients, parse_raw_recipient))
  use iv <- result.try(utils.decode_base64_url(iv_b64, name: "iv"))
  use ciphertext <- result.try(utils.decode_base64_url(
    ct_b64,
    name: "ciphertext",
  ))
  use tag <- result.try(utils.decode_base64_url(tag_b64, name: "tag"))
  use _ <- result.try(content_encryption.validate_iv_tag_sizes(enc, iv:, tag:))

  Ok(EncryptedMultiJwe(
    enc:,
    protected_b64:,
    recipients:,
    iv:,
    ciphertext:,
    tag:,
  ))
}

/// Build a decryptor pinned to expected algorithms and keys.
pub fn decryptor(
  key_alg: gose.KeyEncryptionAlg,
  content_alg: gose.ContentAlg,
  keys keys: List(gose.Key(String)),
) -> Result(Decryptor, gose.GoseError) {
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_jwe_decryption(key_alg, _)),
  )
  Ok(Decryptor(key_alg:, content_alg:, keys:))
}

/// Decrypt a multi-recipient JWE.
pub fn decrypt(
  decryptor: Decryptor,
  message: MultiJwe(Encrypted),
) -> Result(BitArray, gose.GoseError) {
  let Decryptor(key_alg:, content_alg: expected_enc, keys:) = decryptor
  let assert EncryptedMultiJwe(
    enc: actual_enc,
    protected_b64:,
    recipients:,
    iv:,
    ciphertext:,
    tag:,
  ) = message

  use _ <- result.try(key_helpers.require_matching_content_algorithm(
    expected_enc,
    actual_enc,
  ))

  let expected_alg_str = jose.key_encryption_alg_to_string(key_alg)
  let matching =
    list.filter(recipients, fn(r) { r.alg_str == expected_alg_str })

  let aead_aad = content_encryption.build_jwe_aad(protected_b64, option.None)

  try_decrypt_recipients(
    matching,
    keys,
    key_alg,
    actual_enc,
    iv,
    aead_aad,
    ciphertext,
    tag,
    Error(gose.CryptoError("no matching recipient found")),
  )
}

fn reject_direct_algorithms(
  alg: gose.KeyEncryptionAlg,
  continue: fn() -> Result(a, gose.GoseError),
) -> Result(a, gose.GoseError) {
  let is_direct = case alg {
    gose.Direct | gose.EcdhEs(gose.EcdhEsDirect) -> True
    gose.AesKeyWrap(..)
    | gose.ChaCha20KeyWrap(_)
    | gose.RsaEncryption(_)
    | gose.EcdhEs(gose.EcdhEsAesKw(_))
    | gose.EcdhEs(gose.EcdhEsChaCha20Kw(_))
    | gose.Pbes2(_) -> False
  }
  use <- bool.guard(
    when: is_direct,
    return: Error(gose.InvalidState(
      "Direct key agreement cannot be used with multi-recipient JWE",
    )),
  )
  continue()
}

fn reject_pbes2_algorithms(
  alg: gose.KeyEncryptionAlg,
  continue: fn() -> Result(a, gose.GoseError),
) -> Result(a, gose.GoseError) {
  let is_pbes2 = case alg {
    gose.Pbes2(_) -> True
    gose.Direct
    | gose.AesKeyWrap(..)
    | gose.ChaCha20KeyWrap(_)
    | gose.RsaEncryption(_)
    | gose.EcdhEs(_) -> False
  }
  use <- bool.guard(
    when: is_pbes2,
    return: Error(gose.InvalidState(
      "PBES2 algorithms require a password; use the single-recipient JWE API",
    )),
  )
  continue()
}

fn enc_header_json(enc: gose.ContentAlg) -> BitArray {
  json.object([#("enc", json.string(jose.content_alg_to_string(enc)))])
  |> json.to_string
  |> bit_array.from_string
}

fn wrap_cek_for_recipient(
  recipient: PendingRecipient,
  cek: BitArray,
) -> Result(EncryptedRecipient, gose.GoseError) {
  let alg_str = jose.key_encryption_alg_to_string(recipient.alg)
  case recipient.alg {
    gose.EcdhEs(gose.EcdhEsAesKw(size)) ->
      wrap_ecdh_es_aes_kw(alg_str, recipient.key, cek, size)
    gose.EcdhEs(gose.EcdhEsChaCha20Kw(variant)) ->
      wrap_ecdh_es_chacha20_kw(alg_str, recipient.key, cek, variant)
    gose.AesKeyWrap(gose.AesGcmKw, size) ->
      wrap_aes_gcm_kw(alg_str, recipient.key, cek, size)
    gose.ChaCha20KeyWrap(variant) ->
      wrap_chacha20_kw(alg_str, recipient.key, cek, variant)
    _ -> {
      use encrypted_key <- result.try(wrap_cek(
        recipient.alg,
        recipient.key,
        cek,
      ))
      Ok(SimpleRecipient(alg_str:, encrypted_key:))
    }
  }
}

fn wrap_ecdh_es_aes_kw(
  alg_str: String,
  key: gose.Key(String),
  cek: BitArray,
  size: gose.AesKeySize,
) -> Result(EncryptedRecipient, gose.GoseError) {
  use #(wrapped, epk) <- result.try(key_encryption.wrap_ecdh_es_kw(
    key,
    cek:,
    size:,
    alg_id: alg_str,
    apu: option.None,
    apv: option.None,
  ))
  Ok(EcdhEsRecipient(
    alg_str:,
    encrypted_key: wrapped,
    epk:,
    apu: option.None,
    apv: option.None,
  ))
}

fn wrap_ecdh_es_chacha20_kw(
  alg_str: String,
  key: gose.Key(String),
  cek: BitArray,
  variant: gose.ChaCha20Kw,
) -> Result(EncryptedRecipient, gose.GoseError) {
  use #(encrypted_cek, epk, kw_iv, kw_tag) <- result.try(
    key_encryption.wrap_ecdh_es_chacha20_kw(
      key,
      cek:,
      variant:,
      alg_id: alg_str,
      apu: option.None,
      apv: option.None,
    ),
  )
  Ok(EcdhEsKwWithIvTagRecipient(
    alg_str:,
    encrypted_key: encrypted_cek,
    epk:,
    apu: option.None,
    apv: option.None,
    kw_iv:,
    kw_tag:,
  ))
}

fn wrap_aes_gcm_kw(
  alg_str: String,
  key: gose.Key(String),
  cek: BitArray,
  size: gose.AesKeySize,
) -> Result(EncryptedRecipient, gose.GoseError) {
  use kek <- result.try(key_encryption.get_octet_key(
    key,
    gose.aes_key_size(size),
  ))
  let kw_iv = crypto.random_bytes(12)
  use #(encrypted_cek, kw_tag) <- result.try(key_encryption.wrap_aes_gcm(
    kek,
    cek:,
    iv: kw_iv,
    size:,
  ))
  Ok(KwWithIvTagRecipient(
    alg_str:,
    encrypted_key: encrypted_cek,
    kw_iv:,
    kw_tag:,
  ))
}

fn wrap_chacha20_kw(
  alg_str: String,
  key: gose.Key(String),
  cek: BitArray,
  variant: gose.ChaCha20Kw,
) -> Result(EncryptedRecipient, gose.GoseError) {
  use kek <- result.try(key_encryption.get_octet_key(key, 32))
  let nonce_size = gose.chacha20_kw_nonce_size(variant)
  let kw_iv = crypto.random_bytes(nonce_size)
  use #(encrypted_cek, kw_tag) <- result.try(
    key_encryption.wrap_chacha20_by_variant(kek, cek:, nonce: kw_iv, variant:),
  )
  Ok(KwWithIvTagRecipient(
    alg_str:,
    encrypted_key: encrypted_cek,
    kw_iv:,
    kw_tag:,
  ))
}

fn wrap_cek(
  alg: gose.KeyEncryptionAlg,
  key: gose.Key(String),
  cek: BitArray,
) -> Result(BitArray, gose.GoseError) {
  case alg {
    gose.AesKeyWrap(gose.AesKw, size) ->
      key_encryption.wrap_aes_kw(key, cek:, size:)
    gose.RsaEncryption(rsa_alg) -> wrap_rsa(rsa_alg, key, cek)
    gose.AesKeyWrap(gose.AesGcmKw, _)
    | gose.ChaCha20KeyWrap(_)
    | gose.EcdhEs(_)
    | gose.Direct
    | gose.Pbes2(_) ->
      Error(gose.InvalidState(
        "unsupported algorithm for multi-recipient JWE: "
        <> jose.key_encryption_alg_to_string(alg),
      ))
  }
}

fn wrap_rsa(
  alg: gose.RsaEncryptionAlg,
  key: gose.Key(String),
  cek: BitArray,
) -> Result(BitArray, gose.GoseError) {
  case alg {
    gose.RsaPkcs1v15 -> key_encryption.wrap_rsa_pkcs1v15(key, cek)
    gose.RsaOaepSha1 ->
      key_encryption.wrap_rsa_oaep(key, cek:, hash_alg: hash.Sha1)
    gose.RsaOaepSha256 ->
      key_encryption.wrap_rsa_oaep(key, cek:, hash_alg: hash.Sha256)
  }
}

fn unwrap_cek(
  alg: gose.KeyEncryptionAlg,
  key: gose.Key(String),
  recipient: EncryptedRecipient,
  enc: gose.ContentAlg,
) -> Result(BitArray, gose.GoseError) {
  case alg {
    gose.AesKeyWrap(gose.AesKw, size) ->
      key_encryption.unwrap_aes_kw(
        key,
        encrypted_key: recipient.encrypted_key,
        size:,
      )
    gose.AesKeyWrap(gose.AesGcmKw, size) ->
      unwrap_aes_gcm_kw(key, recipient, size)
    gose.ChaCha20KeyWrap(variant) -> unwrap_chacha20_kw(key, recipient, variant)
    gose.RsaEncryption(gose.RsaPkcs1v15) ->
      key_encryption.unwrap_rsa_pkcs1v15_safe(
        key,
        encrypted_key: recipient.encrypted_key,
        enc:,
      )
    gose.RsaEncryption(gose.RsaOaepSha1) ->
      key_encryption.unwrap_rsa_oaep(
        key,
        encrypted_key: recipient.encrypted_key,
        hash_alg: hash.Sha1,
      )
    gose.RsaEncryption(gose.RsaOaepSha256) ->
      key_encryption.unwrap_rsa_oaep(
        key,
        encrypted_key: recipient.encrypted_key,
        hash_alg: hash.Sha256,
      )
    gose.EcdhEs(gose.EcdhEsAesKw(size)) ->
      unwrap_ecdh_es_aes_kw(key, recipient, size)
    gose.EcdhEs(gose.EcdhEsChaCha20Kw(variant)) ->
      unwrap_ecdh_es_chacha20_kw(key, recipient, variant)
    gose.Direct | gose.EcdhEs(gose.EcdhEsDirect) | gose.Pbes2(_) ->
      Error(gose.InvalidState(
        "unsupported algorithm for multi-recipient JWE decryption: "
        <> jose.key_encryption_alg_to_string(alg),
      ))
  }
}

fn unwrap_aes_gcm_kw(
  key: gose.Key(String),
  recipient: EncryptedRecipient,
  size: gose.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  let assert KwWithIvTagRecipient(encrypted_key:, kw_iv:, kw_tag:, ..) =
    recipient
  use kek <- result.try(key_encryption.get_octet_key(
    key,
    gose.aes_key_size(size),
  ))
  key_encryption.unwrap_aes_gcm(
    kek,
    encrypted_cek: encrypted_key,
    iv: kw_iv,
    tag: kw_tag,
    size:,
  )
}

fn unwrap_chacha20_kw(
  key: gose.Key(String),
  recipient: EncryptedRecipient,
  variant: gose.ChaCha20Kw,
) -> Result(BitArray, gose.GoseError) {
  let assert KwWithIvTagRecipient(encrypted_key:, kw_iv:, kw_tag:, ..) =
    recipient
  use kek <- result.try(key_encryption.get_octet_key(key, 32))
  key_encryption.unwrap_chacha20_by_variant(
    kek,
    encrypted_cek: encrypted_key,
    nonce: kw_iv,
    tag: kw_tag,
    variant:,
  )
}

fn unwrap_ecdh_es_aes_kw(
  key: gose.Key(String),
  recipient: EncryptedRecipient,
  size: gose.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  let assert EcdhEsRecipient(encrypted_key:, epk:, apu:, apv:, ..) = recipient
  let alg_id =
    jose.key_encryption_alg_to_string(gose.EcdhEs(gose.EcdhEsAesKw(size)))
  key_encryption.unwrap_ecdh_es_kw(
    key,
    encrypted_key:,
    size:,
    alg_id:,
    epk:,
    apu:,
    apv:,
  )
}

fn unwrap_ecdh_es_chacha20_kw(
  key: gose.Key(String),
  recipient: EncryptedRecipient,
  variant: gose.ChaCha20Kw,
) -> Result(BitArray, gose.GoseError) {
  let assert EcdhEsKwWithIvTagRecipient(
    encrypted_key:,
    epk:,
    apu:,
    apv:,
    kw_iv:,
    kw_tag:,
    ..,
  ) = recipient
  let alg_id =
    jose.key_encryption_alg_to_string(
      gose.EcdhEs(gose.EcdhEsChaCha20Kw(variant)),
    )
  key_encryption.unwrap_ecdh_es_chacha20_kw(
    key,
    encrypted_key:,
    variant:,
    alg_id:,
    epk:,
    apu:,
    apv:,
    kw_iv:,
    kw_tag:,
  )
}

fn recipient_to_json(recipient: EncryptedRecipient) -> json.Json {
  let #(alg_str, encrypted_key, header_fields) = case recipient {
    SimpleRecipient(alg_str:, encrypted_key:) -> #(alg_str, encrypted_key, [])
    EcdhEsRecipient(alg_str:, encrypted_key:, epk:, apu:, apv:) -> #(
      alg_str,
      encrypted_key,
      build_epk_fields(epk, apu, apv),
    )
    KwWithIvTagRecipient(alg_str:, encrypted_key:, kw_iv:, kw_tag:) -> #(
      alg_str,
      encrypted_key,
      build_kw_fields(kw_iv, kw_tag),
    )
    EcdhEsKwWithIvTagRecipient(
      alg_str:,
      encrypted_key:,
      epk:,
      apu:,
      apv:,
      kw_iv:,
      kw_tag:,
    ) -> #(
      alg_str,
      encrypted_key,
      list.append(
        build_epk_fields(epk, apu, apv),
        build_kw_fields(kw_iv, kw_tag),
      ),
    )
  }

  let all_header_fields = [#("alg", json.string(alg_str)), ..header_fields]
  let fields = [#("header", json.object(all_header_fields))]
  let fields = case bit_array.byte_size(encrypted_key) {
    0 -> fields
    _ -> [
      #("encrypted_key", json.string(utils.encode_base64_url(encrypted_key))),
      ..fields
    ]
  }
  json.object(fields)
}

fn build_epk_fields(
  epk: key_encryption.EphemeralPublicKey,
  apu: Option(BitArray),
  apv: Option(BitArray),
) -> List(#(String, json.Json)) {
  let fields = case epk {
    key_encryption.EcEphemeralKey(curve:, x:, y:) -> [
      #(
        "epk",
        json.object([
          #("kty", json.string("EC")),
          #("crv", json.string(utils.ec_curve_to_string(curve))),
          #("x", json.string(utils.encode_base64_url(x))),
          #("y", json.string(utils.encode_base64_url(y))),
        ]),
      ),
    ]
    key_encryption.XdhEphemeralKey(curve:, x:) -> [
      #(
        "epk",
        json.object([
          #("kty", json.string("OKP")),
          #("crv", json.string(utils.xdh_curve_to_string(curve))),
          #("x", json.string(utils.encode_base64_url(x))),
        ]),
      ),
    ]
  }
  let fields = case apu {
    option.Some(a) -> [
      #("apu", json.string(utils.encode_base64_url(a))),
      ..fields
    ]
    option.None -> fields
  }
  case apv {
    option.Some(a) -> [
      #("apv", json.string(utils.encode_base64_url(a))),
      ..fields
    ]
    option.None -> fields
  }
}

fn build_kw_fields(
  kw_iv: BitArray,
  kw_tag: BitArray,
) -> List(#(String, json.Json)) {
  [
    #("iv", json.string(utils.encode_base64_url(kw_iv))),
    #("tag", json.string(utils.encode_base64_url(kw_tag))),
  ]
}

fn parse_enc_from_protected(
  protected_b64: String,
) -> Result(gose.ContentAlg, gose.GoseError) {
  use protected_bytes <- result.try(utils.decode_base64_url(
    protected_b64,
    name: "protected header",
  ))
  let decoder = {
    use enc_str <- decode.field("enc", decode.string)
    decode.success(enc_str)
  }
  use enc_str <- result.try(
    json.parse_bits(protected_bytes, decoder)
    |> result.replace_error(gose.ParseError("missing enc in protected header")),
  )
  jose.content_alg_from_string(enc_str)
}

fn parse_raw_recipient(
  raw: #(decode.Dynamic, Option(String)),
) -> Result(EncryptedRecipient, gose.GoseError) {
  let #(header_raw, ek_opt) = raw
  let header_decoder = {
    use alg <- decode.field("alg", decode.string)
    use epk <- decode.optional_field(
      "epk",
      option.None,
      decode.optional(epk_decoder()),
    )
    use apu <- decode.optional_field(
      "apu",
      option.None,
      decode.optional(decode.string),
    )
    use apv <- decode.optional_field(
      "apv",
      option.None,
      decode.optional(decode.string),
    )
    use iv <- decode.optional_field(
      "iv",
      option.None,
      decode.optional(decode.string),
    )
    use tag <- decode.optional_field(
      "tag",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(#(alg, epk, apu, apv, iv, tag))
  }
  use #(alg_str, epk_raw, apu_b64, apv_b64, iv_b64, tag_b64) <- result.try(
    decode.run(header_raw, header_decoder)
    |> result.replace_error(gose.ParseError("missing alg in recipient header")),
  )
  use encrypted_key <- result.try(decode_optional_encrypted_key(ek_opt))
  use epk <- result.try(parse_optional_epk(epk_raw))
  use apu <- result.try(decode_optional_b64(apu_b64, "apu"))
  use apv <- result.try(decode_optional_b64(apv_b64, "apv"))
  use kw_iv <- result.try(decode_optional_b64(iv_b64, "iv"))
  use kw_tag <- result.try(decode_optional_b64(tag_b64, "tag"))
  build_encrypted_recipient(
    alg_str,
    encrypted_key,
    epk,
    apu,
    apv,
    kw_iv,
    kw_tag,
  )
}

fn build_encrypted_recipient(
  alg_str: String,
  encrypted_key: BitArray,
  epk: Option(key_encryption.EphemeralPublicKey),
  apu: Option(BitArray),
  apv: Option(BitArray),
  kw_iv: Option(BitArray),
  kw_tag: Option(BitArray),
) -> Result(EncryptedRecipient, gose.GoseError) {
  case epk, kw_iv, kw_tag {
    option.Some(epk), option.Some(kw_iv), option.Some(kw_tag) ->
      Ok(EcdhEsKwWithIvTagRecipient(
        alg_str:,
        encrypted_key:,
        epk:,
        apu:,
        apv:,
        kw_iv:,
        kw_tag:,
      ))
    option.Some(epk), option.None, option.None ->
      Ok(EcdhEsRecipient(alg_str:, encrypted_key:, epk:, apu:, apv:))
    option.None, option.Some(kw_iv), option.Some(kw_tag) ->
      Ok(KwWithIvTagRecipient(alg_str:, encrypted_key:, kw_iv:, kw_tag:))
    option.None, option.None, option.None ->
      Ok(SimpleRecipient(alg_str:, encrypted_key:))
    _, _, _ ->
      Error(gose.ParseError(
        "invalid recipient header field combination for " <> alg_str,
      ))
  }
}

fn epk_decoder() -> decode.Decoder(#(String, String, String, Option(String))) {
  use kty <- decode.field("kty", decode.string)
  use crv <- decode.field("crv", decode.string)
  use x <- decode.field("x", decode.string)
  use y <- decode.optional_field(
    "y",
    option.None,
    decode.optional(decode.string),
  )
  decode.success(#(kty, crv, x, y))
}

fn parse_optional_epk(
  raw: Option(#(String, String, String, Option(String))),
) -> Result(Option(key_encryption.EphemeralPublicKey), gose.GoseError) {
  case raw {
    option.None -> Ok(option.None)
    option.Some(#(kty, crv, x_b64, y_opt)) -> {
      use x <- result.try(
        bit_array.base64_url_decode(x_b64)
        |> result.replace_error(gose.ParseError("invalid epk x base64")),
      )
      case kty {
        "EC" -> {
          use y_b64 <- result.try(option.to_result(
            y_opt,
            gose.ParseError("EC epk requires y coordinate"),
          ))
          use y <- result.try(
            bit_array.base64_url_decode(y_b64)
            |> result.replace_error(gose.ParseError("invalid epk y base64")),
          )
          use curve <- result.try(utils.ec_curve_from_string(crv))
          Ok(option.Some(key_encryption.EcEphemeralKey(curve:, x:, y:)))
        }
        "OKP" -> {
          use curve <- result.try(utils.xdh_curve_from_string(crv))
          Ok(option.Some(key_encryption.XdhEphemeralKey(curve:, x:)))
        }
        _ -> Error(gose.ParseError("unsupported epk kty: " <> kty))
      }
    }
  }
}

fn decode_optional_b64(
  raw: Option(String),
  label: String,
) -> Result(Option(BitArray), gose.GoseError) {
  case raw {
    option.None -> Ok(option.None)
    option.Some(b64) ->
      utils.decode_base64_url(b64, name: label)
      |> result.map(option.Some)
  }
}

fn decode_optional_encrypted_key(
  raw: Option(String),
) -> Result(BitArray, gose.GoseError) {
  case raw {
    option.Some(b64) -> utils.decode_base64_url(b64, name: "encrypted_key")
    option.None -> Ok(<<>>)
  }
}

fn try_decrypt_recipients(
  recipients: List(EncryptedRecipient),
  keys: List(gose.Key(String)),
  key_alg: gose.KeyEncryptionAlg,
  enc: gose.ContentAlg,
  iv: BitArray,
  aead_aad: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
  last_error: Result(BitArray, gose.GoseError),
) -> Result(BitArray, gose.GoseError) {
  case recipients {
    [] -> last_error
    [recipient, ..rest] -> {
      let result =
        try_keys_for_recipient(
          recipient,
          keys,
          key_alg,
          enc,
          iv,
          aead_aad,
          ciphertext,
          tag,
        )
      case result {
        Ok(plaintext) -> Ok(plaintext)
        Error(e) ->
          try_decrypt_recipients(
            rest,
            keys,
            key_alg,
            enc,
            iv,
            aead_aad,
            ciphertext,
            tag,
            Error(e),
          )
      }
    }
  }
}

fn try_keys_for_recipient(
  recipient: EncryptedRecipient,
  keys: List(gose.Key(String)),
  key_alg: gose.KeyEncryptionAlg,
  enc: gose.ContentAlg,
  iv: BitArray,
  aead_aad: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  try_keys(
    keys,
    recipient,
    key_alg,
    enc,
    iv,
    aead_aad,
    ciphertext,
    tag,
    Error(gose.CryptoError("no key could decrypt")),
  )
}

fn try_keys(
  keys: List(gose.Key(String)),
  recipient: EncryptedRecipient,
  key_alg: gose.KeyEncryptionAlg,
  enc: gose.ContentAlg,
  iv: BitArray,
  aead_aad: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
  last_error: Result(BitArray, gose.GoseError),
) -> Result(BitArray, gose.GoseError) {
  case keys {
    [] -> last_error
    [key, ..rest] -> {
      let result =
        unwrap_and_decrypt(
          recipient,
          key,
          key_alg,
          enc,
          iv,
          aead_aad,
          ciphertext,
          tag,
        )
      case result {
        Ok(plaintext) -> Ok(plaintext)
        Error(gose.CryptoError(_) as e) ->
          try_keys(
            rest,
            recipient,
            key_alg,
            enc,
            iv,
            aead_aad,
            ciphertext,
            tag,
            Error(e),
          )
        Error(gose.VerificationFailed as e) ->
          try_keys(
            rest,
            recipient,
            key_alg,
            enc,
            iv,
            aead_aad,
            ciphertext,
            tag,
            Error(e),
          )
        Error(e) -> Error(e)
      }
    }
  }
}

fn unwrap_and_decrypt(
  recipient: EncryptedRecipient,
  key: gose.Key(String),
  key_alg: gose.KeyEncryptionAlg,
  enc: gose.ContentAlg,
  iv: BitArray,
  aead_aad: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use cek <- result.try(unwrap_cek(key_alg, key, recipient, enc))
  content_encryption.decrypt_content(
    enc,
    cek:,
    iv:,
    aad: aead_aad,
    ciphertext:,
    tag:,
  )
}
