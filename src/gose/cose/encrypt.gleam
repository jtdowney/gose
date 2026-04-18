//// COSE_Encrypt multi-recipient encryption and decryption
//// ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)).
////
//// ## Example
////
//// ```gleam
//// import gose
//// import gose/cose/encrypt
////
//// let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
//// let plaintext = <<"hello COSE":utf8>>
////
//// let assert Ok(message) = encrypt.new(gose.AesGcm(gose.Aes128))
//// let assert Ok(r) = encrypt.new_aes_kw_recipient(gose.Aes128, key: k)
//// let message = encrypt.add_recipient(message, r)
//// let assert Ok(encrypted) = encrypt.encrypt(message, plaintext)
////
//// let data = encrypt.serialize(encrypted)
//// let assert Ok(parsed) = encrypt.parse(data)
//// let assert Ok(decryptor) =
////   encrypt.decryptor(
////     gose.AesKeyWrap(gose.AesKw, gose.Aes128),
////     gose.AesGcm(gose.Aes128),
////     keys: [k],
////   )
//// let assert Ok(decrypted) = encrypt.decrypt(decryptor, parsed)
//// ```

import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/option
import gleam/result
import gose
import gose/cbor
import gose/cose
import gose/internal/content_encryption
import gose/internal/cose_structure
import gose/internal/key_encryption
import gose/internal/key_helpers
import kryptos/block
import kryptos/crypto
import kryptos/hash

/// Phantom type for a COSE_Encrypt message that has not yet been encrypted.
pub type Unencrypted

/// Phantom type for a COSE_Encrypt message that has been encrypted or parsed.
pub type Encrypted

/// ECDH-ES direct key agreement variant, distinguishing the HKDF hash
/// used in COSE key derivation.
///
/// JOSE always uses Concat KDF with SHA-256 for ECDH-ES, so this
/// distinction only exists in COSE.
pub type EcdhEsDirectVariant {
  /// ECDH-ES + HKDF-256 (COSE algorithm -25)
  EcdhEsHkdf256
  /// ECDH-ES + HKDF-512 (COSE algorithm -26)
  EcdhEsHkdf512
}

/// A pending recipient to be added to a COSE_Encrypt message.
type PendingRecipient {
  PendingRecipient(
    alg: gose.KeyEncryptionAlg,
    key: gose.Key(BitArray),
    ecdh_es_variant: option.Option(EcdhEsDirectVariant),
    apu: option.Option(BitArray),
    apv: option.Option(BitArray),
  )
}

/// Recipient family phantom: direct shared secret.
pub type Direct

/// Recipient family phantom: AES Key Wrap.
pub type AesKw

/// Recipient family phantom: RSA-OAEP.
pub type Rsa

/// Recipient family phantom: ECDH-ES (direct or with AES-KW).
pub type EcdhEs

/// A per-recipient builder parameterized by the recipient algorithm family.
pub opaque type Recipient(family) {
  Recipient(pending: PendingRecipient)
}

/// An encrypted per-recipient structure.
type EncryptedRecipient {
  EncryptedRecipient(
    protected: List(cose.Header),
    protected_serialized: BitArray,
    unprotected: List(cose.Header),
    ciphertext: BitArray,
  )
}

/// A COSE_Encrypt message parameterized by encryption state.
pub opaque type Encrypt(state) {
  UnencryptedEncrypt(
    content_alg: gose.ContentAlg,
    protected: List(cose.Header),
    unprotected: List(cose.Header),
    recipients: List(PendingRecipient),
    aad: BitArray,
  )
  EncryptedEncrypt(
    protected: List(cose.Header),
    protected_serialized: BitArray,
    unprotected: List(cose.Header),
    ciphertext: BitArray,
    recipients: List(EncryptedRecipient),
  )
}

/// A decryptor pinned to expected key encryption and content encryption algorithms.
pub opaque type Decryptor {
  Decryptor(
    key_alg: gose.KeyEncryptionAlg,
    content_alg: gose.ContentAlg,
    keys: List(gose.Key(BitArray)),
    ecdh_es_variant: option.Option(EcdhEsDirectVariant),
  )
}

/// Create a new COSE_Encrypt message with the given content encryption algorithm.
pub fn new(enc: gose.ContentAlg) -> Result(Encrypt(Unencrypted), gose.GoseError) {
  use alg_id <- result.try(cose.content_alg_to_int(enc))
  Ok(
    UnencryptedEncrypt(
      content_alg: enc,
      protected: [cose.Alg(alg_id)],
      unprotected: [],
      recipients: [],
      aad: <<>>,
    ),
  )
}

/// Build a direct-shared-secret recipient.
pub fn new_direct_recipient(
  key key: gose.Key(BitArray),
) -> Result(Recipient(Direct), gose.GoseError) {
  let alg = gose.Direct
  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(alg, key))
  Ok(new_pending(alg:, key:, ecdh_es_variant: option.None))
}

/// Build an AES Key Wrap recipient.
pub fn new_aes_kw_recipient(
  size: gose.AesKeySize,
  key key: gose.Key(BitArray),
) -> Result(Recipient(AesKw), gose.GoseError) {
  let alg = gose.AesKeyWrap(gose.AesKw, size)
  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(alg, key))
  Ok(new_pending(alg:, key:, ecdh_es_variant: option.None))
}

/// Build an RSA-OAEP recipient.
pub fn new_rsa_recipient(
  rsa_alg: gose.RsaEncryptionAlg,
  key key: gose.Key(BitArray),
) -> Result(Recipient(Rsa), gose.GoseError) {
  let alg = gose.RsaEncryption(rsa_alg)
  use _ <- result.try(cose.key_encryption_alg_to_int(alg))
  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(alg, key))
  Ok(new_pending(alg:, key:, ecdh_es_variant: option.None))
}

/// Build an ECDH-ES direct recipient with a specific HKDF variant.
pub fn new_ecdh_es_direct_recipient(
  variant: EcdhEsDirectVariant,
  key key: gose.Key(BitArray),
) -> Result(Recipient(EcdhEs), gose.GoseError) {
  let alg = gose.EcdhEs(gose.EcdhEsDirect)
  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(alg, key))
  Ok(new_pending(alg:, key:, ecdh_es_variant: option.Some(variant)))
}

/// Build an ECDH-ES + AES-KW recipient.
pub fn new_ecdh_es_aes_kw_recipient(
  size: gose.AesKeySize,
  key key: gose.Key(BitArray),
) -> Result(Recipient(EcdhEs), gose.GoseError) {
  let alg = gose.EcdhEs(gose.EcdhEsAesKw(size))
  use _ <- result.try(key_helpers.validate_key_for_jwe_encryption(alg, key))
  Ok(new_pending(alg:, key:, ecdh_es_variant: option.None))
}

fn new_pending(
  alg alg: gose.KeyEncryptionAlg,
  key key: gose.Key(BitArray),
  ecdh_es_variant ecdh_es_variant: option.Option(EcdhEsDirectVariant),
) -> Recipient(family) {
  Recipient(pending: PendingRecipient(
    alg:,
    key:,
    ecdh_es_variant:,
    apu: option.None,
    apv: option.None,
  ))
}

/// Set the PartyU identity (apu) for an ECDH-ES recipient.
pub fn with_apu(r: Recipient(EcdhEs), apu: BitArray) -> Recipient(EcdhEs) {
  Recipient(pending: PendingRecipient(..r.pending, apu: option.Some(apu)))
}

/// Set the PartyV identity (apv) for an ECDH-ES recipient.
pub fn with_apv(r: Recipient(EcdhEs), apv: BitArray) -> Recipient(EcdhEs) {
  Recipient(pending: PendingRecipient(..r.pending, apv: option.Some(apv)))
}

/// Add a built recipient to the message.
pub fn add_recipient(
  message: Encrypt(Unencrypted),
  recipient: Recipient(family),
) -> Encrypt(Unencrypted) {
  let assert UnencryptedEncrypt(recipients:, ..) = message
  UnencryptedEncrypt(
    ..message,
    recipients: list.append(recipients, [recipient.pending]),
  )
}

/// Set external additional authenticated data (AAD) for the encryption operation.
pub fn with_aad(
  message: Encrypt(Unencrypted),
  aad aad: BitArray,
) -> Encrypt(Unencrypted) {
  let assert UnencryptedEncrypt(..) = message
  UnencryptedEncrypt(..message, aad:)
}

/// Add a key ID to the unprotected headers.
pub fn with_kid(
  message: Encrypt(Unencrypted),
  kid: BitArray,
) -> Encrypt(Unencrypted) {
  let assert UnencryptedEncrypt(unprotected:, ..) = message
  UnencryptedEncrypt(..message, unprotected: [cose.Kid(kid), ..unprotected])
}

/// Add a content type to the protected headers.
///
/// RFC 9052 permits either bucket. Encrypted messages place it in protected
/// so it is covered by the AEAD authentication.
pub fn with_content_type(
  message: Encrypt(Unencrypted),
  ct ct: cose.ContentType,
) -> Encrypt(Unencrypted) {
  let assert UnencryptedEncrypt(protected:, ..) = message
  UnencryptedEncrypt(..message, protected: [cose.ContentType(ct), ..protected])
}

/// Add critical header labels to the protected headers.
pub fn with_critical(
  message: Encrypt(Unencrypted),
  labels: List(Int),
) -> Encrypt(Unencrypted) {
  let assert UnencryptedEncrypt(protected:, ..) = message
  UnencryptedEncrypt(..message, protected: [cose.Crit(labels), ..protected])
}

/// Encrypt the plaintext for all added recipients.
///
/// Reads `aad` from the builder state set via `with_aad`.
pub fn encrypt(
  message: Encrypt(Unencrypted),
  plaintext plaintext: BitArray,
) -> Result(Encrypt(Encrypted), gose.GoseError) {
  let assert UnencryptedEncrypt(
    content_alg:,
    protected:,
    unprotected:,
    recipients:,
    aad:,
  ) = message
  use <- require_non_empty_recipients(recipients)
  use <- validate_single_recipient_constraint(recipients)

  let protected_serialized = cose_structure.serialize_protected(protected)

  use #(cek, encrypted_recipients) <- result.try(
    generate_cek_and_wrap_recipients(content_alg, recipients),
  )

  let iv = content_encryption.generate_iv(content_alg)
  let enc_structure =
    cose_structure.build_enc_structure(
      context: "Encrypt",
      protected_serialized:,
      aad:,
    )

  use #(ciphertext, tag) <- result.try(content_encryption.encrypt_content(
    content_alg,
    cek:,
    iv:,
    aad: enc_structure,
    plaintext:,
  ))

  let ciphertext_with_tag = bit_array.concat([ciphertext, tag])
  let unprotected = [cose.Iv(iv), ..unprotected]

  Ok(EncryptedEncrypt(
    protected:,
    protected_serialized:,
    unprotected:,
    ciphertext: ciphertext_with_tag,
    recipients: encrypted_recipients,
  ))
}

/// Build a decryptor pinned to expected algorithms and keys.
///
/// For `EcdhEs(EcdhEsDirect)`, use `ecdh_es_direct_decryptor` instead so the
/// HKDF variant (HKDF-256 or HKDF-512) is chosen explicitly.
pub fn decryptor(
  key_alg: gose.KeyEncryptionAlg,
  content_alg: gose.ContentAlg,
  keys keys: List(gose.Key(BitArray)),
) -> Result(Decryptor, gose.GoseError) {
  use <- bool.guard(
    when: key_alg == gose.EcdhEs(gose.EcdhEsDirect),
    return: Error(gose.InvalidState(
      "use ecdh_es_direct_decryptor to choose HKDF variant",
    )),
  )
  use _ <- result.try(cose.key_encryption_alg_to_int(key_alg))
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_jwe_decryption(key_alg, _)),
  )
  Ok(Decryptor(key_alg:, content_alg:, keys:, ecdh_es_variant: option.None))
}

/// Build a decryptor for ECDH-ES direct with a specific HKDF variant.
///
/// Use this instead of `decryptor` when you need to decrypt messages
/// encrypted with ECDH-ES+HKDF-512 (COSE algorithm -26).
pub fn ecdh_es_direct_decryptor(
  variant: EcdhEsDirectVariant,
  content_alg: gose.ContentAlg,
  keys keys: List(gose.Key(BitArray)),
) -> Result(Decryptor, gose.GoseError) {
  let key_alg = gose.EcdhEs(gose.EcdhEsDirect)
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_jwe_decryption(key_alg, _)),
  )
  Ok(Decryptor(
    key_alg:,
    content_alg:,
    keys:,
    ecdh_es_variant: option.Some(variant),
  ))
}

/// Decrypt a COSE_Encrypt message.
pub fn decrypt(
  decryptor: Decryptor,
  message: Encrypt(Encrypted),
) -> Result(BitArray, gose.GoseError) {
  decrypt_with_aad(decryptor, message:, aad: <<>>)
}

/// Decrypt with externally-supplied AAD.
pub fn decrypt_with_aad(
  decryptor: Decryptor,
  message message: Encrypt(Encrypted),
  aad aad: BitArray,
) -> Result(BitArray, gose.GoseError) {
  let Decryptor(
    key_alg: expected_key_alg,
    content_alg: expected_content_alg,
    keys:,
    ecdh_es_variant:,
  ) = decryptor
  let assert EncryptedEncrypt(
    protected:,
    protected_serialized:,
    unprotected:,
    ciphertext: ciphertext_with_tag,
    recipients:,
  ) = message

  use actual_content_alg <- result.try(
    cose_structure.extract_content_alg_from_serialized(protected_serialized),
  )
  use _ <- result.try(key_helpers.require_matching_content_algorithm(
    expected_content_alg,
    actual_content_alg,
  ))
  use _ <- result.try(cose_structure.validate_crit(protected, unprotected))

  let matching_recipients =
    list.filter(recipients, fn(r) { recipient_alg(r) == Ok(expected_key_alg) })

  use iv <- result.try(cose.iv(unprotected))
  use #(ciphertext, tag) <- result.try(cose_structure.split_ciphertext_tag(
    ciphertext_with_tag,
    tag_size: content_encryption.tag_size(actual_content_alg),
  ))

  let enc_structure =
    cose_structure.build_enc_structure(
      context: "Encrypt",
      protected_serialized:,
      aad:,
    )

  try_decrypt_recipients(
    matching_recipients,
    keys,
    expected_key_alg,
    actual_content_alg,
    ecdh_es_variant,
    iv,
    enc_structure,
    ciphertext,
    tag,
    Error(gose.CryptoError("no matching recipient found")),
  )
}

/// Encode an encrypted message as an untagged CBOR COSE_Encrypt array.
pub fn serialize(message: Encrypt(Encrypted)) -> BitArray {
  cbor.encode(to_cbor_value(message))
}

/// Encode an encrypted message as a CBOR-tagged (tag 96) COSE_Encrypt structure.
pub fn serialize_tagged(message: Encrypt(Encrypted)) -> BitArray {
  cbor.encode(cbor.Tag(96, to_cbor_value(message)))
}

fn to_cbor_value(message: Encrypt(Encrypted)) -> cbor.Value {
  let assert EncryptedEncrypt(
    protected_serialized:,
    unprotected:,
    ciphertext:,
    recipients:,
    ..,
  ) = message

  cbor.Array([
    cbor.Bytes(protected_serialized),
    cbor.Map(cose.headers_to_cbor(unprotected)),
    cbor.Bytes(ciphertext),
    cbor.Array(list.map(recipients, serialize_recipient)),
  ])
}

/// Decode a CBOR-encoded COSE_Encrypt message, accepting both tagged and untagged forms.
pub fn parse(data: BitArray) -> Result(Encrypt(Encrypted), gose.GoseError) {
  use value <- result.try(cbor.decode(data))
  parse_cbor_value(value)
}

/// Extract the key ID from the message headers.
pub fn kid(message: Encrypt(Encrypted)) -> Result(BitArray, gose.GoseError) {
  let assert EncryptedEncrypt(protected:, unprotected:, ..) = message
  cose.kid(list.append(protected, unprotected))
}

/// Extract the content type from the message headers.
pub fn content_type(
  message: Encrypt(Encrypted),
) -> Result(cose.ContentType, gose.GoseError) {
  let assert EncryptedEncrypt(protected:, unprotected:, ..) = message
  cose.content_type(list.append(protected, unprotected))
}

/// Extract the critical header labels from the message headers.
pub fn critical(
  message: Encrypt(Encrypted),
) -> Result(List(Int), gose.GoseError) {
  let assert EncryptedEncrypt(protected:, unprotected:, ..) = message
  cose.critical(list.append(protected, unprotected))
}

/// Return the raw protected headers.
pub fn protected_headers(message: Encrypt(Encrypted)) -> List(cose.Header) {
  let assert EncryptedEncrypt(protected:, ..) = message
  protected
}

/// Return the raw unprotected headers.
pub fn unprotected_headers(message: Encrypt(Encrypted)) -> List(cose.Header) {
  let assert EncryptedEncrypt(unprotected:, ..) = message
  unprotected
}

fn require_non_empty_recipients(
  recipients: List(PendingRecipient),
  continue: fn() -> Result(a, gose.GoseError),
) -> Result(a, gose.GoseError) {
  use <- bool.guard(
    when: list.is_empty(recipients),
    return: Error(gose.InvalidState("at least one recipient required")),
  )
  continue()
}

fn validate_single_recipient_constraint(
  recipients: List(PendingRecipient),
  continue: fn() -> Result(a, gose.GoseError),
) -> Result(a, gose.GoseError) {
  let has_direct =
    list.any(recipients, fn(r) {
      case r.alg {
        gose.Direct | gose.EcdhEs(gose.EcdhEsDirect) -> True
        gose.AesKeyWrap(..)
        | gose.ChaCha20KeyWrap(_)
        | gose.RsaEncryption(_)
        | gose.EcdhEs(gose.EcdhEsAesKw(_))
        | gose.EcdhEs(gose.EcdhEsChaCha20Kw(_))
        | gose.Pbes2(_) -> False
      }
    })
  use <- bool.guard(
    when: has_direct && list.length(recipients) > 1,
    return: Error(gose.InvalidState(
      "Direct and ECDH-ES Direct key agreement require exactly one recipient",
    )),
  )
  continue()
}

fn generate_cek_and_wrap_recipients(
  content_alg: gose.ContentAlg,
  recipients: List(PendingRecipient),
) -> Result(#(BitArray, List(EncryptedRecipient)), gose.GoseError) {
  case recipients {
    [PendingRecipient(alg: gose.Direct, key:, ..)] -> {
      use cek <- result.try(key_encryption.unwrap_direct(key, content_alg))
      use recipient <- result.try(encrypt_direct_recipient())
      Ok(#(cek, [recipient]))
    }
    [
      PendingRecipient(
        alg: gose.EcdhEs(gose.EcdhEsDirect),
        key:,
        ecdh_es_variant: option.Some(variant),
        apu:,
        apv:,
      ),
    ] -> encrypt_ecdh_es_direct(key, content_alg, variant, apu:, apv:)
    _ -> {
      let cek = content_encryption.generate_cek(content_alg)
      use encrypted_recipients <- result.try(
        list.try_map(recipients, wrap_recipient(_, cek)),
      )
      Ok(#(cek, encrypted_recipients))
    }
  }
}

fn encrypt_ecdh_es_direct(
  key: gose.Key(BitArray),
  content_alg: gose.ContentAlg,
  variant: EcdhEsDirectVariant,
  apu apu: option.Option(BitArray),
  apv apv: option.Option(BitArray),
) -> Result(#(BitArray, List(EncryptedRecipient)), gose.GoseError) {
  use #(shared_secret, epk) <- result.try(
    key_encryption.compute_ecdh_shared_secret(key),
  )
  use content_alg_id <- result.try(cose.content_alg_to_int(content_alg))
  let alg_id = ecdh_variant_to_cose_id(variant)
  let key_len = gose.content_alg_key_size(content_alg)
  let protected = append_party_headers([cose.Alg(alg_id)], apu:, apv:)
  let recipient_protected = cose_structure.serialize_protected(protected)
  use cek <- result.try(derive_cose_ecdh_key(
    shared_secret,
    hash_algorithm: ecdh_variant_hash_algorithm(variant),
    algorithm_id: content_alg_id,
    key_data_length: key_len,
    recipient_protected:,
    party_u_identity: apu,
    party_v_identity: apv,
  ))
  let recipient =
    EncryptedRecipient(
      protected:,
      protected_serialized: recipient_protected,
      unprotected: [cose.Unknown(cbor.Int(-1), epk_to_cbor(epk))],
      ciphertext: <<>>,
    )
  Ok(#(cek, [recipient]))
}

fn append_party_headers(
  headers: List(cose.Header),
  apu apu: option.Option(BitArray),
  apv apv: option.Option(BitArray),
) -> List(cose.Header) {
  let headers = case apu {
    option.Some(bytes) -> [
      cose.Unknown(cbor.Int(-21), cbor.Bytes(bytes)),
      ..headers
    ]
    option.None -> headers
  }
  case apv {
    option.Some(bytes) -> [
      cose.Unknown(cbor.Int(-24), cbor.Bytes(bytes)),
      ..headers
    ]
    option.None -> headers
  }
}

fn extract_party_u(headers: List(cose.Header)) -> option.Option(BitArray) {
  find_unknown_bytes(headers, -21)
}

fn extract_party_v(headers: List(cose.Header)) -> option.Option(BitArray) {
  find_unknown_bytes(headers, -24)
}

fn find_unknown_bytes(
  headers: List(cose.Header),
  label: Int,
) -> option.Option(BitArray) {
  case headers {
    [] -> option.None
    [cose.Unknown(cbor.Int(found), cbor.Bytes(b)), ..] if found == label ->
      option.Some(b)
    [_, ..rest] -> find_unknown_bytes(rest, label)
  }
}

fn wrap_recipient(
  recipient: PendingRecipient,
  cek: BitArray,
) -> Result(EncryptedRecipient, gose.GoseError) {
  case recipient.alg {
    gose.AesKeyWrap(gose.AesKw, size) ->
      encrypt_aes_kw_recipient(recipient.key, cek, size)
    gose.RsaEncryption(rsa_alg) ->
      encrypt_rsa_oaep_recipient(recipient.key, cek, rsa_alg)
    gose.EcdhEs(gose.EcdhEsAesKw(size)) ->
      encrypt_ecdh_es_aes_kw_recipient(
        recipient.key,
        cek,
        size,
        apu: recipient.apu,
        apv: recipient.apv,
      )
    gose.Direct
    | gose.AesKeyWrap(gose.AesGcmKw, _)
    | gose.ChaCha20KeyWrap(_)
    | gose.EcdhEs(gose.EcdhEsDirect)
    | gose.EcdhEs(gose.EcdhEsChaCha20Kw(_))
    | gose.Pbes2(_) ->
      Error(gose.InvalidState(
        "unsupported key encryption algorithm for COSE_Encrypt",
      ))
  }
}

fn ecdh_variant_to_cose_id(variant: EcdhEsDirectVariant) -> Int {
  case variant {
    EcdhEsHkdf256 -> -25
    EcdhEsHkdf512 -> -26
  }
}

fn ecdh_variant_hash_algorithm(
  variant: EcdhEsDirectVariant,
) -> hash.HashAlgorithm {
  case variant {
    EcdhEsHkdf256 -> hash.Sha256
    EcdhEsHkdf512 -> hash.Sha512
  }
}

fn encrypt_direct_recipient() -> Result(EncryptedRecipient, gose.GoseError) {
  Ok(
    EncryptedRecipient(
      protected: [],
      protected_serialized: <<>>,
      unprotected: [cose.Alg(-6)],
      ciphertext: <<>>,
    ),
  )
}

fn encrypt_aes_kw_recipient(
  key: gose.Key(BitArray),
  cek: BitArray,
  size: gose.AesKeySize,
) -> Result(EncryptedRecipient, gose.GoseError) {
  use alg_id <- result.try(
    cose.key_encryption_alg_to_int(gose.AesKeyWrap(gose.AesKw, size)),
  )
  use encrypted_cek <- result.try(key_encryption.wrap_aes_kw(key, cek:, size:))
  Ok(EncryptedRecipient(
    protected: [],
    protected_serialized: <<>>,
    unprotected: [cose.Alg(alg_id)],
    ciphertext: encrypted_cek,
  ))
}

fn encrypt_rsa_oaep_recipient(
  key: gose.Key(BitArray),
  cek: BitArray,
  rsa_alg: gose.RsaEncryptionAlg,
) -> Result(EncryptedRecipient, gose.GoseError) {
  use alg_id <- result.try(
    cose.key_encryption_alg_to_int(gose.RsaEncryption(rsa_alg)),
  )
  use hash_alg <- result.try(rsa_hash_for_alg(rsa_alg))
  use encrypted_cek <- result.try(key_encryption.wrap_rsa_oaep(
    key,
    cek:,
    hash_alg:,
  ))
  Ok(EncryptedRecipient(
    protected: [],
    protected_serialized: <<>>,
    unprotected: [cose.Alg(alg_id)],
    ciphertext: encrypted_cek,
  ))
}

fn encrypt_ecdh_es_aes_kw_recipient(
  key: gose.Key(BitArray),
  cek: BitArray,
  size: gose.AesKeySize,
  apu apu: option.Option(BitArray),
  apv apv: option.Option(BitArray),
) -> Result(EncryptedRecipient, gose.GoseError) {
  use alg_id <- result.try(
    cose.key_encryption_alg_to_int(gose.EcdhEs(gose.EcdhEsAesKw(size))),
  )
  use #(shared_secret, epk) <- result.try(
    key_encryption.compute_ecdh_shared_secret(key),
  )
  let protected = append_party_headers([], apu:, apv:)
  let protected_serialized = cose_structure.serialize_protected(protected)
  let kw_key_len = gose.aes_key_size(size)
  use kek <- result.try(derive_cose_ecdh_key(
    shared_secret,
    hash_algorithm: hash.Sha256,
    algorithm_id: aes_kw_cose_id(size),
    key_data_length: kw_key_len,
    recipient_protected: protected_serialized,
    party_u_identity: apu,
    party_v_identity: apv,
  ))
  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  use wrapped <- result.try(
    block.wrap(cipher, cek)
    |> result.replace_error(gose.CryptoError("AES Key Wrap failed")),
  )
  Ok(EncryptedRecipient(
    protected:,
    protected_serialized:,
    unprotected: [
      cose.Alg(alg_id),
      cose.Unknown(cbor.Int(-1), epk_to_cbor(epk)),
    ],
    ciphertext: wrapped,
  ))
}

fn aes_kw_cose_id(size: gose.AesKeySize) -> Int {
  case size {
    gose.Aes128 -> -3
    gose.Aes192 -> -4
    gose.Aes256 -> -5
  }
}

fn recipient_alg(
  recipient: EncryptedRecipient,
) -> Result(gose.KeyEncryptionAlg, gose.GoseError) {
  cose_structure.extract_key_encryption_alg_from_headers(recipient.protected)
  |> result.lazy_or(fn() {
    cose_structure.extract_key_encryption_alg_from_headers(
      recipient.unprotected,
    )
  })
}

fn try_decrypt_recipients(
  recipients: List(EncryptedRecipient),
  keys: List(gose.Key(BitArray)),
  key_alg: gose.KeyEncryptionAlg,
  content_alg: gose.ContentAlg,
  ecdh_es_variant: option.Option(EcdhEsDirectVariant),
  iv: BitArray,
  enc_structure: BitArray,
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
          content_alg,
          ecdh_es_variant,
          iv,
          enc_structure,
          ciphertext,
          tag,
        )
      case result {
        Ok(plaintext) -> Ok(plaintext)
        Error(gose.CryptoError(_) as e) ->
          try_decrypt_recipients(
            rest,
            keys,
            key_alg,
            content_alg,
            ecdh_es_variant,
            iv,
            enc_structure,
            ciphertext,
            tag,
            Error(e),
          )
        Error(e) -> Error(e)
      }
    }
  }
}

fn try_keys_for_recipient(
  recipient: EncryptedRecipient,
  keys: List(gose.Key(BitArray)),
  key_alg: gose.KeyEncryptionAlg,
  content_alg: gose.ContentAlg,
  ecdh_es_variant: option.Option(EcdhEsDirectVariant),
  iv: BitArray,
  enc_structure: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use _ <- result.try(cose_structure.validate_crit(
    recipient.protected,
    recipient.unprotected,
  ))
  try_keys(
    keys,
    recipient,
    key_alg,
    content_alg,
    ecdh_es_variant,
    iv,
    enc_structure,
    ciphertext,
    tag,
    Error(gose.CryptoError("no key could decrypt")),
  )
}

fn try_keys(
  keys: List(gose.Key(BitArray)),
  recipient: EncryptedRecipient,
  key_alg: gose.KeyEncryptionAlg,
  content_alg: gose.ContentAlg,
  ecdh_es_variant: option.Option(EcdhEsDirectVariant),
  iv: BitArray,
  enc_structure: BitArray,
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
          content_alg,
          ecdh_es_variant,
          iv,
          enc_structure,
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
            content_alg,
            ecdh_es_variant,
            iv,
            enc_structure,
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
  key: gose.Key(BitArray),
  key_alg: gose.KeyEncryptionAlg,
  content_alg: gose.ContentAlg,
  ecdh_es_variant: option.Option(EcdhEsDirectVariant),
  iv: BitArray,
  enc_structure: BitArray,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, gose.GoseError) {
  use cek <- result.try(unwrap_cek(
    recipient,
    key,
    key_alg,
    content_alg,
    ecdh_es_variant,
  ))
  content_encryption.decrypt_content(
    content_alg,
    cek:,
    iv:,
    aad: enc_structure,
    ciphertext:,
    tag:,
  )
}

fn unwrap_cek(
  recipient: EncryptedRecipient,
  key: gose.Key(BitArray),
  key_alg: gose.KeyEncryptionAlg,
  content_alg: gose.ContentAlg,
  ecdh_es_variant: option.Option(EcdhEsDirectVariant),
) -> Result(BitArray, gose.GoseError) {
  case key_alg {
    gose.Direct -> key_encryption.unwrap_direct(key, content_alg)
    gose.AesKeyWrap(gose.AesKw, size) ->
      key_encryption.unwrap_aes_kw(
        key,
        encrypted_key: recipient.ciphertext,
        size:,
      )
    gose.RsaEncryption(rsa_alg) -> {
      use hash_alg <- result.try(rsa_hash_for_alg(rsa_alg))
      key_encryption.unwrap_rsa_oaep(
        key,
        encrypted_key: recipient.ciphertext,
        hash_alg:,
      )
    }
    gose.EcdhEs(gose.EcdhEsDirect) -> {
      // Safe: Decryptor constructors pair EcdhEsDirect with Some(variant).
      let assert option.Some(variant) = ecdh_es_variant
      unwrap_ecdh_es_direct(recipient, key, content_alg, variant)
    }
    gose.EcdhEs(gose.EcdhEsAesKw(size)) ->
      unwrap_ecdh_es_aes_kw(recipient, key, size)
    gose.AesKeyWrap(gose.AesGcmKw, _)
    | gose.ChaCha20KeyWrap(_)
    | gose.EcdhEs(gose.EcdhEsChaCha20Kw(_))
    | gose.Pbes2(_) ->
      Error(gose.InvalidState(
        "unsupported key encryption algorithm for COSE_Encrypt",
      ))
  }
}

fn unwrap_ecdh_es_direct(
  recipient: EncryptedRecipient,
  key: gose.Key(BitArray),
  content_alg: gose.ContentAlg,
  variant: EcdhEsDirectVariant,
) -> Result(BitArray, gose.GoseError) {
  use epk <- result.try(extract_epk(recipient.unprotected))
  use shared_secret <- result.try(
    key_encryption.compute_ecdh_shared_secret_with_epk(key, epk),
  )
  use content_alg_id <- result.try(cose.content_alg_to_int(content_alg))
  let key_len = gose.content_alg_key_size(content_alg)
  derive_cose_ecdh_key(
    shared_secret,
    hash_algorithm: ecdh_variant_hash_algorithm(variant),
    algorithm_id: content_alg_id,
    key_data_length: key_len,
    recipient_protected: recipient.protected_serialized,
    party_u_identity: extract_party_u(recipient.protected),
    party_v_identity: extract_party_v(recipient.protected),
  )
}

fn unwrap_ecdh_es_aes_kw(
  recipient: EncryptedRecipient,
  key: gose.Key(BitArray),
  size: gose.AesKeySize,
) -> Result(BitArray, gose.GoseError) {
  use epk <- result.try(extract_epk(recipient.unprotected))
  use shared_secret <- result.try(
    key_encryption.compute_ecdh_shared_secret_with_epk(key, epk),
  )
  let kw_key_len = gose.aes_key_size(size)
  use kek <- result.try(derive_cose_ecdh_key(
    shared_secret,
    hash_algorithm: hash.Sha256,
    algorithm_id: aes_kw_cose_id(size),
    key_data_length: kw_key_len,
    recipient_protected: recipient.protected_serialized,
    party_u_identity: extract_party_u(recipient.protected),
    party_v_identity: extract_party_v(recipient.protected),
  ))
  use cipher <- result.try(content_encryption.aes_cipher(size, kek))
  block.unwrap(cipher, recipient.ciphertext)
  |> result.replace_error(gose.CryptoError("AES Key Unwrap failed"))
}

fn rsa_hash_for_alg(
  rsa_alg: gose.RsaEncryptionAlg,
) -> Result(hash.HashAlgorithm, gose.GoseError) {
  case rsa_alg {
    gose.RsaOaepSha1 -> Ok(hash.Sha1)
    gose.RsaOaepSha256 -> Ok(hash.Sha256)
    gose.RsaPkcs1v15 ->
      Error(gose.InvalidState("RSA-PKCS1v15 is not supported in COSE"))
  }
}

fn serialize_recipient(recipient: EncryptedRecipient) -> cbor.Value {
  cbor.Array([
    cbor.Bytes(recipient.protected_serialized),
    cbor.Map(cose.headers_to_cbor(recipient.unprotected)),
    cbor.Bytes(recipient.ciphertext),
  ])
}

fn parse_cbor_value(
  value: cbor.Value,
) -> Result(Encrypt(Encrypted), gose.GoseError) {
  use items <- result.try(cose_structure.parse_cose_array_value(
    value,
    expected_tag: 96,
    expected_length: 4,
  ))
  case items {
    [
      cbor.Bytes(protected_serialized),
      cbor.Map(unprotected_cbor),
      cbor.Bytes(ciphertext),
      cbor.Array(recipient_values),
    ] -> {
      use protected <- result.try(cose_structure.decode_protected(
        protected_serialized,
      ))
      use unprotected <- result.try(cose_structure.decode_unprotected(
        unprotected_cbor,
      ))
      use _ <- result.try(cose_structure.validate_no_header_overlap(
        protected,
        unprotected,
      ))
      use _ <- result.try(cose_structure.validate_iv_partial_iv_exclusion(
        protected,
        unprotected,
      ))
      use recipients <- result.try(list.try_map(
        recipient_values,
        parse_recipient,
      ))
      Ok(EncryptedEncrypt(
        protected:,
        protected_serialized:,
        unprotected:,
        ciphertext:,
        recipients:,
      ))
    }
    _ -> Error(gose.ParseError("invalid COSE_Encrypt structure"))
  }
}

fn parse_recipient(
  value: cbor.Value,
) -> Result(EncryptedRecipient, gose.GoseError) {
  case value {
    cbor.Array([
      cbor.Bytes(protected_serialized),
      cbor.Map(unprotected_cbor),
      cbor.Bytes(ciphertext),
    ]) ->
      parse_recipient_fields(protected_serialized, unprotected_cbor, ciphertext)
    cbor.Array([cbor.Bytes(_), cbor.Map(_), cbor.Bytes(_), cbor.Array(_)]) ->
      Error(gose.ParseError("nested COSE recipients are not supported"))
    _ -> Error(gose.ParseError("invalid COSE_recipient structure"))
  }
}

fn parse_recipient_fields(
  protected_serialized: BitArray,
  unprotected_cbor: List(#(cbor.Value, cbor.Value)),
  ciphertext: BitArray,
) -> Result(EncryptedRecipient, gose.GoseError) {
  use protected <- result.try(cose_structure.decode_protected(
    protected_serialized,
  ))
  use unprotected <- result.try(cose_structure.decode_unprotected(
    unprotected_cbor,
  ))
  use _ <- result.try(cose_structure.validate_no_header_overlap(
    protected,
    unprotected,
  ))
  use _ <- result.try(cose_structure.validate_iv_partial_iv_exclusion(
    protected,
    unprotected,
  ))
  use <- validate_no_private_epk(unprotected)
  Ok(EncryptedRecipient(
    protected:,
    protected_serialized:,
    unprotected:,
    ciphertext:,
  ))
}

fn validate_no_private_epk(
  unprotected: List(cose.Header),
  continue: fn() -> Result(a, gose.GoseError),
) -> Result(a, gose.GoseError) {
  case find_unknown_header(unprotected, cbor.Int(-1)) {
    Ok(cbor.Map(epk_pairs)) -> {
      let has_private = list.any(epk_pairs, fn(pair) { pair.0 == cbor.Int(-4) })
      use <- bool.guard(
        when: has_private,
        return: Error(gose.ParseError(
          "ephemeral public key must not contain private material",
        )),
      )
      continue()
    }
    _ -> continue()
  }
}

fn epk_to_cbor(epk: key_encryption.EphemeralPublicKey) -> cbor.Value {
  case epk {
    key_encryption.EcEphemeralKey(curve:, x:, y:) -> {
      let crv_id = cose.ec_curve_to_cose(curve)
      cbor.Map([
        #(cbor.Int(1), cbor.Int(2)),
        #(cbor.Int(-1), cbor.Int(crv_id)),
        #(cbor.Int(-2), cbor.Bytes(x)),
        #(cbor.Int(-3), cbor.Bytes(y)),
      ])
    }
    key_encryption.XdhEphemeralKey(curve:, x:) -> {
      let crv_id = cose.xdh_curve_to_cose(curve)
      cbor.Map([
        #(cbor.Int(1), cbor.Int(1)),
        #(cbor.Int(-1), cbor.Int(crv_id)),
        #(cbor.Int(-2), cbor.Bytes(x)),
      ])
    }
  }
}

fn extract_epk(
  unprotected: List(cose.Header),
) -> Result(key_encryption.EphemeralPublicKey, gose.GoseError) {
  case find_unknown_header(unprotected, cbor.Int(-1)) {
    Ok(cbor.Map(pairs)) -> parse_epk(pairs)
    _ ->
      Error(gose.ParseError(
        "missing ephemeral public key (label -1) in recipient",
      ))
  }
}

fn find_unknown_header(
  headers: List(cose.Header),
  key: cbor.Value,
) -> Result(cbor.Value, Nil) {
  list.find_map(headers, fn(header) {
    case header {
      cose.Unknown(k, v) if k == key -> Ok(v)
      _ -> Error(Nil)
    }
  })
}

fn parse_epk(
  pairs: List(#(cbor.Value, cbor.Value)),
) -> Result(key_encryption.EphemeralPublicKey, gose.GoseError) {
  case list.key_find(pairs, cbor.Int(1)) {
    Ok(cbor.Int(2)) -> parse_ec_epk(pairs)
    Ok(cbor.Int(1)) -> parse_okp_epk(pairs)
    _ -> Error(gose.ParseError("unsupported EPK key type"))
  }
}

fn parse_ec_epk(
  pairs: List(#(cbor.Value, cbor.Value)),
) -> Result(key_encryption.EphemeralPublicKey, gose.GoseError) {
  use crv_id <- result.try(lookup_int(pairs, -1, "missing EC curve in EPK"))
  use curve <- result.try(cose.ec_curve_from_cose(crv_id))
  use x <- result.try(lookup_bytes(pairs, -2, "missing EC x in EPK"))
  use y <- result.try(lookup_bytes(pairs, -3, "missing EC y in EPK"))
  Ok(key_encryption.EcEphemeralKey(curve:, x:, y:))
}

fn parse_okp_epk(
  pairs: List(#(cbor.Value, cbor.Value)),
) -> Result(key_encryption.EphemeralPublicKey, gose.GoseError) {
  use crv_id <- result.try(lookup_int(pairs, -1, "missing OKP curve in EPK"))
  use curve <- result.try(cose.xdh_curve_from_cose(crv_id))
  use x <- result.try(lookup_bytes(pairs, -2, "missing OKP x in EPK"))
  Ok(key_encryption.XdhEphemeralKey(curve:, x:))
}

fn lookup_int(
  pairs: List(#(cbor.Value, cbor.Value)),
  label: Int,
  error_msg: String,
) -> Result(Int, gose.GoseError) {
  case list.key_find(pairs, cbor.Int(label)) {
    Ok(cbor.Int(v)) -> Ok(v)
    _ -> Error(gose.ParseError(error_msg))
  }
}

fn lookup_bytes(
  pairs: List(#(cbor.Value, cbor.Value)),
  label: Int,
  error_msg: String,
) -> Result(BitArray, gose.GoseError) {
  case list.key_find(pairs, cbor.Int(label)) {
    Ok(cbor.Bytes(v)) -> Ok(v)
    _ -> Error(gose.ParseError(error_msg))
  }
}

@internal
pub fn derive_cose_ecdh_key(
  shared_secret: BitArray,
  hash_algorithm hash_algorithm: hash.HashAlgorithm,
  algorithm_id algorithm_id: Int,
  key_data_length key_data_length: Int,
  recipient_protected recipient_protected: BitArray,
  party_u_identity party_u_identity: option.Option(BitArray),
  party_v_identity party_v_identity: option.Option(BitArray),
) -> Result(BitArray, gose.GoseError) {
  let context =
    cbor.encode(
      cbor.Array([
        cbor.Int(algorithm_id),
        encode_party_info(party_u_identity),
        encode_party_info(party_v_identity),
        cbor.Array([
          cbor.Int(key_data_length * 8),
          cbor.Bytes(recipient_protected),
        ]),
      ]),
    )

  crypto.hkdf(
    hash_algorithm,
    input: shared_secret,
    salt: option.None,
    info: context,
    length: key_data_length,
  )
  |> result.replace_error(gose.CryptoError("HKDF failed"))
}

fn encode_party_info(identity: option.Option(BitArray)) -> cbor.Value {
  let identity_value = case identity {
    option.Some(bytes) -> cbor.Bytes(bytes)
    option.None -> cbor.Null
  }
  cbor.Array([identity_value, cbor.Null, cbor.Null])
}
