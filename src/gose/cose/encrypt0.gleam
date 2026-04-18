//// COSE_Encrypt0 single-recipient encryption and decryption
//// ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)).
////
//// ## Example
////
//// ```gleam
//// import gose
//// import gose/cose/encrypt0
////
//// let k = gose.generate_enc_key(gose.AesGcm(gose.Aes128))
//// let plaintext = <<"hello COSE":utf8>>
////
//// let assert Ok(message) = encrypt0.new(gose.AesGcm(gose.Aes128))
//// let assert Ok(encrypted) = encrypt0.encrypt(message, k, plaintext)
////
//// let data = encrypt0.serialize(encrypted)
//// let assert Ok(parsed) = encrypt0.parse(data)
//// let assert Ok(decryptor) = encrypt0.decryptor(gose.AesGcm(gose.Aes128), key: k)
//// let assert Ok(decrypted) = encrypt0.decrypt(decryptor, parsed)
//// ```
////
//// ## Phantom Types
////
//// `Encrypt0(state)` uses a phantom type to track encryption state:
//// - `Unencrypted`: created via `new`, ready to encrypt
//// - `Encrypted`: encrypted or parsed, can be serialized or decrypted

import gleam/bit_array
import gleam/list
import gleam/result
import gose
import gose/cbor
import gose/cose
import gose/internal/content_encryption
import gose/internal/cose_structure
import gose/internal/key_helpers

/// Phantom type for a COSE_Encrypt0 message that has not yet been encrypted.
pub type Unencrypted

/// Phantom type for a COSE_Encrypt0 message that has been encrypted or parsed.
pub type Encrypted

/// A decryptor pinned to a content encryption algorithm and a single symmetric key.
pub opaque type Decryptor {
  Decryptor(alg: gose.ContentAlg, key: gose.Key(BitArray))
}

/// A COSE_Encrypt0 message parameterized by encryption state.
pub opaque type Encrypt0(state) {
  UnencryptedEncrypt0(
    protected: List(cose.Header),
    unprotected: List(cose.Header),
    aad: BitArray,
  )
  EncryptedEncrypt0(
    protected: List(cose.Header),
    protected_serialized: BitArray,
    unprotected: List(cose.Header),
    ciphertext: BitArray,
  )
}

/// Create a new unencrypted COSE_Encrypt0 message with the given content encryption algorithm.
pub fn new(
  alg: gose.ContentAlg,
) -> Result(Encrypt0(Unencrypted), gose.GoseError) {
  use alg_id <- result.try(cose.content_alg_to_int(alg))
  Ok(
    UnencryptedEncrypt0(
      protected: [cose.Alg(alg_id)],
      unprotected: [],
      aad: <<>>,
    ),
  )
}

/// Encrypt the plaintext with the given symmetric key.
pub fn encrypt(
  message: Encrypt0(Unencrypted),
  key key: gose.Key(BitArray),
  plaintext plaintext: BitArray,
) -> Result(Encrypt0(Encrypted), gose.GoseError) {
  let assert UnencryptedEncrypt0(protected:, unprotected:, aad:) = message

  use alg <- result.try(cose_structure.extract_content_alg_from_headers(
    protected,
  ))
  use _ <- result.try(key_helpers.validate_key_for_content_encryption(alg, key))
  use cek <- result.try(extract_cek(key))

  let protected_serialized = cose_structure.serialize_protected(protected)
  let iv = content_encryption.generate_iv(alg)
  let aad =
    cose_structure.build_enc_structure(
      context: "Encrypt0",
      protected_serialized:,
      aad:,
    )

  use #(ciphertext, tag) <- result.try(content_encryption.encrypt_content(
    alg,
    cek:,
    iv:,
    aad:,
    plaintext:,
  ))

  let ciphertext_with_tag = bit_array.concat([ciphertext, tag])
  let unprotected = [cose.Iv(iv), ..unprotected]

  Ok(EncryptedEncrypt0(
    protected:,
    protected_serialized:,
    unprotected:,
    ciphertext: ciphertext_with_tag,
  ))
}

/// Build a decryptor pinned to a single algorithm and key.
pub fn decryptor(
  alg: gose.ContentAlg,
  key key: gose.Key(BitArray),
) -> Result(Decryptor, gose.GoseError) {
  use _ <- result.try(key_helpers.validate_key_for_content_decryption(alg, key))
  Ok(Decryptor(alg:, key:))
}

/// Decrypt a COSE_Encrypt0 message, returning the plaintext.
pub fn decrypt(
  decryptor: Decryptor,
  message: Encrypt0(Encrypted),
) -> Result(BitArray, gose.GoseError) {
  decrypt_with_aad(decryptor, message, aad: <<>>)
}

/// Decrypt with additional externally-supplied authenticated data (AAD).
pub fn decrypt_with_aad(
  decryptor: Decryptor,
  message message: Encrypt0(Encrypted),
  aad aad: BitArray,
) -> Result(BitArray, gose.GoseError) {
  let Decryptor(alg: expected_alg, key:) = decryptor
  let assert EncryptedEncrypt0(
    protected:,
    protected_serialized:,
    unprotected:,
    ciphertext: ciphertext_with_tag,
  ) = message

  use actual_alg <- result.try(
    cose_structure.extract_content_alg_from_serialized(protected_serialized),
  )
  use _ <- result.try(key_helpers.require_matching_content_algorithm(
    expected_alg,
    actual_alg,
  ))
  use _ <- result.try(cose_structure.validate_crit(protected, unprotected))
  use cek <- result.try(extract_cek(key))
  use iv <- result.try(cose.iv(unprotected))
  use #(ciphertext, tag) <- result.try(cose_structure.split_ciphertext_tag(
    ciphertext_with_tag,
    tag_size: content_encryption.tag_size(expected_alg),
  ))

  let aad =
    cose_structure.build_enc_structure(
      context: "Encrypt0",
      protected_serialized:,
      aad:,
    )
  content_encryption.decrypt_content(
    expected_alg,
    cek:,
    iv:,
    aad:,
    ciphertext:,
    tag:,
  )
}

/// Encode an encrypted message as an untagged CBOR COSE_Encrypt0 array.
pub fn serialize(message: Encrypt0(Encrypted)) -> BitArray {
  cbor.encode(to_cbor_value(message))
}

/// Encode an encrypted message as a CBOR-tagged (tag 16) COSE_Encrypt0 structure.
pub fn serialize_tagged(message: Encrypt0(Encrypted)) -> BitArray {
  cbor.encode(cbor.Tag(16, to_cbor_value(message)))
}

fn to_cbor_value(message: Encrypt0(Encrypted)) -> cbor.Value {
  let assert EncryptedEncrypt0(
    protected_serialized:,
    unprotected:,
    ciphertext:,
    ..,
  ) = message

  cbor.Array([
    cbor.Bytes(protected_serialized),
    cbor.Map(cose.headers_to_cbor(unprotected)),
    cbor.Bytes(ciphertext),
  ])
}

/// Decode a CBOR-encoded COSE_Encrypt0 message, accepting both tagged and untagged forms.
pub fn parse(data: BitArray) -> Result(Encrypt0(Encrypted), gose.GoseError) {
  use value <- result.try(cbor.decode(data))
  parse_cbor_value(value)
}

/// Set external additional authenticated data (AAD) for the encryption operation.
pub fn with_aad(
  message: Encrypt0(Unencrypted),
  aad aad: BitArray,
) -> Encrypt0(Unencrypted) {
  let assert UnencryptedEncrypt0(..) = message
  UnencryptedEncrypt0(..message, aad:)
}

/// Add a key ID to the unprotected headers.
pub fn with_kid(
  message: Encrypt0(Unencrypted),
  kid: BitArray,
) -> Encrypt0(Unencrypted) {
  let assert UnencryptedEncrypt0(unprotected:, ..) = message
  UnencryptedEncrypt0(..message, unprotected: [cose.Kid(kid), ..unprotected])
}

/// Add a content type to the protected headers.
///
/// RFC 9052 permits either bucket. Encrypted messages place it in protected
/// so it is covered by the AEAD authentication.
pub fn with_content_type(
  message: Encrypt0(Unencrypted),
  ct ct: cose.ContentType,
) -> Encrypt0(Unencrypted) {
  let assert UnencryptedEncrypt0(protected:, ..) = message
  UnencryptedEncrypt0(..message, protected: [cose.ContentType(ct), ..protected])
}

/// Add critical header labels to the protected headers.
pub fn with_critical(
  message: Encrypt0(Unencrypted),
  labels: List(Int),
) -> Encrypt0(Unencrypted) {
  let assert UnencryptedEncrypt0(protected:, ..) = message
  UnencryptedEncrypt0(..message, protected: [cose.Crit(labels), ..protected])
}

/// Extract the key ID from the message headers.
pub fn kid(message: Encrypt0(Encrypted)) -> Result(BitArray, gose.GoseError) {
  let assert EncryptedEncrypt0(protected:, unprotected:, ..) = message
  cose.kid(list.append(protected, unprotected))
}

/// Extract the content type from the message headers.
pub fn content_type(
  message: Encrypt0(Encrypted),
) -> Result(cose.ContentType, gose.GoseError) {
  let assert EncryptedEncrypt0(protected:, unprotected:, ..) = message
  cose.content_type(list.append(protected, unprotected))
}

/// Extract the critical header labels from the message headers.
pub fn critical(
  message: Encrypt0(Encrypted),
) -> Result(List(Int), gose.GoseError) {
  let assert EncryptedEncrypt0(protected:, unprotected:, ..) = message
  cose.critical(list.append(protected, unprotected))
}

/// Return the raw protected headers.
pub fn protected_headers(message: Encrypt0(Encrypted)) -> List(cose.Header) {
  let assert EncryptedEncrypt0(protected:, ..) = message
  protected
}

/// Return the raw unprotected headers.
pub fn unprotected_headers(message: Encrypt0(Encrypted)) -> List(cose.Header) {
  let assert EncryptedEncrypt0(unprotected:, ..) = message
  unprotected
}

fn extract_cek(key: gose.Key(BitArray)) -> Result(BitArray, gose.GoseError) {
  gose.material_octet_secret(gose.material(key))
}

fn parse_cbor_value(
  value: cbor.Value,
) -> Result(Encrypt0(Encrypted), gose.GoseError) {
  use items <- result.try(cose_structure.parse_cose_array_value(
    value,
    expected_tag: 16,
    expected_length: 3,
  ))
  case items {
    [
      cbor.Bytes(protected_serialized),
      cbor.Map(unprotected_cbor),
      cbor.Bytes(ciphertext),
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
      Ok(EncryptedEncrypt0(
        protected:,
        protected_serialized:,
        unprotected:,
        ciphertext:,
      ))
    }
    _ -> Error(gose.ParseError("invalid COSE_Encrypt0 structure"))
  }
}
