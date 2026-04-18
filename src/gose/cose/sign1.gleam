//// COSE_Sign1 single-signer signing and verification
//// ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)).
////
//// ## Example
////
//// ```gleam
//// import gose
//// import gose/cose/sign1
//// import kryptos/ec
////
//// let k = gose.generate_ec(ec.P256)
//// let payload = <<"hello":utf8>>
////
//// let assert Ok(signed) =
////   sign1.new(gose.Ecdsa(gose.EcdsaP256))
////   |> sign1.sign(k, payload)
////
//// let data = sign1.serialize(signed)
//// let assert Ok(parsed) = sign1.parse(data)
//// let assert Ok(verifier) =
////   sign1.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [k])
//// let assert Ok(Nil) = sign1.verify(verifier, parsed)
//// ```
////
//// ## Phantom Types
////
//// `Sign1(state)` uses a phantom type to track signing state:
//// - `Unsigned`: created via `new`, ready to sign
//// - `Signed`: signed or parsed, can be serialized or verified
////
//// ## Algorithm Pinning
////
//// Each verifier is pinned to a single algorithm. The token's protected
//// header `alg` must match the verifier's expected algorithm.

import gleam/list
import gleam/option.{type Option}
import gleam/result
import gose
import gose/cbor
import gose/cose
import gose/internal/cose_structure
import gose/internal/key_helpers
import gose/internal/signing

/// Phantom type for a COSE_Sign1 message that has not yet been signed.
pub type Unsigned

/// Phantom type for a COSE_Sign1 message that has been signed or parsed.
pub type Signed

/// A COSE_Sign1 message parameterized by signing state.
pub opaque type Sign1(state) {
  UnsignedSign1(
    protected: List(cose.Header),
    unprotected: List(cose.Header),
    detached: Bool,
    aad: BitArray,
  )
  SignedSign1(
    protected: List(cose.Header),
    protected_serialized: BitArray,
    unprotected: List(cose.Header),
    payload: Option(BitArray),
    signature: BitArray,
  )
}

/// Holds an algorithm and set of keys for verifying a COSE_Sign1 message.
pub opaque type Verifier {
  Verifier(alg: gose.DigitalSignatureAlg, keys: List(gose.Key(BitArray)))
}

/// Create a new unsigned COSE_Sign1 message with the given signature algorithm in the protected header.
pub fn new(alg: gose.DigitalSignatureAlg) -> Sign1(Unsigned) {
  let alg_id = cose.signature_alg_to_int(alg)
  UnsignedSign1(
    protected: [cose.Alg(alg_id)],
    unprotected: [],
    detached: False,
    aad: <<>>,
  )
}

/// Sign the payload with the given key, producing a signed COSE_Sign1 message.
pub fn sign(
  message: Sign1(Unsigned),
  key key: gose.Key(BitArray),
  payload payload: BitArray,
) -> Result(Sign1(Signed), gose.GoseError) {
  let assert UnsignedSign1(protected:, unprotected:, detached:, aad:) = message

  use alg <- result.try(cose_structure.extract_signing_alg_from_headers(
    protected,
  ))
  use _ <- result.try(key_helpers.validate_signing_key_type(alg, key))
  use _ <- result.try(key_helpers.validate_key_use(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_ops(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_algorithm_signing(key, alg))

  let protected_serialized = cose_structure.serialize_protected(protected)
  let to_sign = build_sig_structure(protected_serialized, aad, payload)

  use sig <- result.try(signing.compute_signature(alg, key:, message: to_sign))

  let stored_payload = case detached {
    True -> option.None
    False -> option.Some(payload)
  }

  Ok(SignedSign1(
    protected:,
    protected_serialized:,
    unprotected:,
    payload: stored_payload,
    signature: sig,
  ))
}

/// Encode a signed message as an untagged CBOR COSE_Sign1 array.
pub fn serialize(message: Sign1(Signed)) -> BitArray {
  cbor.encode(to_cbor_value(message))
}

/// Encode a signed message as a CBOR-tagged (tag 18) COSE_Sign1 structure.
pub fn serialize_tagged(message: Sign1(Signed)) -> BitArray {
  cbor.encode(cbor.Tag(18, to_cbor_value(message)))
}

fn to_cbor_value(message: Sign1(Signed)) -> cbor.Value {
  let assert SignedSign1(
    protected_serialized:,
    unprotected:,
    payload:,
    signature:,
    ..,
  ) = message

  let payload_value = case payload {
    option.Some(p) -> cbor.Bytes(p)
    option.None -> cbor.Null
  }

  cbor.Array([
    cbor.Bytes(protected_serialized),
    cbor.Map(cose.headers_to_cbor(unprotected)),
    payload_value,
    cbor.Bytes(signature),
  ])
}

/// Decode a CBOR-encoded COSE_Sign1 message, accepting both tagged and untagged forms.
pub fn parse(data: BitArray) -> Result(Sign1(Signed), gose.GoseError) {
  use value <- result.try(cbor.decode(data))
  parse_cbor_value(value)
}

/// Return the payload from a signed message. Returns `Error(Nil)` if detached.
pub fn payload(message: Sign1(Signed)) -> Result(BitArray, Nil) {
  let assert SignedSign1(payload:, ..) = message
  option.to_result(payload, Nil)
}

/// Build a verifier pinned to a single algorithm and one or more keys.
pub fn verifier(
  alg: gose.DigitalSignatureAlg,
  keys keys: List(gose.Key(BitArray)),
) -> Result(Verifier, gose.GoseError) {
  let signing_alg = gose.DigitalSignature(alg)
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_signing_verification(
      signing_alg,
      _,
    )),
  )
  Ok(Verifier(alg:, keys:))
}

/// Verify the signature of a signed COSE_Sign1 message against the verifier's expected algorithm and keys.
pub fn verify(
  verifier: Verifier,
  message message: Sign1(Signed),
) -> Result(Nil, gose.GoseError) {
  verify_with_aad(verifier, message, <<>>)
}

/// Verify the signature with additional externally-supplied authenticated data (AAD).
pub fn verify_with_aad(
  verifier: Verifier,
  message message: Sign1(Signed),
  aad aad: BitArray,
) -> Result(Nil, gose.GoseError) {
  let Verifier(alg: expected_alg, keys:) = verifier
  let expected_signing_alg = gose.DigitalSignature(expected_alg)
  let assert SignedSign1(
    protected:,
    protected_serialized:,
    unprotected:,
    signature:,
    payload:,
  ) = message

  use actual_alg <- result.try(
    cose_structure.extract_signing_alg_from_serialized(protected_serialized),
  )
  use _ <- result.try(key_helpers.require_matching_signing_algorithm(
    expected_signing_alg,
    actual_alg,
  ))
  use _ <- result.try(cose_structure.validate_crit(protected, unprotected))

  use payload_bytes <- result.try(cose_structure.require_embedded_payload(
    payload,
  ))
  let to_sign = build_sig_structure(protected_serialized, aad, payload_bytes)

  cose_structure.try_verify_keys(
    expected_signing_alg,
    keys:,
    message: to_sign,
    signature:,
  )
}

/// Verify the signature of a detached-payload COSE_Sign1 message.
///
/// The caller must supply the payload that was detached from the message.
/// Returns an error if the message already contains an embedded payload.
pub fn verify_detached(
  verifier: Verifier,
  message message: Sign1(Signed),
  payload payload: BitArray,
) -> Result(Nil, gose.GoseError) {
  verify_detached_with_aad(verifier, message, payload, <<>>)
}

/// Verify a detached-payload COSE_Sign1 message with external AAD.
pub fn verify_detached_with_aad(
  verifier: Verifier,
  message message: Sign1(Signed),
  payload payload: BitArray,
  aad aad: BitArray,
) -> Result(Nil, gose.GoseError) {
  let Verifier(alg: expected_alg, keys:) = verifier
  let expected_signing_alg = gose.DigitalSignature(expected_alg)
  let assert SignedSign1(
    protected:,
    protected_serialized:,
    unprotected:,
    signature:,
    payload: existing_payload,
  ) = message

  use _ <- result.try(cose_structure.require_detached_payload(existing_payload))
  use actual_alg <- result.try(
    cose_structure.extract_signing_alg_from_serialized(protected_serialized),
  )
  use _ <- result.try(key_helpers.require_matching_signing_algorithm(
    expected_signing_alg,
    actual_alg,
  ))
  use _ <- result.try(cose_structure.validate_crit(protected, unprotected))

  let to_sign = build_sig_structure(protected_serialized, aad, payload)

  cose_structure.try_verify_keys(
    expected_signing_alg,
    keys:,
    message: to_sign,
    signature:,
  )
}

/// Mark the message for detached payload. The payload is still provided to
/// `sign` for signature computation but not included in the serialized output.
pub fn with_detached(message: Sign1(Unsigned)) -> Sign1(Unsigned) {
  let assert UnsignedSign1(..) = message
  UnsignedSign1(..message, detached: True)
}

/// Set external additional authenticated data (AAD) for the signing operation.
pub fn with_aad(message: Sign1(Unsigned), aad aad: BitArray) -> Sign1(Unsigned) {
  let assert UnsignedSign1(..) = message
  UnsignedSign1(..message, aad:)
}

/// Add a key ID to the unprotected headers.
pub fn with_kid(message: Sign1(Unsigned), kid kid: BitArray) -> Sign1(Unsigned) {
  let assert UnsignedSign1(unprotected:, ..) = message
  UnsignedSign1(..message, unprotected: [cose.Kid(kid), ..unprotected])
}

/// Add a content type to the unprotected headers.
///
/// RFC 9052 permits either bucket. Signed messages place it in unprotected,
/// consistent with `with_kid`.
pub fn with_content_type(
  message: Sign1(Unsigned),
  ct ct: cose.ContentType,
) -> Sign1(Unsigned) {
  let assert UnsignedSign1(unprotected:, ..) = message
  UnsignedSign1(..message, unprotected: [cose.ContentType(ct), ..unprotected])
}

/// Add critical header labels to the protected headers.
pub fn with_critical(
  message: Sign1(Unsigned),
  labels labels: List(Int),
) -> Sign1(Unsigned) {
  let assert UnsignedSign1(protected:, ..) = message
  UnsignedSign1(..message, protected: [cose.Crit(labels), ..protected])
}

/// Extract the key ID from the message headers.
pub fn kid(message: Sign1(Signed)) -> Result(BitArray, gose.GoseError) {
  let assert SignedSign1(protected:, unprotected:, ..) = message
  cose.kid(list.append(protected, unprotected))
}

/// Extract the content type from the message headers.
pub fn content_type(
  message: Sign1(Signed),
) -> Result(cose.ContentType, gose.GoseError) {
  let assert SignedSign1(protected:, unprotected:, ..) = message
  cose.content_type(list.append(protected, unprotected))
}

/// Extract the critical header labels from the message headers.
pub fn critical(message: Sign1(Signed)) -> Result(List(Int), gose.GoseError) {
  let assert SignedSign1(protected:, unprotected:, ..) = message
  cose.critical(list.append(protected, unprotected))
}

/// Return the raw protected headers.
pub fn protected_headers(message: Sign1(Signed)) -> List(cose.Header) {
  let assert SignedSign1(protected:, ..) = message
  protected
}

/// Return the raw unprotected headers.
pub fn unprotected_headers(message: Sign1(Signed)) -> List(cose.Header) {
  let assert SignedSign1(unprotected:, ..) = message
  unprotected
}

fn build_sig_structure(
  protected_serialized: BitArray,
  aad: BitArray,
  payload: BitArray,
) -> BitArray {
  cbor.encode(
    cbor.Array([
      cbor.Text("Signature1"),
      cbor.Bytes(protected_serialized),
      cbor.Bytes(aad),
      cbor.Bytes(payload),
    ]),
  )
}

fn parse_cbor_value(value: cbor.Value) -> Result(Sign1(Signed), gose.GoseError) {
  use items <- result.try(cose_structure.parse_cose_array_value(
    value,
    expected_tag: 18,
    expected_length: 4,
  ))
  case items {
    [
      cbor.Bytes(protected_serialized),
      cbor.Map(unprotected_cbor),
      payload_value,
      cbor.Bytes(signature),
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
      use payload <- result.try(cose_structure.decode_payload(payload_value))
      Ok(SignedSign1(
        protected:,
        protected_serialized:,
        unprotected:,
        payload:,
        signature:,
      ))
    }
    _ -> Error(gose.ParseError("invalid COSE_Sign1 structure"))
  }
}
