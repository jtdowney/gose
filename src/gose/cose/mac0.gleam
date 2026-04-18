//// COSE_Mac0 single-recipient MAC creation and verification
//// ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)).
////
//// ## Example
////
//// ```gleam
//// import gose
//// import gose/cose/mac0
////
//// let k = gose.generate_hmac_key(gose.HmacSha256)
//// let payload = <<"hello":utf8>>
////
//// let assert Ok(tagged) =
////   mac0.new(gose.Hmac(gose.HmacSha256))
////   |> mac0.tag(k, payload)
////
//// let data = mac0.serialize(tagged)
//// let assert Ok(parsed) = mac0.parse(data)
//// let assert Ok(verifier) =
////   mac0.verifier(gose.Hmac(gose.HmacSha256), keys: [k])
//// let assert Ok(Nil) = mac0.verify(verifier, parsed)
//// ```
////
//// ## Phantom Types
////
//// `Mac0(state)` uses a phantom type to track MAC state:
//// - `Untagged`: created via `new`, ready to tag
//// - `Tagged`: tagged or parsed, can be serialized or verified
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

/// Phantom type for a COSE_Mac0 message that has not yet been tagged.
pub type Untagged

/// Phantom type for a COSE_Mac0 message that has been tagged or parsed.
pub type Tagged

/// A COSE_Mac0 message parameterized by MAC state.
pub opaque type Mac0(state) {
  UntaggedMac0(
    protected: List(cose.Header),
    unprotected: List(cose.Header),
    detached: Bool,
    aad: BitArray,
  )
  TaggedMac0(
    protected: List(cose.Header),
    protected_serialized: BitArray,
    unprotected: List(cose.Header),
    payload: Option(BitArray),
    mac_tag: BitArray,
  )
}

/// Holds an algorithm and set of keys for verifying a COSE_Mac0 message.
pub opaque type Verifier {
  Verifier(alg: gose.MacAlg, keys: List(gose.Key(BitArray)))
}

/// Create a new untagged COSE_Mac0 message with the given MAC algorithm in the protected header.
pub fn new(alg: gose.MacAlg) -> Mac0(Untagged) {
  let alg_id = cose.mac_alg_to_int(alg)
  UntaggedMac0(
    protected: [cose.Alg(alg_id)],
    unprotected: [],
    detached: False,
    aad: <<>>,
  )
}

/// Compute the MAC tag over the payload with the given key.
pub fn tag(
  message: Mac0(Untagged),
  key key: gose.Key(BitArray),
  payload payload: BitArray,
) -> Result(Mac0(Tagged), gose.GoseError) {
  let assert UntaggedMac0(protected:, unprotected:, detached:, aad:) = message

  use alg <- result.try(cose_structure.extract_signing_alg_from_headers(
    protected,
  ))
  use _ <- result.try(key_helpers.validate_signing_key_type(alg, key))
  use _ <- result.try(key_helpers.validate_key_use(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_ops(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_algorithm_signing(key, alg))

  let protected_serialized = cose_structure.serialize_protected(protected)
  let to_mac = build_mac_structure(protected_serialized, aad, payload)

  use computed_tag <- result.try(signing.compute_signature(
    alg,
    key:,
    message: to_mac,
  ))

  let stored_payload = case detached {
    True -> option.None
    False -> option.Some(payload)
  }

  Ok(TaggedMac0(
    protected:,
    protected_serialized:,
    unprotected:,
    payload: stored_payload,
    mac_tag: computed_tag,
  ))
}

/// Encode a tagged message as an untagged CBOR COSE_Mac0 array.
pub fn serialize(message: Mac0(Tagged)) -> BitArray {
  cbor.encode(to_cbor_value(message))
}

/// Encode a tagged message as a CBOR-tagged (tag 17) COSE_Mac0 structure.
pub fn serialize_tagged(message: Mac0(Tagged)) -> BitArray {
  cbor.encode(cbor.Tag(17, to_cbor_value(message)))
}

fn to_cbor_value(message: Mac0(Tagged)) -> cbor.Value {
  let assert TaggedMac0(
    protected_serialized:,
    unprotected:,
    payload:,
    mac_tag:,
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
    cbor.Bytes(mac_tag),
  ])
}

/// Decode a CBOR-encoded COSE_Mac0 message, accepting both tagged and untagged forms.
pub fn parse(data: BitArray) -> Result(Mac0(Tagged), gose.GoseError) {
  use value <- result.try(cbor.decode(data))
  parse_cbor_value(value)
}

/// Return the payload from a tagged message. Returns `Error(Nil)` if detached.
pub fn payload(message: Mac0(Tagged)) -> Result(BitArray, Nil) {
  let assert TaggedMac0(payload:, ..) = message
  option.to_result(payload, Nil)
}

/// Build a verifier pinned to a single algorithm and one or more keys.
pub fn verifier(
  alg: gose.MacAlg,
  keys keys: List(gose.Key(BitArray)),
) -> Result(Verifier, gose.GoseError) {
  let signing_alg = gose.Mac(alg)
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_signing_verification(
      signing_alg,
      _,
    )),
  )
  Ok(Verifier(alg:, keys:))
}

/// Verify the MAC tag of a COSE_Mac0 message against the verifier's expected algorithm and keys.
pub fn verify(
  verifier: Verifier,
  message message: Mac0(Tagged),
) -> Result(Nil, gose.GoseError) {
  verify_with_aad(verifier, message, <<>>)
}

/// Verify the MAC tag with additional externally-supplied authenticated data (AAD).
pub fn verify_with_aad(
  verifier: Verifier,
  message message: Mac0(Tagged),
  aad aad: BitArray,
) -> Result(Nil, gose.GoseError) {
  let Verifier(alg: expected_alg, keys:) = verifier
  let expected_signing_alg = gose.Mac(expected_alg)
  let assert TaggedMac0(
    protected:,
    protected_serialized:,
    unprotected:,
    mac_tag:,
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
  let to_mac = build_mac_structure(protected_serialized, aad, payload_bytes)

  cose_structure.try_verify_keys(
    expected_signing_alg,
    keys:,
    message: to_mac,
    signature: mac_tag,
  )
}

/// Verify the MAC tag of a detached-payload COSE_Mac0 message.
///
/// The caller must supply the payload that was detached from the message.
/// Returns an error if the message already contains an embedded payload.
pub fn verify_detached(
  verifier: Verifier,
  message message: Mac0(Tagged),
  payload payload: BitArray,
) -> Result(Nil, gose.GoseError) {
  verify_detached_with_aad(verifier, message, payload, <<>>)
}

/// Verify a detached-payload COSE_Mac0 message with external AAD.
pub fn verify_detached_with_aad(
  verifier: Verifier,
  message message: Mac0(Tagged),
  payload payload: BitArray,
  aad aad: BitArray,
) -> Result(Nil, gose.GoseError) {
  let Verifier(alg: expected_alg, keys:) = verifier
  let expected_signing_alg = gose.Mac(expected_alg)
  let assert TaggedMac0(
    protected:,
    protected_serialized:,
    unprotected:,
    mac_tag:,
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

  let to_mac = build_mac_structure(protected_serialized, aad, payload)

  cose_structure.try_verify_keys(
    expected_signing_alg,
    keys:,
    message: to_mac,
    signature: mac_tag,
  )
}

/// Mark the message for detached payload. The payload is still provided to
/// `tag` for MAC computation but not included in the serialized output.
pub fn with_detached(message: Mac0(Untagged)) -> Mac0(Untagged) {
  let assert UntaggedMac0(..) = message
  UntaggedMac0(..message, detached: True)
}

/// Set external additional authenticated data (AAD) for the MAC operation.
pub fn with_aad(message: Mac0(Untagged), aad aad: BitArray) -> Mac0(Untagged) {
  let assert UntaggedMac0(..) = message
  UntaggedMac0(..message, aad:)
}

/// Add a key ID to the unprotected headers.
pub fn with_kid(message: Mac0(Untagged), kid kid: BitArray) -> Mac0(Untagged) {
  let assert UntaggedMac0(unprotected:, ..) = message
  UntaggedMac0(..message, unprotected: [cose.Kid(kid), ..unprotected])
}

/// Add a content type to the unprotected headers.
///
/// RFC 9052 permits either bucket. MACed messages place it in unprotected,
/// consistent with `with_kid`.
pub fn with_content_type(
  message: Mac0(Untagged),
  ct ct: cose.ContentType,
) -> Mac0(Untagged) {
  let assert UntaggedMac0(unprotected:, ..) = message
  UntaggedMac0(..message, unprotected: [cose.ContentType(ct), ..unprotected])
}

/// Add critical header labels to the protected headers.
pub fn with_critical(
  message: Mac0(Untagged),
  labels labels: List(Int),
) -> Mac0(Untagged) {
  let assert UntaggedMac0(protected:, ..) = message
  UntaggedMac0(..message, protected: [cose.Crit(labels), ..protected])
}

/// Extract the key ID from the message headers.
pub fn kid(message: Mac0(Tagged)) -> Result(BitArray, gose.GoseError) {
  let assert TaggedMac0(protected:, unprotected:, ..) = message
  cose.kid(list.append(protected, unprotected))
}

/// Extract the content type from the message headers.
pub fn content_type(
  message: Mac0(Tagged),
) -> Result(cose.ContentType, gose.GoseError) {
  let assert TaggedMac0(protected:, unprotected:, ..) = message
  cose.content_type(list.append(protected, unprotected))
}

/// Extract the critical header labels from the message headers.
pub fn critical(message: Mac0(Tagged)) -> Result(List(Int), gose.GoseError) {
  let assert TaggedMac0(protected:, unprotected:, ..) = message
  cose.critical(list.append(protected, unprotected))
}

/// Return the raw protected headers.
pub fn protected_headers(message: Mac0(Tagged)) -> List(cose.Header) {
  let assert TaggedMac0(protected:, ..) = message
  protected
}

/// Return the raw unprotected headers.
pub fn unprotected_headers(message: Mac0(Tagged)) -> List(cose.Header) {
  let assert TaggedMac0(unprotected:, ..) = message
  unprotected
}

fn build_mac_structure(
  protected_serialized: BitArray,
  aad: BitArray,
  payload: BitArray,
) -> BitArray {
  cbor.encode(
    cbor.Array([
      cbor.Text("MAC0"),
      cbor.Bytes(protected_serialized),
      cbor.Bytes(aad),
      cbor.Bytes(payload),
    ]),
  )
}

fn parse_cbor_value(value: cbor.Value) -> Result(Mac0(Tagged), gose.GoseError) {
  use items <- result.try(cose_structure.parse_cose_array_value(
    value,
    expected_tag: 17,
    expected_length: 4,
  ))
  case items {
    [
      cbor.Bytes(protected_serialized),
      cbor.Map(unprotected_cbor),
      payload_value,
      cbor.Bytes(mac_tag),
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
      Ok(TaggedMac0(
        protected:,
        protected_serialized:,
        unprotected:,
        payload:,
        mac_tag:,
      ))
    }
    _ -> Error(gose.ParseError("invalid COSE_Mac0 structure"))
  }
}
