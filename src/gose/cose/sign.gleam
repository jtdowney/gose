//// COSE_Sign multi-signer signing and verification
//// ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)).
////
//// ## Example
////
//// ```gleam
//// import gose/algorithm
//// import gose/cose/sign
//// import gose/key
//// import kryptos/ec
////
//// let payload = <<"hello":utf8>>
//// let k1 = key.generate_ec(ec.P256)
//// let k2 = key.generate_ec(ec.P384)
////
//// let assert Ok(body) =
////   sign.new(payload:)
////   |> sign.sign(algorithm.Ecdsa(algorithm.EcdsaP256), key: k1)
//// let assert Ok(body) =
////   sign.sign(body, algorithm.Ecdsa(algorithm.EcdsaP384), key: k2)
//// let signed = sign.assemble(body)
////
//// let data = sign.serialize(signed)
//// let assert Ok(parsed) = sign.parse(data)
//// let assert Ok(verifier) =
////   sign.verifier(algorithm.Ecdsa(algorithm.EcdsaP256), keys: [k1])
//// let assert Ok(Nil) = sign.verify(verifier, parsed)
//// ```
////
//// ## Building, signing, assembling
////
//// `Body(state)` uses a phantom to enforce ordering:
//// 1. `new(payload:)` returns `Body(Building)`.
//// 2. `with_*` builders only accept `Body(Building)`, so configuration
////    happens before any signature is computed.
//// 3. `sign(body, alg, key)` computes a signature over the body and returns
////    `Body(Signed)`. Calling `sign` from either state yields `Signed`, so
////    subsequent signers just chain: `|> sign(_, alg2, key2)`.
//// 4. `assemble(body)` finalizes a `Body(Signed)` into `Sign(Signed)`.
////
//// Because builders require `Body(Building)`, mutating the body after any
//// `sign` call is a compile error. The body each signer signed over matches
//// the body that gets serialized on the wire.
////
//// ## Algorithm Pinning
////
//// Each verifier is pinned to a single signature algorithm. The matched
//// signer's protected header `alg` must match the verifier's expected algorithm.

import gleam/list
import gleam/option.{type Option}
import gleam/result
import gose
import gose/algorithm
import gose/cbor
import gose/cose
import gose/cose/algorithm as cose_algorithm
import gose/internal/cose_structure
import gose/internal/key_helpers
import gose/internal/signing
import gose/key

/// Phantom type: body under construction, no signatures yet.
pub type Building

/// Phantom type: body with at least one signature, or a finalized message.
pub type Signed

/// Outer message body holding body-level protected and unprotected headers,
/// the payload, and any accumulated signatures.
pub opaque type Body(state) {
  Body(
    protected: List(cose.Header),
    unprotected: List(cose.Header),
    detached: Bool,
    aad: BitArray,
    payload: BitArray,
    signatures: List(Signature),
  )
}

type Signature {
  Signature(
    protected: List(cose.Header),
    protected_serialized: BitArray,
    unprotected: List(cose.Header),
    signature: BitArray,
  )
}

/// A COSE_Sign message parameterized by signing state.
pub opaque type Sign(state) {
  SignedSign(
    protected: List(cose.Header),
    protected_serialized: BitArray,
    unprotected: List(cose.Header),
    payload: Option(BitArray),
    signatures: List(Signature),
  )
}

/// Holds an algorithm and set of keys for verifying a COSE_Sign message.
pub opaque type Verifier {
  Verifier(alg: algorithm.DigitalSignatureAlg, keys: List(key.Key(BitArray)))
}

/// Create a new body pinned to the payload all signers will sign.
pub fn new(payload payload: BitArray) -> Body(Building) {
  Body(
    protected: [],
    unprotected: [],
    detached: False,
    aad: <<>>,
    payload:,
    signatures: [],
  )
}

/// Mark the message for detached payload. The payload captured on
/// `new(payload:)` is still covered by each signature, but `assemble`
/// omits it from the serialized output.
pub fn with_detached(body: Body(Building)) -> Body(Building) {
  Body(..body, detached: True)
}

/// Set external additional authenticated data (AAD) for the signing operation.
pub fn with_aad(body: Body(Building), aad aad: BitArray) -> Body(Building) {
  Body(..body, aad:)
}

/// Add a key ID to the body's unprotected headers.
pub fn with_kid(body: Body(Building), kid kid: BitArray) -> Body(Building) {
  Body(..body, unprotected: [cose.Kid(kid), ..body.unprotected])
}

/// Add a content type to the body's unprotected headers.
///
/// RFC 9052 permits either bucket. Signed messages place it in unprotected,
/// consistent with `with_kid`.
pub fn with_content_type(
  body: Body(Building),
  ct ct: cose.ContentType,
) -> Body(Building) {
  Body(..body, unprotected: [cose.ContentType(ct), ..body.unprotected])
}

/// Add critical header labels to the body's protected headers.
pub fn with_critical(
  body: Body(Building),
  labels labels: List(Int),
) -> Body(Building) {
  Body(..body, protected: [cose.Crit(labels), ..body.protected])
}

/// Compute a per-signer signature over the body's payload and append it to
/// the body. Transitions the body to `Signed` state, preventing further
/// `with_*` mutations at compile time.
pub fn sign(
  body: Body(state),
  alg alg: algorithm.DigitalSignatureAlg,
  key key: key.Key(BitArray),
) -> Result(Body(Signed), gose.GoseError) {
  let signing_alg = algorithm.DigitalSignature(alg)
  use _ <- result.try(key_helpers.validate_signing_key_type(signing_alg, key))
  use _ <- result.try(key_helpers.validate_key_use(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_ops(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_algorithm_signing(
    key,
    signing_alg,
  ))

  let alg_id = cose_algorithm.signature_alg_to_int(alg)
  let sign_protected = [cose.Alg(alg_id)]
  let sign_protected_serialized =
    cose_structure.serialize_protected(sign_protected)
  let body_protected_serialized =
    cose_structure.serialize_protected(body.protected)

  let to_sign =
    build_sig_structure(
      body_protected_serialized,
      sign_protected_serialized,
      body.aad,
      body.payload,
    )

  use sig_bytes <- result.try(signing.compute_signature(
    signing_alg,
    key:,
    message: to_sign,
  ))

  let signature =
    Signature(
      protected: sign_protected,
      protected_serialized: sign_protected_serialized,
      unprotected: [],
      signature: sig_bytes,
    )

  Ok(
    Body(
      protected: body.protected,
      unprotected: body.unprotected,
      detached: body.detached,
      aad: body.aad,
      payload: body.payload,
      signatures: [signature, ..body.signatures],
    ),
  )
}

/// Finalize a signed body into a serializable COSE_Sign message.
pub fn assemble(body: Body(Signed)) -> Sign(Signed) {
  let protected_serialized = cose_structure.serialize_protected(body.protected)

  let stored_payload = case body.detached {
    True -> option.None
    False -> option.Some(body.payload)
  }

  SignedSign(
    protected: body.protected,
    protected_serialized:,
    unprotected: body.unprotected,
    payload: stored_payload,
    signatures: list.reverse(body.signatures),
  )
}

/// Return the payload from a signed message. Returns `Error(Nil)` if detached.
pub fn payload(message: Sign(Signed)) -> Result(BitArray, Nil) {
  let SignedSign(payload:, ..) = message
  option.to_result(payload, Nil)
}

/// Extract the key ID from the body-level headers.
pub fn kid(message: Sign(Signed)) -> Result(BitArray, gose.GoseError) {
  let SignedSign(protected:, unprotected:, ..) = message
  cose.kid(list.append(protected, unprotected))
}

/// Extract the content type from the body-level headers.
pub fn content_type(
  message: Sign(Signed),
) -> Result(cose.ContentType, gose.GoseError) {
  let SignedSign(protected:, unprotected:, ..) = message
  cose.content_type(list.append(protected, unprotected))
}

/// Extract the critical header labels from the body-level headers.
pub fn critical(message: Sign(Signed)) -> Result(List(Int), gose.GoseError) {
  let SignedSign(protected:, unprotected:, ..) = message
  cose.critical(list.append(protected, unprotected))
}

/// Return the raw body-level protected headers.
pub fn protected_headers(message: Sign(Signed)) -> List(cose.Header) {
  let SignedSign(protected:, ..) = message
  protected
}

/// Return the raw body-level unprotected headers.
pub fn unprotected_headers(message: Sign(Signed)) -> List(cose.Header) {
  let SignedSign(unprotected:, ..) = message
  unprotected
}

/// Encode a signed message as an untagged CBOR COSE_Sign array.
pub fn serialize(message: Sign(Signed)) -> BitArray {
  cbor.encode(to_cbor_value(message))
}

/// Encode a signed message as a CBOR-tagged (tag 98) COSE_Sign structure.
pub fn serialize_tagged(message: Sign(Signed)) -> BitArray {
  cbor.encode(cbor.Tag(98, to_cbor_value(message)))
}

fn to_cbor_value(message: Sign(Signed)) -> cbor.Value {
  let SignedSign(protected_serialized:, unprotected:, payload:, signatures:, ..) =
    message

  let payload_value = case payload {
    option.Some(p) -> cbor.Bytes(p)
    option.None -> cbor.Null
  }

  cbor.Array([
    cbor.Bytes(protected_serialized),
    cbor.Map(cose.headers_to_cbor(unprotected)),
    payload_value,
    cbor.Array(list.map(signatures, serialize_signature)),
  ])
}

/// Decode a CBOR-encoded COSE_Sign message, accepting both tagged and untagged forms.
pub fn parse(data: BitArray) -> Result(Sign(Signed), gose.GoseError) {
  use value <- result.try(cbor.decode(data))
  parse_cbor_value(value)
}

/// Build a verifier pinned to a single signature algorithm and one or more keys.
pub fn verifier(
  alg: algorithm.DigitalSignatureAlg,
  keys keys: List(key.Key(BitArray)),
) -> Result(Verifier, gose.GoseError) {
  let signing_alg = algorithm.DigitalSignature(alg)
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_signing_verification(
      signing_alg,
      _,
    )),
  )
  Ok(Verifier(alg:, keys:))
}

/// Verify the first matching signer's signature.
pub fn verify(
  verifier: Verifier,
  message: Sign(Signed),
) -> Result(Nil, gose.GoseError) {
  verify_with_aad(verifier, message:, aad: <<>>)
}

/// Verify with externally-supplied AAD.
pub fn verify_with_aad(
  verifier: Verifier,
  message message: Sign(Signed),
  aad aad: BitArray,
) -> Result(Nil, gose.GoseError) {
  let SignedSign(
    protected:,
    protected_serialized:,
    unprotected:,
    signatures:,
    payload:,
  ) = message
  use _ <- result.try(cose_structure.validate_crit(protected, unprotected))
  use payload_bytes <- result.try(cose_structure.require_embedded_payload(
    payload,
  ))
  try_verify_signers(
    verifier,
    signatures,
    protected_serialized,
    aad,
    payload_bytes,
  )
}

/// Verify a detached-payload message.
pub fn verify_detached(
  verifier: Verifier,
  message message: Sign(Signed),
  payload payload: BitArray,
) -> Result(Nil, gose.GoseError) {
  verify_detached_with_aad(verifier, message:, payload:, aad: <<>>)
}

/// Verify a detached-payload message with external AAD.
pub fn verify_detached_with_aad(
  verifier: Verifier,
  message message: Sign(Signed),
  payload payload: BitArray,
  aad aad: BitArray,
) -> Result(Nil, gose.GoseError) {
  let SignedSign(
    protected:,
    protected_serialized:,
    unprotected:,
    signatures:,
    payload: existing_payload,
  ) = message
  use _ <- result.try(cose_structure.validate_crit(protected, unprotected))
  use _ <- result.try(cose_structure.require_detached_payload(existing_payload))
  try_verify_signers(verifier, signatures, protected_serialized, aad, payload)
}

fn try_verify_signers(
  verifier: Verifier,
  signatures: List(Signature),
  body_protected: BitArray,
  aad: BitArray,
  payload: BitArray,
) -> Result(Nil, gose.GoseError) {
  let Verifier(alg: expected_alg, keys:) = verifier
  let signing_alg = algorithm.DigitalSignature(expected_alg)

  let matching =
    list.filter(signatures, fn(sig) {
      cose_structure.extract_signature_alg_from_headers(sig.protected)
      == Ok(expected_alg)
    })

  do_verify_signers(
    matching,
    signing_alg,
    keys,
    body_protected,
    aad,
    payload,
    Error(gose.VerificationFailed),
  )
}

fn do_verify_signers(
  signatures: List(Signature),
  signing_alg: algorithm.SigningAlg,
  keys: List(key.Key(BitArray)),
  body_protected: BitArray,
  aad: BitArray,
  payload: BitArray,
  last_error: Result(Nil, gose.GoseError),
) -> Result(Nil, gose.GoseError) {
  case signatures {
    [] -> last_error
    [sig, ..rest] ->
      case
        try_verify_one_signature(
          sig,
          signing_alg,
          keys,
          body_protected,
          aad,
          payload,
        )
      {
        Ok(Nil) -> Ok(Nil)
        Error(gose.VerificationFailed as e) | Error(gose.CryptoError(_) as e) ->
          do_verify_signers(
            rest,
            signing_alg,
            keys,
            body_protected,
            aad,
            payload,
            Error(e),
          )
        Error(e) -> Error(e)
      }
  }
}

fn try_verify_one_signature(
  sig: Signature,
  signing_alg: algorithm.SigningAlg,
  keys: List(key.Key(BitArray)),
  body_protected: BitArray,
  aad: BitArray,
  payload: BitArray,
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(cose_structure.validate_crit(
    sig.protected,
    sig.unprotected,
  ))
  let to_verify =
    build_sig_structure(body_protected, sig.protected_serialized, aad, payload)
  cose_structure.try_verify_keys(
    signing_alg,
    keys:,
    message: to_verify,
    signature: sig.signature,
  )
}

fn build_sig_structure(
  body_protected: BitArray,
  sign_protected: BitArray,
  aad: BitArray,
  payload: BitArray,
) -> BitArray {
  cbor.encode(
    cbor.Array([
      cbor.Text("Signature"),
      cbor.Bytes(body_protected),
      cbor.Bytes(sign_protected),
      cbor.Bytes(aad),
      cbor.Bytes(payload),
    ]),
  )
}

fn serialize_signature(sig: Signature) -> cbor.Value {
  cbor.Array([
    cbor.Bytes(sig.protected_serialized),
    cbor.Map(cose.headers_to_cbor(sig.unprotected)),
    cbor.Bytes(sig.signature),
  ])
}

fn parse_cbor_value(value: cbor.Value) -> Result(Sign(Signed), gose.GoseError) {
  use items <- result.try(cose_structure.parse_cose_array_value(
    value,
    expected_tag: 98,
    expected_length: 4,
  ))
  case items {
    [
      cbor.Bytes(protected_serialized),
      cbor.Map(unprotected_pairs),
      payload_value,
      cbor.Array(signature_values),
    ] -> {
      use protected <- result.try(cose_structure.decode_protected(
        protected_serialized,
      ))
      use unprotected <- result.try(cose_structure.decode_unprotected(
        unprotected_pairs,
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
      use signatures <- result.try(list.try_map(
        signature_values,
        parse_signature,
      ))
      Ok(SignedSign(
        protected:,
        protected_serialized:,
        unprotected:,
        payload:,
        signatures:,
      ))
    }
    _ -> Error(gose.ParseError("invalid COSE_Sign structure"))
  }
}

fn parse_signature(value: cbor.Value) -> Result(Signature, gose.GoseError) {
  case value {
    cbor.Array([
      cbor.Bytes(protected_serialized),
      cbor.Map(unprotected_pairs),
      cbor.Bytes(signature),
    ]) -> {
      use protected <- result.try(cose_structure.decode_protected(
        protected_serialized,
      ))
      use unprotected <- result.try(cose_structure.decode_unprotected(
        unprotected_pairs,
      ))
      use _ <- result.try(cose_structure.validate_no_header_overlap(
        protected,
        unprotected,
      ))
      use _ <- result.try(cose_structure.validate_iv_partial_iv_exclusion(
        protected,
        unprotected,
      ))
      Ok(Signature(protected:, protected_serialized:, unprotected:, signature:))
    }
    _ -> Error(gose.ParseError("invalid COSE_Signature structure"))
  }
}
