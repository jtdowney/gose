//// JWS JSON Serialization for multi-signer signing and verification
//// ([RFC 7515 Section 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1)).
////
//// ## Example
////
//// ```gleam
//// import gleam/json
//// import gose
//// import gose/jose/jws_multi
//// import kryptos/ec
//// import kryptos/eddsa
////
//// let payload = <<"hello":utf8>>
//// let k1 = gose.generate_ec(ec.P256)
//// let k2 = gose.generate_eddsa(eddsa.Ed25519)
////
//// let assert Ok(body) =
////   jws_multi.new(payload:)
////   |> jws_multi.sign(
////     gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)),
////     key: k1,
////   )
//// let assert Ok(body) =
////   body
////   |> jws_multi.sign(gose.DigitalSignature(gose.Eddsa), key: k2)
//// let multi = jws_multi.assemble(body)
////
//// let json_str = jws_multi.serialize_json(multi) |> json.to_string
//// let assert Ok(parsed) = jws_multi.parse_json(json_str)
//// let assert Ok(v) =
////   jws_multi.verifier(
////     gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)),
////     keys: [k1],
////   )
//// let assert Ok(Nil) = jws_multi.verify(v, parsed)
//// ```
////
//// ## Phantom States
////
//// `Body(Building)` supports payload configuration (`with_detached`). Calling
//// `sign` transitions the body to `Body(Signed)`, which `assemble` finalizes
//// into a serializable `MultiJws`. The type system prevents modifying the
//// body after any signature has been computed.
////
//// ## Algorithm Pinning
////
//// Each verifier is pinned to a single algorithm. The matched signer's
//// protected header `alg` must match the verifier's expected algorithm.

import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gose
import gose/internal/jws_payload
import gose/internal/key_helpers
import gose/internal/signing
import gose/internal/utils
import gose/jose

/// Phantom state: body under construction, no signatures yet.
pub type Building

/// Phantom state: body with at least one signature.
pub type Signed

/// Outer body for a multi-signer JWS, parameterized by signing state.
pub opaque type Body(state) {
  Body(
    payload: BitArray,
    detached: Bool,
    encoding: jws_payload.Encoding,
    signatures: List(Signature),
  )
}

type Signature {
  Signature(
    alg: gose.SigningAlg,
    protected_b64: String,
    signature: BitArray,
    encoding: jws_payload.Encoding,
  )
}

/// A multi-signer JWS message (JSON General Serialization).
pub opaque type MultiJws {
  MultiJws(
    payload: BitArray,
    payload_segment: String,
    signatures: List(Signature),
    detached: Bool,
    encoding: jws_payload.Encoding,
  )
}

/// A verifier pinned to a single algorithm and one or more keys.
pub opaque type Verifier {
  Verifier(alg: gose.SigningAlg, keys: List(gose.Key(String)))
}

/// Create a new body pinned to the payload all signers will sign.
pub fn new(payload payload: BitArray) -> Body(Building) {
  Body(
    payload:,
    detached: False,
    encoding: jws_payload.Base64Url,
    signatures: [],
  )
}

/// Mark the body as using a detached payload (RFC 7515 Appendix F).
///
/// The payload is still signed but omitted from the serialized JSON. Callers
/// verify with `verify_detached`, supplying the payload separately.
pub fn with_detached(body: Body(Building)) -> Body(Building) {
  Body(..body, detached: True)
}

/// Mark the body as using an unencoded payload (RFC 7797, b64=false).
///
/// Every signature carries `"crit":["b64"],"b64":false` and the serialized
/// payload holds the literal text. Signing fails unless it is valid UTF-8.
pub fn with_unencoded(body: Body(Building)) -> Body(Building) {
  Body(..body, encoding: jws_payload.Unencoded)
}

/// Compute a per-signer JWS signature over the body's payload and append it
/// to the body. Transitions the body to `Signed` state, preventing further
/// `with_*` mutations at compile time.
pub fn sign(
  body: Body(state),
  alg alg: gose.SigningAlg,
  key key: gose.Key(String),
) -> Result(Body(Signed), gose.GoseError) {
  use _ <- result.try(key_helpers.validate_signing_key_type(alg, key))
  use _ <- result.try(key_helpers.validate_key_use(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_ops(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_algorithm_signing(key, alg))

  use payload_segment <- result.try(jws_payload.encode(
    payload: body.payload,
    encoding: body.encoding,
  ))

  let protected_json = header_json(alg, body.encoding)
  let protected_b64 = utils.encode_base64_url(protected_json)
  let signing_input = protected_b64 <> "." <> payload_segment

  use sig <- result.try(signing.compute_signature(
    alg,
    key:,
    message: bit_array.from_string(signing_input),
  ))

  let signature =
    Signature(alg:, protected_b64:, signature: sig, encoding: body.encoding)
  Ok(
    Body(
      payload: body.payload,
      detached: body.detached,
      encoding: body.encoding,
      signatures: [signature, ..body.signatures],
    ),
  )
}

/// Finalize a signed body into a serializable multi-signer JWS.
pub fn assemble(body: Body(Signed)) -> MultiJws {
  let assert Ok(payload_segment) =
    jws_payload.encode(payload: body.payload, encoding: body.encoding)

  MultiJws(
    payload: body.payload,
    payload_segment:,
    signatures: list.reverse(body.signatures),
    detached: body.detached,
    encoding: body.encoding,
  )
}

/// Return the payload. Returns an empty `BitArray` for messages parsed with
/// a detached payload.
pub fn payload(message: MultiJws) -> BitArray {
  message.payload
}

/// Check whether the message was built or parsed with a detached payload.
pub fn is_detached(message: MultiJws) -> Bool {
  message.detached
}

/// Check if the message uses an unencoded payload (b64=false per RFC 7797).
pub fn has_unencoded_payload(message: MultiJws) -> Bool {
  message.encoding == jws_payload.Unencoded
}

/// Serialize as JWS JSON General Serialization. For messages built with
/// `with_detached`, the payload field is omitted.
pub fn serialize_json(message: MultiJws) -> json.Json {
  let sig_objects =
    list.map(message.signatures, fn(sig) {
      json.object([
        #("protected", json.string(sig.protected_b64)),
        #("signature", json.string(utils.encode_base64_url(sig.signature))),
      ])
    })

  let fields = case message.detached {
    True -> [#("signatures", json.preprocessed_array(sig_objects))]
    False -> [
      #("payload", json.string(message.payload_segment)),
      #("signatures", json.preprocessed_array(sig_objects)),
    ]
  }
  json.object(fields)
}

/// Parse a JWS from JSON General Serialization format. A missing `payload`
/// field indicates a detached payload per RFC 7515 Appendix F.
pub fn parse_json(json_str: String) -> Result(MultiJws, gose.GoseError) {
  let sig_decoder = {
    use protected <- decode.field("protected", decode.string)
    use signature <- decode.field("signature", decode.string)
    decode.success(#(protected, signature))
  }
  let decoder = {
    use payload <- decode.optional_field(
      "payload",
      option.None,
      decode.optional(decode.string),
    )
    use signatures <- decode.field("signatures", decode.list(sig_decoder))
    decode.success(#(payload, signatures))
  }

  use #(payload_b64_opt, raw_sigs) <- result.try(
    json.parse(json_str, decoder)
    |> result.replace_error(gose.ParseError("invalid JWS JSON")),
  )

  use signatures <- result.try(list.try_map(raw_sigs, parse_raw_signature))
  use encoding <- result.try(agreed_encoding(signatures))

  case payload_b64_opt {
    option.Some(payload_segment) -> {
      use payload <- result.try(jws_payload.decode(
        segment: payload_segment,
        encoding:,
      ))
      Ok(MultiJws(
        payload:,
        payload_segment:,
        signatures:,
        detached: False,
        encoding:,
      ))
    }
    option.None ->
      Ok(MultiJws(
        payload: <<>>,
        payload_segment: "",
        signatures:,
        detached: True,
        encoding:,
      ))
  }
}

fn agreed_encoding(
  signatures: List(Signature),
) -> Result(jws_payload.Encoding, gose.GoseError) {
  case signatures {
    [] -> Error(gose.ParseError("JWS JSON (general) has no signatures"))
    [first, ..rest] ->
      case list.all(rest, fn(sig) { sig.encoding == first.encoding }) {
        True -> Ok(first.encoding)
        False ->
          Error(gose.ParseError(
            "signatures disagree on b64; RFC 7797 requires a single value",
          ))
      }
  }
}

/// Build a verifier pinned to a single algorithm and one or more keys.
pub fn verifier(
  alg: gose.SigningAlg,
  keys keys: List(gose.Key(String)),
) -> Result(Verifier, gose.GoseError) {
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_signing_verification(
      alg,
      _,
    )),
  )
  Ok(Verifier(alg:, keys:))
}

/// Verify the first matching signer's signature.
///
/// Returns `InvalidState` if the message was parsed with a detached payload;
/// use `verify_detached` instead.
pub fn verify(
  verifier: Verifier,
  message: MultiJws,
) -> Result(Nil, gose.GoseError) {
  use <- bool.guard(
    when: message.detached,
    return: Error(gose.InvalidState(
      "JWS payload is detached; use verify_detached instead",
    )),
  )
  do_verify(verifier, message, message.payload_segment)
}

/// Verify a detached-payload JWS by supplying the payload at verify time.
pub fn verify_detached(
  verifier: Verifier,
  message message: MultiJws,
  payload payload: BitArray,
) -> Result(Nil, gose.GoseError) {
  use <- bool.guard(
    when: !message.detached,
    return: Error(gose.InvalidState(
      "JWS payload is not detached; use verify instead",
    )),
  )
  use payload_segment <- result.try(jws_payload.encode(
    payload:,
    encoding: message.encoding,
  ))
  do_verify(verifier, message, payload_segment)
}

fn do_verify(
  verifier: Verifier,
  message: MultiJws,
  payload_segment: String,
) -> Result(Nil, gose.GoseError) {
  let Verifier(alg: expected_alg, keys:) = verifier

  let matching =
    list.filter(message.signatures, fn(sig) { sig.alg == expected_alg })

  case matching {
    [] -> Error(gose.VerificationFailed)
    [sig, ..] -> {
      let signing_input = sig.protected_b64 <> "." <> payload_segment
      do_verify_keys(
        expected_alg,
        keys,
        bit_array.from_string(signing_input),
        sig.signature,
      )
    }
  }
}

fn header_json(
  alg: gose.SigningAlg,
  encoding: jws_payload.Encoding,
) -> BitArray {
  let b64_fields = case encoding {
    jws_payload.Unencoded -> [
      #("b64", json.bool(False)),
      #("crit", json.array(["b64"], json.string)),
    ]
    jws_payload.Base64Url -> []
  }

  [#("alg", json.string(jose.signing_alg_to_string(alg))), ..b64_fields]
  |> json.object
  |> json.to_string
  |> bit_array.from_string
}

fn parse_raw_signature(
  raw: #(String, String),
) -> Result(Signature, gose.GoseError) {
  let #(protected_b64, sig_b64) = raw
  use protected_bytes <- result.try(utils.decode_base64_url(
    protected_b64,
    name: "protected header",
  ))
  use #(alg, encoding) <- result.try(parse_protected_header(protected_bytes))
  use signature <- result.try(utils.decode_base64_url(
    sig_b64,
    name: "signature",
  ))
  Ok(Signature(alg:, protected_b64:, signature:, encoding:))
}

fn parse_protected_header(
  header_bytes: BitArray,
) -> Result(#(gose.SigningAlg, jws_payload.Encoding), gose.GoseError) {
  let decoder = {
    use alg_str <- decode.field("alg", decode.string)
    use crit <- decode.optional_field(
      "crit",
      option.None,
      decode.optional(decode.list(decode.string)),
    )
    use b64 <- decode.optional_field(
      "b64",
      option.None,
      decode.optional(decode.bool),
    )
    decode.success(#(alg_str, crit, b64))
  }
  use #(alg_str, crit, b64) <- result.try(
    json.parse_bits(header_bytes, decoder)
    |> result.replace_error(gose.ParseError("missing alg in protected header")),
  )
  use encoding <- result.try(jws_payload.encoding_from_headers(crit:, b64:))

  jose.signing_alg_from_string(alg_str)
  |> result.map(fn(alg) { #(alg, encoding) })
}

fn do_verify_keys(
  alg: gose.SigningAlg,
  keys: List(gose.Key(String)),
  message: BitArray,
  signature: BitArray,
) -> Result(Nil, gose.GoseError) {
  case keys {
    [] -> Error(gose.VerificationFailed)
    [key, ..rest] ->
      case signing.verify_signature(alg, key:, message:, signature:) {
        Ok(Nil) -> Ok(Nil)
        Error(gose.VerificationFailed) ->
          do_verify_keys(alg, rest, message, signature)
        Error(err) -> Error(err)
      }
  }
}
