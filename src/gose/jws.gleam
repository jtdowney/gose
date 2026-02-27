//// JSON Web Signature (JWS) - [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html)
////
//// This module provides digital signature functionality using all algorithms
//// from RFC 7518: HMAC (HS256/384/512), RSA (RS256/384/512, PS256/384/512),
//// ECDSA (ES256/384/512), and EdDSA.
////
//// ## Example
////
//// ```gleam
//// import gose/jws
//// import gose/jwa
//// import gose/jwk
////
//// let key = jwk.generate_hmac_key(jwa.HmacSha256)
//// let payload = <<"hello world":utf8>>
////
//// // Create and sign a JWS
//// let assert Ok(signed) = jws.new(jwa.JwsHmac(jwa.HmacSha256))
////   |> jws.sign(key, payload)
////
//// // Serialize to compact format
//// let assert Ok(token) = jws.serialize_compact(signed)
////
//// // Parse and verify using a Verifier
//// let assert Ok(parsed) = jws.parse_compact(token)
//// let assert Ok(verifier) = jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
//// let assert Ok(True) = jws.verify(verifier, parsed)
//// ```
////
//// ## Phantom Types
////
//// `Jws(state, origin)` uses two phantom type parameters:
////
//// - **State** tracks signing progress:
////   - `Unsigned` — created via `new`, ready to sign
////   - `Signed` — signed or parsed, can be serialized or verified
//// - **Origin** tracks how the JWS was obtained:
////   - `Built` — created via `new` and `sign`
////   - `Parsed` — obtained from `parse_compact` or `parse_json`
////
//// This prevents calling `decode_unprotected_header` on a builder-created JWS
//// (which has no raw JSON to decode from) and ensures `serialize_compact` only
//// accepts signed instances.
////
//// ## Algorithm Pinning
////
//// Each verifier is pinned to a single algorithm. This is a deliberate
//// security design, not a limitation. Algorithm confusion attacks
//// (e.g., CVE-2015-9235) exploit libraries that trust the `alg` header
//// from the token itself, allowing an attacker to switch from an asymmetric
//// algorithm to HMAC and sign with a public key. By requiring the caller
//// to declare the expected algorithm upfront, gose ensures the token's
//// `alg` header is verified against the application's intent, not the
//// other way around. This follows RFC 8725 Section 3.1: the algorithm
//// used for verification should be specified by the application, not
//// taken from the message.
////
//// Algorithm pinning is enforced at multiple levels:
////
//// 1. **Verifier pinning**: `verifier()` requires the expected algorithm;
////    tokens with different algorithms are rejected by `verify` and
////    `verify_detached`.
//// 2. **JWK `alg` metadata**: If a key has `alg` set via `jwk.with_alg`,
////    the JWS algorithm must match during signing and verification.
//// 3. **JWT verifier**: `jwt.verifier()` requires the expected algorithm upfront;
////    tokens with different algorithms are rejected.
//// 4. **Key type validation**: The key type must match the algorithm (RSA for
////    RS256, EC P-256 for ES256, etc.).
////
//// ### Multi-Algorithm Verification
////
//// When migrating between algorithms (e.g., RS256 to ES256) or consuming
//// tokens from issuers that use different algorithms, create one verifier
//// per algorithm and try each in sequence:
////
//// ```gleam
//// let assert Ok(rs_verifier) =
////   jws.verifier(jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256), keys: rsa_keys)
//// let assert Ok(ec_verifier) =
////   jws.verifier(jwa.JwsEcdsa(jwa.EcdsaP256), keys: ec_keys)
////
//// let assert Ok(parsed) = jws.parse_compact(token)
//// let result = case jws.verify(rs_verifier, parsed) {
////   Ok(True) -> Ok(True)
////   _ -> jws.verify(ec_verifier, parsed)
//// }
//// ```
////
//// This keeps each verifier's algorithm policy explicit and auditable,
//// rather than hiding multi-algorithm logic inside the library.
////
//// ## Custom Headers
////
//// Custom headers can be added via `with_header` when building a JWS. For
//// parsed JWS, use `decode_custom_headers` with a custom decoder to extract
//// header values. `with_header` rejects reserved names (`alg`, `kid`, `typ`,
//// `cty`, `crit`, `b64`) to prevent conflicts with standard behavior.
////
//// ## Unprotected Headers
////
//// Unprotected headers can be added via `with_unprotected` (for JSON serialization)
//// and accessed via `decode_unprotected_header`. When parsing JSON format,
//// unprotected header names must not overlap with protected header names.
////
//// **Security Warning:** Unprotected headers are NOT integrity protected.
//// They can be modified by an attacker without invalidating the signature.
//// Only use for non-security-critical metadata.
////
//// ## Critical Header Support
////
//// The `crit` header is validated per RFC 7515:
//// - Empty arrays are rejected
//// - Standard headers cannot appear in `crit`
//// - `b64` (RFC 7797 unencoded payload) is the only supported extension
//// - Unknown extensions are rejected
////
//// ## Key Metadata
////
//// JWK metadata (`use`, `key_ops`) is enforced during signing and verification.
//// Keys with incompatible metadata are rejected.
////
//// ## JSON Serialization Limitations
////
//// - **Single signature only**: General JSON Serialization rejects JWS with
////   multiple signatures. Use separate JWS objects for multi-signature needs.

import gleam/bit_array
import gleam/bool
import gleam/dict
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set
import gleam/string
import gose
import gose/internal/jws/signing
import gose/internal/key_helpers
import gose/internal/utils
import gose/jwa
import gose/jwk

const protected_only_headers = ["crit", "b64"]

const reserved_header_names = ["alg", "kid", "typ", "cty", "crit", "b64"]

/// Phantom type for JWS created via builder (new + sign).
pub type Built

/// Phantom type for JWS obtained by parsing a token.
pub type Parsed

/// Phantom type for signed JWS.
pub type Signed

/// Phantom type for unsigned JWS.
pub type Unsigned

type JwsHeader {
  JwsHeader(
    alg: jwa.JwsAlg,
    kid: Option(String),
    typ: Option(String),
    cty: Option(String),
    custom: dict.Dict(String, json.Json),
  )
}

/// A JSON Web Signature with phantom types for state and origin tracking.
///
/// The origin phantom type distinguishes between JWS created via builders
/// (`Built`) and JWS obtained by parsing tokens (`Parsed`). This enables
/// compile-time enforcement that `decode_unprotected_header` only works on
/// parsed instances.
pub opaque type Jws(state, origin) {
  UnsignedJws(
    header: JwsHeader,
    payload: BitArray,
    detached: Bool,
    unencoded_payload: Bool,
    unprotected: dict.Dict(String, json.Json),
  )
  SignedJws(
    header: JwsHeader,
    header_raw: Option(decode.Dynamic),
    payload: BitArray,
    detached: Bool,
    unencoded_payload: Bool,
    protected_b64: String,
    payload_segment: String,
    signature: BitArray,
    unprotected: dict.Dict(String, json.Json),
    unprotected_raw: Option(decode.Dynamic),
  )
}

/// A JWS verifier that enforces algorithm pinning and validates key compatibility.
///
/// Create with `verifier()`. The verifier validates that:
/// - All keys are compatible with the algorithm
/// - Each key's `use` field (if set) is `Signing`
/// - Each key's `key_ops` field (if set) includes `Verify`
pub opaque type Verifier {
  Verifier(alg: jwa.JwsAlg, keys: List(jwk.Jwk))
}

/// Create a new unsigned JWS with the specified signing algorithm. The payload
/// is provided at sign time via `sign`.
///
/// ## Parameters
///
/// - `alg` - The JWS signing algorithm to use (e.g., `jwa.JwsHmac(jwa.HmacSha256)`,
///   `jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256)`, `jwa.JwsEcdsa(jwa.EcdsaP256)`, `jwa.JwsEddsa`).
///
/// ## Returns
///
/// An unsigned `Jws` ready for signing.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(signed) = jws.new(jwa.JwsHmac(jwa.HmacSha256))
///   |> jws.sign(key, <<"hello":utf8>>)
/// ```
pub fn new(alg: jwa.JwsAlg) -> Jws(Unsigned, Built) {
  UnsignedJws(
    header: JwsHeader(alg:, kid: None, typ: None, cty: None, custom: dict.new()),
    payload: <<>>,
    detached: False,
    unencoded_payload: False,
    unprotected: dict.new(),
  )
}

/// Create a verifier for JWS signature verification.
///
/// Accepts one or more keys for key rotation scenarios. The verifier pins
/// the expected algorithm and will reject tokens with different algorithms.
///
/// Key selection during verification:
/// 1. If the JWS has a `kid` header, prioritize keys with matching kid
/// 2. Try keys in order until one succeeds
/// 3. Fail if no key verifies the signature
///
/// ## Parameters
///
/// - `alg` - The expected JWS signing algorithm. Tokens with a different
///   algorithm will be rejected during verification.
/// - `keys` - One or more JWKs to try during verification. Supports key
///   rotation by accepting multiple keys.
///
/// ## Returns
///
/// `Ok(Verifier)` with the configured verifier, or `Error(InvalidState)` if
/// the key list is empty, any key type is incompatible with the algorithm,
/// any key's `use` field is set but not `Signing`, or any key's `key_ops`
/// field is set but doesn't include `Verify`.
pub fn verifier(
  alg: jwa.JwsAlg,
  keys keys: List(jwk.Jwk),
) -> Result(Verifier, gose.GoseError) {
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_jws_verification(alg, _)),
  )
  Ok(Verifier(alg:, keys:))
}

/// Set the content type (cty) header parameter.
///
/// ## Parameters
///
/// - `jws` - The unsigned JWS.
/// - `cty` - The content type string (e.g. `"JWT"`).
///
/// ## Returns
///
/// The `Jws` with the `cty` header set.
pub fn with_cty(jws: Jws(Unsigned, Built), cty: String) -> Jws(Unsigned, Built) {
  map_unsigned_header(jws, fn(h) { JwsHeader(..h, cty: Some(cty)) })
}

/// Mark this JWS as using a detached payload.
///
/// The payload will not be included in the serialized output, but is still
/// provided at sign time and used for signature computation.
///
/// ## Parameters
///
/// - `jws` - The unsigned JWS to mark as detached.
///
/// ## Returns
///
/// The `Jws` configured for detached payload mode.
pub fn with_detached(jws: Jws(Unsigned, Built)) -> Jws(Unsigned, Built) {
  let assert UnsignedJws(
    header:,
    payload:,
    unencoded_payload:,
    unprotected:,
    ..,
  ) = jws
  UnsignedJws(
    header:,
    payload:,
    detached: True,
    unencoded_payload:,
    unprotected:,
  )
}

/// Add a custom protected header field.
///
/// Custom headers are sorted alphabetically by name and appear after standard fields (alg, kid, typ, cty).
/// Returns an error if the name is a reserved header (`alg`, `kid`, `typ`, `cty`,
/// `crit`, `b64`) to prevent security issues like algorithm confusion.
///
/// If the same header name is set multiple times, the last value wins.
///
/// ## Parameters
///
/// - `jws` - The unsigned JWS to add the header to.
/// - `name` - The header parameter name (must not be a reserved name).
/// - `value` - The JSON value for the header parameter.
///
/// ## Returns
///
/// `Ok(Jws(Unsigned, Built))` with the custom header added, or
/// `Error(InvalidState)` if the header name is reserved.
pub fn with_header(
  jws: Jws(Unsigned, Built),
  name: String,
  value: json.Json,
) -> Result(Jws(Unsigned, Built), gose.GoseError) {
  use <- bool.guard(
    when: list.contains(reserved_header_names, name),
    return: Error(gose.InvalidState(
      "cannot set reserved header via with_header: " <> name,
    )),
  )
  Ok(
    map_unsigned_header(jws, fn(h) {
      JwsHeader(..h, custom: dict.insert(h.custom, name, value))
    }),
  )
}

/// Set the key ID (kid) header parameter.
///
/// ## Parameters
///
/// - `jws` - The unsigned JWS.
/// - `kid` - The key identifier string.
///
/// ## Returns
///
/// The `Jws` with the `kid` header set.
pub fn with_kid(jws: Jws(Unsigned, Built), kid: String) -> Jws(Unsigned, Built) {
  map_unsigned_header(jws, fn(h) { JwsHeader(..h, kid: Some(kid)) })
}

/// Set the type (typ) header parameter (e.g., "JWT").
///
/// ## Parameters
///
/// - `jws` - The unsigned JWS.
/// - `typ` - The type string (e.g. `"JWT"`).
///
/// ## Returns
///
/// The `Jws` with the `typ` header set.
pub fn with_typ(jws: Jws(Unsigned, Built), typ: String) -> Jws(Unsigned, Built) {
  map_unsigned_header(jws, fn(h) { JwsHeader(..h, typ: Some(typ)) })
}

/// Mark this JWS as using an unencoded payload (RFC 7797, b64=false).
///
/// The payload will be included directly in the serialized output without
/// base64 encoding. The header will include `"crit":["b64"],"b64":false`.
/// The payload is still provided at sign time.
///
/// ## Parameters
///
/// - `jws` - The unsigned JWS to mark as unencoded.
///
/// ## Returns
///
/// The `Jws` configured for unencoded payload mode.
pub fn with_unencoded(jws: Jws(Unsigned, Built)) -> Jws(Unsigned, Built) {
  let assert UnsignedJws(header:, payload:, detached:, unprotected:, ..) = jws
  UnsignedJws(
    header:,
    payload:,
    detached:,
    unencoded_payload: True,
    unprotected:,
  )
}

/// Add an unprotected header field (for JSON serialization only).
///
/// **Security Warning:** Unprotected headers are NOT integrity protected.
/// They can be modified by an attacker without invalidating the signature.
/// Only use for non-security-critical metadata.
///
/// Returns an error if the name is a protected-only header (`crit`, `b64`) which
/// MUST be integrity protected per RFC 7515/7797.
///
/// Compact serialization will return an error if unprotected headers are present.
///
/// If the same header name is set multiple times, the last value wins.
///
/// ## Parameters
///
/// - `jws` - The unsigned JWS to add the unprotected header to.
/// - `name` - The header parameter name (must not be a protected-only header).
/// - `value` - The JSON value for the header parameter.
///
/// ## Returns
///
/// `Ok(Jws(Unsigned, Built))` with the unprotected header added, or
/// `Error(InvalidState)` if the header name is protected-only (`crit`, `b64`).
pub fn with_unprotected(
  jws: Jws(Unsigned, Built),
  name: String,
  value: json.Json,
) -> Result(Jws(Unsigned, Built), gose.GoseError) {
  use <- bool.guard(
    when: list.contains(protected_only_headers, name),
    return: Error(gose.InvalidState(
      "protected-only header cannot be in unprotected: " <> name,
    )),
  )
  let assert UnsignedJws(
    header:,
    payload:,
    detached:,
    unencoded_payload:,
    unprotected:,
  ) = jws
  Ok(UnsignedJws(
    header:,
    payload:,
    detached:,
    unencoded_payload:,
    unprotected: dict.insert(unprotected, name, value),
  ))
}

fn map_unsigned_header(
  jws: Jws(Unsigned, Built),
  f: fn(JwsHeader) -> JwsHeader,
) -> Jws(Unsigned, Built) {
  let assert UnsignedJws(
    header:,
    payload:,
    detached:,
    unencoded_payload:,
    unprotected:,
  ) = jws
  UnsignedJws(
    header: f(header),
    payload:,
    detached:,
    unencoded_payload:,
    unprotected:,
  )
}

/// Get the algorithm (`alg`) from a JWS.
///
/// ## Parameters
///
/// - `jws` - The JWS to read the algorithm from.
///
/// ## Returns
///
/// The `JwsAlg` signing algorithm.
pub fn alg(jws: Jws(state, origin)) -> jwa.JwsAlg {
  jws.header.alg
}

/// Get the content type (cty) from a JWS header.
///
/// ## Parameters
///
/// - `jws` - The JWS to read the content type from.
///
/// ## Returns
///
/// `Ok(String)` with the content type, or `Error(Nil)` if not set.
pub fn cty(jws: Jws(state, origin)) -> Result(String, Nil) {
  option.to_result(jws.header.cty, Nil)
}

/// Decode custom headers from a parsed JWS using a custom decoder.
///
/// This allows reading non-standard header fields that were present during parsing.
/// For JWS built via `new`, you already know what headers you set.
///
/// ## Parameters
///
/// - `jws` - A signed, parsed JWS containing header data to decode.
/// - `decoder` - A `decode.Decoder` for extracting custom header fields.
///
/// ## Returns
///
/// `Ok(a)` with the decoded custom header value, or `Error(ParseError)` if
/// no header data is available or decoding fails.
pub fn decode_custom_headers(
  jws: Jws(Signed, Parsed),
  decoder: decode.Decoder(a),
) -> Result(a, gose.GoseError) {
  let assert SignedJws(header_raw:, ..) = jws
  case header_raw {
    Some(raw) ->
      decode.run(raw, decoder)
      |> result.replace_error(gose.ParseError("failed to decode custom headers"))
    None -> Error(gose.ParseError("no header data available"))
  }
}

/// Decode the unprotected header using a custom decoder.
///
/// **Security Warning:** Unprotected headers are NOT integrity protected.
/// They can be modified by an attacker without invalidating the signature.
/// Only use for non-security-critical metadata.
///
/// This function only works on parsed JWS instances. When building a JWS,
/// you already know what unprotected headers you set - use `has_unprotected_header`
/// to check their presence.
///
/// ## Parameters
///
/// - `jws` - A signed, parsed JWS that may contain unprotected headers.
/// - `decoder` - A `decode.Decoder` for extracting unprotected header fields.
///
/// ## Returns
///
/// `Ok(a)` with the decoded unprotected header value, or `Error(ParseError)`
/// if no unprotected headers are present or decoding fails.
pub fn decode_unprotected_header(
  jws: Jws(Signed, Parsed),
  decoder: decode.Decoder(a),
) -> Result(a, gose.GoseError) {
  let assert SignedJws(unprotected_raw:, ..) = jws
  case unprotected_raw {
    Some(raw) ->
      decode.run(raw, decoder)
      |> result.replace_error(gose.ParseError(
        "failed to decode unprotected header",
      ))
    None -> Error(gose.ParseError("no unprotected headers present"))
  }
}

/// Check if the JWS has unprotected headers.
///
/// Returns True if the JWS was parsed from JSON with unprotected headers,
/// or if unprotected headers were added via `with_unprotected`.
///
/// ## Parameters
///
/// - `jws` - The signed JWS to check.
///
/// ## Returns
///
/// `True` if unprotected headers are present, `False` otherwise.
pub fn has_unprotected_header(jws: Jws(Signed, origin)) -> Bool {
  let assert SignedJws(unprotected:, unprotected_raw:, ..) = jws
  option.is_some(unprotected_raw) || !dict.is_empty(unprotected)
}

/// Check if the JWS has a detached payload.
///
/// ## Parameters
///
/// - `jws` - The JWS to check.
///
/// ## Returns
///
/// `True` if the JWS uses a detached payload, `False` otherwise.
pub fn is_detached(jws: Jws(state, origin)) -> Bool {
  case jws {
    UnsignedJws(detached:, ..) -> detached
    SignedJws(detached:, ..) -> detached
  }
}

/// Check if the JWS uses an unencoded payload (b64=false per RFC 7797).
///
/// ## Parameters
///
/// - `jws` - The JWS to check.
///
/// ## Returns
///
/// `True` if the JWS uses an unencoded payload, `False` otherwise.
pub fn has_unencoded_payload(jws: Jws(state, origin)) -> Bool {
  case jws {
    UnsignedJws(unencoded_payload:, ..) -> unencoded_payload
    SignedJws(unencoded_payload:, ..) -> unencoded_payload
  }
}

/// Get the key ID (kid) from a JWS header.
///
/// **Security Warning:** The `kid` value comes from the token and is untrusted
/// input. If you use it to look up keys (from a database, filesystem, or key
/// store), you must sanitize it first to prevent injection attacks:
/// - Use parameterized queries for database lookups
/// - Validate the format matches your expected key ID pattern
/// - Never use it directly in file paths or shell commands
///
/// ## Parameters
///
/// - `jws` - The JWS to read the key ID from.
///
/// ## Returns
///
/// `Ok(String)` with the key ID, or `Error(Nil)` if not set.
pub fn kid(jws: Jws(state, origin)) -> Result(String, Nil) {
  option.to_result(jws.header.kid, Nil)
}

/// Get the payload from a JWS.
///
/// ## Parameters
///
/// - `jws` - The JWS to read the payload from.
///
/// ## Returns
///
/// The payload as a `BitArray`.
pub fn payload(jws: Jws(state, origin)) -> BitArray {
  case jws {
    UnsignedJws(payload:, ..) -> payload
    SignedJws(payload:, ..) -> payload
  }
}

/// Get the type (typ) from a JWS header.
///
/// ## Parameters
///
/// - `jws` - The JWS to read the type from.
///
/// ## Returns
///
/// `Ok(String)` with the type, or `Error(Nil)` if not set.
pub fn typ(jws: Jws(state, origin)) -> Result(String, Nil) {
  option.to_result(jws.header.typ, Nil)
}

/// Sign an unsigned JWS with the provided key.
///
/// JWK metadata (`use`, `key_ops`) is enforced when present:
/// - Keys with `use=enc` are rejected
/// - Keys with `key_ops` that don't include `sign` are rejected
///
/// ## Parameters
///
/// - `jws` - The unsigned JWS to sign.
/// - `key` - The JWK to sign with. Must match the JWS algorithm.
/// - `payload` - The payload bytes to sign.
///
/// ## Returns
///
/// `Ok(Jws(Signed, Built))` with the signed JWS ready for serialization,
/// `Error(InvalidState)` on key type mismatch, metadata incompatibility, or
/// invalid UTF-8 in unencoded payload, or `Error(CryptoError)` if the signing
/// operation fails.
pub fn sign(
  jws: Jws(Unsigned, Built),
  key key: jwk.Jwk,
  payload payload: BitArray,
) -> Result(Jws(Signed, Built), gose.GoseError) {
  let assert UnsignedJws(
    header:,
    detached:,
    unencoded_payload:,
    unprotected:,
    ..,
  ) = jws

  use _ <- result.try(key_helpers.validate_jws_key_type(header.alg, key))
  use _ <- result.try(key_helpers.validate_key_use(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_ops(key, key_helpers.ForSigning))
  use _ <- result.try(key_helpers.validate_key_algorithm_jws(key, header.alg))

  let protected_json = header_to_json(header, unencoded_payload)
  let protected_b64 = utils.encode_base64_url(protected_json)

  use payload_segment <- result.try(
    encode_payload_segment(payload, unencoded_payload)
    |> result.replace_error(gose.InvalidState(
      "unencoded payload must be valid UTF-8",
    )),
  )
  let signing_input = protected_b64 <> "." <> payload_segment

  use signature <- result.try(signing.compute_signature(
    header.alg,
    key,
    bit_array.from_string(signing_input),
  ))

  Ok(SignedJws(
    header:,
    header_raw: None,
    payload:,
    protected_b64:,
    payload_segment:,
    signature:,
    detached:,
    unencoded_payload:,
    unprotected:,
    unprotected_raw: None,
  ))
}

fn do_verify(
  jws: Jws(Signed, origin),
  key key: jwk.Jwk,
) -> Result(Bool, gose.GoseError) {
  let assert SignedJws(
    header:,
    protected_b64:,
    payload_segment:,
    signature:,
    detached:,
    ..,
  ) = jws

  use _ <- result.try(key_helpers.validate_key_use(
    key,
    key_helpers.ForVerification,
  ))
  use _ <- result.try(key_helpers.validate_key_ops(
    key,
    key_helpers.ForVerification,
  ))
  use _ <- result.try(key_helpers.validate_key_algorithm_jws(key, header.alg))

  use <- bool.guard(
    detached,
    Error(gose.InvalidState(
      "Cannot verify detached JWS without payload. Use verify_detached instead.",
    )),
  )

  let signing_input = protected_b64 <> "." <> payload_segment
  signing.verify_signature(
    header.alg,
    key,
    bit_array.from_string(signing_input),
    signature,
  )
}

fn do_verify_with_payload(
  jws: Jws(Signed, origin),
  payload: BitArray,
  key key: jwk.Jwk,
) -> Result(Bool, gose.GoseError) {
  let assert SignedJws(
    header:,
    protected_b64:,
    signature:,
    unencoded_payload:,
    ..,
  ) = jws

  use _ <- result.try(key_helpers.validate_key_use(
    key,
    key_helpers.ForVerification,
  ))
  use _ <- result.try(key_helpers.validate_key_ops(
    key,
    key_helpers.ForVerification,
  ))
  use _ <- result.try(key_helpers.validate_key_algorithm_jws(key, header.alg))

  use payload_segment <- result.try(
    encode_payload_segment(payload, unencoded_payload)
    |> result.replace_error(gose.InvalidState(
      "unencoded payload must be valid UTF-8",
    )),
  )
  let signing_input = protected_b64 <> "." <> payload_segment
  signing.verify_signature(
    header.alg,
    key,
    bit_array.from_string(signing_input),
    signature,
  )
}

fn encode_payload_segment(
  payload: BitArray,
  unencoded: Bool,
) -> Result(String, Nil) {
  case unencoded {
    True -> bit_array.to_string(payload)
    False -> Ok(utils.encode_base64_url(payload))
  }
}

fn decode_payload_segment(
  segment: String,
  unencoded: Bool,
) -> Result(BitArray, gose.GoseError) {
  case unencoded {
    True -> Ok(bit_array.from_string(segment))
    False -> utils.decode_base64_url(segment, "payload")
  }
}

fn validate_optional_crit(
  crit: Option(List(String)),
  b64: Option(Bool),
) -> Result(Nil, gose.GoseError) {
  case crit {
    Some(crit_list) -> validate_crit(crit_list, b64)
    None -> Ok(Nil)
  }
}

/// Verify a JWS signature using the verifier.
///
/// Checks:
/// 1. Token's `alg` header matches the verifier's expected algorithm
/// 2. Signature is valid for one of the verifier's keys
///
/// When multiple keys are configured, keys with matching `kid` are tried first.
///
/// ## Parameters
///
/// - `verifier` - A `Verifier` created via `verifier()` with pinned algorithm
///   and keys.
/// - `jws` - The signed JWS to verify.
///
/// ## Returns
///
/// `Ok(True)` if the signature is valid for one of the verifier's keys,
/// `Ok(False)` if no key produced a valid signature, or `Error(GoseError)`
/// if the token's algorithm doesn't match the verifier's expected algorithm.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(v) =
///   jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
/// let assert Ok(parsed) = jws.parse_compact(token)
/// let assert Ok(True) = jws.verify(v, parsed)
/// ```
pub fn verify(
  verifier: Verifier,
  jws: Jws(Signed, origin),
) -> Result(Bool, gose.GoseError) {
  let Verifier(alg: expected_alg, keys:) = verifier
  use _ <- result.try(key_helpers.require_matching_jws_algorithm(
    expected_alg,
    alg(jws),
  ))

  let jws_kid = option.from_result(kid(jws))
  let ordered_keys = key_helpers.order_keys_by_kid(keys, jws_kid)
  try_verify_keys(jws, ordered_keys)
}

fn try_verify_keys(
  jws: Jws(Signed, origin),
  keys: List(jwk.Jwk),
) -> Result(Bool, gose.GoseError) {
  case keys {
    [] -> Ok(False)
    [key, ..rest] ->
      case do_verify(jws, key:) {
        Ok(True) -> Ok(True)
        Ok(False) -> try_verify_keys(jws, rest)
        Error(err) -> Error(err)
      }
  }
}

/// Verify a JWS with a detached payload using the verifier.
///
/// Use this when the payload was not included in the serialized JWS.
///
/// ## Parameters
///
/// - `verifier` - A `Verifier` created via `verifier()` with pinned algorithm
///   and keys.
/// - `jws` - The signed JWS with a detached payload to verify.
/// - `payload` - The detached payload bytes to verify against.
///
/// ## Returns
///
/// `Ok(True)` if the signature is valid for one of the verifier's keys,
/// `Ok(False)` if no key produced a valid signature, or `Error(GoseError)`
/// if the token's algorithm doesn't match the verifier's expected algorithm.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(v) =
///   jws.verifier(jwa.JwsHmac(jwa.HmacSha256), [key])
/// let assert Ok(parsed) = jws.parse_compact(detached_token)
/// let assert Ok(True) = jws.verify_detached(v, parsed, payload)
/// ```
pub fn verify_detached(
  verifier: Verifier,
  jws: Jws(Signed, origin),
  payload: BitArray,
) -> Result(Bool, gose.GoseError) {
  use <- bool.guard(
    when: !is_detached(jws),
    return: Error(gose.InvalidState(
      "JWS payload is not detached; use verify instead",
    )),
  )

  let Verifier(alg: expected_alg, keys:) = verifier
  use _ <- result.try(key_helpers.require_matching_jws_algorithm(
    expected_alg,
    alg(jws),
  ))

  let jws_kid = option.from_result(kid(jws))
  let ordered_keys = key_helpers.order_keys_by_kid(keys, jws_kid)
  try_verify_detached_keys(jws, payload, ordered_keys)
}

fn try_verify_detached_keys(
  jws: Jws(Signed, origin),
  payload: BitArray,
  keys: List(jwk.Jwk),
) -> Result(Bool, gose.GoseError) {
  case keys {
    [] -> Ok(False)
    [key, ..rest] ->
      case do_verify_with_payload(jws, payload, key:) {
        Ok(True) -> Ok(True)
        Ok(False) -> try_verify_detached_keys(jws, payload, rest)
        Error(err) -> Error(err)
      }
  }
}

fn header_to_json(header: JwsHeader, unencoded_payload: Bool) -> BitArray {
  let alg_field = #("alg", json.string(jwa.jws_alg_to_string(header.alg)))
  let optional_fields =
    list.filter_map(
      [
        option.map(header.kid, fn(k) { #("kid", json.string(k)) }),
        option.map(header.typ, fn(t) { #("typ", json.string(t)) }),
        option.map(header.cty, fn(c) { #("cty", json.string(c)) }),
      ],
      option.to_result(_, Nil),
    )

  let b64_fields = case unencoded_payload {
    True -> [
      #("b64", json.bool(False)),
      #("crit", json.array(["b64"], json.string)),
    ]
    False -> []
  }

  let fields =
    list.flatten([
      [alg_field],
      optional_fields,
      b64_fields,
      header.custom
        |> dict.to_list
        |> list.sort(fn(a, b) { string.compare(a.0, b.0) }),
    ])
  json.object(fields)
  |> json.to_string
  |> bit_array.from_string
}

/// Parse a JWS from compact format.
///
/// Returns a signed JWS that can be verified with a `Verifier`.
/// An empty payload segment (`header..signature`) is treated as a detached
/// payload; use `verify_detached` to verify with the out-of-band payload.
///
/// ## Parameters
///
/// - `token` - The compact serialization string
///   (`header.payload.signature`).
///
/// ## Returns
///
/// `Ok(Jws(Signed, Parsed))` with the parsed JWS ready for verification,
/// or `Error(ParseError)` if the token is malformed or the header is invalid.
pub fn parse_compact(
  token: String,
) -> Result(Jws(Signed, Parsed), gose.GoseError) {
  case string.split(token, ".") {
    [protected_b64, payload_b64, sig_b64] -> {
      let detached = payload_b64 == ""
      build_signed_jws(protected_b64, payload_b64, sig_b64, detached)
    }
    _ ->
      Error(gose.ParseError("invalid compact serialization: expected 3 parts"))
  }
}

/// Serialize a signed JWS to compact format.
///
/// Format: `{base64url(header)}.{base64url(payload)}.{base64url(signature)}`
///
/// For detached payloads: `{base64url(header)}..{base64url(signature)}`
///
/// For unencoded payloads (b64=false): `{base64url(header)}.{payload}.{base64url(signature)}`
///
/// Returns an error if the payload contains `.` characters when using b64=false,
/// as this would create an invalid compact serialization (RFC 7797).
/// Use JSON serialization instead for payloads containing periods.
///
/// ## Parameters
///
/// - `jws` - The signed JWS to serialize.
///
/// ## Returns
///
/// `Ok(String)` with the compact serialization string, or
/// `Error(InvalidState)` if unprotected headers are present (not supported
/// in compact format) or the unencoded payload contains `.` characters.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(token) = jws.serialize_compact(signed)
/// ```
pub fn serialize_compact(
  jws: Jws(Signed, Built),
) -> Result(String, gose.GoseError) {
  let assert SignedJws(
    protected_b64:,
    payload_segment:,
    signature:,
    detached:,
    unencoded_payload:,
    unprotected:,
    ..,
  ) = jws

  use <- bool.guard(
    when: !dict.is_empty(unprotected),
    return: Error(gose.InvalidState(
      "cannot serialize to compact format: unprotected headers are only supported in JSON serialization",
    )),
  )

  use <- bool.guard(
    when: unencoded_payload
      && !detached
      && string.contains(payload_segment, "."),
    return: Error(gose.InvalidState(
      "unencoded payload cannot contain '.' for compact serialization",
    )),
  )

  let sig_b64 = utils.encode_base64_url(signature)
  case detached {
    True -> Ok(protected_b64 <> ".." <> sig_b64)
    False -> Ok(protected_b64 <> "." <> payload_segment <> "." <> sig_b64)
  }
}

/// Serialize a signed JWS to JSON Flattened format.
///
/// Format: `{"payload":"...","protected":"...","signature":"..."}`
///
/// For detached payloads, the payload field is omitted.
/// If unprotected headers are present, includes the `header` field.
///
/// ## Parameters
///
/// - `jws` - The signed JWS to serialize.
///
/// ## Returns
///
/// A `json.Json` value representing the JWS in JSON Flattened Serialization.
/// Use `json.to_string` to convert to a JSON string.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(signed) =
///   jws.new(jwa.JwsHmac(jwa.HmacSha256))
///   |> jws.sign(key, payload)
/// let json_str =
///   jws.serialize_json_flattened(signed)
///   |> json.to_string
/// ```
pub fn serialize_json_flattened(jws: Jws(Signed, Built)) -> json.Json {
  let assert SignedJws(
    protected_b64:,
    payload_segment:,
    signature:,
    detached:,
    unprotected:,
    ..,
  ) = jws
  let sig_b64 = utils.encode_base64_url(signature)

  let base_fields = case detached {
    True -> [
      #("protected", json.string(protected_b64)),
      #("signature", json.string(sig_b64)),
    ]
    False -> [
      #("payload", json.string(payload_segment)),
      #("protected", json.string(protected_b64)),
      #("signature", json.string(sig_b64)),
    ]
  }

  let fields = case dict.is_empty(unprotected) {
    True -> base_fields
    False -> {
      let header_obj = json.object(dict.to_list(unprotected))
      [#("header", header_obj), ..base_fields]
    }
  }

  json.object(fields)
}

/// Serialize a signed JWS to JSON General format.
///
/// Format: `{"payload":"...","signatures":[{"protected":"...","signature":"..."}]}`
///
/// For detached payloads, the payload field is omitted.
/// If unprotected headers are present, includes the `header` field in the signature entry.
///
/// ## Parameters
///
/// - `jws` - The signed JWS to serialize.
///
/// ## Returns
///
/// A `json.Json` value representing the JWS in JSON General Serialization.
/// Use `json.to_string` to convert to a JSON string.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(signed) =
///   jws.new(jwa.JwsHmac(jwa.HmacSha256))
///   |> jws.sign(key, payload)
/// let json_str =
///   jws.serialize_json_general(signed)
///   |> json.to_string
/// ```
pub fn serialize_json_general(jws: Jws(Signed, Built)) -> json.Json {
  let assert SignedJws(
    protected_b64:,
    payload_segment:,
    signature:,
    detached:,
    unprotected:,
    ..,
  ) = jws
  let sig_b64 = utils.encode_base64_url(signature)

  let sig_base_fields = [
    #("protected", json.string(protected_b64)),
    #("signature", json.string(sig_b64)),
  ]

  let sig_fields = case dict.is_empty(unprotected) {
    True -> sig_base_fields
    False -> {
      let header_obj = json.object(dict.to_list(unprotected))
      [#("header", header_obj), ..sig_base_fields]
    }
  }

  let sig_obj = json.object(sig_fields)

  let fields = case detached {
    True -> [#("signatures", json.preprocessed_array([sig_obj]))]
    False -> [
      #("payload", json.string(payload_segment)),
      #("signatures", json.preprocessed_array([sig_obj])),
    ]
  }

  json.object(fields)
}

/// Parse a JWS from JSON format (supports both General and Flattened).
///
/// ## Parameters
///
/// - `json_str` - A JSON string in either General or Flattened JWS
///   Serialization format.
///
/// ## Returns
///
/// `Ok(Jws(Signed, Parsed))` with the parsed JWS ready for verification,
/// or `Error(ParseError)` if the JSON is malformed, the header is invalid,
/// or the General format contains multiple signatures.
pub fn parse_json(
  json_str: String,
) -> Result(Jws(Signed, Parsed), gose.GoseError) {
  case is_general_json_format(json_str) {
    True -> parse_json_general(json_str)
    False -> parse_json_flattened(json_str)
  }
}

fn build_signed_jws(
  protected_b64: String,
  payload_segment: String,
  sig_b64: String,
  detached: Bool,
) -> Result(Jws(Signed, Parsed), gose.GoseError) {
  use #(header, unencoded_payload, header_raw, _custom_keys) <- result.try(
    parse_protected_header(protected_b64),
  )
  use signature <- result.try(utils.decode_base64_url(sig_b64, "signature"))

  use payload <- result.try(decode_payload_segment(
    payload_segment,
    unencoded_payload,
  ))

  Ok(SignedJws(
    header:,
    header_raw:,
    payload:,
    protected_b64:,
    payload_segment:,
    signature:,
    detached:,
    unencoded_payload:,
    unprotected: dict.new(),
    unprotected_raw: None,
  ))
}

fn is_general_json_format(json_str: String) -> Bool {
  let detector = {
    use _ <- decode.field("signatures", decode.dynamic)
    decode.success(True)
  }
  json.parse(json_str, detector) |> result.is_ok
}

/// Known extensions that we support
const known_extensions = ["b64"]

fn parse_header_json(
  json_bits: BitArray,
) -> Result(
  #(JwsHeader, Bool, Option(decode.Dynamic), set.Set(String)),
  gose.GoseError,
) {
  let standard_decoder = {
    use alg <- decode.field("alg", decode.string)
    use kid <- decode.optional_field(
      "kid",
      None,
      decode.optional(decode.string),
    )
    use typ <- decode.optional_field(
      "typ",
      None,
      decode.optional(decode.string),
    )
    use cty <- decode.optional_field(
      "cty",
      None,
      decode.optional(decode.string),
    )
    use crit <- decode.optional_field(
      "crit",
      None,
      decode.optional(decode.list(decode.string)),
    )
    use b64 <- decode.optional_field("b64", None, decode.optional(decode.bool))
    decode.success(#(alg, kid, typ, cty, crit, b64))
  }

  use raw_dynamic <- result.try(
    json.parse_bits(json_bits, decode.dynamic)
    |> result.replace_error(gose.ParseError("invalid header JSON")),
  )

  use #(alg_str, kid, typ, cty, crit, b64) <- result.try(
    decode.run(raw_dynamic, standard_decoder)
    |> result.replace_error(gose.ParseError("invalid header JSON")),
  )

  use _ <- result.try(validate_optional_crit(crit, b64))

  let b64_in_crit =
    option.map(crit, list.contains(_, "b64"))
    |> option.unwrap(False)

  use <- bool.guard(
    when: option.is_some(b64) && !b64_in_crit,
    return: Error(gose.ParseError("b64 header present but not in crit")),
  )

  use alg <- result.try(jwa.jws_alg_from_string(alg_str))
  let unencoded_payload = b64 == Some(False)

  use all_keys <- result.try(
    decode.run(raw_dynamic, decode.dict(decode.string, decode.dynamic))
    |> result.replace_error(gose.ParseError("invalid header JSON")),
  )
  let custom_keys =
    dict.keys(all_keys)
    |> list.filter(fn(k) { !list.contains(reserved_header_names, k) })
    |> set.from_list

  Ok(#(
    JwsHeader(alg:, kid:, typ:, cty:, custom: dict.new()),
    unencoded_payload,
    Some(raw_dynamic),
    custom_keys,
  ))
}

fn parse_json_flattened(
  json_str: String,
) -> Result(Jws(Signed, Parsed), gose.GoseError) {
  let decoder = {
    use protected <- decode.field("protected", decode.string)
    use signature <- decode.field("signature", decode.string)
    use payload_opt <- decode.optional_field(
      "payload",
      None,
      decode.optional(decode.string),
    )
    use unprotected_header_raw <- decode.optional_field(
      "header",
      None,
      decode.optional(decode.dynamic),
    )
    decode.success(#(protected, signature, payload_opt, unprotected_header_raw))
  }

  use #(protected_b64, sig_b64, payload_opt, unprotected_header_raw) <- result.try(
    json.parse(json_str, decoder)
    |> result.replace_error(gose.ParseError("invalid JWS JSON (flattened)")),
  )

  use #(header, unencoded_payload, header_raw, custom_keys) <- result.try(
    parse_protected_header(protected_b64),
  )
  use #(unprotected, unprotected_raw) <- result.try(parse_unprotected_header(
    unprotected_header_raw,
    header,
    custom_keys,
  ))
  use signature <- result.try(utils.decode_base64_url(sig_b64, "signature"))

  let #(payload_b64, detached) = case payload_opt {
    Some(p) -> #(p, False)
    None -> #("", True)
  }
  use payload <- result.try(decode_payload_segment(
    payload_b64,
    unencoded_payload,
  ))
  Ok(SignedJws(
    header:,
    header_raw:,
    payload:,
    protected_b64:,
    payload_segment: payload_b64,
    signature:,
    detached:,
    unencoded_payload:,
    unprotected:,
    unprotected_raw:,
  ))
}

/// Parse a JWS from JSON General format.
///
/// **Note:** Only single signatures are supported. RFC 7515 defines
/// General Serialization to support multiple signatures per payload, but
/// this implementation rejects JWS JSON with more than one signature object.
fn parse_json_general(
  json_str: String,
) -> Result(Jws(Signed, Parsed), gose.GoseError) {
  let decoder = {
    use signatures <- decode.field(
      "signatures",
      decode.list(signature_decoder()),
    )
    use payload_opt <- decode.optional_field(
      "payload",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(signatures, payload_opt))
  }

  use #(signatures, payload_opt) <- result.try(
    json.parse(json_str, decoder)
    |> result.replace_error(gose.ParseError("invalid JWS JSON (general)")),
  )

  case signatures {
    [#(protected_b64, sig_b64, unprotected_header_raw)] -> {
      use #(header, unencoded_payload, header_raw, custom_keys) <- result.try(
        parse_protected_header(protected_b64),
      )
      use #(unprotected, unprotected_raw) <- result.try(
        parse_unprotected_header(unprotected_header_raw, header, custom_keys),
      )
      use signature <- result.try(utils.decode_base64_url(sig_b64, "signature"))

      let #(payload_b64, detached) = case payload_opt {
        Some(p) -> #(p, False)
        None -> #("", True)
      }
      use payload <- result.try(decode_payload_segment(
        payload_b64,
        unencoded_payload,
      ))
      Ok(SignedJws(
        header:,
        header_raw:,
        payload:,
        protected_b64:,
        payload_segment: payload_b64,
        signature:,
        detached:,
        unencoded_payload:,
        unprotected:,
        unprotected_raw:,
      ))
    }
    [_, _, ..] ->
      Error(gose.ParseError(
        "JWS JSON (general) has multiple signatures (not supported)",
      ))
    [] -> Error(gose.ParseError("JWS JSON (general) has no signatures"))
  }
}

fn parse_protected_header(
  b64: String,
) -> Result(
  #(JwsHeader, Bool, Option(decode.Dynamic), set.Set(String)),
  gose.GoseError,
) {
  use header_bits <- result.try(utils.decode_base64_url(b64, "header"))
  parse_header_json(header_bits)
}

/// Parse and validate unprotected headers, checking for disjointness with protected.
fn parse_unprotected_header(
  header_raw: Option(decode.Dynamic),
  protected: JwsHeader,
  protected_custom_keys: set.Set(String),
) -> Result(
  #(dict.Dict(String, json.Json), Option(decode.Dynamic)),
  gose.GoseError,
) {
  case header_raw {
    None -> Ok(#(dict.new(), None))
    Some(raw) -> {
      use unprotected_dict <- result.try(
        decode.run(raw, decode.dict(decode.string, decode.dynamic))
        |> result.replace_error(gose.ParseError(
          "unprotected header must be an object",
        )),
      )
      let unprotected_names = dict.keys(unprotected_dict)
      use _ <- result.try(validate_no_protected_only_headers(unprotected_names))
      use _ <- result.try(validate_header_disjointness(
        protected,
        protected_custom_keys,
        unprotected_names,
      ))
      Ok(#(dict.new(), Some(raw)))
    }
  }
}

fn signature_decoder() -> decode.Decoder(
  #(String, String, Option(decode.Dynamic)),
) {
  use protected <- decode.field("protected", decode.string)
  use signature <- decode.field("signature", decode.string)
  use header_raw <- decode.optional_field(
    "header",
    None,
    decode.optional(decode.dynamic),
  )
  decode.success(#(protected, signature, header_raw))
}

/// Standard JWS header parameters that must not appear in crit (RFC 7515 Section 4.1)
const standard_headers = [
  "alg",
  "jku",
  "jwk",
  "kid",
  "x5u",
  "x5c",
  "x5t",
  "x5t#S256",
  "typ",
  "cty",
  "crit",
]

fn validate_crit(
  crit: List(String),
  b64: Option(Bool),
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(utils.validate_crit_headers(
    crit,
    standard_headers,
    known_extensions,
  ))

  let crit_set = set.from_list(crit)
  case set.contains(crit_set, "b64") && option.is_none(b64) {
    True ->
      Error(gose.ParseError("b64 listed in crit but not present in header"))
    False -> Ok(Nil)
  }
}

/// Validate that unprotected header names don't overlap with protected header names.
fn validate_header_disjointness(
  protected: JwsHeader,
  protected_custom_keys: set.Set(String),
  unprotected_names: List(String),
) -> Result(Nil, gose.GoseError) {
  let optional_headers =
    list.filter_map(
      [
        option.map(protected.kid, fn(_) { "kid" }),
        option.map(protected.typ, fn(_) { "typ" }),
        option.map(protected.cty, fn(_) { "cty" }),
      ],
      option.to_result(_, Nil),
    )
  let protected_set =
    set.from_list(["alg", ..optional_headers])
    |> set.union(protected_custom_keys)
  let unprotected_set = set.from_list(unprotected_names)
  let overlap = set.intersection(protected_set, unprotected_set)
  case set.is_empty(overlap) {
    True -> Ok(Nil)
    False ->
      Error(gose.ParseError(
        "header names must be disjoint, overlap: "
        <> string.join(set.to_list(overlap), ", "),
      ))
  }
}

/// Validate that no protected-only headers appear in unprotected.
fn validate_no_protected_only_headers(
  names: List(String),
) -> Result(Nil, gose.GoseError) {
  let violations = list.filter(names, list.contains(protected_only_headers, _))
  case list.is_empty(violations) {
    True -> Ok(Nil)
    False ->
      Error(gose.ParseError(
        "protected-only headers in unprotected: "
        <> string.join(violations, ", "),
      ))
  }
}
