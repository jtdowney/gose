//// JSON Web Token (JWT) - [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)
////
//// This module provides JWT functionality built on top of JWS for signing
//// and verification. JWTs are a compact, URL-safe means of representing
//// claims to be transferred between two parties.
////
//// ## Phantom Types
////
//// JWT uses phantom types to enforce compile-time safety:
//// - `Jwt(Unverified)` - A JWT that has been parsed but not yet verified
//// - `Jwt(Verified)` - A JWT with verified signature, safe to trust claims
////
//// ## Example
////
//// ```gleam
//// import gleam/dynamic/decode
//// import gleam/time/duration
//// import gleam/time/timestamp
//// import gose/jwa
//// import gose/jwk
//// import gose/jwt
////
//// let key = jwk.generate_hmac_key(jwa.HmacSha256)
//// let now = timestamp.system_time()
////
//// // Create claims and sign
//// let claims = jwt.claims()
////   |> jwt.with_subject("user123")
////   |> jwt.with_issuer("my-app")
////   |> jwt.with_expiration(timestamp.add(now, duration.hours(1)))
////
//// let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
//// let token = jwt.serialize(signed)
////
//// // Verify and validate using Verifier (enforces algorithm pinning)
//// let assert Ok(verifier) = jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
//// let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)
////
//// // Decode verified claims
//// let decoder = {
////   use sub <- decode.field("sub", decode.string)
////   decode.success(sub)
//// }
//// let assert Ok(subject) = jwt.decode(verified, decoder)
//// ```

import gleam/bit_array
import gleam/bool
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/float
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import gose
import gose/internal/key_helpers
import gose/jwa
import gose/jwk
import gose/jws

const reserved_claims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

/// JWT error type with structured variants for domain-specific errors.
///
/// Used by both signed JWTs (`jwt` module) and encrypted JWTs (`encrypted_jwt`
/// module). Provides rich variants for validation errors (expiration, audience,
/// issuer, etc.) and wraps underlying JOSE layer errors via `JoseError`.
///
/// ## Example
///
/// ```gleam
/// case jwt.verify_and_validate(verifier, token, now) {
///   Ok(verified) -> io.println("Success!")
///   Error(jwt.TokenExpired(at)) -> io.println("Token expired")
///   Error(jwt.InvalidSignature) -> io.println("Bad signature")
///   Error(jwt.JoseError(gose_err)) -> io.println("JOSE error: " <> gose.error_message(gose_err))
///   Error(e) -> io.println("Error: " <> string.inspect(e))
/// }
/// ```
pub type JwtError {
  /// The JWS signature did not verify against any of the provided keys.
  InvalidSignature
  /// JWE decryption failed (wrong key, corrupted ciphertext, etc.).
  DecryptionFailed(reason: String)
  /// The `exp` claim is in the past.
  TokenExpired(expired_at: Timestamp)
  /// The `nbf` claim is in the future.
  TokenNotYetValid(valid_from: Timestamp)
  /// The `exp` claim is required by the verifier but absent.
  MissingExpiration
  /// The `iat` claim is required by the verifier but absent.
  MissingIssuedAt
  /// The `iat` claim is in the future.
  IssuedInFuture(issued_at: Timestamp)
  /// The token age (now − `iat`) exceeds the configured `max_age` in seconds.
  TokenTooOld(issued_at: Timestamp, max_age: Int)
  /// The `jti` claim is empty or otherwise invalid.
  InvalidJti(jti: String)
  /// The `iss` claim does not match the expected issuer.
  IssuerMismatch(expected: String, actual: Option(String))
  /// The `aud` claim does not contain the expected audience.
  AudienceMismatch(expected: String, actual: Option(List(String)))
  /// The token's JWS algorithm does not match the expected algorithm.
  JwsAlgorithmMismatch(expected: jwa.JwsAlg, actual: jwa.JwsAlg)
  /// The token's JWE algorithm or encryption does not match expected values.
  JweAlgorithmMismatch(
    expected_alg: jwa.JweAlg,
    expected_enc: jwa.Enc,
    actual_alg: jwa.JweAlg,
    actual_enc: jwa.Enc,
  )
  /// A `kid` header is required for key lookup but absent from the token.
  MissingKid
  /// The token's `kid` does not match any key in the provided set.
  UnknownKid(kid: String)
  /// The token could not be parsed (invalid compact serialization, bad
  /// base64, malformed header JSON, etc.).
  MalformedToken(reason: String)
  /// The claims payload is valid JSON but a required field is missing or
  /// has an unexpected type.
  ClaimDecodingFailed(reason: String)
  /// A security-sensitive header (e.g. `alg`) appears in the unprotected
  /// header, which is not integrity-protected.
  InsecureUnprotectedHeader(header: String)
  /// A claim value is invalid (empty audience list, reserved claim name, etc.).
  InvalidClaim(reason: String)
  /// An error from the underlying JOSE layer (JWS, JWE, or JWK).
  JoseError(error: gose.GoseError)
}

/// Convert a JOSE error to a MalformedToken error.
@internal
pub fn gose_error_to_malformed_token_error(err: gose.GoseError) -> JwtError {
  MalformedToken(gose.error_message(err))
}

/// Phantom type for unverified JWT.
pub type Unverified

/// Phantom type for verified JWT.
pub type Verified

/// JWT claims set.
///
/// Contains the registered claims from RFC 7519 and supports custom claims.
pub opaque type Claims {
  Claims(
    iss: Option(String),
    sub: Option(String),
    aud: Option(List(String)),
    exp: Option(Int),
    nbf: Option(Int),
    iat: Option(Int),
    jti: Option(String),
    custom: Dict(String, Json),
  )
}

/// A JSON Web Token with phantom type for state tracking.
pub opaque type Jwt(state) {
  Jwt(alg: jwa.JwsAlg, kid: Option(String), claims: Claims, token: String)
}

/// Policy for kid (Key ID) header validation during JWT verification.
pub type KidPolicy {
  /// No kid requirement - prioritize matching keys but try all (default)
  NoKidRequirement
  /// Token must have a kid header, but it doesn't need to match a configured key
  RequireKid
  /// Token must have a kid header AND it must match a configured key's kid
  RequireKidMatch
}

/// Options for JWT validation.
pub type JwtValidationOptions {
  JwtValidationOptions(
    /// Expected `iss` claim. If `Some`, the token's issuer must match exactly
    /// or `IssuerMismatch` is returned. `None` skips the check.
    issuer: Option(String),
    /// Expected `aud` claim. If `Some`, the token's audience list must contain
    /// this value or `AudienceMismatch` is returned. `None` skips the check.
    audience: Option(String),
    /// Tolerance in seconds for time-based checks (`exp`, `nbf`, `iat`).
    /// Accounts for clock drift between issuer and verifier.
    clock_skew: Int,
    /// Whether the `exp` claim must be present. If `True` and absent,
    /// `MissingExpiration` is returned.
    require_exp: Bool,
    /// Maximum allowed token age in seconds (now − `iat`). If `Some`, tokens
    /// older than this are rejected with `TokenTooOld`. Requires `iat` to be
    /// present; returns `MissingIssuedAt` if absent.
    max_token_age: Option(Int),
    /// Custom validation function for the `jti` (JWT ID) claim. Receives the
    /// `jti` value; return `True` to accept, `False` to reject with
    /// `InvalidJti`. Useful for replay detection.
    jti_validator: Option(fn(String) -> Bool),
    /// Controls how the `kid` header is handled for key selection. See
    /// `KidPolicy` for the available modes.
    kid_policy: KidPolicy,
  )
}

/// A JWT verifier that enforces algorithm pinning and validates key compatibility.
///
/// Create with `verifier()`. The verifier validates that:
/// - All keys are compatible with the algorithm
/// - Each key's `use` field (if set) is `Signing`
/// - Each key's `key_ops` field (if set) includes `Verify`
pub opaque type Verifier {
  Verifier(alg: jwa.JwsAlg, keys: List(jwk.Jwk), options: JwtValidationOptions)
}

/// Create default validation options.
///
/// Default settings:
/// - No issuer validation
/// - No audience validation
/// - 60 seconds clock skew tolerance
/// - Expiration claim required
/// - No max token age
/// - No JWT ID validator
/// - No kid requirement (prioritizes matching keys but tries all)
///
/// When an `iat` claim is present, it is always checked to ensure it is not
/// in the future (beyond clock skew), regardless of whether `max_token_age`
/// is configured.
pub fn default_validation() -> JwtValidationOptions {
  JwtValidationOptions(
    issuer: None,
    audience: None,
    clock_skew: 60,
    require_exp: True,
    max_token_age: None,
    jti_validator: None,
    kid_policy: NoKidRequirement,
  )
}

/// Set a custom JWT ID (jti) validator.
///
/// The validator function receives the `jti` claim value and should return
/// `True` if the ID is valid, `False` if it should be rejected.
///
/// Common use cases:
/// - Check against a revocation list
/// - Verify the ID hasn't been seen before (replay prevention)
/// - Validate format/structure of the ID
///
/// If the token has no `jti` claim, the validator is not called.
///
/// ## Parameters
///
/// - `options` - The validation options to update.
/// - `validator` - A function that receives the `jti` value and returns
///   `True` if valid.
///
/// ## Returns
///
/// The updated `JwtValidationOptions` with the custom jti validator.
pub fn with_jti_validator(
  options: JwtValidationOptions,
  validator: fn(String) -> Bool,
) -> JwtValidationOptions {
  JwtValidationOptions(..options, jti_validator: Some(validator))
}

/// Set the maximum token age in seconds.
///
/// If set, tokens with an `iat` claim older than `now - max_age_seconds` will
/// be rejected with `TokenTooOld`. Requires the `iat` claim to be present.
/// Tokens without `iat` are rejected with `MissingIssuedAt`.
///
/// ## Parameters
///
/// - `options` - The validation options to update.
/// - `max_age_seconds` - The maximum allowed token age in seconds.
///
/// ## Returns
///
/// The updated `JwtValidationOptions` with the max token age set.
pub fn with_max_token_age(
  options: JwtValidationOptions,
  max_age_seconds: Int,
) -> JwtValidationOptions {
  JwtValidationOptions(..options, max_token_age: Some(max_age_seconds))
}

fn build_verifier(
  alg: jwa.JwsAlg,
  keys: List(jwk.Jwk),
  options: JwtValidationOptions,
) -> Result(Verifier, gose.GoseError) {
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_jws_verification(alg, _)),
  )
  Ok(Verifier(alg:, keys:, options:))
}

/// Create a verifier for JWT signature verification and claim validation.
///
/// Each verifier is pinned to a single algorithm. This prevents algorithm
/// confusion attacks where an attacker changes the `alg` header to trick
/// the verifier into using the wrong algorithm (see RFC 8725 Section 3.1).
/// For multi-algorithm scenarios (e.g., algorithm migration), create one
/// verifier per algorithm and try each in sequence:
///
/// ```gleam
/// let assert Ok(rs_verifier) = jwt.verifier(
///   jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256),
///   keys: rsa_keys,
///   options: jwt.default_validation(),
/// )
/// let assert Ok(ec_verifier) = jwt.verifier(
///   jwa.JwsEcdsa(jwa.EcdsaP256),
///   keys: ec_keys,
///   options: jwt.default_validation(),
/// )
///
/// let result = case jwt.verify_and_validate(rs_verifier, token, now) {
///   Ok(verified) -> Ok(verified)
///   _ -> jwt.verify_and_validate(ec_verifier, token, now)
/// }
/// ```
///
/// Accepts one or more keys for key rotation scenarios.
///
/// Key selection during verification:
/// 1. If token has `kid` header, prioritize keys with matching kid
/// 2. Try keys in order until one succeeds
/// 3. Fail if no key verifies the signature
///
/// Returns an error if:
/// - The key list is empty
/// - Any algorithm is incompatible with any key type
/// - Any key's `use` field is set but not `Signing`
/// - Any key's `key_ops` field is set but doesn't include `Verify`
///
/// ## Parameters
///
/// - `alg` - The expected JWS algorithm; tokens using a different algorithm are rejected.
/// - `keys` - One or more keys to try during verification (supports key rotation).
/// - `options` - Validation options controlling claim checks (expiration, issuer, etc.).
///
/// ## Returns
///
/// `Ok(Verifier)` ready for use with `verify_and_validate`, or
/// `Error(JwtError)` if any key is incompatible with the algorithm or has
/// incorrect usage constraints.
pub fn verifier(
  alg: jwa.JwsAlg,
  keys keys: List(jwk.Jwk),
  options options: JwtValidationOptions,
) -> Result(Verifier, JwtError) {
  build_verifier(alg, keys, options)
  |> result.map_error(JoseError)
}

/// Create an empty claims set with no registered or custom claims.
/// Use the `with_*` functions to populate claims before signing.
///
/// ## Returns
///
/// An empty `Claims` value with no registered or custom claims set.
pub fn claims() -> Claims {
  Claims(
    iss: None,
    sub: None,
    aud: None,
    exp: None,
    nbf: None,
    iat: None,
    jti: None,
    custom: dict.new(),
  )
}

/// Set a single audience (aud) claim.
///
/// ## Parameters
///
/// - `claims` - The claims set to update.
/// - `aud` - The audience string.
///
/// ## Returns
///
/// The `Claims` with the `aud` claim set.
pub fn with_audience(claims: Claims, aud: String) -> Claims {
  Claims(..claims, aud: Some([aud]))
}

/// Set multiple audiences (aud) claim.
///
/// Returns an error if the audience list is empty.
///
/// ## Parameters
///
/// - `claims` - The claims set to update.
/// - `aud` - The list of audience strings.
///
/// ## Returns
///
/// `Ok(Claims)` with the audience list set, or `Error(JwtError)` if the
/// audience list is empty.
pub fn with_audiences(
  claims: Claims,
  aud: List(String),
) -> Result(Claims, JwtError) {
  case aud {
    [] -> Error(InvalidClaim("audience list cannot be empty"))
    _ -> Ok(Claims(..claims, aud: Some(aud)))
  }
}

/// Set a custom claim.
///
/// Returns an error if the key is a reserved claim name. Use the dedicated
/// setters for registered claims (e.g., `with_issuer`, `with_subject`).
///
/// ## Parameters
///
/// - `claims` - The claims set to add the custom claim to.
/// - `key` - The claim name (must not be a reserved claim like "iss", "sub", etc.).
/// - `value` - The JSON value for the claim.
///
/// ## Returns
///
/// `Ok(Claims)` with the custom claim added, or `Error(JwtError)` if the
/// key is a reserved claim name.
pub fn with_claim(
  claims: Claims,
  key: String,
  value: Json,
) -> Result(Claims, JwtError) {
  case list.contains(reserved_claims, key) {
    True -> Error(InvalidClaim("use dedicated setter for " <> key <> " claim"))
    False ->
      Ok(Claims(..claims, custom: dict.insert(claims.custom, key, value)))
  }
}

/// Set the expiration time (exp) claim.
///
/// ## Parameters
///
/// - `claims` - The claims set to update.
/// - `exp` - The expiration timestamp.
///
/// ## Returns
///
/// The `Claims` with the `exp` claim set.
pub fn with_expiration(claims: Claims, exp: Timestamp) -> Claims {
  let #(seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(exp)
  Claims(..claims, exp: Some(seconds))
}

/// Set the issued at time (iat) claim.
///
/// ## Parameters
///
/// - `claims` - The claims set to update.
/// - `iat` - The issued-at timestamp.
///
/// ## Returns
///
/// The `Claims` with the `iat` claim set.
pub fn with_issued_at(claims: Claims, iat: Timestamp) -> Claims {
  let #(seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(iat)
  Claims(..claims, iat: Some(seconds))
}

/// Set the issuer (iss) claim.
///
/// ## Parameters
///
/// - `claims` - The claims set to update.
/// - `iss` - The issuer string.
///
/// ## Returns
///
/// The `Claims` with the `iss` claim set.
pub fn with_issuer(claims: Claims, iss: String) -> Claims {
  Claims(..claims, iss: Some(iss))
}

/// Set the JWT ID (jti) claim.
///
/// ## Parameters
///
/// - `claims` - The claims set to update.
/// - `jti` - The unique token identifier.
///
/// ## Returns
///
/// The `Claims` with the `jti` claim set.
pub fn with_jwt_id(claims: Claims, jti: String) -> Claims {
  Claims(..claims, jti: Some(jti))
}

/// Set the not before time (nbf) claim.
///
/// ## Parameters
///
/// - `claims` - The claims set to update.
/// - `nbf` - The not-before timestamp.
///
/// ## Returns
///
/// The `Claims` with the `nbf` claim set.
pub fn with_not_before(claims: Claims, nbf: Timestamp) -> Claims {
  let #(seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(nbf)
  Claims(..claims, nbf: Some(seconds))
}

/// Set the subject (sub) claim.
///
/// ## Parameters
///
/// - `claims` - The claims set to update.
/// - `sub` - The subject string.
///
/// ## Returns
///
/// The `Claims` with the `sub` claim set.
pub fn with_subject(claims: Claims, sub: String) -> Claims {
  Claims(..claims, sub: Some(sub))
}

/// Get the algorithm (`alg`) from a JWT.
///
/// ## Parameters
///
/// - `jwt` - The JWT to read the algorithm from.
///
/// ## Returns
///
/// The `JwsAlg` used to sign the token.
pub fn alg(jwt: Jwt(state)) -> jwa.JwsAlg {
  let Jwt(alg:, ..) = jwt
  alg
}

/// Get the key ID (kid) from a JWT header.
///
/// **Security Warning:** The `kid` value comes from the token and is untrusted
/// input. If you use it to look up keys (from a database, filesystem, or key
/// store), you must sanitize it first to prevent injection attacks.
///
/// ## Parameters
///
/// - `jwt` - The JWT to read the key ID from.
///
/// ## Returns
///
/// `Ok(String)` with the key ID, or `Error(Nil)` if no `kid` is set.
pub fn kid(jwt: Jwt(state)) -> Result(String, Nil) {
  let Jwt(kid:, ..) = jwt
  option.to_result(kid, Nil)
}

/// Sign a JWT with the provided key.
///
/// Automatically sets `typ: "JWT"` in the header.
///
/// ## Example
///
/// ```gleam
/// let claims = jwt.claims()
///   |> jwt.with_subject("user123")
///   |> jwt.with_expiration(exp)
///
/// let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)
/// let token = jwt.serialize(signed)
/// ```
///
/// ## Parameters
///
/// - `alg` - The JWS algorithm to use for signing.
/// - `claims` - The claims set to include in the JWT payload.
/// - `key` - The signing key (must be compatible with the algorithm).
///
/// ## Returns
///
/// `Ok(Jwt(Verified))` with the signed JWT ready to serialize with
/// `serialize()`, or `Error(JwtError)` if signing fails due to key
/// incompatibility or a crypto error. The token is marked `Verified`
/// because locally-signed tokens are implicitly trusted.
pub fn sign(
  alg: jwa.JwsAlg,
  claims: Claims,
  key: jwk.Jwk,
) -> Result(Jwt(Verified), JwtError) {
  let kid = option.from_result(jwk.kid(key))
  let payload = claims_to_json(claims)
  let payload_bits =
    json.to_string(payload)
    |> bit_array.from_string

  let unsigned =
    jws.new(alg)
    |> jws.with_typ("JWT")
    |> apply_optional_kid(kid)

  do_sign(unsigned, key, payload_bits, alg, kid, claims)
  |> result.map_error(JoseError)
}

fn do_sign(
  unsigned: jws.Jws(jws.Unsigned, jws.Built),
  key: jwk.Jwk,
  payload_bits: BitArray,
  alg: jwa.JwsAlg,
  kid: Option(String),
  claims: Claims,
) -> Result(Jwt(Verified), gose.GoseError) {
  use signed <- result.try(jws.sign(unsigned, key, payload_bits))
  jws.serialize_compact(signed)
  |> result.map(fn(token) { Jwt(alg:, kid:, claims:, token:) })
}

fn apply_optional_kid(
  unsigned: jws.Jws(jws.Unsigned, jws.Built),
  kid: Option(String),
) -> jws.Jws(jws.Unsigned, jws.Built) {
  case kid {
    Some(k) -> jws.with_kid(unsigned, k)
    None -> unsigned
  }
}

/// Verify a JWT's signature and validate its claims using a Verifier.
///
/// Checks:
/// 1. Token's `alg` header matches the verifier's expected algorithm
/// 2. Signature is valid for one of the verifier's keys
/// 3. Claims pass validation (exp, nbf, iss, aud per options)
///
/// When multiple keys are configured:
/// - Keys with matching `kid` are tried first (if token has `kid` header)
/// - `kid_policy` controls kid header enforcement (see `KidPolicy` type)
/// - With `NoKidRequirement`, all keys are tried with matching keys prioritized
///
/// ## Parameters
///
/// - `verifier` - A verifier created with `verifier()` that pins the algorithm and keys.
/// - `token` - The JWT compact-serialized string to verify.
/// - `now` - The current timestamp, used for time-based claim validation.
///
/// ## Returns
///
/// `Ok(Jwt(Verified))` with the verified JWT whose claims can be safely
/// trusted, or `Error(JwtError)` if signature verification or claim
/// validation fails.
pub fn verify_and_validate(
  verifier: Verifier,
  token: String,
  now: Timestamp,
) -> Result(Jwt(Verified), JwtError) {
  let Verifier(alg: expected_alg, keys:, options:) = verifier
  use signed_jws <- result.try(parse_jws(token))
  use _ <- result.try(require_jwt_compatible_jws(signed_jws))
  use _ <- result.try(require_matching_algorithm(
    expected_alg,
    jws.alg(signed_jws),
  ))

  let token_kid = option.from_result(jws.kid(signed_jws))
  use verification_keys <- result.try(select_keys_by_policy(
    keys,
    token_kid,
    options.kid_policy,
  ))

  use _ <- result.try(try_verify_with_keys(
    signed_jws,
    expected_alg,
    verification_keys,
  ))
  use jwt <- result.try(build_verified_jwt(signed_jws, token))
  use _ <- result.try(validate_claims(jwt.claims, now, options))
  Ok(jwt)
}

fn parse_jws(token: String) -> Result(jws.Jws(jws.Signed, jws.Parsed), JwtError) {
  jws.parse_compact(token)
  |> result.map_error(gose_error_to_malformed_token_error)
}

/// Validate that a signed JWS is compatible with JWT requirements.
/// JWTs do not support detached payloads or unencoded payloads (b64=false).
fn require_jwt_compatible_jws(
  signed_jws: jws.Jws(jws.Signed, jws.Parsed),
) -> Result(Nil, JwtError) {
  use <- bool.guard(
    when: jws.is_detached(signed_jws),
    return: Error(MalformedToken("JWTs do not support detached payloads")),
  )
  case jws.has_unencoded_payload(signed_jws), has_unprotected_alg(signed_jws) {
    True, _ ->
      Error(MalformedToken("JWTs do not support unencoded payloads (b64=false)"))
    _, True -> Error(InsecureUnprotectedHeader("alg"))
    _, _ -> Ok(Nil)
  }
}

fn has_unprotected_alg(signed_jws: jws.Jws(jws.Signed, jws.Parsed)) -> Bool {
  use <- bool.guard(
    when: !jws.has_unprotected_header(signed_jws),
    return: False,
  )
  let alg_decoder = {
    use alg <- decode.optional_field(
      "alg",
      None,
      decode.optional(decode.dynamic),
    )
    decode.success(alg)
  }
  case jws.decode_unprotected_header(signed_jws, alg_decoder) {
    Ok(Some(_)) -> True
    _ -> False
  }
}

/// Select and order keys based on kid matching policy.
///
/// Filters and reorders the provided keys according to the token's `kid`
/// header and the configured `KidPolicy`.
@internal
pub fn select_keys_by_policy(
  keys: List(jwk.Jwk),
  token_kid: Option(String),
  kid_policy: KidPolicy,
) -> Result(List(jwk.Jwk), JwtError) {
  case token_kid, kid_policy {
    None, NoKidRequirement -> Ok(keys)
    None, RequireKid -> Error(MissingKid)
    None, RequireKidMatch -> Error(MissingKid)

    Some(target), RequireKidMatch -> {
      let matching = list.filter(keys, fn(key) { jwk.kid(key) == Ok(target) })
      case matching {
        [] -> Error(UnknownKid(target))
        _ -> Ok(matching)
      }
    }
    Some(target), RequireKid | Some(target), NoKidRequirement -> {
      let #(matching, others) =
        list.partition(keys, fn(key) { jwk.kid(key) == Ok(target) })
      Ok(list.append(matching, others))
    }
  }
}

fn try_verify_with_keys(
  signed_jws: jws.Jws(jws.Signed, jws.Parsed),
  expected_alg: jwa.JwsAlg,
  keys: List(jwk.Jwk),
) -> Result(Nil, JwtError) {
  use verifier <- result.try(
    jws.verifier(expected_alg, keys:)
    |> result.map_error(JoseError),
  )
  case jws.verify(verifier, signed_jws) {
    Ok(True) -> Ok(Nil)
    Ok(False) -> Error(InvalidSignature)
    Error(gose.CryptoError(_)) -> Error(InvalidSignature)
    Error(gose.ParseError(reason)) -> Error(MalformedToken(reason))
    Error(err) -> Error(JoseError(err))
  }
}

fn require_matching_algorithm(
  expected: jwa.JwsAlg,
  actual: jwa.JwsAlg,
) -> Result(Nil, JwtError) {
  case expected == actual {
    True -> Ok(Nil)
    False -> Error(JwsAlgorithmMismatch(expected:, actual:))
  }
}

/// Verify a JWT's signature only, skipping all claim validation.
///
/// **Warning:** This skips expiration, not-before, issuer, and audience checks.
/// Use only when you have a legitimate reason to bypass validation, such as
/// inspecting claims before deciding on validation policy.
///
/// Still enforces algorithm pinning and `kid_policy` for security.
/// When multiple keys are configured, keys with matching `kid` are tried first.
///
/// ## Parameters
///
/// - `verifier` - A verifier created with `verifier()` that pins the algorithm and keys.
/// - `token` - The JWT compact-serialized string to verify.
///
/// ## Returns
///
/// `Ok(Jwt(Verified))` with the verified JWT and unchecked claims, or
/// `Error(JwtError)` if signature verification fails or the algorithm
/// doesn't match.
pub fn verify_and_dangerously_skip_validation(
  verifier: Verifier,
  token: String,
) -> Result(Jwt(Verified), JwtError) {
  let Verifier(alg: expected_alg, keys:, options:) = verifier
  use signed_jws <- result.try(parse_jws(token))
  use _ <- result.try(require_jwt_compatible_jws(signed_jws))
  use _ <- result.try(require_matching_algorithm(
    expected_alg,
    jws.alg(signed_jws),
  ))

  let token_kid = option.from_result(jws.kid(signed_jws))
  use verification_keys <- result.try(select_keys_by_policy(
    keys,
    token_kid,
    options.kid_policy,
  ))

  use _ <- result.try(try_verify_with_keys(
    signed_jws,
    expected_alg,
    verification_keys,
  ))
  build_verified_jwt(signed_jws, token)
}

fn build_verified_jwt(
  signed_jws: jws.Jws(jws.Signed, jws.Parsed),
  token: String,
) -> Result(Jwt(Verified), JwtError) {
  let payload = jws.payload(signed_jws)
  use claims <- result.try(parse_claims_bits(payload))

  let alg = jws.alg(signed_jws)
  let kid = option.from_result(jws.kid(signed_jws))

  Ok(Jwt(alg:, kid:, claims:, token:))
}

/// Validate JWT claims against the configured validation options.
///
/// Checks expiration, not-before, issued-at, issuer, audience,
/// JWT ID, and token age constraints.
@internal
pub fn validate_claims(
  claims: Claims,
  now: Timestamp,
  options: JwtValidationOptions,
) -> Result(Nil, JwtError) {
  let #(now_seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(now)

  use _ <- result.try(validate_exp(claims, now_seconds, options))
  use _ <- result.try(validate_nbf(claims, now_seconds, options))
  use _ <- result.try(validate_issuer(claims, options))
  use _ <- result.try(validate_audience(claims, options))
  use _ <- result.try(validate_iat(claims, now_seconds, options))
  validate_jti(claims, options)
}

/// Serialize a verified JWT to compact format.
///
/// ## Parameters
///
/// - `jwt` - The verified JWT to serialize.
///
/// ## Returns
///
/// The JWT in compact format (`header.payload.signature`).
pub fn serialize(jwt: Jwt(Verified)) -> String {
  jwt.token
}

/// Serialize claims to a JSON string.
///
/// This is useful for encrypted JWTs or other scenarios where you need
/// the raw JSON representation of claims including custom claims.
@internal
pub fn claims_to_json_string(claims: Claims) -> String {
  claims_to_json(claims)
  |> json.to_string
}

fn claims_to_json(claims: Claims) -> Json {
  let registered_fields =
    list.filter_map(
      [
        option.map(claims.iss, fn(v) { #("iss", json.string(v)) }),
        option.map(claims.sub, fn(v) { #("sub", json.string(v)) }),
        option.map(claims.aud, fn(auds) {
          case auds {
            [single] -> #("aud", json.string(single))
            multiple -> #("aud", json.array(multiple, json.string))
          }
        }),
        option.map(claims.exp, fn(v) { #("exp", json.int(v)) }),
        option.map(claims.nbf, fn(v) { #("nbf", json.int(v)) }),
        option.map(claims.iat, fn(v) { #("iat", json.int(v)) }),
        option.map(claims.jti, fn(v) { #("jti", json.string(v)) }),
      ],
      option.to_result(_, Nil),
    )

  let custom_fields = dict.to_list(claims.custom)
  json.object(list.append(registered_fields, custom_fields))
}

/// Decode an unverified JWT's claims using a custom decoder.
///
/// **Warning:** These claims have not been verified. Do not trust them
/// until the JWT has been verified with `verify_and_validate`.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(parsed) = jwt.parse(token)
/// let decoder = {
///   use iss <- decode.field("iss", decode.string)
///   decode.success(iss)
/// }
/// let assert Ok(issuer) = jwt.dangerously_decode_unverified(parsed, decoder)
/// // issuer is untrusted - only use for routing/lookup, not authorization
/// ```
///
/// ## Parameters
///
/// - `jwt` - An unverified JWT obtained from `parse()`.
/// - `decoder` - A `gleam/dynamic/decode` decoder for extracting claims from the raw JSON payload.
///
/// ## Returns
///
/// `Ok(a)` with the decoded value from the unverified claims, or
/// `Error(JwtError)` if the payload cannot be decoded.
pub fn dangerously_decode_unverified(
  jwt: Jwt(Unverified),
  decoder: decode.Decoder(a),
) -> Result(a, JwtError) {
  let Jwt(token:, ..) = jwt
  use payload_bits <- result.try(extract_payload_bits(token))
  json.parse_bits(payload_bits, decoder)
  |> result.replace_error(ClaimDecodingFailed("failed to decode claims"))
}

/// Decode a verified JWT's claims using a custom decoder.
///
/// This allows extracting claims directly into your own types using
/// `gleam/dynamic/decode`. The decoder receives the raw claims JSON.
///
/// ## Example
///
/// ```gleam
/// let decoder = {
///   use sub <- decode.field("sub", decode.string)
///   use role <- decode.field("role", decode.string)
///   decode.success(User(sub:, role:))
/// }
/// let assert Ok(user) = jwt.decode(verified_jwt, decoder)
/// ```
///
/// ## Parameters
///
/// - `jwt` - A verified JWT obtained from `verify_and_validate` or `sign`.
/// - `decoder` - A `gleam/dynamic/decode` decoder for extracting claims from the raw JSON payload.
///
/// ## Returns
///
/// `Ok(a)` with the decoded value from the verified claims, or
/// `Error(JwtError)` if the claims cannot be decoded with the provided
/// decoder.
pub fn decode(
  jwt: Jwt(Verified),
  decoder: decode.Decoder(a),
) -> Result(a, JwtError) {
  use payload_bits <- result.try(extract_payload_bits(jwt.token))
  json.parse_bits(payload_bits, decoder)
  |> result.replace_error(ClaimDecodingFailed("failed to decode claims"))
}

/// Parse a JWT from compact format.
///
/// Returns an unverified JWT that needs to be verified with
/// `verify_and_validate` or `verify_and_dangerously_skip_validation`.
///
/// ## Parameters
///
/// - `token` - The JWT compact-serialized string to parse.
///
/// ## Returns
///
/// `Ok(Jwt(Unverified))` with the parsed but unverified JWT, or
/// `Error(JwtError)` if the token is malformed or uses unsupported JWT
/// features.
pub fn parse(token: String) -> Result(Jwt(Unverified), JwtError) {
  use signed <- result.try(parse_jws(token))
  use _ <- result.try(require_jwt_compatible_jws(signed))

  let payload = jws.payload(signed)
  use claims <- result.try(parse_claims_bits(payload))

  let alg = jws.alg(signed)
  let kid = option.from_result(jws.kid(signed))

  Ok(Jwt(alg:, kid:, claims:, token:))
}

fn extract_payload_bits(token: String) -> Result(BitArray, JwtError) {
  parse_jws(token)
  |> result.map(jws.payload)
}

/// Parse a raw JSON payload into JWT claims.
@internal
pub fn parse_claims_bits(payload: BitArray) -> Result(Claims, JwtError) {
  use all_fields <- result.try(
    json.parse_bits(payload, decode.dict(decode.string, decode.dynamic))
    |> result.replace_error(MalformedToken("invalid claims JSON")),
  )

  parse_claims_from_fields(all_fields)
}

fn extract_optional_audience(
  fields: Dict(String, decode.Dynamic),
) -> Result(Option(List(String)), JwtError) {
  case dict.get(fields, "aud") {
    Ok(value) -> {
      let audience_decoder =
        decode.one_of(decode.list(decode.string), [
          decode.map(decode.string, list.wrap),
        ])
      case decode.run(value, audience_decoder) {
        Ok([]) -> Error(MalformedToken("aud claim cannot be an empty array"))
        Ok(audiences) -> Ok(Some(audiences))
        Error(_) ->
          Error(MalformedToken("aud claim must be a string or array of strings"))
      }
    }
    Error(_) -> Ok(None)
  }
}

fn extract_optional_numeric_date(
  fields: Dict(String, decode.Dynamic),
  key: String,
) -> Result(Option(Int), JwtError) {
  case dict.get(fields, key) {
    Ok(value) -> {
      let numeric_decoder =
        decode.one_of(decode.int, [decode.map(decode.float, float.truncate)])
      decode.run(value, numeric_decoder)
      |> result.map(Some)
      |> result.replace_error(MalformedToken(
        key <> " claim must be a numeric value",
      ))
    }
    Error(_) -> Ok(None)
  }
}

fn extract_optional_string(
  fields: Dict(String, decode.Dynamic),
  key: String,
) -> Result(Option(String), JwtError) {
  case dict.get(fields, key) {
    Ok(value) ->
      decode.run(value, decode.string)
      |> result.map(Some)
      |> result.replace_error(MalformedToken(key <> " claim must be a string"))
    Error(_) -> Ok(None)
  }
}

fn parse_claims_from_fields(
  all_fields: Dict(String, decode.Dynamic),
) -> Result(Claims, JwtError) {
  use iss <- result.try(extract_optional_string(all_fields, "iss"))
  use sub <- result.try(extract_optional_string(all_fields, "sub"))
  use aud <- result.try(extract_optional_audience(all_fields))
  use exp <- result.try(extract_optional_numeric_date(all_fields, "exp"))
  use nbf <- result.try(extract_optional_numeric_date(all_fields, "nbf"))
  use iat <- result.try(extract_optional_numeric_date(all_fields, "iat"))
  use jti <- result.try(extract_optional_string(all_fields, "jti"))

  Ok(Claims(iss:, sub:, aud:, exp:, nbf:, iat:, jti:, custom: dict.new()))
}

fn validate_audience(
  claims: Claims,
  options: JwtValidationOptions,
) -> Result(Nil, JwtError) {
  case options.audience, claims.aud {
    None, _ -> Ok(Nil)
    Some(expected), Some(audiences) ->
      case list.contains(audiences, expected) {
        True -> Ok(Nil)
        False -> Error(AudienceMismatch(expected:, actual: Some(audiences)))
      }
    Some(expected), None -> Error(AudienceMismatch(expected:, actual: None))
  }
}

fn validate_exp(
  claims: Claims,
  now_seconds: Int,
  options: JwtValidationOptions,
) -> Result(Nil, JwtError) {
  case claims.exp, options.require_exp {
    None, True -> Error(MissingExpiration)
    None, False -> Ok(Nil)
    Some(exp), _ -> {
      let adjusted_now = now_seconds - options.clock_skew
      use <- bool.guard(
        when: adjusted_now >= exp,
        return: Error(TokenExpired(timestamp.from_unix_seconds(exp))),
      )
      Ok(Nil)
    }
  }
}

fn validate_iat(
  claims: Claims,
  now_seconds: Int,
  options: JwtValidationOptions,
) -> Result(Nil, JwtError) {
  case claims.iat, options.max_token_age {
    None, Some(_) -> Error(MissingIssuedAt)
    None, None -> Ok(Nil)
    Some(iat), _ -> {
      use _ <- result.try(validate_iat_not_future(iat, now_seconds, options))
      validate_token_age(iat, now_seconds, options)
    }
  }
}

fn validate_issuer(
  claims: Claims,
  options: JwtValidationOptions,
) -> Result(Nil, JwtError) {
  case options.issuer, claims.iss {
    None, _ -> Ok(Nil)
    Some(expected), Some(actual) if expected == actual -> Ok(Nil)
    Some(expected), actual -> Error(IssuerMismatch(expected:, actual:))
  }
}

fn validate_jti(
  claims: Claims,
  options: JwtValidationOptions,
) -> Result(Nil, JwtError) {
  case options.jti_validator, claims.jti {
    None, _ -> Ok(Nil)
    Some(_), None -> Ok(Nil)
    Some(validator), Some(jti) -> {
      use <- bool.guard(when: !validator(jti), return: Error(InvalidJti(jti)))
      Ok(Nil)
    }
  }
}

fn validate_nbf(
  claims: Claims,
  now_seconds: Int,
  options: JwtValidationOptions,
) -> Result(Nil, JwtError) {
  case claims.nbf {
    None -> Ok(Nil)
    Some(nbf) -> {
      let adjusted_now = now_seconds + options.clock_skew
      use <- bool.guard(
        when: adjusted_now < nbf,
        return: Error(TokenNotYetValid(timestamp.from_unix_seconds(nbf))),
      )
      Ok(Nil)
    }
  }
}

fn validate_iat_not_future(
  iat: Int,
  now_seconds: Int,
  options: JwtValidationOptions,
) -> Result(Nil, JwtError) {
  use <- bool.guard(
    when: iat > now_seconds + options.clock_skew,
    return: Error(IssuedInFuture(timestamp.from_unix_seconds(iat))),
  )
  Ok(Nil)
}

fn validate_token_age(
  iat: Int,
  now_seconds: Int,
  options: JwtValidationOptions,
) -> Result(Nil, JwtError) {
  case options.max_token_age {
    None -> Ok(Nil)
    Some(max_age) -> {
      let token_age = now_seconds - iat
      use <- bool.guard(
        when: token_age > max_age,
        return: Error(TokenTooOld(timestamp.from_unix_seconds(iat), max_age)),
      )
      Ok(Nil)
    }
  }
}
