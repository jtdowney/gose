//// CBOR Web Token (CWT) [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html)
////
//// CWT is the CBOR equivalent of JWT, providing claims-based tokens using
//// COSE for signing and verification.
////
//// ## Example
////
//// ```gleam
//// import gleam/time/duration
//// import gleam/time/timestamp
//// import gose
//// import gose/cose/cwt
//// import kryptos/ec
////
//// let signing_key = gose.generate_ec(ec.P256)
//// let now = timestamp.system_time()
//// let exp = timestamp.add(now, duration.hours(1))
////
//// let claims = cwt.new()
////   |> cwt.with_subject("user123")
////   |> cwt.with_issuer("my-app")
////   |> cwt.with_expiration(exp)
////
//// let assert Ok(token) =
////   cwt.sign(
////     claims,
////     alg: gose.Ecdsa(gose.EcdsaP256),
////     key: signing_key,
////   )
////
//// let assert Ok(verifier) =
////   cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
//// let assert Ok(verified) = cwt.verify_and_validate(verifier, token:, now:)
//// let verified_claims = cwt.verified_claims(verified)
//// ```
////
//// ## Phantom Types
////
//// `Cwt(state)` uses a phantom type to track verification state:
//// - `Unverified`: parsed but not yet verified
//// - `Verified`: signature verified and claims validated, safe to trust

import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import gose
import gose/cbor
import gose/cose/sign1
import gose/internal/key_helpers

/// Errors from CWT operations, covering both COSE-layer failures and claim validation.
pub type CwtError {
  /// An error from the underlying COSE layer (signing, verification, decryption, key validation).
  CoseError(gose.GoseError)
  /// The COSE_Sign1 signature did not verify against any of the provided keys.
  InvalidSignature
  /// The token could not be parsed (invalid CBOR, unexpected claim types, etc.).
  MalformedToken(reason: String)
  /// The `exp` claim is in the past.
  TokenExpired(expired_at: Timestamp)
  /// The `nbf` claim is in the future.
  TokenNotYetValid(valid_from: Timestamp)
  /// The `iss` claim does not match the expected issuer.
  IssuerMismatch(expected: String, actual: Option(String))
  /// The `aud` claim does not contain the expected audience.
  AudienceMismatch(expected: String, actual: Option(List(String)))
  /// The `exp` claim is required by the verifier but absent.
  MissingExpiration
  /// COSE decryption failed (wrong key, corrupted ciphertext, etc.).
  DecryptionFailed(reason: String)
  /// A claim value is invalid (empty audience list, etc.).
  InvalidClaim(reason: String)
}

/// Phantom type for a CWT that has been parsed but not yet verified.
pub type Unverified

/// Phantom type for a CWT whose signature and claims have been validated.
pub type Verified

/// The set of claims carried by a CWT (registered + custom).
pub opaque type CwtClaims {
  CwtClaims(
    iss: Option(String),
    sub: Option(String),
    aud: Option(List(String)),
    exp: Option(Int),
    nbf: Option(Int),
    iat: Option(Int),
    cti: Option(BitArray),
    custom: List(#(cbor.Value, cbor.Value)),
  )
}

/// A CWT parameterized by verification state.
pub opaque type Cwt(state) {
  Cwt(claims: CwtClaims)
}

/// Holds algorithm, keys, and validation options for verifying a CWT.
pub opaque type Verifier {
  Verifier(
    alg: gose.DigitalSignatureAlg,
    keys: List(gose.Key(BitArray)),
    expected_issuer: Option(String),
    expected_audience: Option(String),
    clock_skew: Int,
    require_exp: Bool,
  )
}

/// Create an empty set of CWT claims.
pub fn new() -> CwtClaims {
  CwtClaims(
    iss: option.None,
    sub: option.None,
    aud: option.None,
    exp: option.None,
    nbf: option.None,
    iat: option.None,
    cti: option.None,
    custom: [],
  )
}

/// Set the issuer (`iss`, label 1) claim.
pub fn with_issuer(claims: CwtClaims, issuer: String) -> CwtClaims {
  CwtClaims(..claims, iss: option.Some(issuer))
}

/// Set the subject (`sub`, label 2) claim.
pub fn with_subject(claims: CwtClaims, subject: String) -> CwtClaims {
  CwtClaims(..claims, sub: option.Some(subject))
}

/// Set a single audience (`aud`, label 3) claim.
pub fn with_audience(claims: CwtClaims, audience: String) -> CwtClaims {
  CwtClaims(..claims, aud: option.Some([audience]))
}

/// Set multiple audiences (`aud`, label 3) as an array.
pub fn with_audiences(
  claims: CwtClaims,
  audiences: List(String),
) -> Result(CwtClaims, CwtError) {
  case audiences {
    [] -> Error(InvalidClaim("audience list cannot be empty"))
    _ -> Ok(CwtClaims(..claims, aud: option.Some(audiences)))
  }
}

/// Set the expiration time (`exp`, label 4) claim.
pub fn with_expiration(claims: CwtClaims, exp: Timestamp) -> CwtClaims {
  let #(seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(exp)
  CwtClaims(..claims, exp: option.Some(seconds))
}

/// Set the not-before time (`nbf`, label 5) claim.
pub fn with_not_before(claims: CwtClaims, nbf: Timestamp) -> CwtClaims {
  let #(seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(nbf)
  CwtClaims(..claims, nbf: option.Some(seconds))
}

/// Set the issued-at time (`iat`, label 6) claim.
pub fn with_issued_at(claims: CwtClaims, iat: Timestamp) -> CwtClaims {
  let #(seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(iat)
  CwtClaims(..claims, iat: option.Some(seconds))
}

/// Set the CWT ID (`cti`, label 7) claim.
pub fn with_cti(claims: CwtClaims, cti: BitArray) -> CwtClaims {
  CwtClaims(..claims, cti: option.Some(cti))
}

/// Add a custom (non-registered) claim keyed by an arbitrary CBOR value.
///
/// Returns an error if the key collides with a registered CWT label (1-7).
/// If the key already exists in custom claims, the value is replaced.
pub fn with_custom_claim(
  claims: CwtClaims,
  key key: cbor.Value,
  value value: cbor.Value,
) -> Result(CwtClaims, CwtError) {
  case key {
    cbor.Int(n) if n >= 1 && n <= 7 ->
      Error(MalformedToken(
        "custom claim key collides with registered CWT label "
        <> int.to_string(n),
      ))
    _ ->
      Ok(CwtClaims(..claims, custom: list.key_set(claims.custom, key, value)))
  }
}

/// Read the issuer claim.
pub fn issuer(claims: CwtClaims) -> Result(String, Nil) {
  option.to_result(claims.iss, Nil)
}

/// Read the subject claim.
pub fn subject(claims: CwtClaims) -> Result(String, Nil) {
  option.to_result(claims.sub, Nil)
}

/// Read the audience claim as a list of strings.
pub fn audience(claims: CwtClaims) -> Result(List(String), Nil) {
  option.to_result(claims.aud, Nil)
}

/// Read the expiration time as a timestamp.
pub fn expiration(claims: CwtClaims) -> Result(Timestamp, Nil) {
  option.to_result(claims.exp, Nil)
  |> result.map(timestamp.from_unix_seconds)
}

/// Read the not-before time as a timestamp.
pub fn not_before(claims: CwtClaims) -> Result(Timestamp, Nil) {
  option.to_result(claims.nbf, Nil)
  |> result.map(timestamp.from_unix_seconds)
}

/// Read the issued-at time as a timestamp.
pub fn issued_at(claims: CwtClaims) -> Result(Timestamp, Nil) {
  option.to_result(claims.iat, Nil)
  |> result.map(timestamp.from_unix_seconds)
}

/// Read the CWT ID.
pub fn cti(claims: CwtClaims) -> Result(BitArray, Nil) {
  option.to_result(claims.cti, Nil)
}

/// Look up a custom claim by its CBOR key.
pub fn custom_claim(
  claims: CwtClaims,
  key key: cbor.Value,
) -> Result(cbor.Value, Nil) {
  list.key_find(claims.custom, key)
}

/// Sign a set of claims as a COSE_Sign1-wrapped CWT, returning the serialized CBOR bytes.
pub fn sign(
  claims: CwtClaims,
  alg alg: gose.DigitalSignatureAlg,
  key key: gose.Key(BitArray),
) -> Result(BitArray, CwtError) {
  let payload = encode_claims(claims)
  let unsigned = sign1.new(alg)
  sign1.sign(unsigned, key, payload)
  |> result.map(sign1.serialize)
  |> result.map_error(CoseError)
}

/// Build a CWT verifier pinned to a single signature algorithm and one or more keys.
pub fn verifier(
  alg: gose.DigitalSignatureAlg,
  keys keys: List(gose.Key(BitArray)),
) -> Result(Verifier, CwtError) {
  build_verifier(alg, keys)
  |> result.map_error(CoseError)
}

fn build_verifier(
  alg: gose.DigitalSignatureAlg,
  keys: List(gose.Key(BitArray)),
) -> Result(Verifier, gose.GoseError) {
  use <- key_helpers.require_non_empty_keys(keys)
  use _ <- result.try(
    list.try_each(keys, key_helpers.validate_key_for_signing_verification(
      gose.DigitalSignature(alg),
      _,
    )),
  )
  Ok(Verifier(
    alg:,
    keys:,
    expected_issuer: option.None,
    expected_audience: option.None,
    clock_skew: 60,
    require_exp: True,
  ))
}

/// Require the token's `iss` claim to match the given issuer.
pub fn with_issuer_validation(verifier: Verifier, issuer: String) -> Verifier {
  Verifier(..verifier, expected_issuer: option.Some(issuer))
}

/// Require the token's `aud` claim to include the given audience.
pub fn with_audience_validation(
  verifier: Verifier,
  audience: String,
) -> Verifier {
  Verifier(..verifier, expected_audience: option.Some(audience))
}

/// Set the allowed clock skew in seconds (default: 60).
/// Tokens are accepted up to `seconds` past `exp` or before `nbf`.
pub fn with_clock_skew(verifier: Verifier, seconds: Int) -> Verifier {
  Verifier(..verifier, clock_skew: seconds)
}

/// Control whether the `exp` claim is required (default: `True`).
pub fn with_require_expiration(verifier: Verifier, required: Bool) -> Verifier {
  Verifier(..verifier, require_exp: required)
}

/// Parse, verify the signature, and validate claims in one step.
pub fn verify_and_validate(
  verifier: Verifier,
  token token: BitArray,
  now now: Timestamp,
) -> Result(Cwt(Verified), CwtError) {
  let Verifier(alg:, keys:, ..) = verifier
  use parsed <- result.try(parse_sign1(token))
  use _ <- result.try(verify_signature(alg, keys, parsed))
  use payload <- result.try(extract_payload(parsed))
  use claims <- result.try(decode_claims(payload))
  use _ <- result.try(validate_claims(claims, now, verifier))
  Ok(Cwt(claims:))
}

/// Extract the validated claims from a verified CWT.
pub fn verified_claims(cwt: Cwt(Verified)) -> CwtClaims {
  let Cwt(claims:) = cwt
  claims
}

fn parse_sign1(token: BitArray) -> Result(sign1.Sign1(sign1.Signed), CwtError) {
  sign1.parse(token)
  |> result.map_error(fn(err) { MalformedToken(gose.error_message(err)) })
}

fn verify_signature(
  alg: gose.DigitalSignatureAlg,
  keys: List(gose.Key(BitArray)),
  parsed: sign1.Sign1(sign1.Signed),
) -> Result(Nil, CwtError) {
  use sign1_verifier <- result.try(
    sign1.verifier(alg, keys:) |> result.map_error(CoseError),
  )
  case sign1.verify(sign1_verifier, parsed) {
    Ok(Nil) -> Ok(Nil)
    Error(gose.VerificationFailed) -> Error(InvalidSignature)
    Error(gose.CryptoError(_)) -> Error(InvalidSignature)
    Error(err) -> Error(CoseError(err))
  }
}

fn extract_payload(
  parsed: sign1.Sign1(sign1.Signed),
) -> Result(BitArray, CwtError) {
  sign1.payload(parsed)
  |> result.replace_error(MalformedToken("missing payload"))
}

fn encode_claims(claims: CwtClaims) -> BitArray {
  let pairs = encode_registered_claims(claims)
  let all_pairs = list.append(pairs, claims.custom)
  cbor.encode(cbor.Map(all_pairs))
}

fn encode_registered_claims(
  claims: CwtClaims,
) -> List(#(cbor.Value, cbor.Value)) {
  option.values([
    option.map(claims.iss, fn(v) { #(cbor.Int(1), cbor.Text(v)) }),
    option.map(claims.sub, fn(v) { #(cbor.Int(2), cbor.Text(v)) }),
    option.map(claims.aud, encode_audience),
    option.map(claims.exp, fn(v) { #(cbor.Int(4), cbor.Int(v)) }),
    option.map(claims.nbf, fn(v) { #(cbor.Int(5), cbor.Int(v)) }),
    option.map(claims.iat, fn(v) { #(cbor.Int(6), cbor.Int(v)) }),
    option.map(claims.cti, fn(v) { #(cbor.Int(7), cbor.Bytes(v)) }),
  ])
}

fn encode_audience(audiences: List(String)) -> #(cbor.Value, cbor.Value) {
  case audiences {
    [single] -> #(cbor.Int(3), cbor.Text(single))
    multiple -> #(cbor.Int(3), cbor.Array(list.map(multiple, cbor.Text)))
  }
}

fn decode_claims(payload: BitArray) -> Result(CwtClaims, CwtError) {
  case cbor.decode(payload) {
    Ok(cbor.Map(pairs)) -> decode_claims_from_map(pairs)
    Ok(_) -> Error(MalformedToken("CWT claims must be a CBOR map"))
    Error(err) -> Error(MalformedToken(gose.error_message(err)))
  }
}

fn decode_claims_from_map(
  pairs: List(#(cbor.Value, cbor.Value)),
) -> Result(CwtClaims, CwtError) {
  use iss <- result.try(decode_optional_text(pairs, 1, "iss"))
  use sub <- result.try(decode_optional_text(pairs, 2, "sub"))
  use aud <- result.try(decode_optional_audience(pairs))
  use exp <- result.try(decode_optional_int(pairs, 4, "exp"))
  use nbf <- result.try(decode_optional_int(pairs, 5, "nbf"))
  use iat <- result.try(decode_optional_int(pairs, 6, "iat"))
  use cti <- result.try(decode_optional_bytes(pairs, 7, "cti"))
  let custom = extract_custom_claims(pairs)
  Ok(CwtClaims(iss:, sub:, aud:, exp:, nbf:, iat:, cti:, custom:))
}

fn decode_optional_text(
  pairs: List(#(cbor.Value, cbor.Value)),
  label: Int,
  name: String,
) -> Result(Option(String), CwtError) {
  case list.key_find(pairs, cbor.Int(label)) {
    Ok(cbor.Text(v)) -> Ok(option.Some(v))
    Ok(_) -> Error(MalformedToken(name <> " claim must be a text string"))
    Error(_) -> Ok(option.None)
  }
}

fn decode_optional_int(
  pairs: List(#(cbor.Value, cbor.Value)),
  label: Int,
  name: String,
) -> Result(Option(Int), CwtError) {
  case list.key_find(pairs, cbor.Int(label)) {
    Ok(cbor.Int(v)) -> Ok(option.Some(v))
    Ok(_) -> Error(MalformedToken(name <> " claim must be an integer"))
    Error(_) -> Ok(option.None)
  }
}

fn decode_optional_bytes(
  pairs: List(#(cbor.Value, cbor.Value)),
  label: Int,
  name: String,
) -> Result(Option(BitArray), CwtError) {
  case list.key_find(pairs, cbor.Int(label)) {
    Ok(cbor.Bytes(v)) -> Ok(option.Some(v))
    Ok(_) -> Error(MalformedToken(name <> " claim must be a byte string"))
    Error(_) -> Ok(option.None)
  }
}

fn decode_optional_audience(
  pairs: List(#(cbor.Value, cbor.Value)),
) -> Result(Option(List(String)), CwtError) {
  case list.key_find(pairs, cbor.Int(3)) {
    Ok(cbor.Text(v)) -> Ok(option.Some([v]))
    Ok(cbor.Array(items)) -> decode_audience_array(items)
    Ok(_) ->
      Error(MalformedToken(
        "aud claim must be a text string or array of text strings",
      ))
    Error(_) -> Ok(option.None)
  }
}

fn decode_audience_array(
  items: List(cbor.Value),
) -> Result(Option(List(String)), CwtError) {
  list.try_map(items, fn(item) {
    case item {
      cbor.Text(s) -> Ok(s)
      _ -> Error(MalformedToken("aud array must contain only text strings"))
    }
  })
  |> result.map(option.Some)
}

fn extract_custom_claims(
  pairs: List(#(cbor.Value, cbor.Value)),
) -> List(#(cbor.Value, cbor.Value)) {
  list.filter(pairs, fn(pair) {
    case pair.0 {
      cbor.Int(1)
      | cbor.Int(2)
      | cbor.Int(3)
      | cbor.Int(4)
      | cbor.Int(5)
      | cbor.Int(6)
      | cbor.Int(7) -> False
      _ -> True
    }
  })
}

fn validate_claims(
  claims: CwtClaims,
  now: Timestamp,
  verifier: Verifier,
) -> Result(Nil, CwtError) {
  let #(now_seconds, _) = timestamp.to_unix_seconds_and_nanoseconds(now)

  use _ <- result.try(validate_exp(claims, now_seconds, verifier))
  use _ <- result.try(validate_nbf(claims, now_seconds, verifier))
  use _ <- result.try(validate_issuer(claims, verifier))
  validate_audience_claim(claims, verifier)
}

fn validate_exp(
  claims: CwtClaims,
  now_seconds: Int,
  verifier: Verifier,
) -> Result(Nil, CwtError) {
  case claims.exp, verifier.require_exp {
    option.None, True -> Error(MissingExpiration)
    option.None, False -> Ok(Nil)
    option.Some(exp), _ -> {
      let adjusted_now = now_seconds - verifier.clock_skew
      use <- bool.guard(
        when: adjusted_now >= exp,
        return: Error(
          TokenExpired(expired_at: timestamp.from_unix_seconds(exp)),
        ),
      )
      Ok(Nil)
    }
  }
}

fn validate_nbf(
  claims: CwtClaims,
  now_seconds: Int,
  verifier: Verifier,
) -> Result(Nil, CwtError) {
  case claims.nbf {
    option.None -> Ok(Nil)
    option.Some(nbf) -> {
      let adjusted_now = now_seconds + verifier.clock_skew
      use <- bool.guard(
        when: adjusted_now < nbf,
        return: Error(
          TokenNotYetValid(valid_from: timestamp.from_unix_seconds(nbf)),
        ),
      )
      Ok(Nil)
    }
  }
}

fn validate_issuer(
  claims: CwtClaims,
  verifier: Verifier,
) -> Result(Nil, CwtError) {
  case verifier.expected_issuer, claims.iss {
    option.None, _ -> Ok(Nil)
    option.Some(expected), option.Some(actual) if expected == actual -> Ok(Nil)
    option.Some(expected), actual -> Error(IssuerMismatch(expected:, actual:))
  }
}

fn validate_audience_claim(
  claims: CwtClaims,
  verifier: Verifier,
) -> Result(Nil, CwtError) {
  case verifier.expected_audience, claims.aud {
    option.None, _ -> Ok(Nil)
    option.Some(expected), option.Some(audiences) ->
      case list.contains(audiences, expected) {
        True -> Ok(Nil)
        False ->
          Error(AudienceMismatch(expected:, actual: option.Some(audiences)))
      }
    option.Some(expected), option.None ->
      Error(AudienceMismatch(expected:, actual: option.None))
  }
}
