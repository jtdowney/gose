//// JWS payload representation and the protected header parameters that
//// select it ([RFC 7797](https://www.rfc-editor.org/rfc/rfc7797.html)).

import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gose
import gose/internal/utils

/// How a JWS payload is represented in the signing input and serialization.
pub type Encoding {
  /// Payload is base64url-encoded: `b64` absent or true.
  Base64Url
  /// Payload appears literally: `b64:false` per RFC 7797.
  Unencoded
}

/// Standard JWS header parameters that must not appear in `crit`
/// ([RFC 7515 Section 4.1.11](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11)).
const standard_headers = [
  "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty",
  "crit",
]

const known_extensions = ["b64"]

/// Render a payload as the segment that follows the `.` in a signing input.
pub fn encode(
  payload payload: BitArray,
  encoding encoding: Encoding,
) -> Result(String, gose.GoseError) {
  case encoding {
    Unencoded ->
      bit_array.to_string(payload)
      |> result.replace_error(gose.InvalidState(
        "unencoded payload must be valid UTF-8",
      ))
    Base64Url -> Ok(utils.encode_base64_url(payload))
  }
}

/// Recover the payload bytes from a signing input's payload segment.
pub fn decode(
  segment segment: String,
  encoding encoding: Encoding,
) -> Result(BitArray, gose.GoseError) {
  case encoding {
    Unencoded -> Ok(bit_array.from_string(segment))
    Base64Url -> utils.decode_base64_url(segment, name: "payload")
  }
}

/// Determine a payload's encoding from a protected header's `crit` and `b64`
/// parameters, which RFC 7797 Section 6 requires to agree.
pub fn encoding_from_headers(
  crit crit: Option(List(String)),
  b64 b64: Option(Bool),
) -> Result(Encoding, gose.GoseError) {
  use _ <- result.try(validate_optional_crit(crit, b64))
  use <- bool.guard(
    when: option.is_some(b64) && !crit_contains_b64(crit),
    return: Error(gose.ParseError("b64 header present but not in crit")),
  )

  case b64 {
    option.Some(False) -> Ok(Unencoded)
    option.Some(True) -> Ok(Base64Url)
    option.None -> Ok(Base64Url)
  }
}

fn validate_optional_crit(
  crit: Option(List(String)),
  b64: Option(Bool),
) -> Result(Nil, gose.GoseError) {
  case crit {
    option.Some(crit_list) -> validate_crit(crit_list, b64)
    option.None -> Ok(Nil)
  }
}

fn validate_crit(
  crit: List(String),
  b64: Option(Bool),
) -> Result(Nil, gose.GoseError) {
  use _ <- result.try(utils.validate_crit_headers(
    crit,
    standard_headers:,
    known_extensions:,
  ))

  case list.contains(crit, "b64") && option.is_none(b64) {
    True ->
      Error(gose.ParseError("b64 listed in crit but not present in header"))
    False -> Ok(Nil)
  }
}

fn crit_contains_b64(crit: Option(List(String))) -> Bool {
  option.map(crit, list.contains(_, "b64"))
  |> option.unwrap(False)
}
