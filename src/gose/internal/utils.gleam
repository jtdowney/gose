//// Shared utility functions for gose internal use.

import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/result
import gleam/set
import gose
import kryptos/ec
import kryptos/eddsa
import kryptos/xdh

/// Decode a base64url-encoded string, returning a descriptive parse error on failure.
pub fn decode_base64_url(
  b64: String,
  name: String,
) -> Result(BitArray, gose.GoseError) {
  bit_array.base64_url_decode(b64)
  |> result.replace_error(gose.ParseError("invalid " <> name <> " base64"))
}

/// Parse an EC curve from its JWK string representation.
pub fn ec_curve_from_string(s: String) -> Result(ec.Curve, gose.GoseError) {
  case s {
    "P-256" -> Ok(ec.P256)
    "P-384" -> Ok(ec.P384)
    "P-521" -> Ok(ec.P521)
    "secp256k1" -> Ok(ec.Secp256k1)
    _ -> Error(gose.ParseError("unsupported EC curve: " <> s))
  }
}

/// Convert an EC curve to its JWK string representation.
pub fn ec_curve_to_string(curve: ec.Curve) -> String {
  case curve {
    ec.P256 -> "P-256"
    ec.P384 -> "P-384"
    ec.P521 -> "P-521"
    ec.Secp256k1 -> "secp256k1"
  }
}

/// Extract x,y coordinates from an EC public key as raw big-endian bytes.
pub fn ec_public_key_coordinates(
  public: ec.PublicKey,
  curve: ec.Curve,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  let coord_size = ec.coordinate_size(curve)
  let raw_point = ec.public_key_to_raw_point(public)
  let expected_size = 1 + coord_size * 2
  case bit_array.byte_size(raw_point) == expected_size, raw_point {
    True, <<0x04, rest:bits>> ->
      case bit_array.slice(rest, 0, coord_size) {
        Ok(x) ->
          bit_array.slice(rest, coord_size, coord_size)
          |> result.replace_error(gose.InvalidState("invalid raw point format"))
          |> result.map(fn(y) { #(x, y) })
        Error(_) -> Error(gose.InvalidState("invalid raw point format"))
      }
    _, _ -> Error(gose.InvalidState("invalid raw point format"))
  }
}

/// Create an EC public key from curve and x,y coordinates (big-endian bytes).
pub fn ec_public_key_from_coordinates(
  curve: ec.Curve,
  x: BitArray,
  y: BitArray,
) -> Result(ec.PublicKey, gose.GoseError) {
  let coord_size = ec.coordinate_size(curve)
  use <- bool.guard(
    when: bit_array.byte_size(x) != coord_size,
    return: Error(gose.ParseError("EC x coordinate wrong length")),
  )
  use <- bool.guard(
    when: bit_array.byte_size(y) != coord_size,
    return: Error(gose.ParseError("EC y coordinate wrong length")),
  )
  let raw_point = bit_array.concat([<<0x04>>, x, y])
  ec.public_key_from_raw_point(curve, raw_point)
  |> result.replace_error(gose.ParseError("invalid EC coordinates"))
}

/// Parse an EdDSA curve from its JWK string representation.
pub fn eddsa_curve_from_string(s: String) -> Result(eddsa.Curve, gose.GoseError) {
  case s {
    "Ed25519" -> Ok(eddsa.Ed25519)
    "Ed448" -> Ok(eddsa.Ed448)
    _ -> Error(gose.ParseError("unsupported EdDSA curve: " <> s))
  }
}

/// Convert an EdDSA curve to its JWK string representation.
pub fn eddsa_curve_to_string(curve: eddsa.Curve) -> String {
  case curve {
    eddsa.Ed25519 -> "Ed25519"
    eddsa.Ed448 -> "Ed448"
  }
}

/// Encode a bit array as a base64url string without padding.
pub fn encode_base64_url(data: BitArray) -> String {
  bit_array.base64_url_encode(data, False)
}

/// Strip leading zero bytes from a bit array, preserving at least one byte.
pub fn strip_leading_zeros(data: BitArray) -> BitArray {
  case data {
    <<0, rest:bits>> ->
      case bit_array.byte_size(rest) > 0 {
        True -> strip_leading_zeros(rest)
        False -> data
      }
    _ -> data
  }
}

/// Validate a JOSE `crit` header list against supported extension rules.
///
/// Ensures `crit` is non-empty, contains no duplicates, excludes standard
/// headers, and only includes values present in `known_extensions`.
pub fn validate_crit_headers(
  extensions: List(String),
  standard_headers: List(String),
  known_extensions: List(String),
) -> Result(Nil, gose.GoseError) {
  let standard = set.from_list(standard_headers)
  let known = set.from_list(known_extensions)
  let crit_set = set.from_list(extensions)
  use <- bool.guard(
    when: set.is_empty(crit_set),
    return: Error(gose.ParseError("crit array must not be empty")),
  )
  use <- bool.guard(
    when: list.length(extensions) != set.size(crit_set),
    return: Error(gose.ParseError("crit array contains duplicate values")),
  )
  list.try_each(extensions, fn(header) {
    case set.contains(standard, header), set.contains(known, header) {
      True, _ -> Error(gose.ParseError("standard header in crit: " <> header))
      _, True -> Ok(Nil)
      _, False ->
        Error(gose.ParseError("unsupported critical header: " <> header))
    }
  })
}

/// Parse an XDH curve from its JWK string representation.
pub fn xdh_curve_from_string(s: String) -> Result(xdh.Curve, gose.GoseError) {
  case s {
    "X25519" -> Ok(xdh.X25519)
    "X448" -> Ok(xdh.X448)
    _ -> Error(gose.ParseError("unsupported XDH curve: " <> s))
  }
}

/// Convert an XDH curve to its JWK string representation.
pub fn xdh_curve_to_string(curve: xdh.Curve) -> String {
  case curve {
    xdh.X25519 -> "X25519"
    xdh.X448 -> "X448"
  }
}
