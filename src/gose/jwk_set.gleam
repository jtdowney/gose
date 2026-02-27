//// JWK Set - [RFC 7517 Section 5](https://www.rfc-editor.org/rfc/rfc7517.html#section-5)
////
//// A JWK Set is a JSON object containing an array of JWK values.
//// The `keys` member is REQUIRED and contains the array.
////
//// ## Example
////
//// ```gleam
//// // Build a key set
//// let key =
////   jwk.generate_ec(ec.P256)
////   |> jwk.with_kid("key-1")
//// let set =
////   jwk_set.new()
////   |> jwk_set.insert(key)
////
//// // Serialize to JSON and parse back
//// let json_string = jwk_set.to_json(set)
////   |> json.to_string()
//// let assert Ok(parsed) = jwk_set.from_json(json_string)
////
//// // Look up a key by kid
//// let assert Ok(found) = jwk_set.get(parsed, "key-1")
//// ```

import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gose
import gose/jwk

/// A JSON Web Key Set containing zero or more JWKs.
pub opaque type JwkSet {
  JwkSet(keys: List(jwk.Jwk))
}

/// Create a JWK Set from a list of keys.
///
/// ## Parameters
///
/// - `keys` - The list of JWKs to include in the set.
///
/// ## Returns
///
/// A new `JwkSet` containing the given keys.
pub fn from_list(keys: List(jwk.Jwk)) -> JwkSet {
  JwkSet(keys:)
}

/// Create an empty JWK Set.
///
/// ## Returns
///
/// A new `JwkSet` with no keys.
pub fn new() -> JwkSet {
  JwkSet(keys: [])
}

/// Serialize a JWK Set to its JSON representation.
///
/// ## Parameters
///
/// - `jwk_set` - The JWK Set to serialize.
///
/// ## Returns
///
/// A `json.Json` value containing `{"keys": [...]}` with each key
/// serialized via `jwk.to_json()`.
pub fn to_json(jwk_set: JwkSet) -> json.Json {
  let json_keys = list.map(jwk_set.keys, jwk.to_json)
  json.object([#("keys", json.preprocessed_array(json_keys))])
}

/// Get all keys from a JWK Set as a list.
///
/// ## Parameters
///
/// - `jwk_set` - The JWK Set to extract keys from.
///
/// ## Returns
///
/// The list of JWKs contained in the set.
pub fn to_list(jwk_set: JwkSet) -> List(jwk.Jwk) {
  jwk_set.keys
}

/// Parse a JWK Set from a JSON string.
///
/// The `keys` array is required. Unknown top-level members are ignored per RFC.
///
/// ## Parameters
///
/// - `json_str` - The JSON string containing a JWK Set object.
///
/// ## Returns
///
/// `Ok(JwkSet)` with the parsed key set (silently skipping invalid keys),
/// or `Error(ParseError)` if the `keys` array is missing or malformed.
pub fn from_json(json_str: String) -> Result(JwkSet, gose.GoseError) {
  parse_keys_array(json.parse(json_str, _))
  |> result.map(parse_keys_lenient)
}

/// Parse a JWK Set from a JSON BitArray.
///
/// The `keys` array is required. Unknown top-level members are ignored per RFC.
///
/// ## Parameters
///
/// - `json_bits` - The JSON BitArray containing a JWK Set object.
///
/// ## Returns
///
/// `Ok(JwkSet)` with the parsed key set (silently skipping invalid keys),
/// or `Error(ParseError)` if the `keys` array is missing or malformed.
pub fn from_json_bits(json_bits: BitArray) -> Result(JwkSet, gose.GoseError) {
  parse_keys_array(json.parse_bits(json_bits, _))
  |> result.map(parse_keys_lenient)
}

/// Parse a JWK Set from a JSON string, failing on any invalid key.
///
/// Unlike `from_json` which silently skips invalid keys, this function
/// returns an error if any key in the array fails to parse. The error
/// message includes the index of the invalid key.
///
/// Note that RFC 7517 Section 5 says implementations SHOULD ignore JWKs
/// with unrecognised key types, missing required members, or unsupported
/// parameter values. Prefer `from_json` unless you need to guarantee
/// every key in the set is valid.
///
/// ## Parameters
///
/// - `json_str` - The JSON string containing a JWK Set object.
///
/// ## Returns
///
/// `Ok(JwkSet)` with all parsed keys, or `Error(ParseError)` if the `keys`
/// array is missing, malformed, or any individual key fails to parse.
pub fn from_json_strict(json_str: String) -> Result(JwkSet, gose.GoseError) {
  parse_keys_array(json.parse(json_str, _))
  |> result.try(parse_keys_strict)
  |> result.map(JwkSet)
}

/// Parse a JWK Set from a JSON BitArray, failing on any invalid key.
///
/// Unlike `from_json_bits` which silently skips invalid keys, this function
/// returns an error if any key in the array fails to parse. The error
/// message includes the index of the invalid key.
///
/// Note that RFC 7517 Section 5 says implementations SHOULD ignore JWKs
/// with unrecognised key types, missing required members, or unsupported
/// parameter values. Prefer `from_json_bits` unless you need to guarantee
/// every key in the set is valid.
///
/// ## Parameters
///
/// - `json_bits` - The JSON BitArray containing a JWK Set object.
///
/// ## Returns
///
/// `Ok(JwkSet)` with all parsed keys, or `Error(ParseError)` if the `keys`
/// array is missing, malformed, or any individual key fails to parse.
pub fn from_json_strict_bits(
  json_bits: BitArray,
) -> Result(JwkSet, gose.GoseError) {
  parse_keys_array(json.parse_bits(json_bits, _))
  |> result.try(parse_keys_strict)
  |> result.map(JwkSet)
}

/// Return a lenient decoder for JWK Set values.
///
/// Invalid keys are silently skipped, matching `from_json` behavior.
///
/// ## Returns
///
/// A `Decoder(JwkSet)` that parses the `keys` array, skipping any
/// individual key that fails to parse.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(set) = json.parse(json_string, jwk_set.decoder())
/// ```
pub fn decoder() -> decode.Decoder(JwkSet) {
  use keys_dyn <- decode.field("keys", decode.list(decode.dynamic))
  decode.success(parse_keys_lenient(keys_dyn))
}

/// Return a strict decoder for JWK Set values.
///
/// Unlike `decoder()`, this fails if any key in the set is invalid.
///
/// Note that RFC 7517 Section 5 says implementations SHOULD ignore JWKs
/// with unrecognised key types, missing required members, or unsupported
/// parameter values. Prefer `decoder()` unless you need to guarantee
/// every key in the set is valid.
///
/// ## Returns
///
/// A `Decoder(JwkSet)` that parses the `keys` array and fails if any
/// individual key is invalid.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(set) = json.parse(json_string, jwk_set.strict_decoder())
/// ```
pub fn strict_decoder() -> decode.Decoder(JwkSet) {
  use keys <- decode.field("keys", decode.list(jwk.decoder()))
  decode.success(JwkSet(keys:))
}

fn parse_keys_array(
  parse: fn(decode.Decoder(List(decode.Dynamic))) ->
    Result(List(decode.Dynamic), json.DecodeError),
) -> Result(List(decode.Dynamic), gose.GoseError) {
  parse(decode.at(["keys"], decode.list(decode.dynamic)))
  |> result.replace_error(gose.ParseError("missing or invalid keys array"))
}

fn parse_keys_lenient(keys_dyn: List(decode.Dynamic)) -> JwkSet {
  let keys =
    list.filter_map(keys_dyn, fn(key_dyn) {
      jwk.from_dynamic(key_dyn)
      |> result.replace_error(Nil)
    })
  JwkSet(keys:)
}

fn parse_keys_strict(
  keys_dyn: List(decode.Dynamic),
) -> Result(List(jwk.Jwk), gose.GoseError) {
  list.index_fold(keys_dyn, Ok([]), fn(acc, key_dyn, index) {
    use keys <- result.try(acc)
    case jwk.from_dynamic(key_dyn) {
      Ok(key) -> Ok([key, ..keys])
      Error(err) -> {
        let reason = gose.error_message(err)
        Error(gose.ParseError(
          "invalid key at index " <> int.to_string(index) <> ": " <> reason,
        ))
      }
    }
  })
  |> result.map(list.reverse)
}

/// Find a key by its key ID (kid).
///
/// ## Parameters
///
/// - `jwk_set` - The JWK Set to search.
/// - `kid` - The key ID to look up.
///
/// ## Returns
///
/// `Ok(Jwk)` with the matching key, or `Error(Nil)` if no key with the
/// given kid exists.
pub fn get(jwk_set: JwkSet, kid: String) -> Result(jwk.Jwk, Nil) {
  list.find(jwk_set.keys, fn(key) {
    case jwk.kid(key) {
      Ok(k) -> k == kid
      Error(_) -> False
    }
  })
}

/// Add a key to the set.
///
/// Keys are prepended, so if a key with the same `kid` already exists,
/// the newer key shadows the older one — `get` will return the most
/// recently inserted key.
///
/// ## Parameters
///
/// - `jwk_set` - The JWK Set to add the key to.
/// - `key` - The JWK to insert.
///
/// ## Returns
///
/// A new `JwkSet` with the key prepended.
pub fn insert(jwk_set: JwkSet, key key: jwk.Jwk) -> JwkSet {
  JwkSet(keys: [key, ..jwk_set.keys])
}

/// Remove a key by its key ID (kid).
///
/// ## Parameters
///
/// - `jwk_set` - The JWK Set to remove from.
/// - `kid` - The key ID of the key to remove.
///
/// ## Returns
///
/// A new `JwkSet` without the matching key. If no key with the given kid
/// exists, returns the set unchanged.
pub fn delete(jwk_set: JwkSet, kid kid: String) -> JwkSet {
  let filtered =
    list.filter(jwk_set.keys, fn(key) {
      case jwk.kid(key) {
        Ok(k) -> k != kid
        Error(_) -> True
      }
    })
  JwkSet(keys: filtered)
}

/// Filter keys by a predicate function.
///
/// ## Parameters
///
/// - `jwk_set` - The JWK Set to filter.
/// - `predicate` - A function applied to each key; keys returning `True` are kept.
///
/// ## Returns
///
/// A new `JwkSet` containing only the keys for which the predicate
/// returns `True`.
pub fn filter(jwk_set: JwkSet, keeping predicate: fn(jwk.Jwk) -> Bool) -> JwkSet {
  JwkSet(keys: list.filter(jwk_set.keys, predicate))
}

/// Get the first key in the set.
///
/// Useful for single-key sets or when any key will suffice.
///
/// ## Parameters
///
/// - `jwk_set` - The JWK Set to query.
///
/// ## Returns
///
/// `Ok(Jwk)` with the first key, or `Error(Nil)` if the set is empty.
pub fn first(jwk_set: JwkSet) -> Result(jwk.Jwk, Nil) {
  list.first(jwk_set.keys)
}
