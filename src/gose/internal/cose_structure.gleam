import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/pair
import gleam/result
import gleam/set
import gose
import gose/algorithm
import gose/cbor
import gose/cose
import gose/cose/algorithm as cose_algorithm
import gose/internal/signing
import gose/key

pub fn serialize_protected(headers: List(cose.Header)) -> BitArray {
  case headers {
    [] -> <<>>
    _ -> cbor.encode(cbor.Map(cose.headers_to_cbor(headers)))
  }
}

pub fn decode_protected(
  data: BitArray,
) -> Result(List(cose.Header), gose.GoseError) {
  case bit_array.byte_size(data) {
    0 -> Ok([])
    _ -> {
      use value <- result.try(cbor.decode(data))
      case value {
        cbor.Map([]) ->
          Error(gose.ParseError(
            "empty protected header must be encoded as the empty bstr",
          ))
        cbor.Map(pairs) -> cose.headers_from_cbor(pairs)
        _ -> Error(gose.ParseError("protected header is not a CBOR map"))
      }
    }
  }
}

pub fn decode_unprotected(
  pairs: List(#(cbor.Value, cbor.Value)),
) -> Result(List(cose.Header), gose.GoseError) {
  cose.headers_from_cbor(pairs)
}

pub fn validate_no_header_overlap(
  protected: List(cose.Header),
  unprotected: List(cose.Header),
) -> Result(Nil, gose.GoseError) {
  let protected_cbor = cose.headers_to_cbor(protected)
  let unprotected_cbor = cose.headers_to_cbor(unprotected)
  let protected_keys = list.map(protected_cbor, pair.first)
  let has_overlap =
    list.any(unprotected_cbor, fn(entry) {
      list.contains(protected_keys, entry.0)
    })
  use <- bool.guard(
    when: has_overlap,
    return: Error(gose.ParseError(
      "duplicate label in protected and unprotected headers",
    )),
  )
  Ok(Nil)
}

pub fn validate_iv_partial_iv_exclusion(
  protected: List(cose.Header),
  unprotected: List(cose.Header),
) -> Result(Nil, gose.GoseError) {
  let all_headers = list.append(protected, unprotected)
  let has_iv =
    list.any(all_headers, fn(h) {
      case h {
        cose.Iv(_) -> True
        _ -> False
      }
    })
  let has_partial_iv =
    list.any(all_headers, fn(h) {
      case h {
        cose.PartialIv(_) -> True
        _ -> False
      }
    })
  use <- bool.guard(
    when: has_iv && has_partial_iv,
    return: Error(gose.ParseError("IV and Partial IV must not both be present")),
  )
  Ok(Nil)
}

/// Validate the `crit` header.
///
/// Only standard COSE header labels (1-7) are accepted in the `crit`
/// array. Application-specific critical headers are not currently
/// supported and will be rejected with a parse error. Standard labels
/// in `crit` are accepted but have no additional effect since they are
/// always understood.
pub fn validate_crit(
  protected: List(cose.Header),
  unprotected: List(cose.Header),
) -> Result(Nil, gose.GoseError) {
  let has_crit_in_unprotected =
    list.any(unprotected, fn(h) {
      case h {
        cose.Crit(_) -> True
        _ -> False
      }
    })
  use <- bool.guard(
    when: has_crit_in_unprotected,
    return: Error(gose.ParseError("crit header must be in the protected bucket")),
  )
  case cose.critical(protected) {
    Error(_) -> Ok(Nil)
    Ok(labels) -> validate_crit_labels(labels, protected)
  }
}

const standard_labels = [1, 2, 3, 4, 5, 6, 7]

fn validate_crit_labels(
  labels: List(Int),
  protected: List(cose.Header),
) -> Result(Nil, gose.GoseError) {
  let crit_set = set.from_list(labels)
  use <- bool.guard(
    when: list.is_empty(labels),
    return: Error(gose.ParseError("crit array must not be empty")),
  )
  use <- bool.guard(
    when: list.length(labels) != set.size(crit_set),
    return: Error(gose.ParseError("crit array contains duplicate values")),
  )
  let protected_keys =
    cose.headers_to_cbor(protected)
    |> list.map(pair.first)
  let standard_set = set.from_list(standard_labels)
  list.try_each(labels, fn(label) {
    let is_present = list.contains(protected_keys, cbor.Int(label))
    use <- bool.guard(
      when: !is_present,
      return: Error(gose.ParseError(
        "crit references label not in protected headers: "
        <> int.to_string(label),
      )),
    )
    case set.contains(standard_set, label) {
      True -> Ok(Nil)
      False ->
        Error(gose.ParseError(
          "unsupported critical header: " <> int.to_string(label),
        ))
    }
  })
}

pub fn extract_signing_alg_from_headers(
  headers: List(cose.Header),
) -> Result(algorithm.SigningAlg, gose.GoseError) {
  use id <- result.try(cose.algorithm(headers))
  cose_algorithm.signing_alg_from_int(id)
}

pub fn extract_signature_alg_from_headers(
  headers: List(cose.Header),
) -> Result(algorithm.DigitalSignatureAlg, gose.GoseError) {
  use id <- result.try(cose.algorithm(headers))
  cose_algorithm.signature_alg_from_int(id)
}

pub fn extract_signature_alg_from_serialized(
  protected_serialized: BitArray,
) -> Result(algorithm.DigitalSignatureAlg, gose.GoseError) {
  with_decoded_protected(
    protected_serialized,
    extract_signature_alg_from_headers,
  )
}

pub fn extract_content_alg_from_headers(
  headers: List(cose.Header),
) -> Result(algorithm.ContentAlg, gose.GoseError) {
  use id <- result.try(cose.algorithm(headers))
  cose_algorithm.content_alg_from_int(id)
}

pub fn extract_signing_alg_from_serialized(
  protected_serialized: BitArray,
) -> Result(algorithm.SigningAlg, gose.GoseError) {
  with_decoded_protected(protected_serialized, extract_signing_alg_from_headers)
}

pub fn extract_content_alg_from_serialized(
  protected_serialized: BitArray,
) -> Result(algorithm.ContentAlg, gose.GoseError) {
  with_decoded_protected(protected_serialized, extract_content_alg_from_headers)
}

pub fn extract_key_encryption_alg_from_headers(
  headers: List(cose.Header),
) -> Result(algorithm.KeyEncryptionAlg, gose.GoseError) {
  use id <- result.try(cose.algorithm(headers))
  cose_algorithm.key_encryption_alg_from_int(id)
}

pub fn extract_key_encryption_alg_from_serialized(
  protected_serialized: BitArray,
) -> Result(algorithm.KeyEncryptionAlg, gose.GoseError) {
  with_decoded_protected(
    protected_serialized,
    extract_key_encryption_alg_from_headers,
  )
}

fn with_decoded_protected(
  protected_serialized: BitArray,
  extract: fn(List(cose.Header)) -> Result(a, gose.GoseError),
) -> Result(a, gose.GoseError) {
  case bit_array.byte_size(protected_serialized) {
    0 -> Error(gose.ParseError("empty protected header, no alg found"))
    _ -> {
      use headers <- result.try(decode_protected(protected_serialized))
      extract(headers)
    }
  }
}

pub fn decode_payload(
  value: cbor.Value,
) -> Result(Option(BitArray), gose.GoseError) {
  case value {
    cbor.Bytes(b) -> Ok(option.Some(b))
    cbor.Null -> Ok(option.None)
    _ -> Error(gose.ParseError("invalid COSE payload: expected bstr or null"))
  }
}

pub fn try_verify_keys(
  alg: algorithm.SigningAlg,
  keys keys: List(key.Key(kid)),
  message message: BitArray,
  signature signature: BitArray,
) -> Result(Nil, gose.GoseError) {
  case keys {
    [] -> Error(gose.VerificationFailed)
    [key, ..rest] ->
      case signing.verify_signature(alg, key:, message:, signature:) {
        Ok(Nil) -> Ok(Nil)
        Error(gose.VerificationFailed) ->
          try_verify_keys(alg, keys: rest, message:, signature:)
        Error(err) -> Error(err)
      }
  }
}

pub fn parse_cose_array(
  data: BitArray,
  expected_tag expected_tag: Int,
  expected_length expected_length: Int,
) -> Result(List(cbor.Value), gose.GoseError) {
  use value <- result.try(cbor.decode(data))
  parse_cose_array_value(value, expected_tag:, expected_length:)
}

pub fn parse_cose_array_value(
  value: cbor.Value,
  expected_tag expected_tag: Int,
  expected_length expected_length: Int,
) -> Result(List(cbor.Value), gose.GoseError) {
  case value {
    cbor.Tag(tag, inner) if tag == expected_tag ->
      parse_cose_array_value(inner, expected_tag:, expected_length:)
    cbor.Array(items) ->
      case list.length(items) == expected_length {
        True -> Ok(items)
        False -> Error(gose.ParseError("invalid COSE structure"))
      }
    _ -> Error(gose.ParseError("invalid COSE structure"))
  }
}

pub fn require_embedded_payload(
  payload: Option(BitArray),
) -> Result(BitArray, gose.GoseError) {
  case payload {
    option.Some(p) -> Ok(p)
    option.None ->
      Error(gose.InvalidState(
        "message has detached payload; use verify_detached",
      ))
  }
}

pub fn require_detached_payload(
  payload: Option(BitArray),
) -> Result(Nil, gose.GoseError) {
  case payload {
    option.None -> Ok(Nil)
    option.Some(_) ->
      Error(gose.InvalidState("message has embedded payload; use verify"))
  }
}

pub fn build_enc_structure(
  context context: String,
  protected_serialized protected_serialized: BitArray,
  aad aad: BitArray,
) -> BitArray {
  cbor.encode(
    cbor.Array([
      cbor.Text(context),
      cbor.Bytes(protected_serialized),
      cbor.Bytes(aad),
    ]),
  )
}

pub fn split_ciphertext_tag(
  ciphertext_with_tag: BitArray,
  tag_size tag_size: Int,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  let total = bit_array.byte_size(ciphertext_with_tag)
  let ct_len = total - tag_size
  case ct_len >= 0 {
    False ->
      Error(gose.ParseError(
        "ciphertext too short to contain authentication tag",
      ))
    True ->
      case
        bit_array.slice(ciphertext_with_tag, 0, ct_len),
        bit_array.slice(ciphertext_with_tag, ct_len, tag_size)
      {
        Ok(ct), Ok(tag) -> Ok(#(ct, tag))
        _, _ ->
          Error(gose.ParseError(
            "failed to split ciphertext and authentication tag",
          ))
      }
  }
}
