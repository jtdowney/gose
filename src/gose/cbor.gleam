//// CBOR encoding and decoding ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html)).
////
//// Used by the COSE layer for binary serialization. The `Value` type
//// represents CBOR data items and is needed for CWT custom claims.
////
//// Indefinite-length encoding is not supported and will return a parse error.

import gleam/bit_array
import gleam/float
import gleam/int
import gleam/list
import gleam/order
import gleam/pair
import gleam/result
import gleam/string
import gose

/// A CBOR data item ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html)).
pub type Value {
  /// An integer, positive or negative.
  Int(Int)
  /// A byte string.
  Bytes(BitArray)
  /// A UTF-8 text string.
  Text(String)
  /// An ordered array of data items.
  Array(List(Value))
  /// A map of key-value pairs. On encoding, pairs are sorted in bytewise
  /// lexicographic order of their encoded keys (core deterministic encoding).
  Map(List(#(Value, Value)))
  /// A tagged data item (tag number and content).
  Tag(Int, Value)
  /// A boolean.
  Bool(Bool)
  /// A floating-point number.
  Float(Float)
  /// Null.
  Null
}

/// Encode a CBOR value to bytes.
///
/// Floats are always encoded as 64-bit doubles. Decoding handles all three
/// widths.
@internal
pub fn encode(value: Value) -> BitArray {
  case value {
    Int(n) -> encode_int(n)
    Bytes(b) -> encode_bytes(b)
    Text(s) -> encode_text(s)
    Array(items) -> encode_array(items)
    Map(pairs) -> encode_map(pairs)
    Tag(tag, content) -> encode_tag(tag, content)
    Bool(True) -> <<0xf5>>
    Bool(False) -> <<0xf4>>
    Float(f) -> <<0xfb, f:float>>
    Null -> <<0xf6>>
  }
}

/// Decode a single CBOR value from bytes. Returns an error if there are
/// trailing bytes after the value.
@internal
pub fn decode(data: BitArray) -> Result(Value, gose.GoseError) {
  use #(value, remainder) <- result.try(decode_with_remainder(data))
  case bit_array.byte_size(remainder) {
    0 -> Ok(value)
    _ -> Error(gose.ParseError("trailing bytes after CBOR value"))
  }
}

/// Decode one CBOR value and return it along with any remaining bytes.
@internal
pub fn decode_with_remainder(
  data: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  case data {
    <<>> -> Error(gose.ParseError("unexpected end of CBOR input"))
    <<major:size(3), info:size(5), rest:bits>> ->
      decode_major(major, info, rest)
    _ -> Error(gose.ParseError("truncated CBOR input"))
  }
}

fn encode_int(n: Int) -> BitArray {
  case n >= 0 {
    True -> encode_major_with_argument(0, n)
    False -> encode_major_with_argument(1, -1 - n)
  }
}

fn encode_bytes(b: BitArray) -> BitArray {
  let length = bit_array.byte_size(b)
  bit_array.append(encode_major_with_argument(2, length), b)
}

fn encode_text(s: String) -> BitArray {
  let bytes = bit_array.from_string(s)
  let length = bit_array.byte_size(bytes)
  bit_array.append(encode_major_with_argument(3, length), bytes)
}

fn encode_array(items: List(Value)) -> BitArray {
  let length = list.length(items)
  let header = encode_major_with_argument(4, length)
  let encoded_items = list.map(items, encode)
  list.fold(encoded_items, header, bit_array.append)
}

fn encode_map(pairs: List(#(Value, Value))) -> BitArray {
  let sorted = sort_map_pairs(pairs)
  let length = list.length(sorted)
  let header = encode_major_with_argument(5, length)
  list.fold(sorted, header, fn(acc, pair) {
    let #(k, v) = pair
    acc
    |> bit_array.append(encode(k))
    |> bit_array.append(encode(v))
  })
}

fn encode_tag(tag: Int, content: Value) -> BitArray {
  bit_array.append(encode_major_with_argument(6, tag), encode(content))
}

fn encode_major_with_argument(major: Int, value: Int) -> BitArray {
  let major_bits = int.bitwise_shift_left(major, 5)
  case value {
    v if v < 24 -> <<{ major_bits + v }>>
    v if v < 256 -> <<{ major_bits + 24 }, v>>
    v if v < 65_536 -> <<{ major_bits + 25 }, v:size(16)>>
    v if v < 4_294_967_296 -> <<{ major_bits + 26 }, v:size(32)>>
    v -> <<{ major_bits + 27 }, v:size(64)>>
  }
}

fn sort_map_pairs(pairs: List(#(Value, Value))) -> List(#(Value, Value)) {
  list.sort(pairs, fn(a, b) {
    let encoded_a = encode(a.0)
    let encoded_b = encode(b.0)
    compare_bit_arrays(encoded_a, encoded_b)
  })
}

fn compare_bit_arrays(a: BitArray, b: BitArray) -> order.Order {
  case a, b {
    <<>>, <<>> -> order.Eq
    <<>>, _ -> order.Lt
    _, <<>> -> order.Gt
    <<byte_a, rest_a:bits>>, <<byte_b, rest_b:bits>> ->
      case int.compare(byte_a, byte_b) {
        order.Eq -> compare_bit_arrays(rest_a, rest_b)
        other -> other
      }
    _, _ -> panic as "non-byte-aligned CBOR in map key sort"
  }
}

fn decode_major(
  major: Int,
  info: Int,
  rest: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  case major {
    0 -> decode_unsigned_int(info, rest)
    1 -> decode_negative_int(info, rest)
    2 -> decode_byte_string(info, rest)
    3 -> decode_text_string(info, rest)
    4 -> decode_array(info, rest)
    5 -> decode_map(info, rest)
    6 -> decode_tag(info, rest)
    7 -> decode_simple(info, rest)
    _ ->
      Error(gose.ParseError(
        "unsupported CBOR major type: " <> int.to_string(major),
      ))
  }
}

fn decode_argument(
  info: Int,
  rest: BitArray,
) -> Result(#(Int, BitArray), gose.GoseError) {
  case info {
    n if n < 24 -> Ok(#(n, rest))
    24 ->
      case rest {
        <<value, remainder:bits>> -> Ok(#(value, remainder))
        _ -> Error(gose.ParseError("truncated CBOR argument"))
      }
    25 ->
      case rest {
        <<value:size(16), remainder:bits>> -> Ok(#(value, remainder))
        _ -> Error(gose.ParseError("truncated CBOR argument"))
      }
    26 ->
      case rest {
        <<value:size(32), remainder:bits>> -> Ok(#(value, remainder))
        _ -> Error(gose.ParseError("truncated CBOR argument"))
      }
    27 ->
      case rest {
        <<value:size(64), remainder:bits>> -> Ok(#(value, remainder))
        _ -> Error(gose.ParseError("truncated CBOR argument"))
      }
    _ ->
      Error(gose.ParseError(
        "invalid CBOR additional info: " <> int.to_string(info),
      ))
  }
}

fn decode_unsigned_int(
  info: Int,
  rest: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  use #(value, remainder) <- result.try(decode_argument(info, rest))
  Ok(#(Int(value), remainder))
}

fn decode_negative_int(
  info: Int,
  rest: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  use #(value, remainder) <- result.try(decode_argument(info, rest))
  Ok(#(Int(-1 - value), remainder))
}

fn decode_byte_string(
  info: Int,
  rest: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  use #(length, after_length) <- result.try(decode_argument(info, rest))
  let remaining_size = bit_array.byte_size(after_length)
  case length > remaining_size {
    True -> Error(gose.ParseError("truncated CBOR byte string"))
    False -> {
      let assert Ok(bytes) = bit_array.slice(after_length, 0, length)
      let assert Ok(remainder) =
        bit_array.slice(after_length, length, remaining_size - length)
      Ok(#(Bytes(bytes), remainder))
    }
  }
}

fn decode_text_string(
  info: Int,
  rest: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  use #(length, after_length) <- result.try(decode_argument(info, rest))
  let remaining_size = bit_array.byte_size(after_length)
  case length > remaining_size {
    True -> Error(gose.ParseError("truncated CBOR text string"))
    False -> {
      let assert Ok(bytes) = bit_array.slice(after_length, 0, length)
      let assert Ok(remainder) =
        bit_array.slice(after_length, length, remaining_size - length)
      case bit_array.to_string(bytes) {
        Ok(text) -> Ok(#(Text(text), remainder))
        Error(_) -> Error(gose.ParseError("invalid UTF-8 in CBOR text string"))
      }
    }
  }
}

fn decode_array(
  info: Int,
  rest: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  use #(length, after_length) <- result.try(decode_argument(info, rest))
  use #(items, remainder) <- result.try(decode_n_items(length, after_length))
  Ok(#(Array(items), remainder))
}

fn decode_n_items(
  count: Int,
  data: BitArray,
) -> Result(#(List(Value), BitArray), gose.GoseError) {
  decode_n_items_loop(count, data, [])
}

fn decode_n_items_loop(
  remaining: Int,
  data: BitArray,
  acc: List(Value),
) -> Result(#(List(Value), BitArray), gose.GoseError) {
  case remaining {
    0 -> Ok(#(list.reverse(acc), data))
    _ -> {
      use #(item, rest) <- result.try(decode_with_remainder(data))
      decode_n_items_loop(remaining - 1, rest, [item, ..acc])
    }
  }
}

fn decode_map(
  info: Int,
  rest: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  use #(length, after_length) <- result.try(decode_argument(info, rest))
  use #(pairs, remainder) <- result.try(decode_n_pairs(length, after_length))
  let keys = list.map(pairs, pair.first)
  case list.length(list.unique(keys)) == list.length(keys) {
    True -> Ok(#(Map(pairs), remainder))
    False -> Error(gose.ParseError("CBOR map contains duplicate keys"))
  }
}

fn decode_n_pairs(
  count: Int,
  data: BitArray,
) -> Result(#(List(#(Value, Value)), BitArray), gose.GoseError) {
  decode_n_pairs_loop(count, data, [])
}

fn decode_n_pairs_loop(
  remaining: Int,
  data: BitArray,
  acc: List(#(Value, Value)),
) -> Result(#(List(#(Value, Value)), BitArray), gose.GoseError) {
  case remaining {
    0 -> Ok(#(list.reverse(acc), data))
    _ -> {
      use #(key, after_key) <- result.try(decode_with_remainder(data))
      use #(value, after_value) <- result.try(decode_with_remainder(after_key))
      decode_n_pairs_loop(remaining - 1, after_value, [#(key, value), ..acc])
    }
  }
}

fn decode_tag(
  info: Int,
  rest: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  use #(tag_number, after_tag) <- result.try(decode_argument(info, rest))
  use #(content, remainder) <- result.try(decode_with_remainder(after_tag))
  Ok(#(Tag(tag_number, content), remainder))
}

fn decode_simple(
  info: Int,
  rest: BitArray,
) -> Result(#(Value, BitArray), gose.GoseError) {
  case info {
    20 -> Ok(#(Bool(False), rest))
    21 -> Ok(#(Bool(True), rest))
    22 -> Ok(#(Null, rest))
    25 -> decode_f16(rest)
    26 -> decode_f32(rest)
    27 -> decode_f64(rest)
    _ ->
      Error(gose.ParseError(
        "unsupported CBOR simple value: " <> int.to_string(info),
      ))
  }
}

fn decode_f16(rest: BitArray) -> Result(#(Value, BitArray), gose.GoseError) {
  case rest {
    <<sign:1, exponent:5, mantissa:10, remainder:bits>> -> {
      use f <- result.try(convert_f16_to_f64(sign, exponent, mantissa))
      Ok(#(Float(f), remainder))
    }
    _ -> Error(gose.ParseError("truncated CBOR float16"))
  }
}

fn convert_f16_to_f64(
  sign: Int,
  exponent: Int,
  mantissa: Int,
) -> Result(Float, gose.GoseError) {
  let sign_factor = case sign {
    0 -> 1.0
    _ -> -1.0
  }
  case exponent {
    0 ->
      case mantissa {
        0 -> Ok(sign_factor *. 0.0)
        _ -> {
          let m = int.to_float(mantissa) /. 1024.0
          Ok(sign_factor *. m *. exp2(-14))
        }
      }
    31 -> Error(gose.ParseError("NaN and Infinity are not supported"))
    _ -> {
      let m = 1.0 +. int.to_float(mantissa) /. 1024.0
      Ok(sign_factor *. m *. exp2(exponent - 15))
    }
  }
}

fn exp2(n: Int) -> Float {
  do_exp2(n, 1.0)
}

fn do_exp2(n: Int, acc: Float) -> Float {
  case n {
    0 -> acc
    _ if n > 0 -> do_exp2(n - 1, acc *. 2.0)
    _ -> do_exp2(n + 1, acc /. 2.0)
  }
}

fn decode_f32(rest: BitArray) -> Result(#(Value, BitArray), gose.GoseError) {
  case rest {
    <<_:1, 255:8, _:23, _remainder:bits>> ->
      Error(gose.ParseError("NaN and Infinity are not supported"))
    <<f:32-float, remainder:bits>> -> Ok(#(Float(f), remainder))
    _ -> Error(gose.ParseError("truncated CBOR float32"))
  }
}

fn decode_f64(rest: BitArray) -> Result(#(Value, BitArray), gose.GoseError) {
  case rest {
    <<_:1, 2047:11, _:52, _remainder:bits>> ->
      Error(gose.ParseError("NaN and Infinity are not supported"))
    <<f:float, remainder:bits>> -> Ok(#(Float(f), remainder))
    _ -> Error(gose.ParseError("truncated CBOR float64"))
  }
}

/// Format a value as CBOR diagnostic notation ([RFC 8949 Section 8](https://www.rfc-editor.org/rfc/rfc8949.html#section-8)).
@internal
pub fn to_diagnostic(value: Value) -> String {
  case value {
    Int(n) -> int.to_string(n)
    Bytes(b) -> "h'" <> bit_array.base16_encode(b) |> string.lowercase <> "'"
    Text(s) -> "\"" <> s <> "\""
    Array(items) ->
      "[" <> string.join(list.map(items, to_diagnostic), ", ") <> "]"
    Map(pairs) ->
      "{"
      <> string.join(
        list.map(pairs, fn(pair) {
          to_diagnostic(pair.0) <> ": " <> to_diagnostic(pair.1)
        }),
        ", ",
      )
      <> "}"
    Tag(tag, content) ->
      int.to_string(tag) <> "(" <> to_diagnostic(content) <> ")"
    Bool(True) -> "true"
    Bool(False) -> "false"
    Float(f) -> float.to_string(f)
    Null -> "null"
  }
}
