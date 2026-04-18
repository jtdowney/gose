import gleam/int
import gleam/list
import gleam/order
import gose
import gose/cbor
import qcheck

pub fn int_canonical_vectors_test() {
  let vectors = [
    #(0, <<0x00>>),
    #(1, <<0x01>>),
    #(10, <<0x0a>>),
    #(23, <<0x17>>),
    #(24, <<0x18, 0x18>>),
    #(25, <<0x18, 0x19>>),
    #(100, <<0x18, 0x64>>),
    #(255, <<0x18, 0xff>>),
    #(256, <<0x19, 0x01, 0x00>>),
    #(1000, <<0x19, 0x03, 0xe8>>),
    #(65_535, <<0x19, 0xff, 0xff>>),
    #(65_536, <<0x1a, 0x00, 0x01, 0x00, 0x00>>),
    #(1_000_000, <<0x1a, 0x00, 0x0f, 0x42, 0x40>>),
    #(4_294_967_295, <<0x1a, 0xff, 0xff, 0xff, 0xff>>),
    #(4_294_967_296, <<0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00>>),
    #(-1, <<0x20>>),
    #(-10, <<0x29>>),
    #(-24, <<0x37>>),
    #(-25, <<0x38, 0x18>>),
    #(-100, <<0x38, 0x63>>),
    #(-1000, <<0x39, 0x03, 0xe7>>),
  ]
  list.each(vectors, fn(pair) {
    let #(value, expected_bytes) = pair
    assert cbor.encode(cbor.Int(value)) == expected_bytes
    assert cbor.decode(expected_bytes) == Ok(cbor.Int(value))
  })
}

pub fn encode_bytes_empty_test() {
  assert cbor.encode(cbor.Bytes(<<>>)) == <<0x40>>
}

pub fn encode_bytes_four_test() {
  assert cbor.encode(cbor.Bytes(<<0x01, 0x02, 0x03, 0x04>>))
    == <<0x44, 0x01, 0x02, 0x03, 0x04>>
}

pub fn encode_text_empty_test() {
  assert cbor.encode(cbor.Text("")) == <<0x60>>
}

pub fn encode_text_a_test() {
  assert cbor.encode(cbor.Text("a")) == <<0x61, 0x61>>
}

pub fn encode_text_ietf_test() {
  assert cbor.encode(cbor.Text("IETF")) == <<0x64, 0x49, 0x45, 0x54, 0x46>>
}

pub fn encode_text_hello_test() {
  assert cbor.encode(cbor.Text("hello"))
    == <<0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f>>
}

pub fn encode_array_empty_test() {
  assert cbor.encode(cbor.Array([])) == <<0x80>>
}

pub fn encode_array_123_test() {
  assert cbor.encode(cbor.Array([cbor.Int(1), cbor.Int(2), cbor.Int(3)]))
    == <<0x83, 0x01, 0x02, 0x03>>
}

pub fn encode_array_nested_test() {
  let value =
    cbor.Array([
      cbor.Int(1),
      cbor.Array([cbor.Int(2), cbor.Int(3)]),
      cbor.Array([cbor.Int(4), cbor.Int(5)]),
    ])
  assert cbor.encode(value)
    == <<0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05>>
}

pub fn encode_map_empty_test() {
  assert cbor.encode(cbor.Map([])) == <<0xa0>>
}

pub fn encode_map_int_keys_test() {
  let value =
    cbor.Map([#(cbor.Int(1), cbor.Int(2)), #(cbor.Int(3), cbor.Int(4))])
  assert cbor.encode(value) == <<0xa2, 0x01, 0x02, 0x03, 0x04>>
}

pub fn encode_map_text_keys_test() {
  let value =
    cbor.Map([#(cbor.Text("a"), cbor.Int(1)), #(cbor.Text("b"), cbor.Int(2))])
  assert cbor.encode(value) == <<0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02>>
}

pub fn encode_tag_cose_sign1_test() {
  let value =
    cbor.Tag(18, cbor.Array([cbor.Bytes(<<>>), cbor.Map([]), cbor.Null]))
  let encoded = cbor.encode(value)
  assert encoded == <<0xd2, 0x83, 0x40, 0xa0, 0xf6>>
}

pub fn encode_null_test() {
  assert cbor.encode(cbor.Null) == <<0xf6>>
}

pub fn decode_bytes_empty_test() {
  assert cbor.decode(<<0x40>>) == Ok(cbor.Bytes(<<>>))
}

pub fn decode_bytes_four_test() {
  assert cbor.decode(<<0x44, 0x01, 0x02, 0x03, 0x04>>)
    == Ok(cbor.Bytes(<<0x01, 0x02, 0x03, 0x04>>))
}

pub fn decode_text_empty_test() {
  assert cbor.decode(<<0x60>>) == Ok(cbor.Text(""))
}

pub fn decode_text_a_test() {
  assert cbor.decode(<<0x61, 0x61>>) == Ok(cbor.Text("a"))
}

pub fn decode_text_ietf_test() {
  assert cbor.decode(<<0x64, 0x49, 0x45, 0x54, 0x46>>) == Ok(cbor.Text("IETF"))
}

pub fn decode_text_hello_test() {
  assert cbor.decode(<<0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f>>)
    == Ok(cbor.Text("hello"))
}

pub fn decode_array_empty_test() {
  assert cbor.decode(<<0x80>>) == Ok(cbor.Array([]))
}

pub fn decode_array_123_test() {
  assert cbor.decode(<<0x83, 0x01, 0x02, 0x03>>)
    == Ok(cbor.Array([cbor.Int(1), cbor.Int(2), cbor.Int(3)]))
}

pub fn decode_array_nested_test() {
  assert cbor.decode(<<0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05>>)
    == Ok(
      cbor.Array([
        cbor.Int(1),
        cbor.Array([cbor.Int(2), cbor.Int(3)]),
        cbor.Array([cbor.Int(4), cbor.Int(5)]),
      ]),
    )
}

pub fn decode_map_empty_test() {
  assert cbor.decode(<<0xa0>>) == Ok(cbor.Map([]))
}

pub fn decode_map_int_keys_test() {
  assert cbor.decode(<<0xa2, 0x01, 0x02, 0x03, 0x04>>)
    == Ok(cbor.Map([#(cbor.Int(1), cbor.Int(2)), #(cbor.Int(3), cbor.Int(4))]))
}

pub fn decode_map_text_keys_test() {
  assert cbor.decode(<<0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02>>)
    == Ok(
      cbor.Map([#(cbor.Text("a"), cbor.Int(1)), #(cbor.Text("b"), cbor.Int(2))]),
    )
}

pub fn decode_map_duplicate_keys_rejected_test() {
  // Map with two entries both keyed by Int(1): {1: 2, 1: 3}
  assert cbor.decode(<<0xa2, 0x01, 0x02, 0x01, 0x03>>)
    == Error(gose.ParseError("CBOR map contains duplicate keys"))
}

pub fn decode_tag_cose_sign1_test() {
  assert cbor.decode(<<0xd2, 0x83, 0x40, 0xa0, 0xf6>>)
    == Ok(cbor.Tag(18, cbor.Array([cbor.Bytes(<<>>), cbor.Map([]), cbor.Null])))
}

pub fn decode_null_test() {
  assert cbor.decode(<<0xf6>>) == Ok(cbor.Null)
}

pub fn decode_with_remainder_returns_rest_test() {
  let assert Ok(#(value, remainder)) =
    cbor.decode_with_remainder(<<0x01, 0x02, 0x03>>)
  assert value == cbor.Int(1)
  assert remainder == <<0x02, 0x03>>
}

pub fn decode_trailing_bytes_error_test() {
  assert cbor.decode(<<0x01, 0x02>>)
    == Error(gose.ParseError("trailing bytes after CBOR value"))
}

pub fn decode_empty_input_test() {
  assert cbor.decode(<<>>)
    == Error(gose.ParseError("unexpected end of CBOR input"))
}

pub fn decode_truncated_1byte_argument_test() {
  assert cbor.decode(<<0x18>>)
    == Error(gose.ParseError("truncated CBOR argument"))
}

pub fn decode_truncated_2byte_argument_test() {
  assert cbor.decode(<<0x19, 0x01>>)
    == Error(gose.ParseError("truncated CBOR argument"))
}

pub fn decode_truncated_2byte_argument_no_data_test() {
  assert cbor.decode(<<0x19>>)
    == Error(gose.ParseError("truncated CBOR argument"))
}

pub fn decode_truncated_4byte_argument_test() {
  assert cbor.decode(<<0x1a, 0x01, 0x02>>)
    == Error(gose.ParseError("truncated CBOR argument"))
}

pub fn decode_truncated_8byte_argument_test() {
  assert cbor.decode(<<0x1b, 0x01>>)
    == Error(gose.ParseError("truncated CBOR argument"))
}

pub fn decode_truncated_byte_string_test() {
  assert cbor.decode(<<0x43, 0x01, 0x02>>)
    == Error(gose.ParseError("truncated CBOR byte string"))
}

pub fn decode_truncated_text_string_test() {
  assert cbor.decode(<<0x63, 0x61, 0x62>>)
    == Error(gose.ParseError("truncated CBOR text string"))
}

pub fn decode_unsupported_simple_value_test() {
  assert cbor.decode(<<0xf3>>)
    == Error(gose.ParseError("unsupported CBOR simple value: 19"))
}

pub fn encode_decode_bool_true_test() {
  let value = cbor.Bool(True)
  assert cbor.encode(value) == <<0xf5>>
  assert cbor.decode(<<0xf5>>) == Ok(cbor.Bool(True))
}

pub fn encode_decode_bool_false_test() {
  let value = cbor.Bool(False)
  assert cbor.encode(value) == <<0xf4>>
  assert cbor.decode(<<0xf4>>) == Ok(cbor.Bool(False))
}

pub fn encode_decode_float_roundtrip_test() {
  let value = cbor.Float(1.5)
  let encoded = cbor.encode(value)
  assert cbor.decode(encoded) == Ok(cbor.Float(1.5))
}

pub fn encode_float_uses_f64_test() {
  let encoded = cbor.encode(cbor.Float(1.0))
  assert encoded == <<0xfb, 1.0:float>>
}

pub fn decode_f16_zero_test() {
  assert cbor.decode(<<0xf9, 0x00, 0x00>>) == Ok(cbor.Float(0.0))
}

pub fn decode_f16_one_test() {
  assert cbor.decode(<<0xf9, 0x3c, 0x00>>) == Ok(cbor.Float(1.0))
}

pub fn decode_f16_one_point_five_test() {
  assert cbor.decode(<<0xf9, 0x3e, 0x00>>) == Ok(cbor.Float(1.5))
}

pub fn decode_f16_negative_two_test() {
  assert cbor.decode(<<0xf9, 0xc0, 0x00>>) == Ok(cbor.Float(-2.0))
}

pub fn decode_f16_positive_infinity_rejected_test() {
  // 0x7c00 = sign=0, exponent=31, mantissa=0 (+Inf)
  assert cbor.decode(<<0xf9, 0x7c, 0x00>>)
    == Error(gose.ParseError("NaN and Infinity are not supported"))
}

pub fn decode_f16_negative_infinity_rejected_test() {
  // 0xfc00 = sign=1, exponent=31, mantissa=0 (-Inf)
  assert cbor.decode(<<0xf9, 0xfc, 0x00>>)
    == Error(gose.ParseError("NaN and Infinity are not supported"))
}

pub fn decode_f16_nan_rejected_test() {
  // 0x7e00 = sign=0, exponent=31, mantissa!=0 (NaN)
  assert cbor.decode(<<0xf9, 0x7e, 0x00>>)
    == Error(gose.ParseError("NaN and Infinity are not supported"))
}

pub fn decode_f32_test() {
  assert cbor.decode(<<0xfa, 1.5:32-float>>) == Ok(cbor.Float(1.5))
}

pub fn decode_f32_positive_infinity_rejected_test() {
  assert cbor.decode(<<0xfa, 0:1, 255:8, 0:23>>)
    == Error(gose.ParseError("NaN and Infinity are not supported"))
}

pub fn decode_f32_negative_infinity_rejected_test() {
  assert cbor.decode(<<0xfa, 1:1, 255:8, 0:23>>)
    == Error(gose.ParseError("NaN and Infinity are not supported"))
}

pub fn decode_f32_nan_rejected_test() {
  assert cbor.decode(<<0xfa, 0:1, 255:8, 1:23>>)
    == Error(gose.ParseError("NaN and Infinity are not supported"))
}

pub fn decode_f64_test() {
  assert cbor.decode(<<0xfb, 1.5:float>>) == Ok(cbor.Float(1.5))
}

pub fn decode_f64_positive_infinity_rejected_test() {
  assert cbor.decode(<<0xfb, 0:1, 2047:11, 0:52>>)
    == Error(gose.ParseError("NaN and Infinity are not supported"))
}

pub fn decode_f64_negative_infinity_rejected_test() {
  assert cbor.decode(<<0xfb, 1:1, 2047:11, 0:52>>)
    == Error(gose.ParseError("NaN and Infinity are not supported"))
}

pub fn decode_f64_nan_rejected_test() {
  assert cbor.decode(<<0xfb, 0:1, 2047:11, 1:52>>)
    == Error(gose.ParseError("NaN and Infinity are not supported"))
}

pub fn diagnostic_bool_true_test() {
  assert cbor.to_diagnostic(cbor.Bool(True)) == "true"
}

pub fn diagnostic_bool_false_test() {
  assert cbor.to_diagnostic(cbor.Bool(False)) == "false"
}

pub fn diagnostic_float_test() {
  assert cbor.to_diagnostic(cbor.Float(1.5)) == "1.5"
}

pub fn encode_map_sorts_text_keys_bytewise_test() {
  let value =
    cbor.Map([
      #(cbor.Text("bb"), cbor.Int(2)),
      #(cbor.Text("a"), cbor.Int(1)),
    ])
  let encoded = cbor.encode(value)
  assert encoded == <<0xa2, 0x61, 0x61, 0x01, 0x62, 0x62, 0x62, 0x02>>
}

pub fn encode_map_sorts_int_keys_bytewise_test() {
  let value =
    cbor.Map([
      #(cbor.Int(3), cbor.Int(4)),
      #(cbor.Int(1), cbor.Int(2)),
    ])
  let encoded = cbor.encode(value)
  assert encoded == <<0xa2, 0x01, 0x02, 0x03, 0x04>>
}

pub fn encode_map_sorts_bytewise_not_length_first_test() {
  let value =
    cbor.Map([
      #(cbor.Int(-1), cbor.Int(0)),
      #(cbor.Int(24), cbor.Int(1)),
    ])
  let encoded = cbor.encode(value)
  assert encoded == <<0xa2, 0x18, 0x18, 0x01, 0x20, 0x00>>
}

pub fn encode_map_sorts_different_types_test() {
  let value =
    cbor.Map([
      #(cbor.Text("a"), cbor.Int(2)),
      #(cbor.Int(1), cbor.Int(1)),
    ])
  let encoded = cbor.encode(value)
  let assert Ok(cbor.Map(pairs)) = cbor.decode(encoded)
  let assert [#(cbor.Int(1), cbor.Int(1)), #(cbor.Text("a"), cbor.Int(2))] =
    pairs
}

pub fn roundtrip_int_property_test() {
  let gen = qcheck.map(qcheck.bounded_int(-1000, 1_000_000), cbor.Int)
  use value <- qcheck.given(gen)
  let encoded = cbor.encode(value)
  assert cbor.decode(encoded) == Ok(value)
}

pub fn roundtrip_bytes_property_test() {
  let gen = qcheck.map(qcheck.byte_aligned_bit_array(), cbor.Bytes)
  use value <- qcheck.given(gen)
  let encoded = cbor.encode(value)
  assert cbor.decode(encoded) == Ok(value)
}

pub fn roundtrip_text_property_test() {
  let gen = qcheck.map(qcheck.string(), cbor.Text)
  use value <- qcheck.given(gen)
  let encoded = cbor.encode(value)
  assert cbor.decode(encoded) == Ok(value)
}

pub fn roundtrip_null_test() {
  let encoded = cbor.encode(cbor.Null)
  assert cbor.decode(encoded) == Ok(cbor.Null)
}

pub fn roundtrip_tree_property_test() {
  let gen = cbor_value_generator(0)
  use value <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(200),
    gen,
  )
  let encoded = cbor.encode(value)
  assert cbor.decode(encoded) == Ok(normalize_map_order(value))
}

pub fn diagnostic_int_test() {
  assert cbor.to_diagnostic(cbor.Int(42)) == "42"
}

pub fn diagnostic_neg_int_test() {
  assert cbor.to_diagnostic(cbor.Int(-1)) == "-1"
}

pub fn diagnostic_bytes_test() {
  assert cbor.to_diagnostic(cbor.Bytes(<<0x01, 0x02, 0x03, 0x04>>))
    == "h'01020304'"
}

pub fn diagnostic_text_test() {
  assert cbor.to_diagnostic(cbor.Text("hello")) == "\"hello\""
}

pub fn diagnostic_array_test() {
  assert cbor.to_diagnostic(cbor.Array([cbor.Int(1), cbor.Int(2), cbor.Int(3)]))
    == "[1, 2, 3]"
}

pub fn diagnostic_map_test() {
  assert cbor.to_diagnostic(
      cbor.Map([#(cbor.Text("a"), cbor.Int(1)), #(cbor.Text("b"), cbor.Int(2))]),
    )
    == "{\"a\": 1, \"b\": 2}"
}

pub fn diagnostic_tag_test() {
  assert cbor.to_diagnostic(cbor.Tag(18, cbor.Bytes(<<>>))) == "18(h'')"
}

pub fn diagnostic_null_test() {
  assert cbor.to_diagnostic(cbor.Null) == "null"
}

fn cbor_value_generator(depth: Int) -> qcheck.Generator(cbor.Value) {
  case depth >= 3 {
    True -> leaf_generator()
    False ->
      qcheck.from_generators(leaf_generator(), [
        array_generator(depth),
        map_generator(depth),
        tag_generator(depth),
      ])
  }
}

fn leaf_generator() -> qcheck.Generator(cbor.Value) {
  qcheck.from_generators(
    qcheck.map(qcheck.bounded_int(-1000, 1_000_000), cbor.Int),
    [
      qcheck.map(
        qcheck.generic_byte_aligned_bit_array(
          values_from: qcheck.bounded_int(0, 255),
          byte_size_from: qcheck.bounded_int(0, 20),
        ),
        cbor.Bytes,
      ),
      qcheck.map(
        qcheck.generic_string(
          qcheck.bounded_codepoint(0x20, 0x7e),
          qcheck.bounded_int(0, 10),
        ),
        cbor.Text,
      ),
      qcheck.return(cbor.Null),
    ],
  )
}

fn array_generator(depth: Int) -> qcheck.Generator(cbor.Value) {
  let element_gen = cbor_value_generator(depth + 1)
  let list_gen =
    qcheck.generic_list(
      elements_from: element_gen,
      length_from: qcheck.bounded_int(0, 5),
    )
  qcheck.map(list_gen, cbor.Array)
}

fn map_generator(depth: Int) -> qcheck.Generator(cbor.Value) {
  let key_gen = leaf_generator()
  let value_gen = cbor_value_generator(depth + 1)
  let pair_gen = qcheck.tuple2(key_gen, value_gen)
  let list_gen =
    qcheck.generic_list(
      elements_from: pair_gen,
      length_from: qcheck.bounded_int(0, 5),
    )
  qcheck.map(list_gen, fn(pairs) { cbor.Map(deduplicate_pairs(pairs, [], [])) })
}

fn deduplicate_pairs(
  pairs: List(#(cbor.Value, cbor.Value)),
  seen_keys: List(cbor.Value),
  acc: List(#(cbor.Value, cbor.Value)),
) -> List(#(cbor.Value, cbor.Value)) {
  case pairs {
    [] -> list.reverse(acc)
    [#(k, v), ..rest] ->
      case list.contains(seen_keys, k) {
        True -> deduplicate_pairs(rest, seen_keys, acc)
        False -> deduplicate_pairs(rest, [k, ..seen_keys], [#(k, v), ..acc])
      }
  }
}

fn tag_generator(depth: Int) -> qcheck.Generator(cbor.Value) {
  let tag_num_gen = qcheck.bounded_int(0, 100)
  let content_gen = cbor_value_generator(depth + 1)
  qcheck.map2(tag_num_gen, content_gen, cbor.Tag)
}

fn normalize_map_order(value: cbor.Value) -> cbor.Value {
  case value {
    cbor.Map(pairs) -> {
      let normalized_pairs =
        list.map(pairs, fn(pair) {
          #(normalize_map_order(pair.0), normalize_map_order(pair.1))
        })
      let unique_pairs = deduplicate_pairs(normalized_pairs, [], [])
      let sorted =
        list.sort(unique_pairs, fn(a, b) {
          let encoded_a = cbor.encode(a.0)
          let encoded_b = cbor.encode(b.0)
          compare_bit_arrays(encoded_a, encoded_b)
        })
      cbor.Map(sorted)
    }
    cbor.Array(items) -> cbor.Array(list.map(items, normalize_map_order))
    cbor.Tag(tag, content) -> cbor.Tag(tag, normalize_map_order(content))
    other -> other
  }
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
    _, _ -> order.Eq
  }
}
