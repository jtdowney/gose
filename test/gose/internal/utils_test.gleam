import gleam/bit_array
import gose
import gose/internal/utils
import gose/test_helpers/generators
import kryptos/ec
import qcheck

pub fn validate_crit_headers_empty_list_test() {
  let assert Error(gose.ParseError(msg)) =
    utils.validate_crit_headers([], ["alg"], [])
  assert msg == "crit array must not be empty"
}

pub fn validate_crit_headers_duplicate_entries_test() {
  let assert Error(gose.ParseError(msg)) =
    utils.validate_crit_headers(["b64", "b64"], ["alg"], ["b64"])
  assert msg == "crit array contains duplicate values"
}

pub fn validate_crit_headers_standard_header_rejected_test() {
  let assert Error(gose.ParseError(msg)) =
    utils.validate_crit_headers(["alg"], ["alg"], ["b64"])
  assert msg == "standard header in crit: alg"
}

pub fn validate_crit_headers_unknown_extension_rejected_test() {
  let assert Error(gose.ParseError(msg)) =
    utils.validate_crit_headers(["unknown"], ["alg"], ["b64"])
  assert msg == "unsupported critical header: unknown"
}

pub fn validate_crit_headers_valid_extension_test() {
  assert utils.validate_crit_headers(["b64"], ["alg"], ["b64"]) == Ok(Nil)
}

pub fn validate_crit_headers_multiple_valid_extensions_test() {
  assert utils.validate_crit_headers(["b64", "example"], ["alg"], [
      "b64", "example",
    ])
    == Ok(Nil)
}

pub fn decode_base64_url_roundtrip_property_test() {
  qcheck.run(qcheck.default_config(), qcheck.byte_aligned_bit_array(), fn(data) {
    let encoded = bit_array.base64_url_encode(data, False)
    let assert Ok(decoded) = utils.decode_base64_url(encoded, "test")
    assert decoded == data
  })
}

pub fn decode_base64_url_invalid_returns_error_test() {
  let assert Error(gose.ParseError(msg)) =
    utils.decode_base64_url("!!invalid!!", "foo")
  assert msg == "invalid foo base64"
}

pub fn encode_base64_url_roundtrip_property_test() {
  qcheck.run(qcheck.default_config(), qcheck.byte_aligned_bit_array(), fn(data) {
    let encoded = utils.encode_base64_url(data)
    let assert Ok(decoded) = bit_array.base64_url_decode(encoded)
    assert decoded == data
  })
}

pub fn strip_leading_zeros_no_zeros_test() {
  assert utils.strip_leading_zeros(<<1, 2, 3>>) == <<1, 2, 3>>
}

pub fn strip_leading_zeros_strips_zeros_test() {
  assert utils.strip_leading_zeros(<<0, 0, 42>>) == <<42>>
}

pub fn strip_leading_zeros_preserves_single_zero_test() {
  assert utils.strip_leading_zeros(<<0>>) == <<0>>
}

pub fn strip_leading_zeros_all_zeros_returns_single_zero_test() {
  assert utils.strip_leading_zeros(<<0, 0, 0>>) == <<0>>
}

pub fn strip_leading_zeros_empty_returns_empty_test() {
  assert utils.strip_leading_zeros(<<>>) == <<>>
}

pub fn ec_curve_roundtrip_test() {
  qcheck.run(
    qcheck.default_config(),
    generators.ec_curve_generator(),
    fn(curve) {
      let s = utils.ec_curve_to_string(curve)
      assert utils.ec_curve_from_string(s) == Ok(curve)
    },
  )
}

pub fn ec_curve_from_string_rejects_invalid_test() {
  let assert Error(gose.ParseError(msg)) = utils.ec_curve_from_string("P-999")
  assert msg == "unsupported EC curve: P-999"
}

pub fn eddsa_curve_roundtrip_test() {
  qcheck.run(
    qcheck.default_config(),
    generators.eddsa_curve_generator(),
    fn(curve) {
      let s = utils.eddsa_curve_to_string(curve)
      assert utils.eddsa_curve_from_string(s) == Ok(curve)
    },
  )
}

pub fn eddsa_curve_from_string_rejects_invalid_test() {
  let assert Error(gose.ParseError(msg)) =
    utils.eddsa_curve_from_string("Ed999")
  assert msg == "unsupported EdDSA curve: Ed999"
}

pub fn xdh_curve_roundtrip_test() {
  qcheck.run(
    qcheck.default_config(),
    generators.xdh_curve_generator(),
    fn(curve) {
      let s = utils.xdh_curve_to_string(curve)
      assert utils.xdh_curve_from_string(s) == Ok(curve)
    },
  )
}

pub fn xdh_curve_from_string_rejects_invalid_test() {
  let assert Error(gose.ParseError(msg)) = utils.xdh_curve_from_string("X999")
  assert msg == "unsupported XDH curve: X999"
}

pub fn ec_coordinates_roundtrip_test() {
  qcheck.run(
    qcheck.default_config(),
    generators.ec_curve_generator(),
    fn(curve) {
      let #(_private, public) = ec.generate_key_pair(curve)
      let assert Ok(#(x, y)) = utils.ec_public_key_coordinates(public, curve)
      let assert Ok(reconstructed) =
        utils.ec_public_key_from_coordinates(curve, x, y)
      assert ec.public_key_to_raw_point(reconstructed)
        == ec.public_key_to_raw_point(public)
    },
  )
}

pub fn ec_public_key_from_coordinates_wrong_x_length_test() {
  let assert Error(gose.ParseError(msg)) =
    utils.ec_public_key_from_coordinates(ec.P256, <<0>>, <<0:size(256)>>)
  assert msg == "EC x coordinate wrong length"
}

pub fn ec_public_key_from_coordinates_wrong_y_length_test() {
  let assert Error(gose.ParseError(msg)) =
    utils.ec_public_key_from_coordinates(ec.P256, <<0:size(256)>>, <<0>>)
  assert msg == "EC y coordinate wrong length"
}

pub fn ec_public_key_from_coordinates_invalid_point_test() {
  let x = <<0:size(256)>>
  let y = <<0:size(256)>>
  assert utils.ec_public_key_from_coordinates(ec.P256, x, y)
    == Error(gose.ParseError("invalid EC coordinates"))
}
