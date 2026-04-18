import gleam/result
import gose
import gose/algorithm
import gose/cbor
import gose/cose/key as cose_key
import gose/key
import gose/test_helpers/generators
import kryptos/crypto
import kryptos/ec
import kryptos/eddsa
import kryptos/rsa
import kryptos/xdh
import qcheck

pub fn ec_curve_roundtrip_property_test() {
  use ec_with_key <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generators.ec_curve_with_key_generator(),
  )
  let generators.EcCurveWithKey(curve, k) = ec_with_key
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.key_type(decoded) == key.EcKeyType
  assert key.ec_curve(decoded) == Ok(curve)
  assert key.ec_public_key_coordinates(decoded)
    == key.ec_public_key_coordinates(k)
}

pub fn rsa_roundtrip_test() {
  let assert Ok(k) = key.generate_rsa(2048)
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.key_type(decoded) == key.RsaKeyType
  let assert Ok(orig_pub) = key.rsa_public_key(k)
  let assert Ok(decoded_pub) = key.rsa_public_key(decoded)
  assert rsa.public_key_modulus(decoded_pub) == rsa.public_key_modulus(orig_pub)
  assert rsa.public_key_exponent_bytes(decoded_pub)
    == rsa.public_key_exponent_bytes(orig_pub)
}

pub fn symmetric_roundtrip_test() {
  let secret = crypto.random_bytes(32)
  let assert Ok(k) = key.from_octet_bits(secret)
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.key_type(decoded) == key.OctKeyType
  assert key.to_octet_bits(decoded) == Ok(secret)
}

pub fn ec_public_key_only_test() {
  let k = key.generate_ec(ec.P256)
  let assert Ok(pub_key) = key.public_key(k)
  let assert Ok(encoded) = cose_key.to_cbor(pub_key)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.key_type(decoded) == key.EcKeyType
  assert key.ec_public_key_coordinates(decoded)
    == key.ec_public_key_coordinates(pub_key)
}

pub fn eddsa_public_key_only_test() {
  let k = key.generate_eddsa(eddsa.Ed25519)
  let assert Ok(pub_key) = key.public_key(k)
  let assert Ok(encoded) = cose_key.to_cbor(pub_key)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.key_type(decoded) == key.OkpKeyType
  assert key.eddsa_curve(decoded) == Ok(eddsa.Ed25519)
}

pub fn rsa_public_key_only_test() {
  let assert Ok(k) = key.generate_rsa(2048)
  let assert Ok(pub_key) = key.public_key(k)
  let assert Ok(encoded) = cose_key.to_cbor(pub_key)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.key_type(decoded) == key.RsaKeyType
  let assert Ok(orig_pub) = key.rsa_public_key(pub_key)
  let assert Ok(decoded_pub) = key.rsa_public_key(decoded)
  assert rsa.public_key_modulus(decoded_pub) == rsa.public_key_modulus(orig_pub)
}

pub fn metadata_kid_roundtrip_test() {
  let k =
    key.generate_ec(ec.P256)
    |> key.with_kid_bits(<<"test-key-1":utf8>>)
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.kid(decoded) == Ok(<<"test-key-1":utf8>>)
}

pub fn metadata_binary_kid_roundtrip_test() {
  let binary_kid = <<0xff, 0xfe, 0x01, 0x02>>
  let k =
    key.generate_ec(ec.P256)
    |> key.with_kid_bits(binary_kid)
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.kid(decoded) == Ok(binary_kid)
}

pub fn metadata_alg_roundtrip_test() {
  let k =
    key.generate_eddsa(eddsa.Ed25519)
    |> key.with_alg(key.SigningAlg(algorithm.DigitalSignature(algorithm.Eddsa)))
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.alg(decoded)
    == Ok(key.SigningAlg(algorithm.DigitalSignature(algorithm.Eddsa)))
}

pub fn metadata_non_utf8_kid_accepted_test() {
  let binary_kid = <<0xff, 0xfe>>
  let cbor_bytes =
    cbor.encode(
      cbor.Map([
        #(cbor.Int(1), cbor.Int(4)),
        #(
          cbor.Int(-1),
          cbor.Bytes(<<
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          >>),
        ),
        #(cbor.Int(2), cbor.Bytes(binary_kid)),
      ]),
    )
  let assert Ok(decoded) = cose_key.from_cbor(cbor_bytes)
  assert key.kid(decoded) == Ok(binary_kid)
}

pub fn metadata_content_alg_roundtrip_test() {
  let k =
    key.generate_hmac_key(algorithm.HmacSha256)
    |> key.with_alg(key.ContentAlg(algorithm.AesGcm(algorithm.Aes128)))
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.alg(decoded)
    == Ok(key.ContentAlg(algorithm.AesGcm(algorithm.Aes128)))
}

pub fn metadata_key_ops_roundtrip_test() {
  let k = key.generate_ec(ec.P256)
  let assert Ok(k) = key.with_key_ops(k, [key.Sign, key.Verify])
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.key_ops(decoded) == Ok([key.Sign, key.Verify])
}

pub fn from_cbor_map_ec_public_test() {
  let k = key.generate_ec(ec.P256)
  let assert Ok(pub_key) = key.public_key(k)
  let assert Ok(#(x, y)) = key.ec_public_key_coordinates(pub_key)
  let map = [
    #(cbor.Int(1), cbor.Int(2)),
    #(cbor.Int(-1), cbor.Int(1)),
    #(cbor.Int(-2), cbor.Bytes(x)),
    #(cbor.Int(-3), cbor.Bytes(y)),
  ]
  let assert Ok(decoded) = cose_key.from_cbor_map(map)
  assert key.key_type(decoded) == key.EcKeyType
  assert key.ec_curve(decoded) == Ok(ec.P256)
  assert key.ec_public_key_coordinates(decoded) == Ok(#(x, y))
}

pub fn error_missing_kty_test() {
  let map = [#(cbor.Int(-1), cbor.Int(1))]
  assert cose_key.from_cbor_map(map)
    == Error(gose.ParseError("missing kty (label 1)"))
}

pub fn error_invalid_kty_test() {
  let map = [#(cbor.Int(1), cbor.Int(99))]
  assert cose_key.from_cbor_map(map)
    == Error(gose.ParseError("unsupported COSE key type: 99"))
}

pub fn error_kty_wrong_type_test() {
  let map = [#(cbor.Int(1), cbor.Text("EC"))]
  assert cose_key.from_cbor_map(map)
    == Error(gose.ParseError("missing kty (label 1) (wrong type)"))
}

pub fn error_ec_missing_curve_test() {
  let map = [
    #(cbor.Int(1), cbor.Int(2)),
    #(cbor.Int(-2), cbor.Bytes(<<0:256>>)),
    #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
  ]
  assert cose_key.from_cbor_map(map)
    == Error(gose.ParseError("missing EC curve (label -1)"))
}

pub fn error_ec_missing_x_test() {
  let map = [
    #(cbor.Int(1), cbor.Int(2)),
    #(cbor.Int(-1), cbor.Int(1)),
    #(cbor.Int(-3), cbor.Bytes(<<0:256>>)),
  ]
  assert cose_key.from_cbor_map(map)
    == Error(gose.ParseError("missing EC x (label -2)"))
}

pub fn error_not_a_map_test() {
  let cbor_bytes = cbor.encode(cbor.Int(42))
  assert cose_key.from_cbor(cbor_bytes)
    == Error(gose.ParseError("COSE_Key must be a CBOR map"))
}

pub fn error_symmetric_empty_test() {
  let map = [
    #(cbor.Int(1), cbor.Int(4)),
    #(cbor.Int(-1), cbor.Bytes(<<>>)),
  ]
  assert cose_key.from_cbor_map(map)
    == Error(gose.InvalidState("oct key must not be empty"))
}

pub fn error_kid_wrong_type_test() {
  let map = [
    #(cbor.Int(1), cbor.Int(4)),
    #(
      cbor.Int(-1),
      cbor.Bytes(<<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>),
    ),
    #(cbor.Int(2), cbor.Int(42)),
  ]
  assert cose_key.from_cbor_map(map)
    == Error(gose.ParseError("key parameter 2 has wrong type"))
}

pub fn error_alg_wrong_type_test() {
  let map = [
    #(cbor.Int(1), cbor.Int(4)),
    #(
      cbor.Int(-1),
      cbor.Bytes(<<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>),
    ),
    #(cbor.Int(3), cbor.Text("ES256")),
  ]
  assert cose_key.from_cbor_map(map)
    == Error(gose.ParseError("key parameter 3 has wrong type"))
}

pub fn error_key_ops_wrong_type_test() {
  let map = [
    #(cbor.Int(1), cbor.Int(4)),
    #(
      cbor.Int(-1),
      cbor.Bytes(<<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>),
    ),
    #(cbor.Int(4), cbor.Int(1)),
  ]
  assert cose_key.from_cbor_map(map)
    == Error(gose.ParseError("key parameter 4 has wrong type"))
}

pub fn to_cbor_jose_only_alg_returns_error_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(k) = key.from_octet_bits(secret)
  let k =
    key.with_alg(
      k,
      key.KeyEncryptionAlg(algorithm.AesKeyWrap(
        algorithm.AesGcmKw,
        algorithm.Aes128,
      )),
    )
  let assert Error(gose.InvalidState(_)) = cose_key.to_cbor(k)
}

pub fn to_cbor_map_symmetric_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
  let assert Ok(k) = key.from_octet_bits(secret)
  let assert Ok(pairs) = cose_key.to_cbor_map(k)
  let assert Ok(cbor.Int(kty)) = find_value(pairs, 1)
  assert kty == 4
  let assert Ok(cbor.Bytes(k_value)) = find_value(pairs, -1)
  assert k_value == secret
}

pub fn eddsa_curve_roundtrip_property_test() {
  use curve <- qcheck.given(generators.eddsa_curve_generator())
  let k = key.generate_eddsa(curve)
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.key_type(decoded) == key.OkpKeyType
  assert key.eddsa_curve(decoded) == Ok(curve)
}

pub fn xdh_curve_roundtrip_property_test() {
  use curve <- qcheck.given(generators.xdh_curve_generator())
  let k = key.generate_xdh(curve)
  let assert Ok(encoded) = cose_key.to_cbor(k)
  let assert Ok(decoded) = cose_key.from_cbor(encoded)
  assert key.key_type(decoded) == key.OkpKeyType
  assert key.xdh_curve(decoded) == Ok(curve)
}

fn find_value(
  pairs: List(#(cbor.Value, cbor.Value)),
  label: Int,
) -> Result(cbor.Value, Nil) {
  case pairs {
    [] -> Error(Nil)
    [#(cbor.Int(l), v), ..] if l == label -> Ok(v)
    [_, ..rest] -> find_value(rest, label)
  }
}

pub fn ec_private_key_xy_mismatch_rejected_test() {
  let k1 = key.generate_ec(ec.P256)
  let k2 = key.generate_ec(ec.P256)
  let assert Ok(cbor.Map(pairs1)) =
    cose_key.to_cbor(k1) |> result.try(cbor.decode)
  let assert Ok(cbor.Map(pairs2)) =
    cose_key.to_cbor(k2) |> result.try(cbor.decode)

  // Take d from k1, x/y from k2
  let assert Ok(d) = find_value(pairs1, -4)
  let assert Ok(x) = find_value(pairs2, -2)
  let assert Ok(y) = find_value(pairs2, -3)
  let mismatched = [
    #(cbor.Int(1), cbor.Int(2)),
    #(cbor.Int(-1), cbor.Int(1)),
    #(cbor.Int(-2), x),
    #(cbor.Int(-3), y),
    #(cbor.Int(-4), d),
  ]
  assert cose_key.from_cbor_map(mismatched)
    == Error(gose.ParseError("x/y do not match computed public key"))
}

pub fn eddsa_private_key_x_mismatch_rejected_test() {
  let k1 = key.generate_eddsa(eddsa.Ed25519)
  let k2 = key.generate_eddsa(eddsa.Ed25519)
  let assert Ok(cbor.Map(pairs1)) =
    cose_key.to_cbor(k1) |> result.try(cbor.decode)
  let assert Ok(cbor.Map(pairs2)) =
    cose_key.to_cbor(k2) |> result.try(cbor.decode)

  let assert Ok(d) = find_value(pairs1, -4)
  let assert Ok(x) = find_value(pairs2, -2)
  let mismatched = [
    #(cbor.Int(1), cbor.Int(1)),
    #(cbor.Int(-1), cbor.Int(6)),
    #(cbor.Int(-2), x),
    #(cbor.Int(-4), d),
  ]
  assert cose_key.from_cbor_map(mismatched)
    == Error(gose.ParseError("x does not match computed public key"))
}

pub fn xdh_private_key_x_mismatch_rejected_test() {
  let k1 = key.generate_xdh(xdh.X25519)
  let k2 = key.generate_xdh(xdh.X25519)
  let assert Ok(cbor.Map(pairs1)) =
    cose_key.to_cbor(k1) |> result.try(cbor.decode)
  let assert Ok(cbor.Map(pairs2)) =
    cose_key.to_cbor(k2) |> result.try(cbor.decode)

  let assert Ok(d) = find_value(pairs1, -4)
  let assert Ok(x) = find_value(pairs2, -2)
  let mismatched = [
    #(cbor.Int(1), cbor.Int(1)),
    #(cbor.Int(-1), cbor.Int(4)),
    #(cbor.Int(-2), x),
    #(cbor.Int(-4), d),
  ]
  assert cose_key.from_cbor_map(mismatched)
    == Error(gose.ParseError("x does not match computed public key"))
}
