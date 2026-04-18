import birdie
import gleam/bit_array
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gose
import gose/algorithm
import gose/internal/utils
import gose/jose/jwk
import gose/key
import gose/test_helpers/fixtures
import gose/test_helpers/generators
import kryptos/crypto
import kryptos/ec
import kryptos/eddsa
import kryptos/hash
import kryptos/xdh
import qcheck

pub fn generate_hmac_key_size_test() {
  let hmac_alg_gen =
    qcheck.from_generators(qcheck.return(algorithm.HmacSha256), [
      qcheck.return(algorithm.HmacSha384),
      qcheck.return(algorithm.HmacSha512),
    ])
  use alg <- qcheck.given(hmac_alg_gen)
  let key = key.generate_hmac_key(alg)
  let expected = algorithm.hmac_alg_key_size(alg)
  assert key.octet_key_size(key) == Ok(expected)
}

pub fn generate_enc_key_size_test() {
  let enc_gen =
    qcheck.from_generators(qcheck.return(algorithm.AesGcm(algorithm.Aes128)), [
      qcheck.return(algorithm.AesGcm(algorithm.Aes192)),
      qcheck.return(algorithm.AesGcm(algorithm.Aes256)),
      qcheck.return(algorithm.AesCbcHmac(algorithm.Aes128)),
      qcheck.return(algorithm.AesCbcHmac(algorithm.Aes192)),
      qcheck.return(algorithm.AesCbcHmac(algorithm.Aes256)),
      qcheck.return(algorithm.ChaCha20Poly1305),
      qcheck.return(algorithm.XChaCha20Poly1305),
    ])
  use enc <- qcheck.given(enc_gen)
  let key = key.generate_enc_key(enc)
  let expected = algorithm.content_alg_key_size(enc)
  assert key.octet_key_size(key) == Ok(expected)
}

pub fn generate_aes_kw_key_size_test() {
  let aes_size_gen =
    qcheck.from_generators(qcheck.return(algorithm.Aes128), [
      qcheck.return(algorithm.Aes192),
      qcheck.return(algorithm.Aes256),
    ])
  use size <- qcheck.given(aes_size_gen)
  let key = key.generate_aes_kw_key(size)
  let expected = algorithm.aes_key_size(size)
  assert key.octet_key_size(key) == Ok(expected)
}

pub fn generate_chacha20_kw_key_size_test() {
  let key = key.generate_chacha20_kw_key()
  assert key.octet_key_size(key) == Ok(32)
}

pub fn octet_from_bits_rejects_empty_test() {
  assert key.from_octet_bits(<<>>)
    == Error(gose.InvalidState("oct key must not be empty"))
}

pub fn octet_json_roundtrip_test() {
  use bytes <- qcheck.given(qcheck.non_empty_byte_aligned_bit_array())
  let assert Ok(key) = key.from_octet_bits(bytes)
  let json_val = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  let assert Ok(parsed_secret) = key.material_octet_secret(key.material(parsed))
  assert parsed_secret == bytes
}

pub fn octet_json_snapshot_test() {
  let assert Ok(key) = key.from_octet_bits(<<"test-secret-key":utf8>>)
  let json_val = jwk.to_json(key)
  json.to_string(json_val)
  |> birdie.snap("oct symmetric key JSON")
}

pub fn octet_key_size_test() {
  let key16 = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes128))
  let key32 = key.generate_hmac_key(algorithm.HmacSha256)
  assert key.octet_key_size(key16) == Ok(16)
  assert key.octet_key_size(key32) == Ok(32)
}

pub fn octet_key_size_rejects_non_octet_test() {
  let key = fixtures.rsa_private_key()
  assert key.octet_key_size(key)
    == Error(gose.InvalidState("key is not an octet key"))
}

pub fn rsa_generation_test() {
  let assert Ok(key) = key.generate_rsa(2048)
  assert key.key_type(key) == key.RsaKeyType
  assert key.is_private_key(key)
}

pub fn rsa_public_key_extraction_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(pub_key) = key.public_key(key)
  assert key.key_type(pub_key) == key.RsaKeyType
  assert !key.is_private_key(pub_key)
}

pub fn rsa_pem_roundtrip_test() {
  let pem = fixtures.load_raw_pem("test/fixtures/rsa_pkcs8_priv.pem")
  let assert Ok(key) = key.from_pem(pem)
  assert key.key_type(key) == key.RsaKeyType
  assert key.is_private_key(key)
  let assert Ok(output) = key.to_pem(key)
  let assert Ok(parsed) = key.from_pem(output)
  assert key.key_type(parsed) == key.RsaKeyType
  assert key.is_private_key(parsed)
}

pub fn rsa_der_roundtrip_test() {
  let der = fixtures.load_raw_der("test/fixtures/rsa_pkcs8_priv.der")
  let assert Ok(key) = key.from_der(der)
  assert key.key_type(key) == key.RsaKeyType
  assert key.is_private_key(key)
  let assert Ok(output) = key.to_der(key)
  let assert Ok(parsed) = key.from_der(output)
  assert key.key_type(parsed) == key.RsaKeyType
  assert key.is_private_key(parsed)
}

pub fn rsa_json_roundtrip_test() {
  let key = fixtures.rsa_private_key()
  let json_val = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  assert key.key_type(parsed) == key.RsaKeyType
  assert key.is_private_key(parsed)
}

pub fn rsa_public_key_json_roundtrip_test() {
  let assert Ok(pub_key) = key.public_key(fixtures.rsa_private_key())
  let json_val = jwk.to_json(pub_key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  assert key.key_type(parsed) == key.RsaKeyType
  assert !key.is_private_key(parsed)
}

pub fn rsa_private_key_json_snapshot_test() {
  let key = fixtures.rsa_private_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val)
  |> birdie.snap("RSA private key JSON")
}

pub fn rsa_public_key_json_snapshot_test() {
  let key = fixtures.rsa_public_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val)
  |> birdie.snap("RSA public key JSON")
}

pub fn rsa_private_key_pem_snapshot_test() {
  let key = fixtures.rsa_private_key()
  let assert Ok(output) = key.to_pem(key)
  output |> birdie.snap("RSA private key PEM")
}

pub fn rsa_public_key_pem_snapshot_test() {
  let key = fixtures.rsa_public_key()
  let assert Ok(output) = key.to_pem(key)
  output |> birdie.snap("RSA public key PEM")
}

pub fn rsa_json_rejects_partial_crt_test() {
  let json_str =
    json.object([
      #("kty", json.string("RSA")),
      #("n", json.string("0vx7ago")),
      #("e", json.string("AQAB")),
      #("d", json.string("X4cT")),
      #("p", json.string("8W4a")),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError(
      "partial CRT fields: all five (p, q, dp, dq, qi) are required if any are present",
    ))
}

pub fn rsa_json_rejects_oth_test() {
  let json_str =
    json.object([
      #("kty", json.string("RSA")),
      #("n", json.string("0vx7ago")),
      #("e", json.string("AQAB")),
      #("d", json.string("X4cT")),
      #(
        "oth",
        json.preprocessed_array([
          json.object([
            #("r", json.string("Lq-MY")),
            #("d", json.string("S34cT")),
            #("t", json.string("cRwFv")),
          ]),
        ]),
      ),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError(
      "multi-prime RSA keys (oth parameter) not supported",
    ))
}

pub fn rsa_thumbprint_private_equals_public_test() {
  let private_key = fixtures.rsa_private_key()
  let assert Ok(public_key) = key.public_key(private_key)
  let assert Ok(private_tp) = jwk.thumbprint(private_key, hash.Sha256)
  let assert Ok(public_tp) = jwk.thumbprint(public_key, hash.Sha256)
  assert private_tp == public_tp
}

pub fn ec_generation_all_curves_test() {
  use curve <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    generators.ec_curve_generator(),
  )
  let key = key.generate_ec(curve)
  let assert Ok(actual) = key.ec_curve(key)
  assert actual == curve
  assert key.key_type(key) == key.EcKeyType
  assert key.is_private_key(key)
}

pub fn ec_public_key_extraction_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(pub_key) = key.public_key(key)
  assert key.key_type(pub_key) == key.EcKeyType
  assert !key.is_private_key(pub_key)
  let assert Ok(ec.P256) = key.ec_curve(pub_key)
}

pub fn ec_json_roundtrip_all_curves_test() {
  use curve_with_key <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generators.ec_curve_with_key_generator(),
  )
  let generators.EcCurveWithKey(curve, key) = curve_with_key
  let json_val = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  let assert Ok(parsed_curve) = key.ec_curve(parsed)
  assert parsed_curve == curve
}

pub fn ec_coordinates_roundtrip_test() {
  use curve_with_key <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generators.ec_curve_with_key_generator(),
  )
  let generators.EcCurveWithKey(curve, key) = curve_with_key
  let assert Ok(pub_key) = key.public_key(key)
  let assert Ok(#(x, y)) = key.ec_public_key_coordinates(pub_key)
  let assert Ok(reconstructed) =
    key.ec_public_key_from_coordinates(curve, x:, y:)
  let assert Ok(#(x2, y2)) = key.ec_public_key_coordinates(reconstructed)
  assert x == x2
  assert y == y2
}

pub fn ec_der_roundtrip_test() {
  let der = fixtures.load_raw_der("test/fixtures/ec_p256_priv.der")
  let assert Ok(key) = key.from_der(der)
  assert key.key_type(key) == key.EcKeyType
  assert key.is_private_key(key)
  let assert Ok(output) = key.to_der(key)
  let assert Ok(parsed) = key.from_der(output)
  assert key.key_type(parsed) == key.EcKeyType
  assert key.is_private_key(parsed)
}

pub fn ec_p256_private_key_json_snapshot_test() {
  let key = fixtures.ec_p256_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val) |> birdie.snap("EC P256 private key JSON")
}

pub fn ec_p256_public_key_json_snapshot_test() {
  let key = fixtures.ec_p256_public_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val) |> birdie.snap("EC P256 public key JSON")
}

pub fn ec_p384_private_key_json_snapshot_test() {
  let key = fixtures.ec_p384_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val) |> birdie.snap("EC P384 private key JSON")
}

pub fn ec_p256_pem_snapshot_test() {
  let key = fixtures.ec_p256_key()
  let assert Ok(output) = key.to_pem(key)
  output |> birdie.snap("EC P256 private key PEM")
}

pub fn ec_secp256k1_pem_roundtrip_test() {
  let pem = fixtures.load_raw_pem("test/fixtures/ec_secp256k1_priv.pem")
  let assert Ok(key) = key.from_pem(pem)
  assert key.is_private_key(key)
  let assert Ok(ec.Secp256k1) = key.ec_curve(key)
  let assert Ok(output) = key.to_pem(key)
  let assert Ok(parsed) = key.from_pem(output)
  assert key.is_private_key(parsed)
  let assert Ok(ec.Secp256k1) = key.ec_curve(parsed)
}

pub fn ec_secp256k1_der_roundtrip_test() {
  let der = fixtures.load_raw_der("test/fixtures/ec_secp256k1_priv.der")
  let assert Ok(key) = key.from_der(der)
  assert key.key_type(key) == key.EcKeyType
  assert key.is_private_key(key)
  let assert Ok(ec.Secp256k1) = key.ec_curve(key)
  let assert Ok(output) = key.to_der(key)
  let assert Ok(parsed) = key.from_der(output)
  assert key.key_type(parsed) == key.EcKeyType
  assert key.is_private_key(parsed)
  let assert Ok(ec.Secp256k1) = key.ec_curve(parsed)
}

pub fn ec_secp256k1_public_key_der_roundtrip_test() {
  let der = fixtures.load_raw_der("test/fixtures/ec_secp256k1_pub.der")
  let assert Ok(key) = key.from_der(der)
  assert key.key_type(key) == key.EcKeyType
  assert !key.is_private_key(key)
  let assert Ok(ec.Secp256k1) = key.ec_curve(key)
  let assert Ok(output) = key.to_der(key)
  let assert Ok(parsed) = key.from_der(output)
  assert key.key_type(parsed) == key.EcKeyType
  assert !key.is_private_key(parsed)
  let assert Ok(ec.Secp256k1) = key.ec_curve(parsed)
}

pub fn ec_secp256k1_json_roundtrip_test() {
  let key = fixtures.ec_secp256k1_key()
  let json_val = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  assert key.is_private_key(parsed)
  let assert Ok(ec.Secp256k1) = key.ec_curve(parsed)
}

pub fn ec_secp256k1_public_key_roundtrip_test() {
  let assert Ok(pub_key) = key.public_key(fixtures.ec_secp256k1_key())
  let json_val = jwk.to_json(pub_key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  assert !key.is_private_key(parsed)
  let assert Ok(ec.Secp256k1) = key.ec_curve(parsed)
}

pub fn ec_coordinates_rejects_short_x_coordinate_test() {
  let result =
    key.ec_public_key_from_coordinates(ec.P256, x: <<1, 2, 3>>, y: <<4, 5, 6>>)
  assert result == Error(gose.ParseError("EC x coordinate wrong length"))
}

pub fn ec_coordinates_rejects_random_bits_test() {
  let random_x = crypto.random_bytes(32)
  let random_y = crypto.random_bytes(32)
  let result =
    key.ec_public_key_from_coordinates(ec.P256, x: random_x, y: random_y)
  assert result == Error(gose.ParseError("invalid EC coordinates"))
}

pub fn ec_thumbprint_private_equals_public_test() {
  let private_key = fixtures.ec_p256_key()
  let assert Ok(public_key) = key.public_key(private_key)
  let assert Ok(private_tp) = jwk.thumbprint(private_key, hash.Sha256)
  let assert Ok(public_tp) = jwk.thumbprint(public_key, hash.Sha256)
  assert private_tp == public_tp
}

pub fn ec_rejects_invalid_curve_test() {
  let json_str =
    json.object([
      #("kty", json.string("EC")),
      #("crv", json.string("P-999")),
      #("x", json.string("abc")),
      #("y", json.string("def")),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("unsupported EC curve: P-999"))
}

pub fn ec_from_json_rejects_short_x_coordinate_test() {
  use cwk <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    generators.ec_curve_with_key_generator(),
  )
  let generators.EcCurveWithKey(curve, key) = cwk
  let coord_size = ec.coordinate_size(curve)
  let crv = utils.ec_curve_to_string(curve)
  let assert Ok(ec_key) = key.ec_public_key(key)
  let raw_point = ec.public_key_to_raw_point(ec_key)
  let assert <<0x04, rest:bits>> = raw_point
  let assert Ok(x) = bit_array.slice(rest, 0, coord_size)
  let assert Ok(y) = bit_array.slice(rest, coord_size, coord_size)
  let assert Ok(short_x) = bit_array.slice(x, 0, coord_size - 1)

  let short_x_json =
    json.object([
      #("kty", json.string("EC")),
      #("crv", json.string(crv)),
      #("x", json.string(bit_array.base64_url_encode(short_x, False))),
      #("y", json.string(bit_array.base64_url_encode(y, False))),
    ])
    |> json.to_string()

  let expected =
    "EC x coordinate must be " <> int.to_string(coord_size) <> " bytes"
  assert jwk.from_json(short_x_json) == Error(gose.ParseError(expected))
}

pub fn ec_from_json_rejects_short_y_coordinate_test() {
  use cwk <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    generators.ec_curve_with_key_generator(),
  )
  let generators.EcCurveWithKey(curve, key) = cwk
  let coord_size = ec.coordinate_size(curve)
  let crv = utils.ec_curve_to_string(curve)
  let assert Ok(ec_key) = key.ec_public_key(key)
  let raw_point = ec.public_key_to_raw_point(ec_key)
  let assert <<0x04, rest:bits>> = raw_point
  let assert Ok(x) = bit_array.slice(rest, 0, coord_size)
  let assert Ok(y) = bit_array.slice(rest, coord_size, coord_size)
  let assert Ok(short_y) = bit_array.slice(y, 0, coord_size - 1)

  let short_y_json =
    json.object([
      #("kty", json.string("EC")),
      #("crv", json.string(crv)),
      #("x", json.string(bit_array.base64_url_encode(x, False))),
      #("y", json.string(bit_array.base64_url_encode(short_y, False))),
    ])
    |> json.to_string()

  let expected =
    "EC y coordinate must be " <> int.to_string(coord_size) <> " bytes"
  assert jwk.from_json(short_y_json) == Error(gose.ParseError(expected))
}

pub fn eddsa_generation_all_curves_test() {
  use curve <- qcheck.given(generators.eddsa_curve_generator())
  let key = key.generate_eddsa(curve)
  let assert Ok(actual) = key.eddsa_curve(key)
  assert actual == curve
  assert key.key_type(key) == key.OkpKeyType
  assert key.is_private_key(key)
}

pub fn eddsa_public_key_extraction_test() {
  let private_key = fixtures.ed25519_key()
  let assert Ok(public_key) = key.public_key(private_key)
  assert !key.is_private_key(public_key)
  let assert Ok(eddsa.Ed25519) = key.eddsa_curve(public_key)
}

pub fn eddsa_json_roundtrip_test() {
  use curve <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generators.eddsa_curve_generator(),
  )
  let key = key.generate_eddsa(curve)
  let json_val = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  let assert Ok(curve_out) = key.eddsa_curve(parsed)
  assert curve == curve_out
}

pub fn eddsa_public_key_json_roundtrip_test() {
  let assert Ok(pub_key) = key.public_key(fixtures.ed25519_key())
  let json_val = jwk.to_json(pub_key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  assert !key.is_private_key(parsed)
  let assert Ok(eddsa.Ed25519) = key.eddsa_curve(parsed)
}

pub fn eddsa_pem_roundtrip_test() {
  let pem = fixtures.load_raw_pem("test/fixtures/ed25519_priv.pem")
  let assert Ok(key) = key.from_pem(pem)
  assert key.is_private_key(key)
  let assert Ok(eddsa.Ed25519) = key.eddsa_curve(key)
  let assert Ok(output) = key.to_pem(key)
  let assert Ok(parsed) = key.from_pem(output)
  assert key.is_private_key(parsed)
  let assert Ok(eddsa.Ed25519) = key.eddsa_curve(parsed)
}

pub fn eddsa_der_roundtrip_test() {
  let der = fixtures.load_raw_der("test/fixtures/ed25519_priv.der")
  let assert Ok(key) = key.from_der(der)
  assert key.is_private_key(key)
  let assert Ok(eddsa.Ed25519) = key.eddsa_curve(key)
  let assert Ok(output) = key.to_der(key)
  let assert Ok(parsed) = key.from_der(output)
  assert key.is_private_key(parsed)
  let assert Ok(eddsa.Ed25519) = key.eddsa_curve(parsed)
}

pub fn eddsa_ed448_pem_roundtrip_test() {
  let pem = fixtures.load_raw_pem("test/fixtures/ed448_priv.pem")
  let assert Ok(key) = key.from_pem(pem)
  assert key.is_private_key(key)
  let assert Ok(eddsa.Ed448) = key.eddsa_curve(key)
  let assert Ok(output) = key.to_pem(key)
  let assert Ok(parsed) = key.from_pem(output)
  assert key.is_private_key(parsed)
  let assert Ok(eddsa.Ed448) = key.eddsa_curve(parsed)
}

pub fn eddsa_ed448_der_roundtrip_test() {
  let der = fixtures.load_raw_der("test/fixtures/ed448_priv.der")
  let assert Ok(key) = key.from_der(der)
  assert key.is_private_key(key)
  let assert Ok(eddsa.Ed448) = key.eddsa_curve(key)
  let assert Ok(output) = key.to_der(key)
  let assert Ok(parsed) = key.from_der(output)
  assert key.is_private_key(parsed)
  let assert Ok(eddsa.Ed448) = key.eddsa_curve(parsed)
}

pub fn eddsa_ed25519_private_key_json_snapshot_test() {
  let key = fixtures.ed25519_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val) |> birdie.snap("Ed25519 private key JSON")
}

pub fn eddsa_ed25519_public_key_json_snapshot_test() {
  let key = fixtures.ed25519_public_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val) |> birdie.snap("Ed25519 public key JSON")
}

pub fn eddsa_ed448_private_key_json_snapshot_test() {
  let key = fixtures.ed448_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val) |> birdie.snap("Ed448 private key JSON")
}

pub fn eddsa_ed25519_pem_snapshot_test() {
  let key = fixtures.ed25519_key()
  let assert Ok(output) = key.to_pem(key)
  output |> birdie.snap("Ed25519 private key PEM")
}

pub fn eddsa_rfc8037_test_vector_test() {
  let json_str =
    json.object([
      #("kty", json.string("OKP")),
      #("crv", json.string("Ed25519")),
      #("d", json.string("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")),
      #("x", json.string("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")),
    ])
    |> json.to_string()
  let assert Ok(key) = jwk.from_json(json_str)
  assert key.is_private_key(key)
  let assert Ok(eddsa.Ed25519) = key.eddsa_curve(key)
}

pub fn eddsa_json_rejects_mismatched_x_test() {
  let json_str =
    json.object([
      #("kty", json.string("OKP")),
      #("crv", json.string("Ed25519")),
      #("d", json.string("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")),
      #("x", json.string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("x does not match computed public key"))
}

pub fn xdh_json_rejects_mismatched_x_test() {
  let key = fixtures.x25519_key()
  let assert Ok(d_bits) = key.to_octet_bits(key)
  let d_b64 = bit_array.base64_url_encode(d_bits, False)
  let json_str =
    json.object([
      #("kty", json.string("OKP")),
      #("crv", json.string("X25519")),
      #("d", json.string(d_b64)),
      #("x", json.string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("x does not match computed public key"))
}

pub fn eddsa_json_rejects_encrypting_use_test() {
  let json_str =
    json.object([
      #("kty", json.string("OKP")),
      #("crv", json.string("Ed25519")),
      #("d", json.string("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")),
      #("x", json.string("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")),
      #("use", json.string("enc")),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.InvalidState(
      "EdDSA keys (Ed25519/Ed448) cannot be used for encryption",
    ))
}

pub fn eddsa_rejects_encrypting_use_test() {
  let key = fixtures.ed25519_key()
  let result = key.with_key_use(key, key.Encrypting)
  assert result
    == Error(gose.InvalidState(
      "EdDSA keys (Ed25519/Ed448) cannot be used for encryption",
    ))
}

pub fn eddsa_thumbprint_private_equals_public_test() {
  let private_key = fixtures.ed25519_key()
  let assert Ok(public_key) = key.public_key(private_key)
  let assert Ok(private_tp) = jwk.thumbprint(private_key, hash.Sha256)
  let assert Ok(public_tp) = jwk.thumbprint(public_key, hash.Sha256)
  assert private_tp == public_tp
}

pub fn xdh_generation_all_curves_test() {
  use curve <- qcheck.given(generators.xdh_curve_generator())
  let key = key.generate_xdh(curve)
  let assert Ok(actual) = key.xdh_curve(key)
  assert actual == curve
  assert key.key_type(key) == key.OkpKeyType
  assert key.is_private_key(key)
}

pub fn xdh_public_key_extraction_test() {
  let private_key = fixtures.x25519_key()
  let assert Ok(public_key) = key.public_key(private_key)
  assert !key.is_private_key(public_key)
  let assert Ok(xdh.X25519) = key.xdh_curve(public_key)
}

pub fn xdh_json_roundtrip_test() {
  use curve <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generators.xdh_curve_generator(),
  )
  let key = key.generate_xdh(curve)
  let json_val = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  let assert Ok(curve_out) = key.xdh_curve(parsed)
  assert curve == curve_out
}

pub fn xdh_public_key_json_roundtrip_test() {
  let assert Ok(pub_key) = key.public_key(fixtures.x25519_key())
  let json_val = jwk.to_json(pub_key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  assert !key.is_private_key(parsed)
  let assert Ok(xdh.X25519) = key.xdh_curve(parsed)
}

pub fn xdh_pem_roundtrip_test() {
  let pem = fixtures.load_raw_pem("test/fixtures/x25519_priv.pem")
  let assert Ok(key) = key.from_pem(pem)
  assert key.is_private_key(key)
  let assert Ok(xdh.X25519) = key.xdh_curve(key)
  let assert Ok(output) = key.to_pem(key)
  let assert Ok(parsed) = key.from_pem(output)
  assert key.is_private_key(parsed)
  let assert Ok(xdh.X25519) = key.xdh_curve(parsed)
}

pub fn xdh_der_roundtrip_test() {
  let der = fixtures.load_raw_der("test/fixtures/x25519_priv.der")
  let assert Ok(key) = key.from_der(der)
  assert key.is_private_key(key)
  let assert Ok(xdh.X25519) = key.xdh_curve(key)
  let assert Ok(output) = key.to_der(key)
  let assert Ok(parsed) = key.from_der(output)
  assert key.is_private_key(parsed)
  let assert Ok(xdh.X25519) = key.xdh_curve(parsed)
}

pub fn xdh_x448_pem_roundtrip_test() {
  let pem = fixtures.load_raw_pem("test/fixtures/x448_priv.pem")
  let assert Ok(key) = key.from_pem(pem)
  assert key.is_private_key(key)
  let assert Ok(xdh.X448) = key.xdh_curve(key)
  let assert Ok(output) = key.to_pem(key)
  let assert Ok(parsed) = key.from_pem(output)
  assert key.is_private_key(parsed)
  let assert Ok(xdh.X448) = key.xdh_curve(parsed)
}

pub fn xdh_x448_der_roundtrip_test() {
  let der = fixtures.load_raw_der("test/fixtures/x448_priv.der")
  let assert Ok(key) = key.from_der(der)
  assert key.is_private_key(key)
  let assert Ok(xdh.X448) = key.xdh_curve(key)
  let assert Ok(output) = key.to_der(key)
  let assert Ok(parsed) = key.from_der(output)
  assert key.is_private_key(parsed)
  let assert Ok(xdh.X448) = key.xdh_curve(parsed)
}

pub fn xdh_x25519_private_key_json_snapshot_test() {
  let key = fixtures.x25519_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val) |> birdie.snap("X25519 private key JSON")
}

pub fn xdh_x25519_public_key_json_snapshot_test() {
  let key = fixtures.x25519_public_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val) |> birdie.snap("X25519 public key JSON")
}

pub fn xdh_x448_private_key_json_snapshot_test() {
  let key = fixtures.x448_key()
  let json_val = jwk.to_json(key)
  json.to_string(json_val) |> birdie.snap("X448 private key JSON")
}

pub fn xdh_x25519_pem_snapshot_test() {
  let key = fixtures.x25519_key()
  let assert Ok(output) = key.to_pem(key)
  output |> birdie.snap("X25519 private key PEM")
}

pub fn xdh_json_rejects_signing_use_test() {
  let json_str =
    json.object([
      #("kty", json.string("OKP")),
      #("crv", json.string("X25519")),
      #("x", json.string("jq8pFZh2ehpg7QjZ-oF6MAZOmjM4UfBENZi7KxWpSG0")),
      #("use", json.string("sig")),
    ])
    |> json.to_string
  assert jwk.from_json(json_str)
    == Error(gose.InvalidState(
      "XDH keys (X25519/X448) cannot be used for signing",
    ))
}

pub fn xdh_rejects_signing_use_test() {
  let key = fixtures.x25519_key()
  let result = key.with_key_use(key, key.Signing)
  assert result
    == Error(gose.InvalidState(
      "XDH keys (X25519/X448) cannot be used for signing",
    ))
}

pub fn xdh_thumbprint_private_equals_public_test() {
  let private_key = fixtures.x25519_key()
  let assert Ok(public_key) = key.public_key(private_key)
  let assert Ok(private_tp) = jwk.thumbprint(private_key, hash.Sha256)
  let assert Ok(public_tp) = jwk.thumbprint(public_key, hash.Sha256)
  assert private_tp == public_tp
}

pub fn kid_roundtrip_test() {
  use kid <- qcheck.given(qcheck.non_empty_string())
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  let key = key.with_kid(key, kid)
  assert key.kid(key) == Ok(kid)
}

pub fn kid_preserved_through_json_test() {
  use kid <- qcheck.given(qcheck.non_empty_string())
  let key = fixtures.ed25519_key()
  let key = key.with_kid(key, kid)
  let json_val = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_val))
  assert key.kid(parsed) == Ok(kid)
}

pub fn key_use_roundtrip_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  let assert Ok(key_sig) = key.with_key_use(key, key.Signing)
  assert key.key_use(key_sig) == Ok(key.Signing)

  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  let assert Ok(key_enc) = key.with_key_use(key, key.Encrypting)
  assert key.key_use(key_enc) == Ok(key.Encrypting)
}

pub fn key_use_json_roundtrip_test() {
  let assert Ok(key) =
    key.generate_hmac_key(algorithm.HmacSha256)
    |> key.with_key_use(key.Signing)
  let json_value = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_value))
  assert key.key_use(parsed) == Ok(key.Signing)

  let assert Ok(key) =
    key.generate_hmac_key(algorithm.HmacSha256)
    |> key.with_key_use(key.Encrypting)
  let json_value = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_value))
  assert key.key_use(parsed) == Ok(key.Encrypting)
}

pub fn key_ops_roundtrip_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  let assert Ok(key) = key.with_key_ops(key, [key.Sign, key.Verify])
  assert key.key_ops(key) == Ok([key.Sign, key.Verify])
}

pub fn key_ops_json_roundtrip_test() {
  let gen =
    qcheck.generic_list(generators.key_op_generator(), qcheck.bounded_int(1, 8))
    |> qcheck.map(list.unique)
  use ops <- qcheck.given(gen)
  let assert Ok(key) =
    fixtures.ed25519_key()
    |> key.with_key_ops(ops)
  let json_value = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_value))
  assert key.key_ops(parsed) == Ok(ops)
}

pub fn key_ops_rejects_empty_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  assert key.with_key_ops(key, [])
    == Error(gose.InvalidState("key_ops must not be empty"))
}

pub fn key_ops_rejects_duplicates_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  let assert Error(gose.InvalidState(_)) =
    key.with_key_ops(key, [key.Sign, key.Sign])

  let json_str =
    json.to_string(
      json.object([
        #("kty", json.string("oct")),
        #("k", json.string("c2VjcmV0")),
        #("key_ops", json.array(["sign", "sign"], json.string)),
      ]),
    )
  let assert Error(gose.ParseError(_)) = jwk.from_json(json_str)
}

pub fn algorithm_roundtrip_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  let key =
    key.with_alg(
      key,
      key.SigningAlg(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256))),
    )
  assert key.alg(key)
    == Ok(key.SigningAlg(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256))))
}

pub fn algorithm_json_roundtrip_test() {
  use alg <- qcheck.given(generators.alg_generator())
  let key =
    fixtures.ed25519_key()
    |> key.with_alg(alg)
  let json_value = jwk.to_json(key)
  let assert Ok(parsed) = jwk.from_json(json.to_string(json_value))
  assert key.alg(parsed) == Ok(alg)
}

pub fn alg_from_string_roundtrip_test() {
  use alg <- qcheck.given(generators.alg_generator())
  assert jwk.alg_from_string(jwk.alg_to_string(alg)) == Ok(alg)
}

pub fn thumbprint_consistent_length_test() {
  let k = key.generate_ec(ec.P256)
  let assert Ok(tp) = jwk.thumbprint(k, hash.Sha256)
  assert string.length(tp) == 43
}

pub fn alg_from_string_rejects_invalid_test() {
  assert jwk.alg_from_string("INVALID")
    == Error(gose.ParseError("unknown algorithm: INVALID"))
}

pub fn key_use_key_ops_consistency_sig_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  let assert Ok(key) = key.with_key_use(key, key.Signing)
  let result = key.with_key_ops(key, [key.Encrypt])
  assert result == Error(gose.InvalidState("key_ops incompatible with use=sig"))
}

pub fn key_use_key_ops_consistency_enc_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  let assert Ok(key) = key.with_key_ops(key, [key.Sign])
  let result = key.with_key_use(key, key.Encrypting)
  assert result == Error(gose.InvalidState("key_ops incompatible with use=enc"))
}

pub fn public_key_maps_sign_to_verify_test() {
  let key = fixtures.ed25519_key()
  let assert Ok(key) = key.with_key_ops(key, [key.Sign])
  let assert Ok(pub_key) = key.public_key(key)
  assert key.key_ops(pub_key) == Ok([key.Verify])
}

pub fn public_key_removes_decrypt_test() {
  let key = fixtures.ed25519_key()
  let assert Ok(key) = key.with_key_ops(key, [key.Encrypt, key.Decrypt])
  let assert Ok(pub_key) = key.public_key(key)
  assert key.key_ops(pub_key) == Ok([key.Encrypt])
}

pub fn public_key_removes_unwrap_key_test() {
  let key = fixtures.ed25519_key()
  let assert Ok(key) = key.with_key_ops(key, [key.WrapKey, key.UnwrapKey])
  let assert Ok(pub_key) = key.public_key(key)
  assert key.key_ops(pub_key) == Ok([key.WrapKey])
}

pub fn public_key_preserves_metadata_test() {
  let key =
    fixtures.ed25519_key()
    |> key.with_kid("my-key")
  let assert Ok(private_key) =
    key.with_key_use(key, key.Signing)
    |> result.try(key.with_key_ops(_, [key.Sign, key.Verify]))
    |> result.map(key.with_alg(
      _,
      key.SigningAlg(algorithm.DigitalSignature(algorithm.Eddsa)),
    ))
  let assert Ok(public_key) = key.public_key(private_key)
  assert key.kid(public_key) == Ok("my-key")
  assert key.key_use(public_key) == Ok(key.Signing)
  assert key.key_ops(public_key) == Ok([key.Verify])
  assert key.alg(public_key)
    == Ok(key.SigningAlg(algorithm.DigitalSignature(algorithm.Eddsa)))
}

pub fn public_key_rejects_octet_key_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  assert key.public_key(key)
    == Error(gose.InvalidState("octet keys are not asymmetric"))
}

pub fn from_pem_rejects_invalid_test() {
  assert key.from_pem("not a pem")
    == Error(gose.ParseError(
      "invalid PEM: not a recognized RSA, EC, EdDSA, or XDH key format",
    ))
}

pub fn from_der_rejects_invalid_test() {
  assert key.from_der(<<1, 2, 3>>)
    == Error(gose.ParseError(
      "invalid DER: not a recognized RSA, EC, EdDSA, or XDH key format",
    ))
}

pub fn to_der_rejects_octet_key_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  assert key.to_der(key)
    == Error(gose.InvalidState("octet keys cannot be serialized to DER"))
}

pub fn to_pem_rejects_octet_key_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret":utf8>>)
  assert key.to_pem(key)
    == Error(gose.InvalidState("octet keys cannot be serialized to PEM"))
}

pub fn from_json_rejects_missing_kty_test() {
  let json_str =
    json.object([#("x", json.string("abc"))])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("missing or invalid kty"))
}

pub fn from_json_rejects_unsupported_kty_test() {
  let json_str =
    json.object([#("kty", json.string("INVALID")), #("x", json.string("abc"))])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("unsupported kty: INVALID"))
}

pub fn from_json_rejects_empty_oct_key_test() {
  let json_str =
    json.object([#("kty", json.string("oct")), #("k", json.string(""))])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("oct key must not be empty"))
}

pub fn from_json_rejects_unsupported_curve_test() {
  let json_str =
    json.object([
      #("kty", json.string("OKP")),
      #("crv", json.string("Ed999")),
      #("x", json.string("abc")),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("unsupported OKP curve: Ed999"))
}

pub fn from_json_rejects_invalid_use_test() {
  let json_str =
    json.object([
      #("kty", json.string("oct")),
      #("k", json.string("c2VjcmV0")),
      #("use", json.string("invalid")),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("invalid use value: invalid"))
}

pub fn from_json_rejects_invalid_key_ops_test() {
  let json_str =
    json.object([
      #("kty", json.string("oct")),
      #("k", json.string("c2VjcmV0")),
      #("key_ops", json.preprocessed_array([json.string("invalid")])),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("invalid key_ops value: invalid"))
}

pub fn from_json_rejects_empty_key_ops_test() {
  let json_str =
    json.object([
      #("kty", json.string("oct")),
      #("k", json.string("c2VjcmV0")),
      #("key_ops", json.preprocessed_array([])),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("key_ops must not be empty"))
}

pub fn from_json_rejects_invalid_alg_test() {
  let json_str =
    json.object([
      #("kty", json.string("oct")),
      #("k", json.string("c2VjcmV0")),
      #("alg", json.string("INVALID")),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.ParseError("unknown algorithm: INVALID"))
}

pub fn from_json_rejects_incompatible_use_ops_test() {
  let json_str =
    json.object([
      #("kty", json.string("oct")),
      #("k", json.string("c2VjcmV0")),
      #("use", json.string("sig")),
      #("key_ops", json.preprocessed_array([json.string("encrypt")])),
    ])
    |> json.to_string()
  assert jwk.from_json(json_str)
    == Error(gose.InvalidState("key_ops incompatible with use=sig"))
}

pub fn thumbprint_rfc7638_test_vector_test() {
  let json_str =
    json.object([
      #("kty", json.string("RSA")),
      #("e", json.string("AQAB")),
      #(
        "n",
        json.string(
          "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        ),
      ),
    ])
    |> json.to_string()
  let assert Ok(key) = jwk.from_json(json_str)
  let assert Ok(tp) = jwk.thumbprint(key, hash.Sha256)
  assert tp == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
}

pub fn eddsa_to_octet_bits_roundtrip_test() {
  use curve <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    generators.eddsa_curve_generator(),
  )
  let key = key.generate_eddsa(curve)
  let assert Ok(bytes) = key.to_octet_bits(key)
  let assert Ok(restored) = key.from_eddsa_bits(curve, bytes)
  let assert Ok(restored_bits) = key.to_octet_bits(restored)
  assert bytes == restored_bits
}

pub fn eddsa_public_to_octet_bits_roundtrip_test() {
  use curve <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    generators.eddsa_curve_generator(),
  )
  let key = key.generate_eddsa(curve)
  let assert Ok(pub_key) = key.public_key(key)
  let assert Ok(bytes) = key.to_octet_bits(pub_key)
  let assert Ok(restored) = key.from_eddsa_public_bits(curve, bytes)
  let assert Ok(restored_bits) = key.to_octet_bits(restored)
  assert bytes == restored_bits
}

pub fn xdh_to_octet_bits_roundtrip_test() {
  use curve <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    generators.xdh_curve_generator(),
  )
  let key = key.generate_xdh(curve)
  let assert Ok(bytes) = key.to_octet_bits(key)
  let assert Ok(restored) = key.from_xdh_bits(curve, bytes)
  let assert Ok(restored_bits) = key.to_octet_bits(restored)
  assert bytes == restored_bits
}

pub fn xdh_public_to_octet_bits_roundtrip_test() {
  use curve <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    generators.xdh_curve_generator(),
  )
  let key = key.generate_xdh(curve)
  let assert Ok(pub_key) = key.public_key(key)
  let assert Ok(bytes) = key.to_octet_bits(pub_key)
  let assert Ok(restored) = key.from_xdh_public_bits(curve, bytes)
  let assert Ok(restored_bits) = key.to_octet_bits(restored)
  assert bytes == restored_bits
}

pub fn from_eddsa_bits_rejects_invalid_test() {
  assert key.from_eddsa_bits(eddsa.Ed25519, <<1, 2, 3>>)
    == Error(gose.ParseError("invalid EdDSA private key bits"))
}

pub fn from_eddsa_public_bits_rejects_invalid_test() {
  assert key.from_eddsa_public_bits(eddsa.Ed25519, <<1, 2, 3>>)
    == Error(gose.ParseError("invalid EdDSA public key bits"))
}

pub fn from_xdh_bits_rejects_invalid_test() {
  assert key.from_xdh_bits(xdh.X25519, <<1, 2, 3>>)
    == Error(gose.ParseError("invalid XDH private key bits"))
}

pub fn from_xdh_public_bits_rejects_invalid_test() {
  assert key.from_xdh_public_bits(xdh.X25519, <<1, 2, 3>>)
    == Error(gose.ParseError("invalid XDH public key bits"))
}

pub fn to_octet_bits_rejects_rsa_key_test() {
  let key = fixtures.rsa_private_key()
  assert key.to_octet_bits(key)
    == Error(gose.InvalidState("key has no single-value byte representation"))
}

pub fn to_octet_bits_rejects_ec_key_test() {
  let key = fixtures.ec_p256_key()
  assert key.to_octet_bits(key)
    == Error(gose.InvalidState("key has no single-value byte representation"))
}

pub fn thumbprint_octet_key_consistency_test() {
  let assert Ok(key) = key.from_octet_bits(<<"secret-key-123":utf8>>)
  let assert Ok(tp) = jwk.thumbprint(key, hash.Sha256)
  let assert Ok(key2) = key.from_octet_bits(<<"secret-key-123":utf8>>)
  let assert Ok(tp2) = jwk.thumbprint(key2, hash.Sha256)
  assert tp == tp2
}

pub fn from_json_bits_roundtrip_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let json_val = jwk.to_json(key)
  let json_bits = bit_array.from_string(json.to_string(json_val))
  let assert Ok(parsed) = jwk.from_json_bits(json_bits)
  let assert Ok(original_secret) = key.material_octet_secret(key.material(key))
  let assert Ok(parsed_secret) = key.material_octet_secret(key.material(parsed))
  assert original_secret == parsed_secret
}

pub fn from_json_bits_rejects_invalid_utf8_test() {
  assert jwk.from_json_bits(<<0xFF, 0xFE>>)
    == Error(gose.ParseError("invalid JSON"))
}

pub fn reject_x509_parameters_test() {
  let oct_jwk_with_field = fn(extra_fields) {
    json.object([
      #("kty", json.string("oct")),
      #(
        "k",
        json.string(
          "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        ),
      ),
      ..extra_fields
    ])
    |> json.to_string
  }

  let jwk_with_x5u =
    oct_jwk_with_field([#("x5u", json.string("https://example.com/cert"))])
  assert jwk.from_json(jwk_with_x5u)
    == Error(gose.ParseError("unsupported X.509 JWK parameter: x5u"))

  let jwk_with_x5c =
    oct_jwk_with_field([
      #("x5c", json.preprocessed_array([json.string("MIIB...")])),
    ])
  assert jwk.from_json(jwk_with_x5c)
    == Error(gose.ParseError("unsupported X.509 JWK parameter: x5c"))

  let jwk_with_x5t =
    oct_jwk_with_field([#("x5t", json.string("dGhpcyBpcyBhIGhhc2g"))])
  assert jwk.from_json(jwk_with_x5t)
    == Error(gose.ParseError("unsupported X.509 JWK parameter: x5t"))

  let jwk_with_x5t_s256 =
    oct_jwk_with_field([#("x5t#S256", json.string("dGhpcyBpcyBhIGhhc2g"))])
  assert jwk.from_json(jwk_with_x5t_s256)
    == Error(gose.ParseError("unsupported X.509 JWK parameter: x5t#S256"))

  let jwk_with_multiple =
    oct_jwk_with_field([
      #("x5c", json.preprocessed_array([json.string("MIIB...")])),
      #("x5u", json.string("https://example.com/cert")),
    ])
  assert jwk.from_json(jwk_with_multiple)
    == Error(gose.ParseError("unsupported X.509 JWK parameter: x5u"))
}

pub fn material_accessors_test() {
  let rsa_key = fixtures.rsa_private_key()
  let ec_key = fixtures.ec_p256_key()
  let eddsa_key = fixtures.ed25519_key()
  let xdh_key = fixtures.x25519_key()

  let assert Ok(_) = key.material_rsa(key.material(rsa_key))
  let assert Error(_) = key.material_rsa(key.material(ec_key))

  let assert Ok(_) = key.material_ec(key.material(ec_key))
  let assert Error(_) = key.material_ec(key.material(rsa_key))

  let assert Ok(_) = key.material_eddsa(key.material(eddsa_key))
  let assert Error(_) = key.material_eddsa(key.material(ec_key))

  let assert Ok(_) = key.material_xdh(key.material(xdh_key))
  let assert Error(_) = key.material_xdh(key.material(ec_key))
}

pub fn public_key_accessors_test() {
  let rsa_key = fixtures.rsa_private_key()
  let ec_key = fixtures.ec_p256_key()
  let eddsa_key = fixtures.ed25519_key()
  let xdh_key = fixtures.x25519_key()

  let assert Ok(_) = key.rsa_public_key(rsa_key)
  let assert Error(_) = key.rsa_public_key(ec_key)

  let assert Ok(_) = key.ec_public_key(ec_key)
  let assert Error(_) = key.ec_public_key(rsa_key)

  let assert Ok(_) = key.eddsa_public_key(eddsa_key)
  let assert Error(_) = key.eddsa_public_key(ec_key)

  let assert Ok(_) = key.xdh_public_key(xdh_key)
  let assert Error(_) = key.xdh_public_key(ec_key)
}

pub fn from_dynamic_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let json_str = jwk.to_json(key) |> json.to_string
  let assert Ok(dyn) = json.parse(json_str, decode.dynamic)
  let assert Ok(parsed) = jwk.from_dynamic(dyn)
  assert key.key_type(parsed) == key.OctKeyType
}

pub fn decoder_with_decode_run_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let json_str = jwk.to_json(key) |> json.to_string
  let assert Ok(dyn) = json.parse(json_str, decode.dynamic)
  let assert Ok(parsed) = decode.run(dyn, jwk.decoder())
  assert key.key_type(parsed) == key.OctKeyType
}

pub fn decoder_with_json_parse_test() {
  let key =
    key.generate_ec(ec.P256)
    |> key.with_kid("ec-key")
  let json_str = jwk.to_json(key) |> json.to_string
  let assert Ok(parsed) = json.parse(json_str, jwk.decoder())
  assert key.key_type(parsed) == key.EcKeyType
  assert key.kid(parsed) == Ok("ec-key")
}

pub fn decoder_in_nested_field_test() {
  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let inner_json = jwk.to_json(key)
  let wrapper =
    json.object([#("signing_key", inner_json)])
    |> json.to_string
  let wrapper_decoder = {
    use k <- decode.field("signing_key", jwk.decoder())
    decode.success(k)
  }
  let assert Ok(dyn) = json.parse(wrapper, decode.dynamic)
  let assert Ok(parsed) = decode.run(dyn, wrapper_decoder)
  assert key.key_type(parsed) == key.OctKeyType
}

pub fn decoder_list_test() {
  let key1 = key.generate_hmac_key(algorithm.HmacSha256)
  let key2 = key.generate_ec(ec.P256)
  let json_str =
    json.preprocessed_array([jwk.to_json(key1), jwk.to_json(key2)])
    |> json.to_string
  let assert Ok(keys) = json.parse(json_str, decode.list(jwk.decoder()))
  assert list.length(keys) == 2
}

pub fn decoder_invalid_input_test() {
  let json_str =
    json.object([#("not", json.string("a-jwk"))])
    |> json.to_string
  let assert Error(_) = json.parse(json_str, jwk.decoder())
}
