//// COSE_Key encoding and decoding ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)).
////
//// Converts between `gose/key.Key` and COSE_Key CBOR representations.
////
//// ## Example
////
//// ```gleam
//// import gose/cose/key as cose_key
//// import gose/key
//// import kryptos/ec
////
//// // Generate an EC key and attach a binary kid (COSE uses BitArray kids)
//// let k =
////   key.generate_ec(ec.P256)
////   |> key.with_kid_bits(<<"my-key":utf8>>)
////
//// // Serialize to CBOR
//// let assert Ok(bytes) = cose_key.to_cbor(k)
////
//// // Parse from CBOR
//// let assert Ok(parsed) = cose_key.from_cbor(bytes)
//// let assert Ok(kid) = key.kid(parsed)
//// assert kid == <<"my-key":utf8>>
//// ```

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/option
import gleam/result
import gose
import gose/cbor
import gose/cose/algorithm as cose_algorithm
import gose/internal/utils
import gose/key
import kryptos/crypto
import kryptos/ec
import kryptos/eddsa
import kryptos/rsa
import kryptos/xdh

/// A key with a COSE-compatible binary kid.
pub type Key =
  key.Key(BitArray)

/// Encode a Key to COSE_Key CBOR bytes.
pub fn to_cbor(k: Key) -> Result(BitArray, gose.GoseError) {
  use pairs <- result.try(to_cbor_map(k))
  Ok(cbor.encode(cbor.Map(pairs)))
}

/// Decode COSE_Key from CBOR bytes to a Key.
pub fn from_cbor(data: BitArray) -> Result(Key, gose.GoseError) {
  use value <- result.try(cbor.decode(data))
  case value {
    cbor.Map(pairs) -> from_cbor_map(pairs)
    _ -> Error(gose.ParseError("COSE_Key must be a CBOR map"))
  }
}

/// Encode to CBOR map entries (for embedding in larger CBOR structures).
pub fn to_cbor_map(
  k: Key,
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  let mat = key.material(k)
  use key_pairs <- result.try(encode_key_material(mat))
  use metadata_pairs <- result.try(encode_metadata(k))
  Ok(list.append(key_pairs, metadata_pairs))
}

/// Decode from CBOR map entries.
pub fn from_cbor_map(
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use kty <- result.try(lookup_int(map, 1, "missing kty (label 1)"))
  use base_key <- result.try(decode_key_by_type(kty, map))
  apply_metadata(base_key, map)
}

fn encode_key_material(
  mat: key.KeyMaterial,
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  case mat {
    key.Ec(ec_mat) -> Ok(encode_ec(ec_mat))
    key.Eddsa(eddsa_mat) -> Ok(encode_eddsa(eddsa_mat))
    key.Xdh(xdh_mat) -> Ok(encode_xdh(xdh_mat))
    key.Rsa(rsa_mat) -> Ok(encode_rsa(rsa_mat))
    key.OctetKey(secret:) -> Ok(encode_symmetric(secret))
  }
}

fn encode_ec(mat: key.EcKeyMaterial) -> List(#(cbor.Value, cbor.Value)) {
  let #(curve, public, private_d) = case mat {
    key.EcPrivate(key: priv, public: public_key, curve: c) -> #(
      c,
      public_key,
      option.Some(priv),
    )
    key.EcPublic(key: public_key, curve: c) -> #(c, public_key, option.None)
  }
  let crv_id = ec_curve_to_cose(curve)
  let raw_point = ec.public_key_to_raw_point(public)
  let coord_size = ec.coordinate_size(curve)
  let assert Ok(x) = bit_array.slice(raw_point, 1, coord_size)
  let assert Ok(y) = bit_array.slice(raw_point, 1 + coord_size, coord_size)

  let pairs = [
    #(cbor.Int(1), cbor.Int(2)),
    #(cbor.Int(-1), cbor.Int(crv_id)),
    #(cbor.Int(-2), cbor.Bytes(x)),
    #(cbor.Int(-3), cbor.Bytes(y)),
  ]
  case private_d {
    option.Some(priv) -> [
      #(cbor.Int(-4), cbor.Bytes(ec.to_bytes(priv))),
      ..pairs
    ]
    option.None -> pairs
  }
}

fn encode_eddsa(mat: key.EddsaKeyMaterial) -> List(#(cbor.Value, cbor.Value)) {
  let #(curve, public_bytes, private_d) = case mat {
    key.EddsaPrivate(key: priv, public: public_key, curve: c) -> #(
      c,
      eddsa.public_key_to_bytes(public_key),
      option.Some(eddsa.to_bytes(priv)),
    )
    key.EddsaPublic(key: public_key, curve: c) -> #(
      c,
      eddsa.public_key_to_bytes(public_key),
      option.None,
    )
  }
  let crv_id = eddsa_curve_to_cose(curve)
  let pairs = [
    #(cbor.Int(1), cbor.Int(1)),
    #(cbor.Int(-1), cbor.Int(crv_id)),
    #(cbor.Int(-2), cbor.Bytes(public_bytes)),
  ]
  case private_d {
    option.Some(d) -> [#(cbor.Int(-4), cbor.Bytes(d)), ..pairs]
    option.None -> pairs
  }
}

fn encode_xdh(mat: key.XdhKeyMaterial) -> List(#(cbor.Value, cbor.Value)) {
  let #(curve, public_bytes, private_d) = case mat {
    key.XdhPrivate(key: priv, public: public_key, curve: c) -> #(
      c,
      xdh.public_key_to_bytes(public_key),
      option.Some(xdh.to_bytes(priv)),
    )
    key.XdhPublic(key: public_key, curve: c) -> #(
      c,
      xdh.public_key_to_bytes(public_key),
      option.None,
    )
  }
  let crv_id = xdh_curve_to_cose(curve)
  let pairs = [
    #(cbor.Int(1), cbor.Int(1)),
    #(cbor.Int(-1), cbor.Int(crv_id)),
    #(cbor.Int(-2), cbor.Bytes(public_bytes)),
  ]
  case private_d {
    option.Some(d) -> [#(cbor.Int(-4), cbor.Bytes(d)), ..pairs]
    option.None -> pairs
  }
}

fn encode_rsa(mat: key.RsaKeyMaterial) -> List(#(cbor.Value, cbor.Value)) {
  case mat {
    key.RsaPrivate(key: priv, public: public_key) -> {
      let n = utils.strip_leading_zeros(rsa.public_key_modulus(public_key))
      let e =
        utils.strip_leading_zeros(rsa.public_key_exponent_bytes(public_key))
      [
        #(cbor.Int(1), cbor.Int(3)),
        #(cbor.Int(-1), cbor.Bytes(n)),
        #(cbor.Int(-2), cbor.Bytes(e)),
        #(cbor.Int(-3), cbor.Bytes(rsa.private_exponent_bytes(priv))),
        #(cbor.Int(-4), cbor.Bytes(rsa.prime1(priv))),
        #(cbor.Int(-5), cbor.Bytes(rsa.prime2(priv))),
        #(cbor.Int(-6), cbor.Bytes(rsa.exponent1(priv))),
        #(cbor.Int(-7), cbor.Bytes(rsa.exponent2(priv))),
        #(cbor.Int(-8), cbor.Bytes(rsa.coefficient(priv))),
      ]
    }
    key.RsaPublic(key: public_key) -> {
      let n = utils.strip_leading_zeros(rsa.public_key_modulus(public_key))
      let e =
        utils.strip_leading_zeros(rsa.public_key_exponent_bytes(public_key))
      [
        #(cbor.Int(1), cbor.Int(3)),
        #(cbor.Int(-1), cbor.Bytes(n)),
        #(cbor.Int(-2), cbor.Bytes(e)),
      ]
    }
  }
}

fn encode_symmetric(secret: BitArray) -> List(#(cbor.Value, cbor.Value)) {
  [
    #(cbor.Int(1), cbor.Int(4)),
    #(cbor.Int(-1), cbor.Bytes(secret)),
  ]
}

fn encode_metadata(
  k: Key,
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  let kid_pair = case key.kid(k) {
    Ok(kid) -> [#(cbor.Int(2), cbor.Bytes(kid))]
    Error(_) -> []
  }
  use alg_pair <- result.try(resolve_alg_metadata(k))
  let ops_pair = case key.key_ops(k) {
    Ok(ops) -> [
      #(
        cbor.Int(4),
        cbor.Array(list.map(ops, fn(op) { cbor.Int(key_op_to_cose(op)) })),
      ),
    ]
    Error(_) -> []
  }
  Ok(list.flatten([kid_pair, alg_pair, ops_pair]))
}

fn resolve_alg_metadata(
  k: key.Key(kid),
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  case key.alg(k) {
    Ok(alg) -> encode_alg_metadata(alg)
    Error(_) -> Ok([])
  }
}

fn encode_alg_metadata(
  alg: key.Alg,
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  case alg {
    key.SigningAlg(signing_alg) ->
      Ok([
        #(cbor.Int(3), cbor.Int(cose_algorithm.signing_alg_to_int(signing_alg))),
      ])
    key.KeyEncryptionAlg(ke_alg) -> {
      use id <- result.map(cose_algorithm.key_encryption_alg_to_int(ke_alg))
      [#(cbor.Int(3), cbor.Int(id))]
    }
    key.ContentAlg(content_alg) -> {
      use id <- result.map(cose_algorithm.content_alg_to_int(content_alg))
      [#(cbor.Int(3), cbor.Int(id))]
    }
  }
}

fn decode_key_by_type(
  kty: Int,
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  case kty {
    1 -> decode_okp(map)
    2 -> decode_ec2(map)
    3 -> decode_rsa(map)
    4 -> decode_symmetric(map)
    _ ->
      Error(gose.ParseError("unsupported COSE key type: " <> int.to_string(kty)))
  }
}

fn decode_ec2(
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use crv_id <- result.try(lookup_int(map, -1, "missing EC curve (label -1)"))
  use curve <- result.try(ec_curve_from_cose(crv_id))
  use x <- result.try(lookup_bytes(map, -2, "missing EC x (label -2)"))
  use y <- result.try(lookup_bytes(map, -3, "missing EC y (label -3)"))
  case has_label(map, -4) {
    True -> {
      use d <- result.try(lookup_bytes(map, -4, "missing EC d (label -4)"))
      use #(private, public) <- result.try(
        ec.from_bytes(curve, d)
        |> result.replace_error(gose.ParseError("invalid EC private key")),
      )
      let computed_point = ec.public_key_to_raw_point(public)
      let raw_point = bit_array.concat([<<0x04>>, x, y])
      use <- bool.guard(
        when: !crypto.constant_time_equal(computed_point, raw_point),
        return: Error(gose.ParseError("x/y do not match computed public key")),
      )
      Ok(key.new_key(key.Ec(key.EcPrivate(key: private, public:, curve:))))
    }
    False -> key.ec_public_key_from_coordinates(curve, x:, y:)
  }
}

fn decode_okp(
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use crv_id <- result.try(lookup_int(map, -1, "missing OKP curve (label -1)"))
  case crv_id {
    6 -> decode_eddsa_key(eddsa.Ed25519, map)
    7 -> decode_eddsa_key(eddsa.Ed448, map)
    4 -> decode_xdh_key(xdh.X25519, map)
    5 -> decode_xdh_key(xdh.X448, map)
    _ ->
      Error(gose.ParseError("unsupported OKP curve: " <> int.to_string(crv_id)))
  }
}

fn decode_eddsa_key(
  curve: eddsa.Curve,
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  case has_label(map, -4) {
    True -> {
      use x <- result.try(lookup_bytes(map, -2, "missing EdDSA x (label -2)"))
      use d <- result.try(lookup_bytes(map, -4, "missing EdDSA d (label -4)"))
      use #(private, public) <- result.try(
        eddsa.from_bytes(curve, d)
        |> result.replace_error(gose.ParseError("invalid EdDSA private key")),
      )
      let computed_x = eddsa.public_key_to_bytes(public)
      use <- bool.guard(
        when: !crypto.constant_time_equal(computed_x, x),
        return: Error(gose.ParseError("x does not match computed public key")),
      )
      Ok(
        key.new_key(key.Eddsa(key.EddsaPrivate(key: private, public:, curve:))),
      )
    }
    False -> {
      use x <- result.try(lookup_bytes(map, -2, "missing EdDSA x (label -2)"))
      key.from_eddsa_public_bits(curve, x)
    }
  }
}

fn decode_xdh_key(
  curve: xdh.Curve,
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  case has_label(map, -4) {
    True -> {
      use x <- result.try(lookup_bytes(map, -2, "missing XDH x (label -2)"))
      use d <- result.try(lookup_bytes(map, -4, "missing XDH d (label -4)"))
      use #(private, public) <- result.try(
        xdh.from_bytes(curve, d)
        |> result.replace_error(gose.ParseError("invalid XDH private key")),
      )
      let computed_x = xdh.public_key_to_bytes(public)
      use <- bool.guard(
        when: !crypto.constant_time_equal(computed_x, x),
        return: Error(gose.ParseError("x does not match computed public key")),
      )
      Ok(key.new_key(key.Xdh(key.XdhPrivate(key: private, public:, curve:))))
    }
    False -> {
      use x <- result.try(lookup_bytes(map, -2, "missing XDH x (label -2)"))
      key.from_xdh_public_bits(curve, x)
    }
  }
}

fn decode_rsa(
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use n <- result.try(lookup_bytes(map, -1, "missing RSA n (label -1)"))
  use e <- result.try(lookup_bytes(map, -2, "missing RSA e (label -2)"))
  case has_label(map, -3) {
    True -> decode_rsa_private(map, n, e)
    False ->
      rsa.public_key_from_components(n, e)
      |> result.replace_error(gose.ParseError(
        "invalid RSA public key components",
      ))
      |> result.map(fn(public_key) {
        key.new_key(key.Rsa(key.RsaPublic(key: public_key)))
      })
  }
}

fn decode_rsa_private(
  map: List(#(cbor.Value, cbor.Value)),
  n: BitArray,
  e: BitArray,
) -> Result(Key, gose.GoseError) {
  use d <- result.try(lookup_bytes(map, -3, "missing RSA d (label -3)"))
  case has_label(map, -4) {
    True -> {
      use p <- result.try(lookup_bytes(map, -4, "missing RSA p (label -4)"))
      use q <- result.try(lookup_bytes(map, -5, "missing RSA q (label -5)"))
      use dp <- result.try(lookup_bytes(map, -6, "missing RSA dp (label -6)"))
      use dq <- result.try(lookup_bytes(map, -7, "missing RSA dq (label -7)"))
      use qi <- result.try(lookup_bytes(map, -8, "missing RSA qi (label -8)"))
      rsa.from_full_components(n, e, d, p, q, dp, dq, qi)
      |> result.replace_error(gose.ParseError(
        "invalid RSA private key components",
      ))
      |> result.map(fn(pair) {
        let #(private, public) = pair
        key.new_key(key.Rsa(key.RsaPrivate(key: private, public:)))
      })
    }
    False ->
      rsa.from_components(n, e, d)
      |> result.replace_error(gose.ParseError(
        "invalid RSA private key components",
      ))
      |> result.map(fn(pair) {
        let #(private, public) = pair
        key.new_key(key.Rsa(key.RsaPrivate(key: private, public:)))
      })
  }
}

fn decode_symmetric(
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use k <- result.try(lookup_bytes(map, -1, "missing symmetric key (label -1)"))
  key.from_octet_bits(k)
}

fn apply_metadata(
  k: Key,
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use k <- result.try(apply_kid(k, map))
  use k <- result.try(apply_alg(k, map))
  apply_key_ops(k, map)
}

fn apply_kid(
  k: Key,
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use opt_kid <- result.try(lookup_bytes_optional(map, 2))
  case opt_kid {
    option.Some(kid_bytes) -> Ok(key.with_kid_bits(k, kid_bytes))
    option.None -> Ok(k)
  }
}

fn apply_alg(
  k: Key,
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use opt_alg_id <- result.try(lookup_int_optional(map, 3))
  case opt_alg_id {
    option.Some(alg_id) -> {
      use alg <- result.map(decode_alg(alg_id))
      key.with_alg(k, alg)
    }
    option.None -> Ok(k)
  }
}

fn apply_key_ops(
  k: Key,
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use opt_ops <- result.try(lookup_array_optional(map, 4))
  case opt_ops {
    option.Some(ops_cbor) -> {
      use ops <- result.try(decode_key_ops(ops_cbor))
      key.with_key_ops(k, ops)
    }
    option.None -> Ok(k)
  }
}

fn decode_alg(id: Int) -> Result(key.Alg, gose.GoseError) {
  case cose_algorithm.signing_alg_from_int(id) {
    Ok(alg) -> Ok(key.SigningAlg(alg))
    Error(_) ->
      case cose_algorithm.key_encryption_alg_from_int(id) {
        Ok(alg) -> Ok(key.KeyEncryptionAlg(alg))
        Error(_) ->
          cose_algorithm.content_alg_from_int(id)
          |> result.map(key.ContentAlg)
          |> result.replace_error(gose.ParseError(
            "unknown COSE algorithm: " <> int.to_string(id),
          ))
      }
  }
}

fn decode_key_ops(
  ops: List(cbor.Value),
) -> Result(List(key.KeyOp), gose.GoseError) {
  list.try_map(ops, fn(v) {
    case v {
      cbor.Int(id) -> key_op_from_cose(id)
      _ -> Error(gose.ParseError("key_ops must contain integers"))
    }
  })
}

@internal
pub fn ec_curve_to_cose(curve: ec.Curve) -> Int {
  case curve {
    ec.P256 -> 1
    ec.P384 -> 2
    ec.P521 -> 3
    ec.Secp256k1 -> 8
  }
}

@internal
pub fn ec_curve_from_cose(id: Int) -> Result(ec.Curve, gose.GoseError) {
  case id {
    1 -> Ok(ec.P256)
    2 -> Ok(ec.P384)
    3 -> Ok(ec.P521)
    8 -> Ok(ec.Secp256k1)
    _ ->
      Error(gose.ParseError("unsupported COSE EC curve: " <> int.to_string(id)))
  }
}

fn eddsa_curve_to_cose(curve: eddsa.Curve) -> Int {
  case curve {
    eddsa.Ed25519 -> 6
    eddsa.Ed448 -> 7
  }
}

@internal
pub fn xdh_curve_to_cose(curve: xdh.Curve) -> Int {
  case curve {
    xdh.X25519 -> 4
    xdh.X448 -> 5
  }
}

@internal
pub fn xdh_curve_from_cose(id: Int) -> Result(xdh.Curve, gose.GoseError) {
  case id {
    4 -> Ok(xdh.X25519)
    5 -> Ok(xdh.X448)
    _ ->
      Error(gose.ParseError("unsupported COSE XDH curve: " <> int.to_string(id)))
  }
}

fn key_op_to_cose(op: key.KeyOp) -> Int {
  case op {
    key.Sign -> 1
    key.Verify -> 2
    key.Encrypt -> 3
    key.Decrypt -> 4
    key.WrapKey -> 5
    key.UnwrapKey -> 6
    key.DeriveKey -> 7
    key.DeriveBits -> 8
  }
}

fn key_op_from_cose(id: Int) -> Result(key.KeyOp, gose.GoseError) {
  case id {
    1 -> Ok(key.Sign)
    2 -> Ok(key.Verify)
    3 -> Ok(key.Encrypt)
    4 -> Ok(key.Decrypt)
    5 -> Ok(key.WrapKey)
    6 -> Ok(key.UnwrapKey)
    7 -> Ok(key.DeriveKey)
    8 -> Ok(key.DeriveBits)
    _ -> Error(gose.ParseError("unknown COSE key_op: " <> int.to_string(id)))
  }
}

fn lookup_int(
  map: List(#(cbor.Value, cbor.Value)),
  label: Int,
  error_msg: String,
) -> Result(Int, gose.GoseError) {
  case list.key_find(map, find: cbor.Int(label)) {
    Ok(cbor.Int(value)) -> Ok(value)
    Ok(_) -> Error(gose.ParseError(error_msg <> " (wrong type)"))
    Error(_) -> Error(gose.ParseError(error_msg))
  }
}

fn lookup_bytes(
  map: List(#(cbor.Value, cbor.Value)),
  label: Int,
  error_msg: String,
) -> Result(BitArray, gose.GoseError) {
  case list.key_find(map, find: cbor.Int(label)) {
    Ok(cbor.Bytes(value)) -> Ok(value)
    Ok(_) -> Error(gose.ParseError(error_msg <> " (wrong type)"))
    Error(_) -> Error(gose.ParseError(error_msg))
  }
}

fn lookup_int_optional(
  map: List(#(cbor.Value, cbor.Value)),
  label: Int,
) -> Result(option.Option(Int), gose.GoseError) {
  case list.key_find(map, find: cbor.Int(label)) {
    Ok(cbor.Int(value)) -> Ok(option.Some(value))
    Ok(_) ->
      Error(gose.ParseError(
        "key parameter " <> int.to_string(label) <> " has wrong type",
      ))
    Error(_) -> Ok(option.None)
  }
}

fn lookup_bytes_optional(
  map: List(#(cbor.Value, cbor.Value)),
  label: Int,
) -> Result(option.Option(BitArray), gose.GoseError) {
  case list.key_find(map, find: cbor.Int(label)) {
    Ok(cbor.Bytes(value)) -> Ok(option.Some(value))
    Ok(_) ->
      Error(gose.ParseError(
        "key parameter " <> int.to_string(label) <> " has wrong type",
      ))
    Error(_) -> Ok(option.None)
  }
}

fn lookup_array_optional(
  map: List(#(cbor.Value, cbor.Value)),
  label: Int,
) -> Result(option.Option(List(cbor.Value)), gose.GoseError) {
  case list.key_find(map, find: cbor.Int(label)) {
    Ok(cbor.Array(items)) -> Ok(option.Some(items))
    Ok(_) ->
      Error(gose.ParseError(
        "key parameter " <> int.to_string(label) <> " has wrong type",
      ))
    Error(_) -> Ok(option.None)
  }
}

fn has_label(map: List(#(cbor.Value, cbor.Value)), label: Int) -> Bool {
  list.key_find(map, find: cbor.Int(label)) |> result.is_ok
}
