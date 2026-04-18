//// Typed accessors and builders for COSE message header parameters,
//// plus the `Key` alias, COSE_Key CBOR serialization, and COSE algorithm
//// integer ID mapping ([RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html)).
////
//// ## Phantom-state vocabulary
////
//// Each COSE message module uses a phantom state type named after the
//// RFC 9052 operation it performs: `Sign1` uses `Unsigned`/`Signed`,
//// `Encrypt0` and `Encrypt` use `Unencrypted`/`Encrypted`, `Mac0` uses
//// `Untagged`/`Tagged`, and `Sign` uses `Building`/`Signed` for its builder
//// body. The names match the RFC terminology rather than a single uniform
//// vocabulary.

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gose
import gose/cbor
import gose/internal/utils
import kryptos/crypto
import kryptos/ec
import kryptos/eddsa
import kryptos/rsa
import kryptos/xdh

/// A key with a COSE-compatible binary kid.
pub type Key =
  gose.Key(BitArray)

/// Well-known CoAP content format identifiers and media type strings
/// used in the COSE content type header (label 3).
pub type ContentType {
  TextPlain
  OctetStream
  Json
  Cbor
  Cwt
  CoseSign
  CoseSign1
  CoseEncrypt
  CoseEncrypt0
  CoseMac
  CoseMac0
  CoseKey
  CoseKeySet
  IntContentType(Int)
  TextContentType(String)
}

/// A COSE header parameter with typed labels and values for well-known
/// headers, plus an `Unknown` fallback for non-standard parameters.
pub type Header {
  Alg(Int)
  Crit(List(Int))
  ContentType(ContentType)
  Kid(BitArray)
  Iv(BitArray)
  PartialIv(BitArray)
  Unknown(cbor.Value, cbor.Value)
}

/// Extract the algorithm identifier (label 1).
pub fn algorithm(headers: List(Header)) -> Result(Int, gose.GoseError) {
  case list.find(headers, is_alg) {
    Ok(Alg(id)) -> Ok(id)
    _ -> Error(gose.ParseError("missing header label 1 (alg)"))
  }
}

/// Extract the critical headers list (label 2).
pub fn critical(headers: List(Header)) -> Result(List(Int), gose.GoseError) {
  case list.find(headers, is_crit) {
    Ok(Crit(labels)) -> Ok(labels)
    _ -> Error(gose.ParseError("missing header label 2 (crit)"))
  }
}

/// Extract the content type (label 3).
pub fn content_type(
  headers: List(Header),
) -> Result(ContentType, gose.GoseError) {
  case list.find(headers, is_content_type) {
    Ok(ContentType(ct)) -> Ok(ct)
    _ -> Error(gose.ParseError("missing header label 3 (content type)"))
  }
}

/// Extract the key ID (label 4).
pub fn kid(headers: List(Header)) -> Result(BitArray, gose.GoseError) {
  case list.find(headers, is_kid) {
    Ok(Kid(k)) -> Ok(k)
    _ -> Error(gose.ParseError("missing header label 4 (kid)"))
  }
}

/// Extract the IV (label 5).
pub fn iv(headers: List(Header)) -> Result(BitArray, gose.GoseError) {
  case list.find(headers, is_iv) {
    Ok(Iv(v)) -> Ok(v)
    _ -> Error(gose.ParseError("missing header label 5 (IV)"))
  }
}

/// Extract the partial IV (label 6).
pub fn partial_iv(headers: List(Header)) -> Result(BitArray, gose.GoseError) {
  case list.find(headers, is_partial_iv) {
    Ok(PartialIv(v)) -> Ok(v)
    _ -> Error(gose.ParseError("missing header label 6 (Partial IV)"))
  }
}

@internal
pub fn header_to_cbor(header: Header) -> #(cbor.Value, cbor.Value) {
  case header {
    Alg(id) -> #(cbor.Int(1), cbor.Int(id))
    Crit(labels) -> #(cbor.Int(2), cbor.Array(list.map(labels, cbor.Int)))
    ContentType(ct) -> #(cbor.Int(3), content_type_to_cbor(ct))
    Kid(k) -> #(cbor.Int(4), cbor.Bytes(k))
    Iv(v) -> #(cbor.Int(5), cbor.Bytes(v))
    PartialIv(v) -> #(cbor.Int(6), cbor.Bytes(v))
    Unknown(key, value) -> #(key, value)
  }
}

@internal
pub fn header_from_cbor(
  pair: #(cbor.Value, cbor.Value),
) -> Result(Header, gose.GoseError) {
  case pair {
    #(cbor.Int(1), cbor.Int(id)) -> Ok(Alg(id))
    #(cbor.Int(1), _) ->
      Error(gose.ParseError("header label 1 (alg): expected Int"))
    #(cbor.Int(2), cbor.Array(values)) -> {
      use labels <- result.map(parse_int_list(values, []))
      Crit(labels)
    }
    #(cbor.Int(2), _) ->
      Error(gose.ParseError("header label 2 (crit): expected Array"))
    #(cbor.Int(3), value) -> {
      use ct <- result.map(content_type_from_cbor(value))
      ContentType(ct)
    }
    #(cbor.Int(4), cbor.Bytes(k)) -> Ok(Kid(k))
    #(cbor.Int(4), _) ->
      Error(gose.ParseError("header label 4 (kid): expected Bytes"))
    #(cbor.Int(5), cbor.Bytes(v)) -> Ok(Iv(v))
    #(cbor.Int(5), _) ->
      Error(gose.ParseError("header label 5 (IV): expected Bytes"))
    #(cbor.Int(6), cbor.Bytes(v)) -> Ok(PartialIv(v))
    #(cbor.Int(6), _) ->
      Error(gose.ParseError("header label 6 (Partial IV): expected Bytes"))
    #(key, value) -> Ok(Unknown(key, value))
  }
}

@internal
pub fn headers_from_cbor(
  pairs: List(#(cbor.Value, cbor.Value)),
) -> Result(List(Header), gose.GoseError) {
  list.try_map(pairs, header_from_cbor)
}

@internal
pub fn headers_to_cbor(headers: List(Header)) -> List(#(cbor.Value, cbor.Value)) {
  list.map(headers, header_to_cbor)
}

@internal
pub fn content_type_to_cbor(ct: ContentType) -> cbor.Value {
  case ct {
    TextPlain -> cbor.Int(0)
    OctetStream -> cbor.Int(42)
    Json -> cbor.Int(50)
    Cbor -> cbor.Int(60)
    Cwt -> cbor.Int(61)
    CoseSign -> cbor.Int(101)
    CoseSign1 -> cbor.Int(102)
    CoseEncrypt -> cbor.Int(103)
    CoseEncrypt0 -> cbor.Int(104)
    CoseMac -> cbor.Int(105)
    CoseMac0 -> cbor.Int(106)
    CoseKey -> cbor.Int(10_001)
    CoseKeySet -> cbor.Int(10_002)
    IntContentType(n) -> cbor.Int(n)
    TextContentType(s) -> cbor.Text(s)
  }
}

fn content_type_from_cbor(
  value: cbor.Value,
) -> Result(ContentType, gose.GoseError) {
  case value {
    cbor.Int(0) -> Ok(TextPlain)
    cbor.Int(42) -> Ok(OctetStream)
    cbor.Int(50) -> Ok(Json)
    cbor.Int(60) -> Ok(Cbor)
    cbor.Int(61) -> Ok(Cwt)
    cbor.Int(101) -> Ok(CoseSign)
    cbor.Int(102) -> Ok(CoseSign1)
    cbor.Int(103) -> Ok(CoseEncrypt)
    cbor.Int(104) -> Ok(CoseEncrypt0)
    cbor.Int(105) -> Ok(CoseMac)
    cbor.Int(106) -> Ok(CoseMac0)
    cbor.Int(10_001) -> Ok(CoseKey)
    cbor.Int(10_002) -> Ok(CoseKeySet)
    cbor.Int(n) -> Ok(IntContentType(n))
    cbor.Text(s) -> Ok(TextContentType(s))
    _ ->
      Error(gose.ParseError(
        "header label 3 (content type): expected Int or Text",
      ))
  }
}

fn is_alg(header: Header) -> Bool {
  case header {
    Alg(_) -> True
    _ -> False
  }
}

fn is_crit(header: Header) -> Bool {
  case header {
    Crit(_) -> True
    _ -> False
  }
}

fn is_content_type(header: Header) -> Bool {
  case header {
    ContentType(_) -> True
    _ -> False
  }
}

fn is_kid(header: Header) -> Bool {
  case header {
    Kid(_) -> True
    _ -> False
  }
}

fn is_iv(header: Header) -> Bool {
  case header {
    Iv(_) -> True
    _ -> False
  }
}

fn is_partial_iv(header: Header) -> Bool {
  case header {
    PartialIv(_) -> True
    _ -> False
  }
}

fn parse_int_list(
  values: List(cbor.Value),
  acc: List(Int),
) -> Result(List(Int), gose.GoseError) {
  case values {
    [] -> Ok(list.reverse(acc))
    [cbor.Int(n), ..rest] -> parse_int_list(rest, [n, ..acc])
    _ -> Error(gose.ParseError("header label 2 (crit): expected array of Int"))
  }
}

/// Encode a `Key` to COSE_Key CBOR bytes ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)).
pub fn key_to_cbor(k: Key) -> Result(BitArray, gose.GoseError) {
  use pairs <- result.try(key_to_cbor_map(k))
  Ok(cbor.encode(cbor.Map(pairs)))
}

/// Decode COSE_Key bytes to a `Key`.
pub fn key_from_cbor(data: BitArray) -> Result(Key, gose.GoseError) {
  use value <- result.try(cbor.decode(data))
  case value {
    cbor.Map(pairs) -> key_from_cbor_map(pairs)
    _ -> Error(gose.ParseError("COSE_Key must be a CBOR map"))
  }
}

/// Encode a `Key` to its CBOR map entries, for embedding in larger
/// CBOR structures.
pub fn key_to_cbor_map(
  k: Key,
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  let mat = gose.material(k)
  use key_pairs <- result.try(encode_key_material(mat))
  use metadata_pairs <- result.try(encode_metadata(k))
  Ok(list.append(key_pairs, metadata_pairs))
}

/// Decode CBOR map entries to a `Key`.
pub fn key_from_cbor_map(
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use kty <- result.try(lookup_int(map, 1, "missing kty (label 1)"))
  use base_key <- result.try(decode_key_by_type(kty, map))
  apply_metadata(base_key, map)
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

fn encode_key_material(
  mat: gose.KeyMaterial,
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  case mat {
    gose.Elliptic(ec_mat) -> Ok(encode_ec(ec_mat))
    gose.Edwards(eddsa_mat) -> Ok(encode_eddsa(eddsa_mat))
    gose.Xdh(xdh_mat) -> Ok(encode_xdh(xdh_mat))
    gose.Rsa(rsa_mat) -> Ok(encode_rsa(rsa_mat))
    gose.OctetKey(secret:) -> Ok(encode_symmetric(secret))
  }
}

fn encode_ec(mat: gose.EcKeyMaterial) -> List(#(cbor.Value, cbor.Value)) {
  let #(curve, public, private_d) = case mat {
    gose.EcPrivate(key: priv, public: public_key, curve: c) -> #(
      c,
      public_key,
      option.Some(priv),
    )
    gose.EcPublic(key: public_key, curve: c) -> #(c, public_key, option.None)
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

fn encode_eddsa(mat: gose.EddsaKeyMaterial) -> List(#(cbor.Value, cbor.Value)) {
  let #(curve, public_bytes, private_d) = case mat {
    gose.EddsaPrivate(key: priv, public: public_key, curve: c) -> #(
      c,
      eddsa.public_key_to_bytes(public_key),
      option.Some(eddsa.to_bytes(priv)),
    )
    gose.EddsaPublic(key: public_key, curve: c) -> #(
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

fn encode_xdh(mat: gose.XdhKeyMaterial) -> List(#(cbor.Value, cbor.Value)) {
  let #(curve, public_bytes, private_d) = case mat {
    gose.XdhPrivate(key: priv, public: public_key, curve: c) -> #(
      c,
      xdh.public_key_to_bytes(public_key),
      option.Some(xdh.to_bytes(priv)),
    )
    gose.XdhPublic(key: public_key, curve: c) -> #(
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

fn encode_rsa(mat: gose.RsaKeyMaterial) -> List(#(cbor.Value, cbor.Value)) {
  case mat {
    gose.RsaPrivate(key: priv, public: public_key) -> {
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
    gose.RsaPublic(key: public_key) -> {
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
  let kid_pair = case gose.kid(k) {
    Ok(kid) -> [#(cbor.Int(2), cbor.Bytes(kid))]
    Error(_) -> []
  }
  use alg_pair <- result.try(resolve_alg_metadata(k))
  let ops_pair = case gose.key_ops(k) {
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
  k: gose.Key(kid),
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  case gose.alg(k) {
    Ok(alg) -> encode_alg_metadata(alg)
    Error(_) -> Ok([])
  }
}

fn encode_alg_metadata(
  alg: gose.Alg,
) -> Result(List(#(cbor.Value, cbor.Value)), gose.GoseError) {
  case alg {
    gose.SigningAlg(signing_alg) ->
      Ok([
        #(cbor.Int(3), cbor.Int(signing_alg_to_int(signing_alg))),
      ])
    gose.KeyEncryptionAlg(ke_alg) -> {
      use id <- result.map(key_encryption_alg_to_int(ke_alg))
      [#(cbor.Int(3), cbor.Int(id))]
    }
    gose.ContentAlg(content_alg) -> {
      use id <- result.map(content_alg_to_int(content_alg))
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
      Ok(
        gose.new_key(
          gose.Elliptic(gose.EcPrivate(key: private, public:, curve:)),
        ),
      )
    }
    False -> gose.ec_public_key_from_coordinates(curve, x:, y:)
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
        gose.new_key(
          gose.Edwards(gose.EddsaPrivate(key: private, public:, curve:)),
        ),
      )
    }
    False -> {
      use x <- result.try(lookup_bytes(map, -2, "missing EdDSA x (label -2)"))
      gose.from_eddsa_public_bits(curve, x)
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
      Ok(gose.new_key(gose.Xdh(gose.XdhPrivate(key: private, public:, curve:))))
    }
    False -> {
      use x <- result.try(lookup_bytes(map, -2, "missing XDH x (label -2)"))
      gose.from_xdh_public_bits(curve, x)
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
        gose.new_key(gose.Rsa(gose.RsaPublic(key: public_key)))
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
        gose.new_key(gose.Rsa(gose.RsaPrivate(key: private, public:)))
      })
    }
    False ->
      rsa.from_components(n, e, d)
      |> result.replace_error(gose.ParseError(
        "invalid RSA private key components",
      ))
      |> result.map(fn(pair) {
        let #(private, public) = pair
        gose.new_key(gose.Rsa(gose.RsaPrivate(key: private, public:)))
      })
  }
}

fn decode_symmetric(
  map: List(#(cbor.Value, cbor.Value)),
) -> Result(Key, gose.GoseError) {
  use k <- result.try(lookup_bytes(map, -1, "missing symmetric key (label -1)"))
  gose.from_octet_bits(k)
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
    option.Some(kid_bytes) -> Ok(gose.with_kid_bits(k, kid_bytes))
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
      gose.with_alg(k, alg)
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
      gose.with_key_ops(k, ops)
    }
    option.None -> Ok(k)
  }
}

fn decode_alg(id: Int) -> Result(gose.Alg, gose.GoseError) {
  case signing_alg_from_int(id) {
    Ok(alg) -> Ok(gose.SigningAlg(alg))
    Error(_) ->
      case key_encryption_alg_from_int(id) {
        Ok(alg) -> Ok(gose.KeyEncryptionAlg(alg))
        Error(_) ->
          content_alg_from_int(id)
          |> result.map(gose.ContentAlg)
          |> result.replace_error(gose.ParseError(
            "unknown COSE algorithm: " <> int.to_string(id),
          ))
      }
  }
}

fn decode_key_ops(
  ops: List(cbor.Value),
) -> Result(List(gose.KeyOp), gose.GoseError) {
  list.try_map(ops, fn(v) {
    case v {
      cbor.Int(id) -> key_op_from_cose(id)
      _ -> Error(gose.ParseError("key_ops must contain integers"))
    }
  })
}

fn eddsa_curve_to_cose(curve: eddsa.Curve) -> Int {
  case curve {
    eddsa.Ed25519 -> 6
    eddsa.Ed448 -> 7
  }
}

fn key_op_to_cose(op: gose.KeyOp) -> Int {
  case op {
    gose.Sign -> 1
    gose.Verify -> 2
    gose.Encrypt -> 3
    gose.Decrypt -> 4
    gose.WrapKey -> 5
    gose.UnwrapKey -> 6
    gose.DeriveKey -> 7
    gose.DeriveBits -> 8
  }
}

fn key_op_from_cose(id: Int) -> Result(gose.KeyOp, gose.GoseError) {
  case id {
    1 -> Ok(gose.Sign)
    2 -> Ok(gose.Verify)
    3 -> Ok(gose.Encrypt)
    4 -> Ok(gose.Decrypt)
    5 -> Ok(gose.WrapKey)
    6 -> Ok(gose.UnwrapKey)
    7 -> Ok(gose.DeriveKey)
    8 -> Ok(gose.DeriveBits)
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

/// Convert a signature algorithm to its COSE integer identifier.
pub fn signature_alg_to_int(alg: gose.DigitalSignatureAlg) -> Int {
  case alg {
    gose.Ecdsa(gose.EcdsaP256) -> -7
    gose.Ecdsa(gose.EcdsaP384) -> -35
    gose.Ecdsa(gose.EcdsaP521) -> -36
    gose.Ecdsa(gose.EcdsaSecp256k1) -> -47
    gose.Eddsa -> -8
    gose.RsaPkcs1(gose.RsaPkcs1Sha256) -> -257
    gose.RsaPkcs1(gose.RsaPkcs1Sha384) -> -258
    gose.RsaPkcs1(gose.RsaPkcs1Sha512) -> -259
    gose.RsaPss(gose.RsaPssSha256) -> -37
    gose.RsaPss(gose.RsaPssSha384) -> -38
    gose.RsaPss(gose.RsaPssSha512) -> -39
  }
}

/// Parse a signature algorithm from its COSE integer identifier.
pub fn signature_alg_from_int(
  id: Int,
) -> Result(gose.DigitalSignatureAlg, gose.GoseError) {
  case id {
    -257 -> Ok(gose.RsaPkcs1(gose.RsaPkcs1Sha256))
    -258 -> Ok(gose.RsaPkcs1(gose.RsaPkcs1Sha384))
    -259 -> Ok(gose.RsaPkcs1(gose.RsaPkcs1Sha512))
    -35 -> Ok(gose.Ecdsa(gose.EcdsaP384))
    -36 -> Ok(gose.Ecdsa(gose.EcdsaP521))
    -37 -> Ok(gose.RsaPss(gose.RsaPssSha256))
    -38 -> Ok(gose.RsaPss(gose.RsaPssSha384))
    -39 -> Ok(gose.RsaPss(gose.RsaPssSha512))
    -47 -> Ok(gose.Ecdsa(gose.EcdsaSecp256k1))
    -7 -> Ok(gose.Ecdsa(gose.EcdsaP256))
    -8 -> Ok(gose.Eddsa)
    _ ->
      Error(gose.ParseError(
        "unknown COSE signature algorithm: " <> int.to_string(id),
      ))
  }
}

/// Convert a MAC algorithm to its COSE integer identifier.
pub fn mac_alg_to_int(alg: gose.MacAlg) -> Int {
  case alg {
    gose.Hmac(gose.HmacSha256) -> 5
    gose.Hmac(gose.HmacSha384) -> 6
    gose.Hmac(gose.HmacSha512) -> 7
  }
}

/// Parse a MAC algorithm from its COSE integer identifier.
pub fn mac_alg_from_int(id: Int) -> Result(gose.MacAlg, gose.GoseError) {
  case id {
    5 -> Ok(gose.Hmac(gose.HmacSha256))
    6 -> Ok(gose.Hmac(gose.HmacSha384))
    7 -> Ok(gose.Hmac(gose.HmacSha512))
    _ ->
      Error(gose.ParseError("unknown COSE MAC algorithm: " <> int.to_string(id)))
  }
}

/// Convert a signing algorithm to its COSE integer identifier.
pub fn signing_alg_to_int(alg: gose.SigningAlg) -> Int {
  case alg {
    gose.DigitalSignature(sig_alg) -> signature_alg_to_int(sig_alg)
    gose.Mac(mac_alg) -> mac_alg_to_int(mac_alg)
  }
}

/// Parse a signing algorithm from its COSE integer identifier.
pub fn signing_alg_from_int(id: Int) -> Result(gose.SigningAlg, gose.GoseError) {
  case signature_alg_from_int(id) {
    Ok(alg) -> Ok(gose.DigitalSignature(alg))
    Error(_) ->
      case mac_alg_from_int(id) {
        Ok(alg) -> Ok(gose.Mac(alg))
        Error(_) ->
          Error(gose.ParseError(
            "unknown COSE signing algorithm: " <> int.to_string(id),
          ))
      }
  }
}

/// Convert a key encryption algorithm to its COSE integer identifier.
///
/// Some key encryption algorithms are JOSE-only and have no COSE
/// identifier, in which case this returns an error.
pub fn key_encryption_alg_to_int(
  alg: gose.KeyEncryptionAlg,
) -> Result(Int, gose.GoseError) {
  case alg {
    gose.Direct -> Ok(-6)
    gose.AesKeyWrap(gose.AesKw, gose.Aes128) -> Ok(-3)
    gose.AesKeyWrap(gose.AesKw, gose.Aes192) -> Ok(-4)
    gose.AesKeyWrap(gose.AesKw, gose.Aes256) -> Ok(-5)
    gose.EcdhEs(gose.EcdhEsDirect) -> Ok(-25)
    gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128)) -> Ok(-29)
    gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes192)) -> Ok(-30)
    gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes256)) -> Ok(-31)
    gose.RsaEncryption(gose.RsaOaepSha1) -> Ok(-40)
    gose.RsaEncryption(gose.RsaOaepSha256) -> Ok(-41)
    gose.AesKeyWrap(gose.AesGcmKw, _)
    | gose.ChaCha20KeyWrap(_)
    | gose.RsaEncryption(gose.RsaPkcs1v15)
    | gose.EcdhEs(gose.EcdhEsChaCha20Kw(_))
    | gose.Pbes2(_) ->
      Error(gose.InvalidState(
        "no COSE identifier for algorithm: " <> string.inspect(alg),
      ))
  }
}

/// Parse a key encryption algorithm from its COSE integer identifier.
///
/// Both ECDH-ES+HKDF-256 (-25) and ECDH-ES+HKDF-512 (-26) map to
/// `EcdhEs(EcdhEsDirect)` because the shared algorithm type does not
/// distinguish the HKDF variant. The HKDF variant is preserved at the
/// `cose/encrypt` layer via `EcdhEsDirectVariant`. Use
/// `new_ecdh_es_direct_recipient` and `ecdh_es_direct_decryptor` for
/// HKDF-512 support.
pub fn key_encryption_alg_from_int(
  id: Int,
) -> Result(gose.KeyEncryptionAlg, gose.GoseError) {
  case id {
    -25 | -26 -> Ok(gose.EcdhEs(gose.EcdhEsDirect))
    -29 -> Ok(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128)))
    -3 -> Ok(gose.AesKeyWrap(gose.AesKw, gose.Aes128))
    -30 -> Ok(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes192)))
    -31 -> Ok(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes256)))
    -4 -> Ok(gose.AesKeyWrap(gose.AesKw, gose.Aes192))
    -5 -> Ok(gose.AesKeyWrap(gose.AesKw, gose.Aes256))
    -6 -> Ok(gose.Direct)
    -40 -> Ok(gose.RsaEncryption(gose.RsaOaepSha1))
    -41 -> Ok(gose.RsaEncryption(gose.RsaOaepSha256))
    _ ->
      Error(gose.ParseError(
        "unknown COSE key encryption algorithm: " <> int.to_string(id),
      ))
  }
}

/// Convert a content encryption algorithm to its COSE integer identifier.
///
/// Some content encryption algorithms are JOSE-only and have no COSE
/// identifier, in which case this returns an error.
pub fn content_alg_to_int(alg: gose.ContentAlg) -> Result(Int, gose.GoseError) {
  case alg {
    gose.AesGcm(gose.Aes128) -> Ok(1)
    gose.AesGcm(gose.Aes192) -> Ok(2)
    gose.AesGcm(gose.Aes256) -> Ok(3)
    gose.ChaCha20Poly1305 -> Ok(24)
    gose.AesCbcHmac(_) | gose.XChaCha20Poly1305 ->
      Error(gose.InvalidState(
        "no COSE identifier for algorithm: " <> string.inspect(alg),
      ))
  }
}

/// Parse a content encryption algorithm from its COSE integer identifier.
pub fn content_alg_from_int(id: Int) -> Result(gose.ContentAlg, gose.GoseError) {
  case id {
    1 -> Ok(gose.AesGcm(gose.Aes128))
    2 -> Ok(gose.AesGcm(gose.Aes192))
    3 -> Ok(gose.AesGcm(gose.Aes256))
    24 -> Ok(gose.ChaCha20Poly1305)
    _ ->
      Error(gose.ParseError(
        "unknown COSE content encryption algorithm: " <> int.to_string(id),
      ))
  }
}
