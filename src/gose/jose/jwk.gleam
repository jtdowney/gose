//// JSON Web Key (JWK) - [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html)
////
//// JSON serialization and deserialization for keys. Key creation,
//// manipulation, and metadata are in `gose`.
////
//// ## Example
////
//// ```gleam
//// import gleam/json
//// import gose
//// import gose/jose/jwk
//// import kryptos/ec
////
//// // Generate an EC key and attach metadata
//// let k =
////   gose.generate_ec(ec.P256)
////   |> gose.with_kid("my-signing-key")
////
//// // Serialize to JSON
//// let json_string = jwk.to_json(k)
////   |> json.to_string()
////
//// // Parse from a JSON string
//// let assert Ok(parsed) = jwk.from_json(json_string)
//// let assert Ok("my-signing-key") = gose.kid(parsed)
//// ```
////
//// ## Duplicate Member Names
////
//// Per RFC 7517 Section 4, JWK member names must be unique. This implementation
//// relies on `gleam_json` for parsing, which uses the first value when
//// duplicate member names are present. Subsequent duplicates are ignored.
////
//// ## Unsupported Parameters
////
//// X.509 certificate chain parameters (RFC 7517 Section 4.6-4.9) are not supported:
//// - `x5u` - X.509 URL
//// - `x5c` - X.509 Certificate Chain
//// - `x5t` - X.509 Certificate SHA-1 Thumbprint
//// - `x5t#S256` - X.509 Certificate SHA-256 Thumbprint
////
//// JWKs containing any of these parameters are rejected with a `ParseError` during
//// parsing. These parameters are not emitted during serialization.

import gleam/bit_array
import gleam/bool
import gleam/dict
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gose
import gose/internal/utils
import gose/jose
import kryptos/crypto
import kryptos/ec
import kryptos/eddsa
import kryptos/hash
import kryptos/rsa
import kryptos/xdh

/// A key with a JWK-compatible string kid.
pub type Key =
  gose.Key(String)

/// Serialize a key to its JSON representation.
pub fn to_json(k: Key) -> json.Json {
  let mat = gose.material(k)
  let base_fields = case mat {
    gose.Edwards(gose.EddsaPrivate(key: private, public:, curve:)) -> {
      let x_bits = eddsa.public_key_to_bytes(public)
      let d_bits = eddsa.to_bytes(private)
      [
        #("kty", json.string("OKP")),
        #("crv", json.string(utils.eddsa_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x_bits))),
        #("d", json.string(utils.encode_base64_url(d_bits))),
      ]
    }
    gose.Edwards(gose.EddsaPublic(key: public, curve:)) -> {
      let x_bits = eddsa.public_key_to_bytes(public)
      [
        #("kty", json.string("OKP")),
        #("crv", json.string(utils.eddsa_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x_bits))),
      ]
    }
    gose.OctetKey(secret:) -> [
      #("kty", json.string("oct")),
      #("k", json.string(utils.encode_base64_url(secret))),
    ]
    gose.Rsa(gose.RsaPrivate(key: private, ..)) -> [
      #("kty", json.string("RSA")),
      #(
        "n",
        rsa.modulus(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "e",
        rsa.public_exponent_bytes(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "d",
        rsa.private_exponent_bytes(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "p",
        rsa.prime1(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "q",
        rsa.prime2(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "dp",
        rsa.exponent1(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "dq",
        rsa.exponent2(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "qi",
        rsa.coefficient(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
    ]
    gose.Rsa(gose.RsaPublic(key: public)) -> [
      #("kty", json.string("RSA")),
      #(
        "n",
        rsa.public_key_modulus(public)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "e",
        rsa.public_key_exponent_bytes(public)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
    ]
    gose.Elliptic(gose.EcPrivate(key: private, public:, curve:)) -> {
      // Safe: all constructors validate the public key against the curve
      let assert Ok(#(x, y)) = gose.ec_raw_coordinates(public, curve:)
      let d_bits = ec.to_bytes(private)
      [
        #("kty", json.string("EC")),
        #("crv", json.string(utils.ec_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x))),
        #("y", json.string(utils.encode_base64_url(y))),
        #("d", json.string(utils.encode_base64_url(d_bits))),
      ]
    }
    gose.Elliptic(gose.EcPublic(key: public, curve:)) -> {
      // Safe: all constructors validate the public key against the curve
      let assert Ok(#(x, y)) = gose.ec_raw_coordinates(public, curve:)
      [
        #("kty", json.string("EC")),
        #("crv", json.string(utils.ec_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x))),
        #("y", json.string(utils.encode_base64_url(y))),
      ]
    }
    gose.Xdh(gose.XdhPrivate(key: private, public:, curve:)) -> {
      let x_bits = xdh.public_key_to_bytes(public)
      let d_bits = xdh.to_bytes(private)
      [
        #("kty", json.string("OKP")),
        #("crv", json.string(utils.xdh_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x_bits))),
        #("d", json.string(utils.encode_base64_url(d_bits))),
      ]
    }
    gose.Xdh(gose.XdhPublic(key: public, curve:)) -> {
      let x_bits = xdh.public_key_to_bytes(public)
      [
        #("kty", json.string("OKP")),
        #("crv", json.string(utils.xdh_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x_bits))),
      ]
    }
  }

  json.object(list.append(base_fields, metadata_fields(k)))
}

fn alg_fields(alg: Option(gose.Alg)) -> List(#(String, json.Json)) {
  case alg {
    option.Some(a) -> [#("alg", json.string(alg_to_string(a)))]
    option.None -> []
  }
}

fn key_op_to_string(op: gose.KeyOp) -> String {
  case op {
    gose.Sign -> "sign"
    gose.Verify -> "verify"
    gose.Encrypt -> "encrypt"
    gose.Decrypt -> "decrypt"
    gose.WrapKey -> "wrapKey"
    gose.UnwrapKey -> "unwrapKey"
    gose.DeriveKey -> "deriveKey"
    gose.DeriveBits -> "deriveBits"
  }
}

fn key_ops_fields(
  key_ops: Option(List(gose.KeyOp)),
) -> List(#(String, json.Json)) {
  case key_ops {
    option.Some(ops) -> [
      #(
        "key_ops",
        json.array(ops, fn(op) { json.string(key_op_to_string(op)) }),
      ),
    ]
    option.None -> []
  }
}

fn key_use_fields(key_use: Option(gose.KeyUse)) -> List(#(String, json.Json)) {
  case key_use {
    option.Some(u) -> [#("use", json.string(key_use_to_string(u)))]
    option.None -> []
  }
}

fn key_use_to_string(key_use: gose.KeyUse) -> String {
  case key_use {
    gose.Signing -> "sig"
    gose.Encrypting -> "enc"
  }
}

fn kid_fields(kid: Option(String)) -> List(#(String, json.Json)) {
  case kid {
    option.Some(k) -> [#("kid", json.string(k))]
    option.None -> []
  }
}

fn metadata_fields(k: Key) -> List(#(String, json.Json)) {
  list.flatten([
    kid_fields(option.from_result(gose.kid(k))),
    key_use_fields(option.from_result(gose.key_use(k))),
    key_ops_fields(option.from_result(gose.key_ops(k))),
    alg_fields(option.from_result(gose.alg(k))),
  ])
}

fn reject_x509_params(dyn: decode.Dynamic) -> Result(Nil, gose.GoseError) {
  let x509_fields = ["x5u", "x5c", "x5t", "x5t#S256"]
  let dict_decoder = decode.dict(decode.string, decode.dynamic)
  let fields_dict =
    decode.run(dyn, dict_decoder)
    |> result.unwrap(dict.new())
  list.try_each(x509_fields, fn(field) {
    case dict.has_key(fields_dict, field) {
      True ->
        Error(gose.ParseError("unsupported X.509 JWK parameter: " <> field))
      False -> Ok(Nil)
    }
  })
}

/// Parse a JWK from a Dynamic value (decoded JSON).
@internal
pub fn from_dynamic(dyn: decode.Dynamic) -> Result(Key, gose.GoseError) {
  use _ <- result.try(reject_x509_params(dyn))
  let kty_decoder = decode.at(["kty"], decode.string)
  use kty <- result.try(
    decode.run(dyn, kty_decoder)
    |> result.replace_error(gose.ParseError("missing or invalid kty")),
  )
  case kty {
    "OKP" -> parse_okp_dynamic(dyn)
    "oct" -> parse_oct_dynamic(dyn)
    "RSA" -> parse_rsa_dynamic(dyn)
    "EC" -> parse_ec_dynamic(dyn)
    _ -> Error(gose.ParseError("unsupported kty: " <> kty))
  }
}

/// Parse a JWK from JSON.
pub fn from_json(json_str: String) -> Result(Key, gose.GoseError) {
  use dyn <- result.try(
    json.parse(json_str, decode.dynamic)
    |> result.replace_error(gose.ParseError("invalid JSON")),
  )
  from_dynamic(dyn)
}

/// Parse a JWK from JSON provided as a `BitArray`.
pub fn from_json_bits(json_bits: BitArray) -> Result(Key, gose.GoseError) {
  use dyn <- result.try(
    json.parse_bits(json_bits, decode.dynamic)
    |> result.replace_error(gose.ParseError("invalid JSON")),
  )
  from_dynamic(dyn)
}

/// Return a decoder for JWK values.
///
/// This lets you compose JWK decoding inside larger decode pipelines, for
/// example with `decode.field`, `decode.list`, or `json.parse`.
///
/// ## Example
///
/// ```gleam
/// // Parse a key directly from a JSON string
/// let assert Ok(k) = json.parse(json_string, jwk.decoder())
///
/// // Use inside a larger decoder
/// use k <- decode.field("signing_key", jwk.decoder())
/// ```
pub fn decoder() -> decode.Decoder(Key) {
  let placeholder =
    gose.build(
      material: gose.OctetKey(secret: <<>>),
      kid: option.None,
      key_use: option.None,
      key_ops: option.None,
      alg: option.None,
    )
  decode.new_primitive_decoder("Key", fn(dyn) {
    from_dynamic(dyn)
    |> result.replace_error(placeholder)
  })
}

fn key_op_from_string(s: String) -> Result(gose.KeyOp, gose.GoseError) {
  case s {
    "sign" -> Ok(gose.Sign)
    "verify" -> Ok(gose.Verify)
    "encrypt" -> Ok(gose.Encrypt)
    "decrypt" -> Ok(gose.Decrypt)
    "wrapKey" -> Ok(gose.WrapKey)
    "unwrapKey" -> Ok(gose.UnwrapKey)
    "deriveKey" -> Ok(gose.DeriveKey)
    "deriveBits" -> Ok(gose.DeriveBits)
    _ -> Error(gose.ParseError("invalid key_ops value: " <> s))
  }
}

fn key_use_from_string(s: String) -> Result(gose.KeyUse, gose.GoseError) {
  case s {
    "sig" -> Ok(gose.Signing)
    "enc" -> Ok(gose.Encrypting)
    _ -> Error(gose.ParseError("invalid use value: " <> s))
  }
}

fn parse_key_metadata(
  use_opt: Option(String),
  key_ops_opt: Option(List(String)),
  alg_opt: Option(String),
) -> Result(
  #(Option(gose.KeyUse), Option(List(gose.KeyOp)), Option(gose.Alg)),
  gose.GoseError,
) {
  use key_use <- result.try(parse_optional(use_opt, key_use_from_string))
  use key_ops <- result.try(parse_optional(key_ops_opt, parse_key_ops))
  use alg <- result.try(parse_optional(alg_opt, alg_from_string))
  use _ <- result.try(gose.validate_key_use_ops(key_use, key_ops))
  Ok(#(key_use, key_ops, alg))
}

fn parse_key_ops(
  ops: List(String),
) -> Result(List(gose.KeyOp), gose.GoseError) {
  use <- bool.guard(
    when: list.is_empty(ops),
    return: Error(gose.ParseError("key_ops must not be empty")),
  )
  use parsed <- result.try(list.try_map(ops, key_op_from_string))
  case list.unique(parsed) != parsed {
    True -> Error(gose.ParseError("key_ops must not contain duplicates"))
    False -> Ok(parsed)
  }
}

fn parse_optional(
  opt: Option(a),
  parser: fn(a) -> Result(b, gose.GoseError),
) -> Result(Option(b), gose.GoseError) {
  case opt {
    option.None -> Ok(option.None)
    option.Some(value) -> result.map(parser(value), option.Some)
  }
}

type EcDecoded {
  EcDecoded(
    crv: String,
    x: String,
    y: String,
    d: Option(String),
    kid: Option(String),
    use_: Option(String),
    key_ops: Option(List(String)),
    alg: Option(String),
  )
}

fn ec_decoder() -> decode.Decoder(EcDecoded) {
  use crv <- decode.field("crv", decode.string)
  use x <- decode.field("x", decode.string)
  use y <- decode.field("y", decode.string)
  use d <- decode.optional_field(
    "d",
    option.None,
    decode.optional(decode.string),
  )
  use kid <- decode.optional_field(
    "kid",
    option.None,
    decode.optional(decode.string),
  )
  use use_ <- decode.optional_field(
    "use",
    option.None,
    decode.optional(decode.string),
  )
  use key_ops <- decode.optional_field(
    "key_ops",
    option.None,
    decode.optional(decode.list(decode.string)),
  )
  use alg <- decode.optional_field(
    "alg",
    option.None,
    decode.optional(decode.string),
  )
  decode.success(EcDecoded(crv:, x:, y:, d:, kid:, use_:, key_ops:, alg:))
}

fn parse_ec_dynamic(dyn: decode.Dynamic) -> Result(Key, gose.GoseError) {
  case decode.run(dyn, ec_decoder()) {
    Ok(decoded) -> process_ec_decoded(decoded)
    Error(_) -> Error(gose.ParseError("invalid EC JSON"))
  }
}

fn process_ec_decoded(decoded: EcDecoded) -> Result(Key, gose.GoseError) {
  let EcDecoded(crv, x_b64, y_b64, d_opt, kid, use_opt, key_ops_opt, alg_opt) =
    decoded
  use curve <- result.try(utils.ec_curve_from_string(crv))
  use x_bits <- result.try(utils.decode_base64_url(x_b64, name: "x"))
  use y_bits <- result.try(utils.decode_base64_url(y_b64, name: "y"))
  use #(key_use, key_ops, alg) <- result.try(parse_key_metadata(
    use_opt,
    key_ops_opt,
    alg_opt,
  ))

  let coord_size = ec.coordinate_size(curve)
  use <- bool.guard(
    when: bit_array.byte_size(x_bits) != coord_size,
    return: Error(gose.ParseError(
      "EC x coordinate must be " <> int.to_string(coord_size) <> " bytes",
    )),
  )
  use <- bool.guard(
    when: bit_array.byte_size(y_bits) != coord_size,
    return: Error(gose.ParseError(
      "EC y coordinate must be " <> int.to_string(coord_size) <> " bytes",
    )),
  )
  let raw_point = bit_array.concat([<<0x04>>, x_bits, y_bits])

  case d_opt {
    option.Some(d_b64) -> {
      use d_bits <- result.try(utils.decode_base64_url(d_b64, name: "d"))
      use #(private, public) <- result.try(
        ec.from_bytes(curve, d_bits)
        |> result.replace_error(gose.ParseError("invalid EC private key bytes")),
      )

      let computed_point = ec.public_key_to_raw_point(public)
      use <- bool.guard(
        when: !crypto.constant_time_equal(computed_point, raw_point),
        return: Error(gose.ParseError("x/y do not match computed public key")),
      )
      Ok(gose.build(
        material: gose.Elliptic(gose.EcPrivate(key: private, public:, curve:)),
        kid:,
        key_use:,
        key_ops:,
        alg:,
      ))
    }
    option.None -> {
      use public <- result.try(
        ec.public_key_from_raw_point(curve, raw_point)
        |> result.replace_error(gose.ParseError(
          "invalid EC public key coordinates",
        )),
      )
      Ok(gose.build(
        material: gose.Elliptic(gose.EcPublic(key: public, curve:)),
        kid:,
        key_use:,
        key_ops:,
        alg:,
      ))
    }
  }
}

type OctDecoded {
  OctDecoded(
    k: String,
    kid: Option(String),
    use_: Option(String),
    key_ops: Option(List(String)),
    alg: Option(String),
  )
}

fn oct_decoder() -> decode.Decoder(OctDecoded) {
  use k <- decode.field("k", decode.string)
  use kid <- decode.optional_field(
    "kid",
    option.None,
    decode.optional(decode.string),
  )
  use use_ <- decode.optional_field(
    "use",
    option.None,
    decode.optional(decode.string),
  )
  use key_ops <- decode.optional_field(
    "key_ops",
    option.None,
    decode.optional(decode.list(decode.string)),
  )
  use alg <- decode.optional_field(
    "alg",
    option.None,
    decode.optional(decode.string),
  )
  decode.success(OctDecoded(k:, kid:, use_:, key_ops:, alg:))
}

fn parse_oct_dynamic(dyn: decode.Dynamic) -> Result(Key, gose.GoseError) {
  case decode.run(dyn, oct_decoder()) {
    Ok(decoded) -> process_oct_decoded(decoded)
    Error(_) -> Error(gose.ParseError("invalid oct JSON"))
  }
}

fn process_oct_decoded(decoded: OctDecoded) -> Result(Key, gose.GoseError) {
  let OctDecoded(k_b64, kid, use_opt, key_ops_opt, alg_opt) = decoded
  use secret <- result.try(utils.decode_base64_url(k_b64, name: "k"))
  use #(key_use, key_ops, alg) <- result.try(parse_key_metadata(
    use_opt,
    key_ops_opt,
    alg_opt,
  ))

  case bit_array.byte_size(secret) == 0 {
    True -> Error(gose.ParseError("oct key must not be empty"))
    False ->
      Ok(gose.build(
        material: gose.OctetKey(secret:),
        kid:,
        key_use:,
        key_ops:,
        alg:,
      ))
  }
}

type OkpDecoded {
  OkpDecoded(
    crv: String,
    x: String,
    d: Option(String),
    kid: Option(String),
    use_: Option(String),
    key_ops: Option(List(String)),
    alg: Option(String),
  )
}

fn okp_decoder() -> decode.Decoder(OkpDecoded) {
  use crv <- decode.field("crv", decode.string)
  use x <- decode.field("x", decode.string)
  use d <- decode.optional_field(
    "d",
    option.None,
    decode.optional(decode.string),
  )
  use kid <- decode.optional_field(
    "kid",
    option.None,
    decode.optional(decode.string),
  )
  use use_ <- decode.optional_field(
    "use",
    option.None,
    decode.optional(decode.string),
  )
  use key_ops <- decode.optional_field(
    "key_ops",
    option.None,
    decode.optional(decode.list(decode.string)),
  )
  use alg <- decode.optional_field(
    "alg",
    option.None,
    decode.optional(decode.string),
  )
  decode.success(OkpDecoded(crv:, x:, d:, kid:, use_:, key_ops:, alg:))
}

fn parse_okp_dynamic(dyn: decode.Dynamic) -> Result(Key, gose.GoseError) {
  case decode.run(dyn, okp_decoder()) {
    Ok(decoded) -> process_okp_decoded(decoded)
    Error(_) -> Error(gose.ParseError("invalid OKP JSON"))
  }
}

fn process_okp_decoded(decoded: OkpDecoded) -> Result(Key, gose.GoseError) {
  let OkpDecoded(crv, x_b64, d_opt, kid, use_opt, key_ops_opt, alg_opt) =
    decoded

  use x_bits <- result.try(utils.decode_base64_url(x_b64, name: "x"))
  use #(key_use, key_ops, alg) <- result.try(parse_key_metadata(
    use_opt,
    key_ops_opt,
    alg_opt,
  ))

  case utils.eddsa_curve_from_string(crv) {
    Ok(eddsa_curve) ->
      parse_eddsa_okp_json(
        eddsa_curve,
        x_bits,
        d_opt,
        kid,
        key_use,
        key_ops,
        alg,
      )
    Error(_) ->
      case utils.xdh_curve_from_string(crv) {
        Ok(xdh_curve) ->
          parse_xdh_okp_json(
            xdh_curve,
            x_bits,
            d_opt,
            kid,
            key_use,
            key_ops,
            alg,
          )
        Error(_) -> Error(gose.ParseError("unsupported OKP curve: " <> crv))
      }
  }
}

fn build_eddsa_material(
  curve: eddsa.Curve,
  x_bits: BitArray,
  d_opt: Option(String),
) -> Result(gose.KeyMaterial, gose.GoseError) {
  case d_opt {
    option.Some(d_b64) -> {
      use d_bits <- result.try(utils.decode_base64_url(d_b64, name: "d"))
      use #(private, public) <- result.try(
        eddsa.from_bytes(curve, d_bits)
        |> result.replace_error(gose.ParseError("invalid private key bytes")),
      )
      let computed_x = eddsa.public_key_to_bytes(public)
      use <- bool.guard(
        when: !crypto.constant_time_equal(computed_x, x_bits),
        return: Error(gose.ParseError("x does not match computed public key")),
      )
      Ok(gose.Edwards(gose.EddsaPrivate(key: private, public:, curve:)))
    }
    option.None -> {
      use public <- result.try(
        eddsa.public_key_from_bytes(curve, x_bits)
        |> result.replace_error(gose.ParseError("invalid public key bytes")),
      )
      Ok(gose.Edwards(gose.EddsaPublic(key: public, curve:)))
    }
  }
}

fn parse_eddsa_okp_json(
  curve: eddsa.Curve,
  x_bits: BitArray,
  d_opt: Option(String),
  kid: Option(String),
  key_use: Option(gose.KeyUse),
  key_ops: Option(List(gose.KeyOp)),
  alg: Option(gose.Alg),
) -> Result(Key, gose.GoseError) {
  use material <- result.try(build_eddsa_material(curve, x_bits, d_opt))
  use _ <- result.try(gose.validate_rfc8037_key_use_public(material, key_use))
  Ok(gose.build(material:, kid:, key_use:, key_ops:, alg:))
}

fn build_xdh_material(
  curve: xdh.Curve,
  x_bits: BitArray,
  d_opt: Option(String),
) -> Result(gose.KeyMaterial, gose.GoseError) {
  case d_opt {
    option.Some(d_b64) -> {
      use d_bits <- result.try(utils.decode_base64_url(d_b64, name: "d"))
      use #(private, public) <- result.try(
        xdh.from_bytes(curve, d_bits)
        |> result.replace_error(gose.ParseError("invalid private key bytes")),
      )
      let computed_x = xdh.public_key_to_bytes(public)
      use <- bool.guard(
        when: !crypto.constant_time_equal(computed_x, x_bits),
        return: Error(gose.ParseError("x does not match computed public key")),
      )
      Ok(gose.Xdh(gose.XdhPrivate(key: private, public:, curve:)))
    }
    option.None -> {
      use public <- result.try(
        xdh.public_key_from_bytes(curve, x_bits)
        |> result.replace_error(gose.ParseError("invalid public key bytes")),
      )
      Ok(gose.Xdh(gose.XdhPublic(key: public, curve:)))
    }
  }
}

fn parse_xdh_okp_json(
  curve: xdh.Curve,
  x_bits: BitArray,
  d_opt: Option(String),
  kid: Option(String),
  key_use: Option(gose.KeyUse),
  key_ops: Option(List(gose.KeyOp)),
  alg: Option(gose.Alg),
) -> Result(Key, gose.GoseError) {
  use material <- result.try(build_xdh_material(curve, x_bits, d_opt))
  use _ <- result.try(gose.validate_rfc8037_key_use_public(material, key_use))
  Ok(gose.build(material:, kid:, key_use:, key_ops:, alg:))
}

fn parse_rsa_private_key_components(
  n_bits: BitArray,
  e_bits: BitArray,
  d_bits: BitArray,
  p_opt: Option(String),
  q_opt: Option(String),
  dp_opt: Option(String),
  dq_opt: Option(String),
  qi_opt: Option(String),
) -> Result(#(rsa.PrivateKey, rsa.PublicKey), gose.GoseError) {
  let crt_fields = [p_opt, q_opt, dp_opt, dq_opt, qi_opt]
  let crt_present =
    crt_fields
    |> list.filter(option.is_some)
    |> list.length
  use <- bool.guard(
    when: crt_present > 0 && crt_present < 5,
    return: Error(gose.ParseError(
      "partial CRT fields: all five (p, q, dp, dq, qi) are required if any are present",
    )),
  )

  case p_opt, q_opt, dp_opt, dq_opt, qi_opt {
    option.Some(p_b64),
      option.Some(q_b64),
      option.Some(dp_b64),
      option.Some(dq_b64),
      option.Some(qi_b64)
    -> {
      use p_bits <- result.try(utils.decode_base64_url(p_b64, name: "p"))
      use q_bits <- result.try(utils.decode_base64_url(q_b64, name: "q"))
      use dp_bits <- result.try(utils.decode_base64_url(dp_b64, name: "dp"))
      use dq_bits <- result.try(utils.decode_base64_url(dq_b64, name: "dq"))
      use qi_bits <- result.try(utils.decode_base64_url(qi_b64, name: "qi"))
      rsa.from_full_components(
        n_bits,
        e_bits,
        d_bits,
        p_bits,
        q_bits,
        dp_bits,
        dq_bits,
        qi_bits,
      )
      |> result.replace_error(gose.ParseError(
        "invalid RSA private key components",
      ))
    }
    _, _, _, _, _ ->
      rsa.from_components(n_bits, e_bits, d_bits)
      |> result.replace_error(gose.ParseError(
        "invalid RSA private key components",
      ))
  }
}

type RsaDecoded {
  RsaDecoded(
    n: String,
    e: String,
    d: Option(String),
    p: Option(String),
    q: Option(String),
    dp: Option(String),
    dq: Option(String),
    qi: Option(String),
    kid: Option(String),
    use_: Option(String),
    key_ops: Option(List(String)),
    alg: Option(String),
    oth: Bool,
  )
}

fn rsa_decoder() -> decode.Decoder(RsaDecoded) {
  use n <- decode.field("n", decode.string)
  use e <- decode.field("e", decode.string)
  use d <- decode.optional_field(
    "d",
    option.None,
    decode.optional(decode.string),
  )
  use p <- decode.optional_field(
    "p",
    option.None,
    decode.optional(decode.string),
  )
  use q <- decode.optional_field(
    "q",
    option.None,
    decode.optional(decode.string),
  )
  use dp <- decode.optional_field(
    "dp",
    option.None,
    decode.optional(decode.string),
  )
  use dq <- decode.optional_field(
    "dq",
    option.None,
    decode.optional(decode.string),
  )
  use qi <- decode.optional_field(
    "qi",
    option.None,
    decode.optional(decode.string),
  )
  use kid <- decode.optional_field(
    "kid",
    option.None,
    decode.optional(decode.string),
  )
  use use_ <- decode.optional_field(
    "use",
    option.None,
    decode.optional(decode.string),
  )
  use key_ops <- decode.optional_field(
    "key_ops",
    option.None,
    decode.optional(decode.list(decode.string)),
  )
  use alg <- decode.optional_field(
    "alg",
    option.None,
    decode.optional(decode.string),
  )
  use oth <- decode.optional_field("oth", False, decode.success(True))
  decode.success(RsaDecoded(
    n:,
    e:,
    d:,
    p:,
    q:,
    dp:,
    dq:,
    qi:,
    kid:,
    use_:,
    key_ops:,
    alg:,
    oth:,
  ))
}

fn parse_rsa_dynamic(dyn: decode.Dynamic) -> Result(Key, gose.GoseError) {
  case decode.run(dyn, rsa_decoder()) {
    Ok(decoded) -> process_rsa_decoded(decoded)
    Error(_) -> Error(gose.ParseError("invalid RSA JSON"))
  }
}

fn process_rsa_decoded(decoded: RsaDecoded) -> Result(Key, gose.GoseError) {
  let RsaDecoded(
    n_b64,
    e_b64,
    d_opt,
    p_opt,
    q_opt,
    dp_opt,
    dq_opt,
    qi_opt,
    kid,
    use_opt,
    key_ops_opt,
    alg_opt,
    oth,
  ) = decoded
  use <- bool.guard(
    when: oth,
    return: Error(gose.ParseError(
      "multi-prime RSA keys (oth parameter) not supported",
    )),
  )
  use n_bits <- result.try(utils.decode_base64_url(n_b64, name: "n"))
  use e_bits <- result.try(utils.decode_base64_url(e_b64, name: "e"))
  use #(key_use, key_ops, alg) <- result.try(parse_key_metadata(
    use_opt,
    key_ops_opt,
    alg_opt,
  ))

  case d_opt {
    option.Some(d_b64) -> {
      use d_bits <- result.try(utils.decode_base64_url(d_b64, name: "d"))
      use #(private, public) <- result.try(parse_rsa_private_key_components(
        n_bits,
        e_bits,
        d_bits,
        p_opt,
        q_opt,
        dp_opt,
        dq_opt,
        qi_opt,
      ))
      Ok(gose.build(
        material: gose.Rsa(gose.RsaPrivate(key: private, public:)),
        kid:,
        key_use:,
        key_ops:,
        alg:,
      ))
    }
    option.None -> {
      use public <- result.try(
        rsa.public_key_from_components(n_bits, e_bits)
        |> result.replace_error(gose.ParseError(
          "invalid RSA public key components",
        )),
      )
      Ok(gose.build(
        material: gose.Rsa(gose.RsaPublic(key: public)),
        kid:,
        key_use:,
        key_ops:,
        alg:,
      ))
    }
  }
}

/// Convert an algorithm (signing, key encryption, or content encryption)
/// to its RFC string representation.
pub fn alg_to_string(alg: gose.Alg) -> String {
  case alg {
    gose.SigningAlg(signing_alg) -> jose.signing_alg_to_string(signing_alg)
    gose.KeyEncryptionAlg(ke_alg) -> jose.key_encryption_alg_to_string(ke_alg)
    gose.ContentAlg(content_alg) -> jose.content_alg_to_string(content_alg)
  }
}

/// Parse an algorithm from its RFC string representation.
pub fn alg_from_string(s: String) -> Result(gose.Alg, gose.GoseError) {
  jose.signing_alg_from_string(s)
  |> result.map(gose.SigningAlg)
  |> result.lazy_or(fn() {
    jose.key_encryption_alg_from_string(s)
    |> result.map(gose.KeyEncryptionAlg)
  })
  |> result.lazy_or(fn() {
    jose.content_alg_from_string(s)
    |> result.map(gose.ContentAlg)
  })
  |> result.replace_error(gose.ParseError("unknown algorithm: " <> s))
}

/// Compute the JWK Thumbprint ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)).
///
/// The thumbprint is a base64url-encoded hash of the canonical JSON
/// representation containing only the required public key members.
/// Private keys produce the same thumbprint as their corresponding public keys.
///
/// RFC 7638 recommends SHA-256 as the hash, but allows other algorithms.
///
/// ## Example
///
/// ```gleam
/// let k = gose.generate_ec(ec.P256)
/// let assert Ok(thumbprint) = jwk.thumbprint(k, hash.Sha256)
/// ```
pub fn thumbprint(
  key: gose.Key(kid),
  algorithm: hash.HashAlgorithm,
) -> Result(String, gose.GoseError) {
  use json_str <- result.try(thumbprint_json(key))
  bit_array.from_string(json_str)
  |> crypto.hash(algorithm, _)
  |> result.replace_error(gose.CryptoError("hash algorithm not supported"))
  |> result.map(utils.encode_base64_url)
}

fn thumbprint_json(k: gose.Key(kid)) -> Result(String, gose.GoseError) {
  case gose.material(k) {
    gose.Elliptic(gose.EcPrivate(public:, curve:, ..))
    | gose.Elliptic(gose.EcPublic(key: public, curve:)) -> {
      use #(x, y) <- result.try(gose.ec_raw_coordinates(public, curve:))
      let crv = utils.ec_curve_to_string(curve)
      let x_b64 = utils.encode_base64_url(x)
      let y_b64 = utils.encode_base64_url(y)
      Ok(
        "{\"crv\":\""
        <> crv
        <> "\",\"kty\":\"EC\",\"x\":\""
        <> x_b64
        <> "\",\"y\":\""
        <> y_b64
        <> "\"}",
      )
    }
    gose.Rsa(gose.RsaPrivate(public:, ..))
    | gose.Rsa(gose.RsaPublic(key: public)) -> {
      let e =
        rsa.public_key_exponent_bytes(public)
        |> utils.strip_leading_zeros
        |> utils.encode_base64_url()
      let n =
        rsa.public_key_modulus(public)
        |> utils.strip_leading_zeros
        |> utils.encode_base64_url()
      Ok("{\"e\":\"" <> e <> "\",\"kty\":\"RSA\",\"n\":\"" <> n <> "\"}")
    }
    gose.Edwards(gose.EddsaPrivate(public:, curve:, ..))
    | gose.Edwards(gose.EddsaPublic(key: public, curve:)) -> {
      let crv = utils.eddsa_curve_to_string(curve)
      let x = eddsa.public_key_to_bytes(public) |> utils.encode_base64_url()
      Ok("{\"crv\":\"" <> crv <> "\",\"kty\":\"OKP\",\"x\":\"" <> x <> "\"}")
    }
    gose.Xdh(gose.XdhPrivate(public:, curve:, ..))
    | gose.Xdh(gose.XdhPublic(key: public, curve:)) -> {
      let crv = utils.xdh_curve_to_string(curve)
      let x = xdh.public_key_to_bytes(public) |> utils.encode_base64_url()
      Ok("{\"crv\":\"" <> crv <> "\",\"kty\":\"OKP\",\"x\":\"" <> x <> "\"}")
    }
    gose.OctetKey(secret:) -> {
      let k = utils.encode_base64_url(secret)
      Ok("{\"k\":\"" <> k <> "\",\"kty\":\"oct\"}")
    }
  }
}
