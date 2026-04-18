//// Typed accessors and builders for COSE message header parameters.
////
//// ## Phantom-state vocabulary
////
//// Each COSE message module uses a phantom state type named after the
//// RFC 9052 operation it performs: `Sign1` uses `Unsigned`/`Signed`,
//// `Encrypt0` and `Encrypt` use `Unencrypted`/`Encrypted`, `Mac0` uses
//// `Untagged`/`Tagged`, and `Sign` uses `Building`/`Signed` for its builder
//// body. The names match the RFC terminology rather than a single uniform
//// vocabulary.

import gleam/list
import gleam/result
import gose
import gose/cbor

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
