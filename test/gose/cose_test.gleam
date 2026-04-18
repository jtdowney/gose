import gose
import gose/cbor
import gose/cose
import qcheck

pub fn algorithm_roundtrips_test() {
  use id <- qcheck.given(qcheck.bounded_int(-1000, 1_000_000))
  assert cose.algorithm([cose.Alg(id)]) == Ok(id)
}

pub fn algorithm_missing_returns_error_test() {
  assert cose.algorithm([])
    == Error(gose.ParseError("missing header label 1 (alg)"))
}

pub fn kid_roundtrips_test() {
  use bytes <- qcheck.given(qcheck.byte_aligned_bit_array())
  assert cose.kid([cose.Kid(bytes)]) == Ok(bytes)
}

pub fn kid_missing_returns_error_test() {
  assert cose.kid([]) == Error(gose.ParseError("missing header label 4 (kid)"))
}

pub fn iv_roundtrips_test() {
  use bytes <- qcheck.given(qcheck.byte_aligned_bit_array())
  assert cose.iv([cose.Iv(bytes)]) == Ok(bytes)
}

pub fn partial_iv_roundtrips_test() {
  use bytes <- qcheck.given(qcheck.byte_aligned_bit_array())
  assert cose.partial_iv([cose.PartialIv(bytes)]) == Ok(bytes)
}

pub fn content_type_well_known_roundtrips_test() {
  assert cose.content_type([cose.ContentType(cose.Json)]) == Ok(cose.Json)
  assert cose.content_type([cose.ContentType(cose.Cbor)]) == Ok(cose.Cbor)
  assert cose.content_type([cose.ContentType(cose.Cwt)]) == Ok(cose.Cwt)
  assert cose.content_type([cose.ContentType(cose.TextPlain)])
    == Ok(cose.TextPlain)
  assert cose.content_type([cose.ContentType(cose.CoseSign1)])
    == Ok(cose.CoseSign1)
}

pub fn content_type_text_roundtrips_test() {
  use ct <- qcheck.given(qcheck.string())
  assert cose.content_type([cose.ContentType(cose.TextContentType(ct))])
    == Ok(cose.TextContentType(ct))
}

pub fn critical_roundtrips_test() {
  use labels <- qcheck.given(qcheck.list_from(qcheck.bounded_int(-100, 100)))
  assert cose.critical([cose.Crit(labels)]) == Ok(labels)
}

pub fn header_cbor_roundtrip_alg_test() {
  let header = cose.Alg(-7)
  let assert Ok(roundtripped) =
    cose.header_from_cbor(cose.header_to_cbor(header))
  assert roundtripped == header
}

pub fn header_cbor_roundtrip_kid_test() {
  let header = cose.Kid(<<"my-key":utf8>>)
  let assert Ok(roundtripped) =
    cose.header_from_cbor(cose.header_to_cbor(header))
  assert roundtripped == header
}

pub fn header_cbor_roundtrip_content_type_well_known_test() {
  let header = cose.ContentType(cose.Json)
  let assert Ok(roundtripped) =
    cose.header_from_cbor(cose.header_to_cbor(header))
  assert roundtripped == header
}

pub fn header_cbor_roundtrip_content_type_text_test() {
  let header = cose.ContentType(cose.TextContentType("application/custom"))
  let assert Ok(roundtripped) =
    cose.header_from_cbor(cose.header_to_cbor(header))
  assert roundtripped == header
}

pub fn header_cbor_roundtrip_unknown_test() {
  let header = cose.Unknown(cbor.Int(99), cbor.Text("custom"))
  let assert Ok(roundtripped) =
    cose.header_from_cbor(cose.header_to_cbor(header))
  assert roundtripped == header
}

pub fn header_from_cbor_rejects_bad_alg_type_test() {
  assert cose.header_from_cbor(#(cbor.Int(1), cbor.Text("bad")))
    == Error(gose.ParseError("header label 1 (alg): expected Int"))
}

pub fn header_from_cbor_rejects_bad_kid_type_test() {
  assert cose.header_from_cbor(#(cbor.Int(4), cbor.Int(42)))
    == Error(gose.ParseError("header label 4 (kid): expected Bytes"))
}

pub fn content_type_to_cbor_well_known_values_test() {
  assert cose.content_type_to_cbor(cose.TextPlain) == cbor.Int(0)
  assert cose.content_type_to_cbor(cose.OctetStream) == cbor.Int(42)
  assert cose.content_type_to_cbor(cose.Json) == cbor.Int(50)
  assert cose.content_type_to_cbor(cose.Cbor) == cbor.Int(60)
  assert cose.content_type_to_cbor(cose.Cwt) == cbor.Int(61)
  assert cose.content_type_to_cbor(cose.CoseSign) == cbor.Int(101)
  assert cose.content_type_to_cbor(cose.CoseSign1) == cbor.Int(102)
  assert cose.content_type_to_cbor(cose.CoseEncrypt) == cbor.Int(103)
  assert cose.content_type_to_cbor(cose.CoseEncrypt0) == cbor.Int(104)
  assert cose.content_type_to_cbor(cose.CoseMac) == cbor.Int(105)
  assert cose.content_type_to_cbor(cose.CoseMac0) == cbor.Int(106)
  assert cose.content_type_to_cbor(cose.CoseKey) == cbor.Int(10_001)
  assert cose.content_type_to_cbor(cose.CoseKeySet) == cbor.Int(10_002)
}
