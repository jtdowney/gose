import gose
import gose/cbor
import gose/cose
import gose/internal/cose_structure

pub fn validate_crit_no_crit_passes_test() {
  assert cose_structure.validate_crit([cose.Alg(-7)], [cose.Kid(<<1, 2, 3>>)])
    == Ok(Nil)
}

pub fn validate_crit_in_unprotected_rejected_test() {
  assert cose_structure.validate_crit([cose.Alg(-7)], [cose.Crit([42])])
    == Error(gose.ParseError("crit header must be in the protected bucket"))
}

pub fn validate_crit_empty_list_rejected_test() {
  assert cose_structure.validate_crit([cose.Alg(-7), cose.Crit([])], [])
    == Error(gose.ParseError("crit array must not be empty"))
}

pub fn validate_crit_duplicate_labels_rejected_test() {
  assert cose_structure.validate_crit(
      [
        cose.Alg(-7),
        cose.Crit([42, 42]),
        cose.Unknown(cbor.Int(42), cbor.Text("val")),
      ],
      [],
    )
    == Error(gose.ParseError("crit array contains duplicate values"))
}

pub fn validate_crit_standard_label_accepted_test() {
  assert cose_structure.validate_crit([cose.Alg(-7), cose.Crit([1])], [])
    == Ok(Nil)
}

pub fn validate_crit_unknown_extension_rejected_test() {
  assert cose_structure.validate_crit(
      [
        cose.Alg(-7),
        cose.Crit([42]),
        cose.Unknown(cbor.Int(42), cbor.Text("val")),
      ],
      [],
    )
    == Error(gose.ParseError("unsupported critical header: 42"))
}

pub fn validate_crit_label_not_in_protected_test() {
  assert cose_structure.validate_crit([cose.Alg(-7), cose.Crit([99])], [])
    == Error(gose.ParseError(
      "crit references label not in protected headers: 99",
    ))
}

pub fn validate_iv_partial_iv_both_present_rejected_test() {
  assert cose_structure.validate_iv_partial_iv_exclusion(
      [cose.Iv(<<1, 2, 3>>), cose.PartialIv(<<4, 5>>)],
      [],
    )
    == Error(gose.ParseError("IV and Partial IV must not both be present"))
}

pub fn validate_iv_partial_iv_split_rejected_test() {
  assert cose_structure.validate_iv_partial_iv_exclusion(
      [cose.Iv(<<1, 2, 3>>)],
      [cose.PartialIv(<<4, 5>>)],
    )
    == Error(gose.ParseError("IV and Partial IV must not both be present"))
}

pub fn validate_iv_partial_iv_only_iv_passes_test() {
  assert cose_structure.validate_iv_partial_iv_exclusion([], [
      cose.Iv(<<1, 2, 3>>),
    ])
    == Ok(Nil)
}

pub fn validate_iv_partial_iv_only_partial_iv_passes_test() {
  assert cose_structure.validate_iv_partial_iv_exclusion(
      [cose.PartialIv(<<4, 5>>)],
      [],
    )
    == Ok(Nil)
}

pub fn validate_iv_partial_iv_neither_passes_test() {
  assert cose_structure.validate_iv_partial_iv_exclusion([cose.Alg(-7)], [
      cose.Kid(<<1, 2, 3>>),
    ])
    == Ok(Nil)
}

pub fn decode_protected_empty_bstr_passes_test() {
  assert cose_structure.decode_protected(<<>>) == Ok([])
}

pub fn decode_protected_empty_map_encoding_rejected_test() {
  assert cose_structure.decode_protected(<<0xa0>>)
    == Error(gose.ParseError(
      "empty protected header must be encoded as the empty bstr",
    ))
}
