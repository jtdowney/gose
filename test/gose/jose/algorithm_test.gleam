import gose
import gose/jose/algorithm as jose_algorithm
import gose/test_helpers/generators
import qcheck

pub fn signing_alg_roundtrip_test() {
  use alg <- qcheck.given(generators.bare_jws_alg_generator())
  let alg_str = jose_algorithm.signing_alg_to_string(alg)
  assert jose_algorithm.signing_alg_from_string(alg_str) == Ok(alg)
}

pub fn key_encryption_alg_roundtrip_test() {
  use alg <- qcheck.given(generators.bare_jwe_alg_generator())
  let alg_str = jose_algorithm.key_encryption_alg_to_string(alg)
  assert jose_algorithm.key_encryption_alg_from_string(alg_str) == Ok(alg)
}

pub fn content_alg_roundtrip_test() {
  use enc <- qcheck.given(generators.jwe_enc_generator())
  let enc_str = jose_algorithm.content_alg_to_string(enc)
  assert jose_algorithm.content_alg_from_string(enc_str) == Ok(enc)
}

pub fn signing_alg_from_jose_rejects_invalid_test() {
  assert jose_algorithm.signing_alg_from_string("INVALID")
    == Error(gose.ParseError("unknown JWS algorithm: INVALID"))
  assert jose_algorithm.signing_alg_from_string("")
    == Error(gose.ParseError("unknown JWS algorithm: "))
}

pub fn signing_alg_from_jose_is_case_sensitive_test() {
  assert jose_algorithm.signing_alg_from_string("hs256")
    == Error(gose.ParseError("unknown JWS algorithm: hs256"))
}

pub fn key_encryption_alg_from_jose_rejects_invalid_test() {
  assert jose_algorithm.key_encryption_alg_from_string("INVALID")
    == Error(gose.ParseError("unknown JWE algorithm: INVALID"))
  assert jose_algorithm.key_encryption_alg_from_string("")
    == Error(gose.ParseError("unknown JWE algorithm: "))
}

pub fn key_encryption_alg_from_jose_is_case_sensitive_test() {
  assert jose_algorithm.key_encryption_alg_from_string("rsa-oaep")
    == Error(gose.ParseError("unknown JWE algorithm: rsa-oaep"))
}

pub fn content_alg_from_jose_rejects_invalid_test() {
  assert jose_algorithm.content_alg_from_string("INVALID")
    == Error(gose.ParseError("unknown content encryption algorithm: INVALID"))
  assert jose_algorithm.content_alg_from_string("")
    == Error(gose.ParseError("unknown content encryption algorithm: "))
}

pub fn content_alg_from_jose_is_case_sensitive_test() {
  assert jose_algorithm.content_alg_from_string("a128gcm")
    == Error(gose.ParseError("unknown content encryption algorithm: a128gcm"))
}
