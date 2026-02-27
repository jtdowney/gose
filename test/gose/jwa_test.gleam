import gose
import gose/jwa
import gose/test_helpers/generators
import qcheck

pub fn jws_alg_roundtrip_test() {
  qcheck.run(
    qcheck.default_config(),
    generators.bare_jws_alg_generator(),
    fn(alg) {
      let alg_str = jwa.jws_alg_to_string(alg)
      assert jwa.jws_alg_from_string(alg_str) == Ok(alg)
    },
  )
}

pub fn jwe_alg_roundtrip_test() {
  qcheck.run(
    qcheck.default_config(),
    generators.bare_jwe_alg_generator(),
    fn(alg) {
      let alg_str = jwa.jwe_alg_to_string(alg)
      assert jwa.jwe_alg_from_string(alg_str) == Ok(alg)
    },
  )
}

pub fn enc_roundtrip_test() {
  qcheck.run(qcheck.default_config(), generators.jwe_enc_generator(), fn(enc) {
    let enc_str = jwa.enc_to_string(enc)
    assert jwa.enc_from_string(enc_str) == Ok(enc)
  })
}

pub fn jws_alg_from_string_rejects_invalid_test() {
  assert jwa.jws_alg_from_string("INVALID")
    == Error(gose.ParseError("unknown JWS algorithm: INVALID"))
}

pub fn jws_alg_from_string_is_case_sensitive_test() {
  assert jwa.jws_alg_from_string("hs256")
    == Error(gose.ParseError("unknown JWS algorithm: hs256"))
}

pub fn jwe_alg_from_string_rejects_invalid_test() {
  assert jwa.jwe_alg_from_string("INVALID")
    == Error(gose.ParseError("unknown JWE algorithm: INVALID"))
}

pub fn jwe_alg_from_string_is_case_sensitive_test() {
  assert jwa.jwe_alg_from_string("rsa-oaep")
    == Error(gose.ParseError("unknown JWE algorithm: rsa-oaep"))
}

pub fn enc_from_string_rejects_invalid_test() {
  assert jwa.enc_from_string("INVALID")
    == Error(gose.ParseError("unknown content encryption algorithm: INVALID"))
}

pub fn enc_from_string_is_case_sensitive_test() {
  assert jwa.enc_from_string("a128gcm")
    == Error(gose.ParseError("unknown content encryption algorithm: a128gcm"))
}

pub fn hmac_alg_octet_key_size_test() {
  assert jwa.hmac_alg_octet_key_size(jwa.HmacSha256) == 32
  assert jwa.hmac_alg_octet_key_size(jwa.HmacSha384) == 48
  assert jwa.hmac_alg_octet_key_size(jwa.HmacSha512) == 64
}

pub fn aes_key_size_in_bytes_test() {
  assert jwa.aes_key_size_in_bytes(jwa.Aes128) == 16
  assert jwa.aes_key_size_in_bytes(jwa.Aes192) == 24
  assert jwa.aes_key_size_in_bytes(jwa.Aes256) == 32
}

pub fn chacha20_kw_nonce_size_test() {
  assert jwa.chacha20_kw_nonce_size(jwa.C20PKw) == 12
  assert jwa.chacha20_kw_nonce_size(jwa.XC20PKw) == 24
}

pub fn jws_alg_from_string_rejects_empty_test() {
  assert jwa.jws_alg_from_string("")
    == Error(gose.ParseError("unknown JWS algorithm: "))
}

pub fn jwe_alg_from_string_rejects_empty_test() {
  assert jwa.jwe_alg_from_string("")
    == Error(gose.ParseError("unknown JWE algorithm: "))
}

pub fn enc_from_string_rejects_empty_test() {
  assert jwa.enc_from_string("")
    == Error(gose.ParseError("unknown content encryption algorithm: "))
}

pub fn enc_octet_key_size_all_variants_test() {
  qcheck.run(qcheck.default_config(), generators.jwe_enc_generator(), fn(enc) {
    let size = jwa.enc_octet_key_size(enc)
    assert size
      == case enc {
        jwa.AesGcm(jwa.Aes128) -> 16
        jwa.AesGcm(jwa.Aes192) -> 24
        jwa.AesGcm(jwa.Aes256) -> 32
        jwa.AesCbcHmac(jwa.Aes128) -> 32
        jwa.AesCbcHmac(jwa.Aes192) -> 48
        jwa.AesCbcHmac(jwa.Aes256) -> 64
        jwa.ChaCha20Poly1305 -> 32
        jwa.XChaCha20Poly1305 -> 32
      }
  })
}
