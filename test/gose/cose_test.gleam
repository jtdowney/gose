import gose
import gose/cbor
import gose/cose
import gose/test_helpers/generators
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

pub fn signing_alg_int_roundtrip_test() {
  use alg <- qcheck.given(generators.bare_jws_alg_generator())
  let id = cose.signing_alg_to_int(alg)
  assert cose.signing_alg_from_int(id) == Ok(alg)
}

pub fn signing_alg_from_cose_unknown_returns_error_test() {
  assert cose.signing_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE signing algorithm: 999"))
}

pub fn signing_alg_from_cose_zero_returns_error_test() {
  assert cose.signing_alg_from_int(0)
    == Error(gose.ParseError("unknown COSE signing algorithm: 0"))
}

pub fn key_encryption_alg_int_roundtrip_test() {
  use alg <- qcheck.given(cose_key_encryption_alg_generator())
  let assert Ok(id) = cose.key_encryption_alg_to_int(alg)
  assert cose.key_encryption_alg_from_int(id) == Ok(alg)
}

pub fn key_encryption_alg_to_cose_direct_spot_check_test() {
  assert cose.key_encryption_alg_to_int(gose.Direct) == Ok(-6)
}

pub fn key_encryption_alg_from_cose_ecdh_es_direct_hkdf512_test() {
  assert cose.key_encryption_alg_from_int(-26)
    == Ok(gose.EcdhEs(gose.EcdhEsDirect))
}

pub fn key_encryption_alg_from_cose_unknown_returns_error_test() {
  assert cose.key_encryption_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE key encryption algorithm: 999"))
}

pub fn key_encryption_alg_to_cose_aes_gcm_kw_returns_error_test() {
  assert cose.key_encryption_alg_to_int(gose.AesKeyWrap(
      gose.AesGcmKw,
      gose.Aes128,
    ))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: AesKeyWrap(AesGcmKw, Aes128)",
    ))
}

pub fn key_encryption_alg_to_cose_chacha20_kw_returns_error_test() {
  assert cose.key_encryption_alg_to_int(gose.ChaCha20KeyWrap(gose.C20PKw))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: ChaCha20KeyWrap(C20PKw)",
    ))
}

pub fn key_encryption_alg_to_cose_ecdh_es_chacha20_kw_returns_error_test() {
  assert cose.key_encryption_alg_to_int(
      gose.EcdhEs(gose.EcdhEsChaCha20Kw(gose.C20PKw)),
    )
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: EcdhEs(EcdhEsChaCha20Kw(C20PKw))",
    ))
}

pub fn key_encryption_alg_to_cose_rsa_pkcs1v15_returns_error_test() {
  assert cose.key_encryption_alg_to_int(gose.RsaEncryption(gose.RsaPkcs1v15))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: RsaEncryption(RsaPkcs1v15)",
    ))
}

pub fn key_encryption_alg_to_cose_pbes2_returns_error_test() {
  assert cose.key_encryption_alg_to_int(gose.Pbes2(gose.Pbes2Sha256Aes128Kw))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: Pbes2(Pbes2Sha256Aes128Kw)",
    ))
}

pub fn content_alg_int_roundtrip_test() {
  use alg <- qcheck.given(cose_content_alg_generator())
  let assert Ok(id) = cose.content_alg_to_int(alg)
  assert cose.content_alg_from_int(id) == Ok(alg)
}

pub fn content_alg_from_cose_unknown_returns_error_test() {
  assert cose.content_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE content encryption algorithm: 999"))
}

pub fn content_alg_to_cose_aes_cbc_hmac_returns_error_test() {
  assert cose.content_alg_to_int(gose.AesCbcHmac(gose.Aes128))
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: AesCbcHmac(Aes128)",
    ))
}

pub fn content_alg_to_cose_xchacha20_poly1305_returns_error_test() {
  assert cose.content_alg_to_int(gose.XChaCha20Poly1305)
    == Error(gose.InvalidState(
      "no COSE identifier for algorithm: XChaCha20Poly1305",
    ))
}

pub fn signature_alg_int_roundtrip_test() {
  use alg <- qcheck.given(cose_signature_alg_generator())
  let id = cose.signature_alg_to_int(alg)
  assert cose.signature_alg_from_int(id) == Ok(alg)
}

pub fn signature_alg_to_cose_es256_spot_check_test() {
  assert cose.signature_alg_to_int(gose.Ecdsa(gose.EcdsaP256)) == -7
}

pub fn signature_alg_from_cose_unknown_returns_error_test() {
  assert cose.signature_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE signature algorithm: 999"))
}

pub fn mac_alg_int_roundtrip_test() {
  use alg <- qcheck.given(cose_mac_alg_generator())
  let id = cose.mac_alg_to_int(alg)
  assert cose.mac_alg_from_int(id) == Ok(alg)
}

pub fn mac_alg_from_cose_unknown_returns_error_test() {
  assert cose.mac_alg_from_int(999)
    == Error(gose.ParseError("unknown COSE MAC algorithm: 999"))
}

fn cose_key_encryption_alg_generator() -> qcheck.Generator(
  gose.KeyEncryptionAlg,
) {
  qcheck.from_generators(qcheck.return(gose.Direct), [
    qcheck.return(gose.AesKeyWrap(gose.AesKw, gose.Aes128)),
    qcheck.return(gose.AesKeyWrap(gose.AesKw, gose.Aes192)),
    qcheck.return(gose.AesKeyWrap(gose.AesKw, gose.Aes256)),
    qcheck.return(gose.EcdhEs(gose.EcdhEsDirect)),
    qcheck.return(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes128))),
    qcheck.return(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes192))),
    qcheck.return(gose.EcdhEs(gose.EcdhEsAesKw(gose.Aes256))),
    qcheck.return(gose.RsaEncryption(gose.RsaOaepSha1)),
    qcheck.return(gose.RsaEncryption(gose.RsaOaepSha256)),
  ])
}

fn cose_content_alg_generator() -> qcheck.Generator(gose.ContentAlg) {
  qcheck.from_generators(qcheck.return(gose.AesGcm(gose.Aes128)), [
    qcheck.return(gose.AesGcm(gose.Aes192)),
    qcheck.return(gose.AesGcm(gose.Aes256)),
    qcheck.return(gose.ChaCha20Poly1305),
  ])
}

fn cose_signature_alg_generator() -> qcheck.Generator(gose.DigitalSignatureAlg) {
  qcheck.from_generators(qcheck.return(gose.Ecdsa(gose.EcdsaP256)), [
    qcheck.return(gose.Ecdsa(gose.EcdsaP384)),
    qcheck.return(gose.Ecdsa(gose.EcdsaP521)),
    qcheck.return(gose.Ecdsa(gose.EcdsaSecp256k1)),
    qcheck.return(gose.Eddsa),
    qcheck.return(gose.RsaPkcs1(gose.RsaPkcs1Sha256)),
    qcheck.return(gose.RsaPkcs1(gose.RsaPkcs1Sha384)),
    qcheck.return(gose.RsaPkcs1(gose.RsaPkcs1Sha512)),
    qcheck.return(gose.RsaPss(gose.RsaPssSha256)),
    qcheck.return(gose.RsaPss(gose.RsaPssSha384)),
    qcheck.return(gose.RsaPss(gose.RsaPssSha512)),
  ])
}

fn cose_mac_alg_generator() -> qcheck.Generator(gose.MacAlg) {
  qcheck.from_generators(qcheck.return(gose.Hmac(gose.HmacSha256)), [
    qcheck.return(gose.Hmac(gose.HmacSha384)),
    qcheck.return(gose.Hmac(gose.HmacSha512)),
  ])
}
