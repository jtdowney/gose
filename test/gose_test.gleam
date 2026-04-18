import gose
import kryptos/ec
import kryptos/eddsa
import kryptos/xdh
import unitest

pub fn main() -> Nil {
  unitest.run(
    unitest.Options(
      ..unitest.default_options(),
      execution_mode: unitest.RunParallelAuto,
    ),
  )
}

pub fn error_message_parse_error_test() {
  assert gose.error_message(gose.ParseError("bad input")) == "bad input"
}

pub fn error_message_crypto_error_test() {
  assert gose.error_message(gose.CryptoError("decrypt failed"))
    == "decrypt failed"
}

pub fn error_message_invalid_state_test() {
  assert gose.error_message(gose.InvalidState("wrong key type"))
    == "wrong key type"
}

pub fn error_message_verification_failed_test() {
  assert gose.error_message(gose.VerificationFailed) == "verification failed"
}

pub fn with_key_ops_empty_list_test() {
  let k = gose.generate_ec(ec.P256)
  assert gose.with_key_ops(k, [])
    == Error(gose.InvalidState("key_ops must not be empty"))
}

pub fn with_key_ops_duplicates_rejected_test() {
  let k = gose.generate_ec(ec.P256)
  assert gose.with_key_ops(k, [gose.Sign, gose.Sign])
    == Error(gose.InvalidState("key_ops must not contain duplicates"))
}

pub fn with_key_ops_use_conflict_test() {
  let k = gose.generate_ec(ec.P256)
  let assert Ok(k) = gose.with_key_use(k, gose.Signing)
  assert gose.with_key_ops(k, [gose.Encrypt])
    == Error(gose.InvalidState("key_ops incompatible with use=sig"))
}

pub fn with_key_use_eddsa_encrypting_rejected_test() {
  let k = gose.generate_eddsa(eddsa.Ed25519)
  assert gose.with_key_use(k, gose.Encrypting)
    == Error(gose.InvalidState(
      "EdDSA keys (Ed25519/Ed448) cannot be used for encryption",
    ))
}

pub fn with_key_use_xdh_signing_rejected_test() {
  let k = gose.generate_xdh(xdh.X25519)
  assert gose.with_key_use(k, gose.Signing)
    == Error(gose.InvalidState(
      "XDH keys (X25519/X448) cannot be used for signing",
    ))
}

pub fn public_key_filters_ops_test() {
  let k = gose.generate_ec(ec.P256)
  let assert Ok(k) = gose.with_key_ops(k, [gose.Sign, gose.Verify])
  let assert Ok(pub_k) = gose.public_key(k)
  assert gose.key_ops(pub_k) == Ok([gose.Verify])
}

pub fn public_key_no_ops_preserved_test() {
  let k = gose.generate_ec(ec.P256)
  let assert Ok(pub_k) = gose.public_key(k)
  assert gose.key_ops(pub_k) == Error(Nil)
}

pub fn public_key_octet_rejected_test() {
  let k = gose.generate_hmac_key(gose.HmacSha256)
  assert gose.public_key(k)
    == Error(gose.InvalidState("octet keys are not asymmetric"))
}

pub fn from_octet_bits_rejects_empty_test() {
  assert gose.from_octet_bits(<<>>)
    == Error(gose.InvalidState("oct key must not be empty"))
}

pub fn key_type_test() {
  let hmac_key = gose.generate_hmac_key(gose.HmacSha256)
  assert gose.key_type(hmac_key) == gose.OctKeyType

  let ec_key = gose.generate_ec(ec.P256)
  assert gose.key_type(ec_key) == gose.EcKeyType

  let eddsa_key = gose.generate_eddsa(eddsa.Ed25519)
  assert gose.key_type(eddsa_key) == gose.OkpKeyType

  let xdh_key = gose.generate_xdh(xdh.X25519)
  assert gose.key_type(xdh_key) == gose.OkpKeyType
}

pub fn with_kid_bits_overrides_prior_with_kid_test() {
  let k =
    gose.generate_ec(ec.P256)
    |> gose.with_kid("string-kid")
    |> gose.with_kid_bits(<<0x01, 0x02, 0x03>>)
  assert gose.kid(k) == Ok(<<0x01, 0x02, 0x03>>)
}

pub fn with_kid_overrides_prior_with_kid_bits_test() {
  let k =
    gose.generate_ec(ec.P256)
    |> gose.with_kid_bits(<<0x01, 0x02, 0x03>>)
    |> gose.with_kid("string-kid")
  assert gose.kid(k) == Ok("string-kid")
}
