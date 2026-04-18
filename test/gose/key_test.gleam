import gose
import gose/algorithm
import gose/key
import kryptos/ec
import kryptos/eddsa
import kryptos/xdh

pub fn with_key_ops_empty_list_test() {
  let k = key.generate_ec(ec.P256)
  assert key.with_key_ops(k, [])
    == Error(gose.InvalidState("key_ops must not be empty"))
}

pub fn with_key_ops_duplicates_rejected_test() {
  let k = key.generate_ec(ec.P256)
  assert key.with_key_ops(k, [key.Sign, key.Sign])
    == Error(gose.InvalidState("key_ops must not contain duplicates"))
}

pub fn with_key_ops_use_conflict_test() {
  let k = key.generate_ec(ec.P256)
  let assert Ok(k) = key.with_key_use(k, key.Signing)
  assert key.with_key_ops(k, [key.Encrypt])
    == Error(gose.InvalidState("key_ops incompatible with use=sig"))
}

pub fn with_key_use_eddsa_encrypting_rejected_test() {
  let k = key.generate_eddsa(eddsa.Ed25519)
  assert key.with_key_use(k, key.Encrypting)
    == Error(gose.InvalidState(
      "EdDSA keys (Ed25519/Ed448) cannot be used for encryption",
    ))
}

pub fn with_key_use_xdh_signing_rejected_test() {
  let k = key.generate_xdh(xdh.X25519)
  assert key.with_key_use(k, key.Signing)
    == Error(gose.InvalidState(
      "XDH keys (X25519/X448) cannot be used for signing",
    ))
}

pub fn public_key_filters_ops_test() {
  let k = key.generate_ec(ec.P256)
  let assert Ok(k) = key.with_key_ops(k, [key.Sign, key.Verify])
  let assert Ok(pub_k) = key.public_key(k)
  assert key.key_ops(pub_k) == Ok([key.Verify])
}

pub fn public_key_no_ops_preserved_test() {
  let k = key.generate_ec(ec.P256)
  let assert Ok(pub_k) = key.public_key(k)
  assert key.key_ops(pub_k) == Error(Nil)
}

pub fn public_key_octet_rejected_test() {
  let k = key.generate_hmac_key(algorithm.HmacSha256)
  assert key.public_key(k)
    == Error(gose.InvalidState("octet keys are not asymmetric"))
}

pub fn from_octet_bits_rejects_empty_test() {
  assert key.from_octet_bits(<<>>)
    == Error(gose.InvalidState("oct key must not be empty"))
}

pub fn key_type_test() {
  let hmac_key = key.generate_hmac_key(algorithm.HmacSha256)
  assert key.key_type(hmac_key) == key.OctKeyType

  let ec_key = key.generate_ec(ec.P256)
  assert key.key_type(ec_key) == key.EcKeyType

  let eddsa_key = key.generate_eddsa(eddsa.Ed25519)
  assert key.key_type(eddsa_key) == key.OkpKeyType

  let xdh_key = key.generate_xdh(xdh.X25519)
  assert key.key_type(xdh_key) == key.OkpKeyType
}

pub fn with_kid_bits_overrides_prior_with_kid_test() {
  let k =
    key.generate_ec(ec.P256)
    |> key.with_kid("string-kid")
    |> key.with_kid_bits(<<0x01, 0x02, 0x03>>)
  assert key.kid(k) == Ok(<<0x01, 0x02, 0x03>>)
}

pub fn with_kid_overrides_prior_with_kid_bits_test() {
  let k =
    key.generate_ec(ec.P256)
    |> key.with_kid_bits(<<0x01, 0x02, 0x03>>)
    |> key.with_kid("string-kid")
  assert key.kid(k) == Ok("string-kid")
}
