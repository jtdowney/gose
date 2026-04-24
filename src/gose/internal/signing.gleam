import gleam/bool
import gleam/result
import gleam/string
import gose
import gose/internal/key_extract
import gose/internal/key_helpers
import gose/internal/utils
import kryptos/crypto
import kryptos/ec
import kryptos/ecdsa
import kryptos/eddsa
import kryptos/hash
import kryptos/hmac
import kryptos/rsa

pub fn compute_signature(
  alg: gose.SigningAlg,
  key key: gose.Key(kid),
  message message: BitArray,
) -> Result(BitArray, gose.GoseError) {
  let mat = gose.material(key)
  case alg {
    gose.Mac(gose.Hmac(hmac_alg)) -> {
      use #(hash_alg, secret) <- result.try(extract_validated_hmac_secret(
        key,
        hmac_alg,
      ))
      crypto.hmac(hash_alg, secret, message)
      |> result.replace_error(gose.CryptoError("HMAC computation failed"))
    }

    gose.DigitalSignature(gose.RsaPkcs1(pkcs1_alg)) -> {
      use private <- result.try(
        key_extract.rsa_private_key(mat)
        |> result.replace_error(gose.InvalidState(
          "RSA algorithms require an RSA private key",
        )),
      )
      let #(hash_alg, padding) = resolve_rsa_pkcs1_params(pkcs1_alg)
      Ok(rsa.sign(private, message, hash_alg, padding))
    }

    gose.DigitalSignature(gose.RsaPss(pss_alg)) -> {
      use private <- result.try(
        key_extract.rsa_private_key(mat)
        |> result.replace_error(gose.InvalidState(
          "RSA algorithms require an RSA private key",
        )),
      )
      let #(hash_alg, padding) = resolve_rsa_pss_params(pss_alg)
      Ok(rsa.sign(private, message, hash_alg, padding))
    }

    gose.DigitalSignature(gose.Ecdsa(ecdsa_alg)) -> {
      let #(hash_alg, expected_curve) = resolve_ecdsa_params(ecdsa_alg)
      use private <- result.try(extract_ec_private_key(
        mat,
        expected_curve,
        string.inspect(alg),
      ))
      Ok(ecdsa.sign_rs(private, message, hash_alg))
    }

    gose.DigitalSignature(gose.Eddsa) -> {
      use private <- result.try(extract_eddsa_private_key(mat))
      Ok(eddsa.sign(private, message))
    }
  }
}

pub fn verify_signature(
  alg: gose.SigningAlg,
  key key: gose.Key(kid),
  message message: BitArray,
  signature signature: BitArray,
) -> Result(Nil, gose.GoseError) {
  let mat = gose.material(key)
  case alg {
    gose.Mac(gose.Hmac(hmac_alg)) -> {
      use #(hash_alg, secret) <- result.try(extract_validated_hmac_secret(
        key,
        hmac_alg,
      ))
      hmac_verify(hash_alg, secret, message, signature)
    }

    gose.DigitalSignature(gose.RsaPkcs1(pkcs1_alg)) -> {
      use public <- result.try(
        key_extract.rsa_public_key(mat)
        |> result.replace_error(gose.InvalidState(
          "RSA algorithms require an RSA key",
        )),
      )
      let #(hash_alg, padding) = resolve_rsa_pkcs1_params(pkcs1_alg)
      require_valid(rsa.verify(public, message, signature, hash_alg, padding))
    }

    gose.DigitalSignature(gose.RsaPss(pss_alg)) -> {
      use public <- result.try(
        key_extract.rsa_public_key(mat)
        |> result.replace_error(gose.InvalidState(
          "RSA algorithms require an RSA key",
        )),
      )
      let #(hash_alg, padding) = resolve_rsa_pss_params(pss_alg)
      require_valid(rsa.verify(public, message, signature, hash_alg, padding))
    }

    gose.DigitalSignature(gose.Ecdsa(ecdsa_alg)) -> {
      let #(hash_alg, expected_curve) = resolve_ecdsa_params(ecdsa_alg)
      use public <- result.try(extract_ec_public_key(
        mat,
        expected_curve,
        string.inspect(alg),
      ))
      require_valid(ecdsa.verify_rs(public, message, signature, hash_alg))
    }

    gose.DigitalSignature(gose.Eddsa) -> {
      use public <- result.try(extract_eddsa_public_key(mat))
      require_valid(eddsa.verify(public, message, signature))
    }
  }
}

fn require_valid(valid: Bool) -> Result(Nil, gose.GoseError) {
  use <- bool.guard(when: !valid, return: Error(gose.VerificationFailed))
  Ok(Nil)
}

fn extract_validated_hmac_secret(
  key: gose.Key(kid),
  hmac_alg: gose.HmacAlg,
) -> Result(#(hash.HashAlgorithm, BitArray), gose.GoseError) {
  use secret <- result.try(
    gose.material_octet_secret(gose.material(key))
    |> result.replace_error(gose.InvalidState(
      "HMAC algorithms require an octet key",
    )),
  )
  let #(hash_alg, min_size, alg_name) = resolve_hmac_params(hmac_alg)
  use _ <- result.try(key_helpers.validate_hmac_key_size(
    key,
    min_size,
    alg_name,
  ))
  Ok(#(hash_alg, secret))
}

fn hmac_verify(
  algorithm: hash.HashAlgorithm,
  key: BitArray,
  message: BitArray,
  expected: BitArray,
) -> Result(Nil, gose.GoseError) {
  case hmac.verify(algorithm, key, message, expected) {
    Ok(True) -> Ok(Nil)
    Ok(False) -> Error(gose.VerificationFailed)
    Error(_) -> Error(gose.CryptoError("HMAC verification failed"))
  }
}

fn resolve_ecdsa_params(alg: gose.EcdsaAlg) -> #(hash.HashAlgorithm, ec.Curve) {
  case alg {
    gose.EcdsaP256 -> #(hash.Sha256, ec.P256)
    gose.EcdsaP384 -> #(hash.Sha384, ec.P384)
    gose.EcdsaP521 -> #(hash.Sha512, ec.P521)
    gose.EcdsaSecp256k1 -> #(hash.Sha256, ec.Secp256k1)
  }
}

fn resolve_hmac_params(
  alg: gose.HmacAlg,
) -> #(hash.HashAlgorithm, Int, String) {
  case alg {
    gose.HmacSha256 -> #(hash.Sha256, 32, "HS256")
    gose.HmacSha384 -> #(hash.Sha384, 48, "HS384")
    gose.HmacSha512 -> #(hash.Sha512, 64, "HS512")
  }
}

fn resolve_rsa_pkcs1_params(
  alg: gose.RsaPkcs1Alg,
) -> #(hash.HashAlgorithm, rsa.SignPadding) {
  case alg {
    gose.RsaPkcs1Sha256 -> #(hash.Sha256, rsa.Pkcs1v15)
    gose.RsaPkcs1Sha384 -> #(hash.Sha384, rsa.Pkcs1v15)
    gose.RsaPkcs1Sha512 -> #(hash.Sha512, rsa.Pkcs1v15)
  }
}

fn resolve_rsa_pss_params(
  alg: gose.RsaPssAlg,
) -> #(hash.HashAlgorithm, rsa.SignPadding) {
  case alg {
    gose.RsaPssSha256 -> #(hash.Sha256, rsa.Pss(rsa.SaltLengthHashLen))
    gose.RsaPssSha384 -> #(hash.Sha384, rsa.Pss(rsa.SaltLengthHashLen))
    gose.RsaPssSha512 -> #(hash.Sha512, rsa.Pss(rsa.SaltLengthHashLen))
  }
}

fn extract_ec_private_key(
  material: gose.KeyMaterial,
  expected_curve: ec.Curve,
  alg_name: String,
) -> Result(ec.PrivateKey, gose.GoseError) {
  let curve_error =
    gose.InvalidState(
      alg_name
      <> " requires an EC private key with "
      <> utils.ec_curve_to_string(expected_curve)
      <> " curve",
    )
  use ec <- result.try(
    gose.material_ec(material) |> result.replace_error(curve_error),
  )
  case ec {
    gose.EcPrivate(key: private, curve:, ..) -> {
      use <- bool.guard(
        when: curve != expected_curve,
        return: Error(curve_error),
      )
      Ok(private)
    }
    gose.EcPublic(..) -> Error(curve_error)
  }
}

fn extract_ec_public_key(
  material: gose.KeyMaterial,
  expected_curve: ec.Curve,
  alg_name: String,
) -> Result(ec.PublicKey, gose.GoseError) {
  let curve_error =
    gose.InvalidState(
      alg_name
      <> " requires an EC key with "
      <> utils.ec_curve_to_string(expected_curve)
      <> " curve",
    )
  use ec <- result.try(
    gose.material_ec(material) |> result.replace_error(curve_error),
  )
  let #(public, curve) = case ec {
    gose.EcPrivate(public:, curve:, ..) -> #(public, curve)
    gose.EcPublic(key: public, curve:) -> #(public, curve)
  }
  use <- bool.guard(when: curve != expected_curve, return: Error(curve_error))
  Ok(public)
}

fn extract_eddsa_private_key(
  material: gose.KeyMaterial,
) -> Result(eddsa.PrivateKey, gose.GoseError) {
  let error = gose.InvalidState("EdDSA requires an EdDSA private key")
  use eddsa <- result.try(
    gose.material_eddsa(material) |> result.replace_error(error),
  )
  case eddsa {
    gose.EddsaPrivate(key: private, ..) -> Ok(private)
    gose.EddsaPublic(..) -> Error(error)
  }
}

fn extract_eddsa_public_key(
  material: gose.KeyMaterial,
) -> Result(eddsa.PublicKey, gose.GoseError) {
  use eddsa <- result.try(
    gose.material_eddsa(material)
    |> result.replace_error(gose.InvalidState("EdDSA requires an EdDSA key")),
  )
  case eddsa {
    gose.EddsaPrivate(public:, ..) -> Ok(public)
    gose.EddsaPublic(key: public, ..) -> Ok(public)
  }
}
