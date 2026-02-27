import gleam/bool
import gleam/result
import gose
import gose/internal/key_helpers
import gose/internal/utils
import gose/jwa
import gose/jwk
import kryptos/crypto
import kryptos/ec
import kryptos/ecdsa
import kryptos/eddsa
import kryptos/hash
import kryptos/hmac
import kryptos/rsa

pub fn compute_signature(
  alg: jwa.JwsAlg,
  key: jwk.Jwk,
  message: BitArray,
) -> Result(BitArray, gose.GoseError) {
  let mat = jwk.material(key)
  case alg {
    jwa.JwsHmac(hmac_alg) -> {
      use secret <- result.try(
        jwk.material_octet_secret(mat)
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
      crypto.hmac(hash_alg, secret, message)
      |> result.replace_error(gose.CryptoError("HMAC computation failed"))
    }

    jwa.JwsRsaPkcs1(pkcs1_alg) -> {
      use private <- result.try(extract_rsa_private_key(mat))
      let #(hash_alg, padding) = resolve_rsa_pkcs1_params(pkcs1_alg)
      Ok(rsa.sign(private, message, hash_alg, padding))
    }

    jwa.JwsRsaPss(pss_alg) -> {
      use private <- result.try(extract_rsa_private_key(mat))
      let #(hash_alg, padding) = resolve_rsa_pss_params(pss_alg)
      Ok(rsa.sign(private, message, hash_alg, padding))
    }

    jwa.JwsEcdsa(ecdsa_alg) -> {
      let #(hash_alg, expected_curve) = resolve_ecdsa_params(ecdsa_alg)
      use private <- result.try(extract_ec_private_key(
        mat,
        expected_curve,
        jwa.jws_alg_to_string(alg),
      ))
      Ok(ecdsa.sign_rs(private, message, hash_alg))
    }

    jwa.JwsEddsa -> {
      use private <- result.try(extract_eddsa_private_key(mat))
      Ok(eddsa.sign(private, message))
    }
  }
}

pub fn verify_signature(
  alg: jwa.JwsAlg,
  key: jwk.Jwk,
  message: BitArray,
  signature: BitArray,
) -> Result(Bool, gose.GoseError) {
  let mat = jwk.material(key)
  case alg {
    jwa.JwsHmac(hmac_alg) -> {
      use secret <- result.try(
        jwk.material_octet_secret(mat)
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
      hmac_verify(hash_alg, secret, message, signature)
    }

    jwa.JwsRsaPkcs1(pkcs1_alg) -> {
      use public <- result.try(extract_rsa_public_key(mat))
      let #(hash_alg, padding) = resolve_rsa_pkcs1_params(pkcs1_alg)
      Ok(rsa.verify(public, message, signature, hash_alg, padding))
    }

    jwa.JwsRsaPss(pss_alg) -> {
      use public <- result.try(extract_rsa_public_key(mat))
      let #(hash_alg, padding) = resolve_rsa_pss_params(pss_alg)
      Ok(rsa.verify(public, message, signature, hash_alg, padding))
    }

    jwa.JwsEcdsa(ecdsa_alg) -> {
      let #(hash_alg, expected_curve) = resolve_ecdsa_params(ecdsa_alg)
      use public <- result.try(extract_ec_public_key(
        mat,
        expected_curve,
        jwa.jws_alg_to_string(alg),
      ))
      Ok(ecdsa.verify_rs(public, message, signature, hash_alg))
    }

    jwa.JwsEddsa -> {
      use public <- result.try(extract_eddsa_public_key(mat))
      Ok(eddsa.verify(public, message, signature))
    }
  }
}

fn hmac_verify(
  algorithm: hash.HashAlgorithm,
  key: BitArray,
  message: BitArray,
  expected: BitArray,
) -> Result(Bool, gose.GoseError) {
  hmac.verify(algorithm, key, message, expected)
  |> result.replace_error(gose.CryptoError("HMAC verification failed"))
}

fn resolve_ecdsa_params(alg: jwa.EcdsaAlg) -> #(hash.HashAlgorithm, ec.Curve) {
  case alg {
    jwa.EcdsaP256 -> #(hash.Sha256, ec.P256)
    jwa.EcdsaP384 -> #(hash.Sha384, ec.P384)
    jwa.EcdsaP521 -> #(hash.Sha512, ec.P521)
    jwa.EcdsaSecp256k1 -> #(hash.Sha256, ec.Secp256k1)
  }
}

fn resolve_hmac_params(alg: jwa.HmacAlg) -> #(hash.HashAlgorithm, Int, String) {
  case alg {
    jwa.HmacSha256 -> #(hash.Sha256, 32, "HS256")
    jwa.HmacSha384 -> #(hash.Sha384, 48, "HS384")
    jwa.HmacSha512 -> #(hash.Sha512, 64, "HS512")
  }
}

fn resolve_rsa_pkcs1_params(
  alg: jwa.RsaPkcs1Alg,
) -> #(hash.HashAlgorithm, rsa.SignPadding) {
  case alg {
    jwa.RsaPkcs1Sha256 -> #(hash.Sha256, rsa.Pkcs1v15)
    jwa.RsaPkcs1Sha384 -> #(hash.Sha384, rsa.Pkcs1v15)
    jwa.RsaPkcs1Sha512 -> #(hash.Sha512, rsa.Pkcs1v15)
  }
}

fn resolve_rsa_pss_params(
  alg: jwa.RsaPssAlg,
) -> #(hash.HashAlgorithm, rsa.SignPadding) {
  case alg {
    jwa.RsaPssSha256 -> #(hash.Sha256, rsa.Pss(rsa.SaltLengthHashLen))
    jwa.RsaPssSha384 -> #(hash.Sha384, rsa.Pss(rsa.SaltLengthHashLen))
    jwa.RsaPssSha512 -> #(hash.Sha512, rsa.Pss(rsa.SaltLengthHashLen))
  }
}

fn extract_ec_private_key(
  material: jwk.KeyMaterial,
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
    jwk.material_ec(material) |> result.replace_error(curve_error),
  )
  case ec {
    jwk.EcPrivate(key: private, curve:, ..) -> {
      use <- bool.guard(
        when: curve != expected_curve,
        return: Error(curve_error),
      )
      Ok(private)
    }
    jwk.EcPublic(..) -> Error(curve_error)
  }
}

fn extract_ec_public_key(
  material: jwk.KeyMaterial,
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
    jwk.material_ec(material) |> result.replace_error(curve_error),
  )
  let #(public, curve) = case ec {
    jwk.EcPrivate(public:, curve:, ..) -> #(public, curve)
    jwk.EcPublic(key: public, curve:) -> #(public, curve)
  }
  use <- bool.guard(when: curve != expected_curve, return: Error(curve_error))
  Ok(public)
}

fn extract_eddsa_private_key(
  material: jwk.KeyMaterial,
) -> Result(eddsa.PrivateKey, gose.GoseError) {
  let error = gose.InvalidState("EdDSA requires an EdDSA private key")
  use eddsa <- result.try(
    jwk.material_eddsa(material) |> result.replace_error(error),
  )
  case eddsa {
    jwk.EddsaPrivate(key: private, ..) -> Ok(private)
    jwk.EddsaPublic(..) -> Error(error)
  }
}

fn extract_eddsa_public_key(
  material: jwk.KeyMaterial,
) -> Result(eddsa.PublicKey, gose.GoseError) {
  use eddsa <- result.try(
    jwk.material_eddsa(material)
    |> result.replace_error(gose.InvalidState("EdDSA requires an EdDSA key")),
  )
  case eddsa {
    jwk.EddsaPrivate(public:, ..) -> Ok(public)
    jwk.EddsaPublic(key: public, ..) -> Ok(public)
  }
}

fn extract_rsa_private_key(
  material: jwk.KeyMaterial,
) -> Result(rsa.PrivateKey, gose.GoseError) {
  let error = gose.InvalidState("RSA algorithms require an RSA private key")
  use rsa <- result.try(
    jwk.material_rsa(material) |> result.replace_error(error),
  )
  case rsa {
    jwk.RsaPrivate(key: private, ..) -> Ok(private)
    jwk.RsaPublic(..) -> Error(error)
  }
}

fn extract_rsa_public_key(
  material: jwk.KeyMaterial,
) -> Result(rsa.PublicKey, gose.GoseError) {
  use rsa <- result.try(
    jwk.material_rsa(material)
    |> result.replace_error(gose.InvalidState(
      "RSA algorithms require an RSA key",
    )),
  )
  case rsa {
    jwk.RsaPrivate(public:, ..) -> Ok(public)
    jwk.RsaPublic(key: public) -> Ok(public)
  }
}
