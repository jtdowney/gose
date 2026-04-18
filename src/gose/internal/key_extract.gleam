//// Typed extractors for RSA key material. Callers translate the `Nil`
//// error to their own context-specific error.

import gose
import kryptos/rsa

pub fn rsa_private_key(
  material: gose.KeyMaterial,
) -> Result(rsa.PrivateKey, Nil) {
  case material {
    gose.Rsa(gose.RsaPrivate(key: private, ..)) -> Ok(private)
    _ -> Error(Nil)
  }
}

pub fn rsa_public_key(material: gose.KeyMaterial) -> Result(rsa.PublicKey, Nil) {
  case material {
    gose.Rsa(gose.RsaPrivate(public:, ..)) -> Ok(public)
    gose.Rsa(gose.RsaPublic(key: public)) -> Ok(public)
    _ -> Error(Nil)
  }
}
