//// Typed extractors for RSA key material. Callers translate the `Nil`
//// error to their own context-specific error.

import gose/key
import kryptos/rsa

pub fn rsa_private_key(material: key.KeyMaterial) -> Result(rsa.PrivateKey, Nil) {
  case material {
    key.Rsa(key.RsaPrivate(key: private, ..)) -> Ok(private)
    _ -> Error(Nil)
  }
}

pub fn rsa_public_key(material: key.KeyMaterial) -> Result(rsa.PublicKey, Nil) {
  case material {
    key.Rsa(key.RsaPrivate(public:, ..)) -> Ok(public)
    key.Rsa(key.RsaPublic(key: public)) -> Ok(public)
    _ -> Error(Nil)
  }
}
