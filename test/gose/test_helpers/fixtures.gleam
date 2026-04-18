import gose/key
import simplifile

pub fn load_pem(path: String) -> key.Key(kid) {
  let assert Ok(pem) = simplifile.read(path)
  let assert Ok(key) = key.from_pem(pem)
  key
}

pub fn load_raw_pem(path: String) -> String {
  let assert Ok(pem) = simplifile.read(path)
  pem
}

pub fn load_raw_der(path: String) -> BitArray {
  let assert Ok(der) = simplifile.read_bits(path)
  der
}

pub fn rsa_private_key() -> key.Key(kid) {
  load_pem("test/fixtures/rsa_pkcs8_priv.pem")
}

pub fn rsa_public_key() -> key.Key(kid) {
  load_pem("test/fixtures/rsa_spki_pub.pem")
}

pub fn ec_p256_key() -> key.Key(kid) {
  load_pem("test/fixtures/ec_p256_priv.pem")
}

pub fn ec_p256_public_key() -> key.Key(kid) {
  load_pem("test/fixtures/ec_p256_pub.pem")
}

pub fn ec_p384_key() -> key.Key(kid) {
  load_pem("test/fixtures/ec_p384_priv.pem")
}

pub fn ec_p384_public_key() -> key.Key(kid) {
  load_pem("test/fixtures/ec_p384_pub.pem")
}

pub fn ec_secp256k1_key() -> key.Key(kid) {
  load_pem("test/fixtures/ec_secp256k1_priv.pem")
}

pub fn ec_secp256k1_public_key() -> key.Key(kid) {
  load_pem("test/fixtures/ec_secp256k1_pub.pem")
}

pub fn ec_p521_key() -> key.Key(kid) {
  load_pem("test/fixtures/ec_p521_priv.pem")
}

pub fn ec_p521_public_key() -> key.Key(kid) {
  load_pem("test/fixtures/ec_p521_pub.pem")
}

pub fn ed25519_key() -> key.Key(kid) {
  load_pem("test/fixtures/ed25519_priv.pem")
}

pub fn ed25519_public_key() -> key.Key(kid) {
  load_pem("test/fixtures/ed25519_pub.pem")
}

pub fn ed448_key() -> key.Key(kid) {
  load_pem("test/fixtures/ed448_priv.pem")
}

pub fn ed448_public_key() -> key.Key(kid) {
  load_pem("test/fixtures/ed448_pub.pem")
}

pub fn x25519_key() -> key.Key(kid) {
  load_pem("test/fixtures/x25519_priv.pem")
}

pub fn x25519_public_key() -> key.Key(kid) {
  load_pem("test/fixtures/x25519_pub.pem")
}

pub fn x448_key() -> key.Key(kid) {
  load_pem("test/fixtures/x448_priv.pem")
}

pub fn x448_public_key() -> key.Key(kid) {
  load_pem("test/fixtures/x448_pub.pem")
}
