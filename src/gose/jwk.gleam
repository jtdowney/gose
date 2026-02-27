//// JSON Web Key (JWK) - [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html)
////
//// This module provides key management for JOSE operations. It supports
//// symmetric keys (octet sequences) and asymmetric keys (RSA, EC, EdDSA).
////
//// ## Example
////
//// ```gleam
//// import gleam/json
//// import gose/jwk
//// import kryptos/ec
////
//// // Generate an EC key and attach metadata
//// let key =
////   jwk.generate_ec(ec.P256)
////   |> jwk.with_kid("my-signing-key")
////
//// // Serialize to JSON
//// let json_string = jwk.to_json(key)
////   |> json.to_string()
////
//// // Parse from a JSON string
//// let assert Ok(parsed) = jwk.from_json(json_string)
//// let assert Ok("my-signing-key") = jwk.kid(parsed)
//// ```
////
//// ## Duplicate Member Names
////
//// Per RFC 7517 Section 4, JWK member names must be unique. This implementation
//// relies on `gleam_json` for parsing, which uses the first value when
//// duplicate member names are present. Subsequent duplicates are ignored.
////
//// ## Unsupported Parameters
////
//// X.509 certificate chain parameters (RFC 7517 Section 4.6-4.9) are not supported:
//// - `x5u` - X.509 URL
//// - `x5c` - X.509 Certificate Chain
//// - `x5t` - X.509 Certificate SHA-1 Thumbprint
//// - `x5t#S256` - X.509 Certificate SHA-256 Thumbprint
////
//// JWKs containing any of these parameters are rejected with a `ParseError` during
//// parsing. These parameters are not emitted during serialization.

import gleam/bit_array
import gleam/bool
import gleam/dict
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gose
import gose/internal/utils
import gose/jwa
import kryptos/crypto
import kryptos/ec
import kryptos/eddsa
import kryptos/hash
import kryptos/rsa
import kryptos/xdh

/// Public Key Use parameter.
///
/// Indicates whether the key is for signing or encryption.
pub type KeyUse {
  /// Key is used for signature operations
  Signing
  /// Key is used for encryption operations
  Encrypting
}

/// Key Operations parameter.
///
/// Identifies the operation(s) for which the key is intended.
pub type KeyOp {
  /// Compute digital signature or MAC
  Sign
  /// Verify digital signature or MAC
  Verify
  /// Encrypt content
  Encrypt
  /// Decrypt content and validate decryption
  Decrypt
  /// Encrypt key
  WrapKey
  /// Decrypt key and validate decryption
  UnwrapKey
  /// Derive key
  DeriveKey
  /// Derive bits not to be used as a key
  DeriveBits
}

/// Algorithm union type for JWK `alg` field.
/// A key can specify either a JWS signing algorithm or a JWE encryption algorithm.
pub type Alg {
  /// JWS signing algorithm
  Jws(jwa.JwsAlg)
  /// JWE key encryption algorithm
  Jwe(jwa.JweAlg)
}

@internal
pub type RsaKeyMaterial {
  RsaPrivate(key: rsa.PrivateKey, public: rsa.PublicKey)
  RsaPublic(key: rsa.PublicKey)
}

@internal
pub type EcKeyMaterial {
  EcPrivate(key: ec.PrivateKey, public: ec.PublicKey, curve: ec.Curve)
  EcPublic(key: ec.PublicKey, curve: ec.Curve)
}

@internal
pub type EddsaKeyMaterial {
  EddsaPrivate(
    key: eddsa.PrivateKey,
    public: eddsa.PublicKey,
    curve: eddsa.Curve,
  )
  EddsaPublic(key: eddsa.PublicKey, curve: eddsa.Curve)
}

@internal
pub type XdhKeyMaterial {
  XdhPrivate(key: xdh.PrivateKey, public: xdh.PublicKey, curve: xdh.Curve)
  XdhPublic(key: xdh.PublicKey, curve: xdh.Curve)
}

@internal
pub opaque type KeyMaterial {
  OctetKey(secret: BitArray)
  Rsa(RsaKeyMaterial)
  Ec(EcKeyMaterial)
  Eddsa(EddsaKeyMaterial)
  Xdh(XdhKeyMaterial)
}

/// Key type identifier (kty parameter).
pub type KeyType {
  /// Symmetric key (oct)
  OctKeyType
  /// RSA key
  RsaKeyType
  /// Elliptic Curve key
  EcKeyType
  /// Octet Key Pair (EdDSA, XDH)
  OkpKeyType
}

/// A JSON Web Key.
///
/// Use constructor functions like `from_octet_bits`, `from_der`,
/// `from_pem`, or `generate_*` to create keys.
pub opaque type Jwk {
  Jwk(
    material: KeyMaterial,
    kid: Option(String),
    key_use: Option(KeyUse),
    key_ops: Option(List(KeyOp)),
    alg: Option(Alg),
  )
}

fn new_jwk(material: KeyMaterial) -> Jwk {
  Jwk(material:, kid: None, key_use: None, key_ops: None, alg: None)
}

@internal
pub fn is_private_key(key: Jwk) -> Bool {
  case key.material {
    OctetKey(..) -> True
    Rsa(RsaPrivate(..)) -> True
    Rsa(RsaPublic(..)) -> False
    Ec(EcPrivate(..)) -> True
    Ec(EcPublic(..)) -> False
    Eddsa(EddsaPrivate(..)) -> True
    Eddsa(EddsaPublic(..)) -> False
    Xdh(XdhPrivate(..)) -> True
    Xdh(XdhPublic(..)) -> False
  }
}

/// Access the key material of a JWK.
@internal
pub fn material(key: Jwk) -> KeyMaterial {
  key.material
}

@internal
pub fn material_octet_secret(
  mat: KeyMaterial,
) -> Result(BitArray, gose.GoseError) {
  case mat {
    OctetKey(secret:) -> Ok(secret)
    Rsa(..) | Ec(..) | Eddsa(..) | Xdh(..) ->
      Error(gose.InvalidState("expected octet key"))
  }
}

@internal
pub fn material_rsa(mat: KeyMaterial) -> Result(RsaKeyMaterial, gose.GoseError) {
  case mat {
    Rsa(rsa) -> Ok(rsa)
    OctetKey(..) | Ec(..) | Eddsa(..) | Xdh(..) ->
      Error(gose.InvalidState("expected RSA key"))
  }
}

@internal
pub fn material_ec(mat: KeyMaterial) -> Result(EcKeyMaterial, gose.GoseError) {
  case mat {
    Ec(ec) -> Ok(ec)
    OctetKey(..) | Rsa(..) | Eddsa(..) | Xdh(..) ->
      Error(gose.InvalidState("expected EC key"))
  }
}

@internal
pub fn material_eddsa(
  mat: KeyMaterial,
) -> Result(EddsaKeyMaterial, gose.GoseError) {
  case mat {
    Eddsa(eddsa) -> Ok(eddsa)
    OctetKey(..) | Rsa(..) | Ec(..) | Xdh(..) ->
      Error(gose.InvalidState("expected EdDSA key"))
  }
}

@internal
pub fn material_xdh(mat: KeyMaterial) -> Result(XdhKeyMaterial, gose.GoseError) {
  case mat {
    Xdh(xdh) -> Ok(xdh)
    OctetKey(..) | Rsa(..) | Ec(..) | Eddsa(..) ->
      Error(gose.InvalidState("expected XDH key"))
  }
}

/// Create a key from DER-encoded data.
///
/// Auto-detects key type (RSA, EC, EdDSA, XDH) and format (PKCS#1, PKCS#8, SPKI).
/// Supports both private and public keys.
///
/// ## Parameters
///
/// - `der` - The DER-encoded key bytes.
///
/// ## Returns
///
/// `Ok(Jwk)` with the parsed key, or `Error(ParseError)` if the DER data
/// is not a recognized key format.
pub fn from_der(der: BitArray) -> Result(Jwk, gose.GoseError) {
  parse_rsa_der(der)
  |> result.lazy_or(fn() { parse_eddsa_der(der) })
  |> result.lazy_or(fn() { parse_xdh_der(der) })
  |> result.lazy_or(fn() { parse_ec_der(der) })
  |> result.map_error(fn(_) {
    gose.ParseError(
      "invalid DER: not a recognized RSA, EC, EdDSA, or XDH key format",
    )
  })
}

fn ec_private_jwk(pair: #(ec.PrivateKey, ec.PublicKey)) -> Jwk {
  let #(private, public) = pair
  let curve = ec.curve(private)
  new_jwk(Ec(EcPrivate(key: private, public:, curve:)))
}

fn ec_public_jwk(public: ec.PublicKey) -> Jwk {
  let curve = ec.public_key_curve(public)
  new_jwk(Ec(EcPublic(key: public, curve:)))
}

fn eddsa_private_jwk(pair: #(eddsa.PrivateKey, eddsa.PublicKey)) -> Jwk {
  let #(private, public) = pair
  let curve = eddsa.curve(private)
  new_jwk(Eddsa(EddsaPrivate(key: private, public:, curve:)))
}

fn eddsa_public_jwk(public: eddsa.PublicKey) -> Jwk {
  let curve = eddsa.public_key_curve(public)
  new_jwk(Eddsa(EddsaPublic(key: public, curve:)))
}

fn rsa_private_jwk(pair: #(rsa.PrivateKey, rsa.PublicKey)) -> Jwk {
  let #(private, public) = pair
  new_jwk(Rsa(RsaPrivate(key: private, public:)))
}

fn rsa_public_jwk(public: rsa.PublicKey) -> Jwk {
  new_jwk(Rsa(RsaPublic(key: public)))
}

fn xdh_private_jwk(pair: #(xdh.PrivateKey, xdh.PublicKey)) -> Jwk {
  let #(private, public) = pair
  let curve = xdh.curve(private)
  new_jwk(Xdh(XdhPrivate(key: private, public:, curve:)))
}

fn xdh_public_jwk(public: xdh.PublicKey) -> Jwk {
  let curve = xdh.public_key_curve(public)
  new_jwk(Xdh(XdhPublic(key: public, curve:)))
}

fn parse_ec_der(der: BitArray) -> Result(Jwk, Nil) {
  ec.from_der(der)
  |> result.map(ec_private_jwk)
  |> result.lazy_or(fn() {
    ec.public_key_from_der(der) |> result.map(ec_public_jwk)
  })
}

fn parse_eddsa_der(der: BitArray) -> Result(Jwk, Nil) {
  eddsa.from_der(der)
  |> result.map(eddsa_private_jwk)
  |> result.lazy_or(fn() {
    eddsa.public_key_from_der(der) |> result.map(eddsa_public_jwk)
  })
}

fn parse_rsa_der(der: BitArray) -> Result(Jwk, Nil) {
  rsa.from_der(der, rsa.Pkcs8)
  |> result.map(rsa_private_jwk)
  |> result.lazy_or(fn() {
    rsa.from_der(der, rsa.Pkcs1) |> result.map(rsa_private_jwk)
  })
  |> result.lazy_or(fn() {
    rsa.public_key_from_der(der, rsa.Spki) |> result.map(rsa_public_jwk)
  })
  |> result.lazy_or(fn() {
    rsa.public_key_from_der(der, rsa.RsaPublicKey) |> result.map(rsa_public_jwk)
  })
}

fn parse_xdh_der(der: BitArray) -> Result(Jwk, Nil) {
  xdh.from_der(der)
  |> result.map(xdh_private_jwk)
  |> result.lazy_or(fn() {
    xdh.public_key_from_der(der) |> result.map(xdh_public_jwk)
  })
}

/// Create an EdDSA key pair from raw private key bytes.
///
/// The public key is derived from the private key.
/// This is the inverse of `to_octet_bits` for EdDSA private keys.
///
/// ## Parameters
///
/// - `curve` - The EdDSA curve (Ed25519 or Ed448).
/// - `private_bits` - The raw private key bits.
///
/// ## Returns
///
/// `Ok(Jwk)` with an EdDSA private key and derived public key, or
/// `Error(ParseError)` if the bits are invalid for the given curve.
pub fn from_eddsa_bits(
  curve: eddsa.Curve,
  private_bits: BitArray,
) -> Result(Jwk, gose.GoseError) {
  eddsa.from_bytes(curve, private_bits)
  |> result.map(fn(pair) {
    let #(private, public) = pair
    new_jwk(Eddsa(EddsaPrivate(key: private, public:, curve:)))
  })
  |> result.replace_error(gose.ParseError("invalid EdDSA private key bits"))
}

/// Create an EdDSA public key from raw bytes.
///
/// This is the inverse of `to_octet_bits` for EdDSA public keys.
///
/// ## Parameters
///
/// - `curve` - The EdDSA curve (Ed25519 or Ed448).
/// - `public_bits` - The raw public key bits.
///
/// ## Returns
///
/// `Ok(Jwk)` with an EdDSA public key, or `Error(ParseError)` if the bits
/// are invalid for the given curve.
pub fn from_eddsa_public_bits(
  curve: eddsa.Curve,
  public_bits: BitArray,
) -> Result(Jwk, gose.GoseError) {
  eddsa.public_key_from_bytes(curve, public_bits)
  |> result.map(fn(public) { new_jwk(Eddsa(EddsaPublic(key: public, curve:))) })
  |> result.replace_error(gose.ParseError("invalid EdDSA public key bits"))
}

/// Create a symmetric key from raw bytes.
///
/// Used for HMAC signing (HS256/384/512) and direct encryption.
/// Returns an error if the secret is empty.
///
/// ## Parameters
///
/// - `secret` - The raw key bytes.
///
/// ## Returns
///
/// `Ok(Jwk)` with a symmetric key wrapping the provided bytes, or
/// `Error(InvalidState)` if the secret is empty.
///
/// ## Example
///
/// ```gleam
/// let secret = crypto.strong_random_bytes(32)
/// let assert Ok(key) = jwk.from_octet_bits(secret)
/// ```
pub fn from_octet_bits(secret: BitArray) -> Result(Jwk, gose.GoseError) {
  case bit_array.byte_size(secret) {
    0 -> Error(gose.InvalidState("oct key must not be empty"))
    _ -> Ok(new_jwk(OctetKey(secret:)))
  }
}

/// Create a key from PEM-encoded data.
///
/// Auto-detects key type (RSA, EC, EdDSA, XDH) and format (PKCS#1, PKCS#8, SPKI).
/// Supports both private and public keys.
///
/// ## Parameters
///
/// - `pem` - The PEM-encoded key string.
///
/// ## Returns
///
/// `Ok(Jwk)` with the parsed key, or `Error(ParseError)` if the PEM data
/// is not a recognized key format.
pub fn from_pem(pem: String) -> Result(Jwk, gose.GoseError) {
  parse_rsa_pem(pem)
  |> result.lazy_or(fn() { parse_eddsa_pem(pem) })
  |> result.lazy_or(fn() { parse_xdh_pem(pem) })
  |> result.lazy_or(fn() { parse_ec_pem(pem) })
  |> result.map_error(fn(_) {
    gose.ParseError(
      "invalid PEM: not a recognized RSA, EC, EdDSA, or XDH key format",
    )
  })
}

fn parse_ec_pem(pem: String) -> Result(Jwk, Nil) {
  ec.from_pem(pem)
  |> result.map(ec_private_jwk)
  |> result.lazy_or(fn() {
    ec.public_key_from_pem(pem) |> result.map(ec_public_jwk)
  })
}

fn parse_eddsa_pem(pem: String) -> Result(Jwk, Nil) {
  eddsa.from_pem(pem)
  |> result.map(eddsa_private_jwk)
  |> result.lazy_or(fn() {
    eddsa.public_key_from_pem(pem) |> result.map(eddsa_public_jwk)
  })
}

fn parse_rsa_pem(pem: String) -> Result(Jwk, Nil) {
  rsa.from_pem(pem, rsa.Pkcs8)
  |> result.map(rsa_private_jwk)
  |> result.lazy_or(fn() {
    rsa.from_pem(pem, rsa.Pkcs1) |> result.map(rsa_private_jwk)
  })
  |> result.lazy_or(fn() {
    rsa.public_key_from_pem(pem, rsa.Spki) |> result.map(rsa_public_jwk)
  })
  |> result.lazy_or(fn() {
    rsa.public_key_from_pem(pem, rsa.RsaPublicKey) |> result.map(rsa_public_jwk)
  })
}

fn parse_xdh_pem(pem: String) -> Result(Jwk, Nil) {
  xdh.from_pem(pem)
  |> result.map(xdh_private_jwk)
  |> result.lazy_or(fn() {
    xdh.public_key_from_pem(pem) |> result.map(xdh_public_jwk)
  })
}

/// Create an XDH key pair from raw private key bytes.
///
/// The public key is derived from the private key.
/// This is the inverse of `to_octet_bits` for XDH private keys.
///
/// ## Parameters
///
/// - `curve` - The XDH curve (X25519 or X448).
/// - `private_bits` - The raw private key bits.
///
/// ## Returns
///
/// `Ok(Jwk)` with an XDH private key and derived public key, or
/// `Error(ParseError)` if the bits are invalid for the given curve.
pub fn from_xdh_bits(
  curve: xdh.Curve,
  private_bits: BitArray,
) -> Result(Jwk, gose.GoseError) {
  xdh.from_bytes(curve, private_bits)
  |> result.map(fn(pair) {
    let #(private, public) = pair
    new_jwk(Xdh(XdhPrivate(key: private, public:, curve:)))
  })
  |> result.replace_error(gose.ParseError("invalid XDH private key bits"))
}

/// Create an XDH public key from raw bytes.
///
/// This is the inverse of `to_octet_bits` for XDH public keys.
///
/// ## Parameters
///
/// - `curve` - The XDH curve (X25519 or X448).
/// - `public_bits` - The raw public key bits.
///
/// ## Returns
///
/// `Ok(Jwk)` with an XDH public key, or `Error(ParseError)` if the bits
/// are invalid for the given curve.
pub fn from_xdh_public_bits(
  curve: xdh.Curve,
  public_bits: BitArray,
) -> Result(Jwk, gose.GoseError) {
  xdh.public_key_from_bytes(curve, public_bits)
  |> result.map(fn(public) { new_jwk(Xdh(XdhPublic(key: public, curve:))) })
  |> result.replace_error(gose.ParseError("invalid XDH public key bits"))
}

/// Generate a new EC key pair for the given curve.
///
/// Supported curves: P256, P384, P521, Secp256k1.
///
/// ## Parameters
///
/// - `curve` - The EC curve to use.
///
/// ## Returns
///
/// A `Jwk` containing the generated EC private key.
pub fn generate_ec(curve: ec.Curve) -> Jwk {
  let #(private, public) = ec.generate_key_pair(curve)
  new_jwk(Ec(EcPrivate(key: private, public:, curve:)))
}

/// Generate a new EdDSA key pair for the given curve.
///
/// Supported curves: Ed25519, Ed448.
///
/// ## Parameters
///
/// - `curve` - The EdDSA curve to use.
///
/// ## Returns
///
/// A `Jwk` containing the generated EdDSA private key.
pub fn generate_eddsa(curve: eddsa.Curve) -> Jwk {
  let #(private, public) = eddsa.generate_key_pair(curve)
  new_jwk(Eddsa(EddsaPrivate(key: private, public:, curve:)))
}

/// Generate a symmetric key for HMAC signing.
///
/// The key size is derived from the algorithm:
/// - `HmacSha256` → 32 bytes
/// - `HmacSha384` → 48 bytes
/// - `HmacSha512` → 64 bytes
///
/// ## Parameters
///
/// - `alg` - The HMAC algorithm variant.
///
/// ## Returns
///
/// A `Jwk` containing a symmetric key of the correct size.
pub fn generate_hmac_key(alg: jwa.HmacAlg) -> Jwk {
  let size = jwa.hmac_alg_octet_key_size(alg)
  let secret = crypto.random_bytes(size)
  new_jwk(OctetKey(secret:))
}

/// Generate a symmetric key for JWE content encryption.
///
/// The key size is derived from the encryption algorithm:
/// - `AesGcm(Aes128)` → 16 bytes
/// - `AesGcm(Aes192)` → 24 bytes
/// - `AesGcm(Aes256)` → 32 bytes
/// - `AesCbcHmac(Aes128)` → 32 bytes (16 + 16 for MAC)
/// - `AesCbcHmac(Aes192)` → 48 bytes (24 + 24 for MAC)
/// - `AesCbcHmac(Aes256)` → 64 bytes (32 + 32 for MAC)
/// - `ChaCha20Poly1305` → 32 bytes
/// - `XChaCha20Poly1305` → 32 bytes
///
/// ## Parameters
///
/// - `enc` - The content encryption algorithm.
///
/// ## Returns
///
/// A `Jwk` containing a symmetric key of the correct size.
pub fn generate_enc_key(enc: jwa.Enc) -> Jwk {
  let size = jwa.enc_octet_key_size(enc)
  let secret = crypto.random_bytes(size)
  new_jwk(OctetKey(secret:))
}

/// Generate a symmetric key for AES Key Wrap.
///
/// The key size is derived from the AES variant:
/// - `Aes128` → 16 bytes
/// - `Aes192` → 24 bytes
/// - `Aes256` → 32 bytes
///
/// ## Parameters
///
/// - `size` - The AES key size.
///
/// ## Returns
///
/// A `Jwk` containing a symmetric key of the correct size.
pub fn generate_aes_kw_key(size: jwa.AesKeySize) -> Jwk {
  let byte_count = jwa.aes_key_size_in_bytes(size)
  let secret = crypto.random_bytes(byte_count)
  new_jwk(OctetKey(secret:))
}

/// Generate a symmetric key for ChaCha20-Poly1305 Key Wrap (C20PKW / XC20PKW).
///
/// Always generates a 32-byte key, as both ChaCha20 and XChaCha20 use 256-bit keys.
///
/// ## Returns
///
/// A `Jwk` containing a 32-byte symmetric key.
pub fn generate_chacha20_kw_key() -> Jwk {
  let secret = crypto.random_bytes(32)
  new_jwk(OctetKey(secret:))
}

/// Generate a new RSA key pair with the given key size in bits.
///
/// ## Parameters
///
/// - `bits` - The RSA key size in bits (e.g. 2048, 4096).
///
/// ## Returns
///
/// `Ok(Jwk)` with the generated RSA key pair, or `Error(CryptoError)` if
/// key generation fails.
pub fn generate_rsa(bits: Int) -> Result(Jwk, gose.GoseError) {
  case rsa.generate_key_pair(bits) {
    Ok(#(private, public)) ->
      Ok(new_jwk(Rsa(RsaPrivate(key: private, public:))))
    Error(_) -> Error(gose.CryptoError("RSA key generation failed"))
  }
}

/// Generate a new XDH key pair for key agreement.
///
/// Supported curves: X25519, X448.
///
/// ## Parameters
///
/// - `curve` - The XDH curve to use.
///
/// ## Returns
///
/// A `Jwk` containing the generated XDH private key.
pub fn generate_xdh(curve: xdh.Curve) -> Jwk {
  let #(private, public) = xdh.generate_key_pair(curve)
  new_jwk(Xdh(XdhPrivate(key: private, public:, curve:)))
}

/// Create an EC public key from curve and x,y coordinates (big-endian bytes).
///
/// ## Parameters
///
/// - `curve` - The EC curve (P256, P384, P521, Secp256k1).
/// - `x` - The x coordinate as big-endian bytes.
/// - `y` - The y coordinate as big-endian bytes.
///
/// ## Returns
///
/// `Ok(Jwk)` with an EC public key, or `Error(GoseError)` if the
/// coordinates are invalid for the curve.
pub fn ec_public_key_from_coordinates(
  curve: ec.Curve,
  x x: BitArray,
  y y: BitArray,
) -> Result(Jwk, gose.GoseError) {
  utils.ec_public_key_from_coordinates(curve, x, y)
  |> result.map(fn(public) { new_jwk(Ec(EcPublic(key: public, curve:))) })
}

/// Set the algorithm (`alg`) metadata parameter on a key.
///
/// ## Parameters
///
/// - `key` - The JWK to update.
/// - `alg` - The algorithm to associate with the key.
///
/// ## Returns
///
/// A new `Jwk` with the `alg` parameter set.
pub fn with_alg(key: Jwk, alg: Alg) -> Jwk {
  Jwk(..key, alg: Some(alg))
}

/// Set the key operations parameter.
///
/// Per RFC 7517, the values should be consistent with `key_use` if both are present:
/// - `Signing` use implies `Sign` and/or `Verify` operations
/// - `Encrypting` use implies `Encrypt`, `Decrypt`, `WrapKey`, `UnwrapKey`, `DeriveKey`, `DeriveBits`
///
/// Returns an error if the list is empty or if the operations are incompatible
/// with the key's existing `key_use`.
///
/// ## Parameters
///
/// - `key` - The JWK to update.
/// - `ops` - The list of key operations to allow.
///
/// ## Returns
///
/// `Ok(Jwk)` with the operations parameter set, or `Error(InvalidState)`
/// if the list is empty, contains duplicates, or is incompatible with
/// `key_use`.
pub fn with_key_ops(key: Jwk, ops: List(KeyOp)) -> Result(Jwk, gose.GoseError) {
  case ops {
    [] -> Error(gose.InvalidState("key_ops must not be empty"))
    _ -> {
      use <- bool.guard(
        when: list.unique(ops) != ops,
        return: Error(gose.InvalidState("key_ops must not contain duplicates")),
      )
      validate_key_use_ops(key.key_use, Some(ops))
      |> result.replace(Jwk(..key, key_ops: Some(ops)))
    }
  }
}

/// Set the public key use parameter.
///
/// Returns an error if the key already has `key_ops` that are incompatible with
/// the specified use, or if the use is incompatible with the key type per RFC
/// 8037 (EdDSA keys can only be used for signing, XDH keys can only be used for
/// encryption).
///
/// ## Parameters
///
/// - `key` - The JWK to update.
/// - `use_` - The intended use (`Signing` or `Encrypting`).
///
/// ## Returns
///
/// `Ok(Jwk)` with the use parameter set, or `Error(InvalidState)` if the
/// use is incompatible with `key_ops` or key type.
pub fn with_key_use(key: Jwk, use_: KeyUse) -> Result(Jwk, gose.GoseError) {
  use _ <- result.try(validate_key_use_ops(Some(use_), key.key_ops))
  use _ <- result.try(validate_rfc8037_key_use(key.material, Some(use_)))
  Ok(Jwk(..key, key_use: Some(use_)))
}

/// Validate key use against RFC 8037 curve restrictions.
/// - EdDSA keys (Ed25519/Ed448): only `sig` allowed
/// - XDH keys (X25519/X448): only `enc` allowed
fn validate_rfc8037_key_use(
  material: KeyMaterial,
  use_: Option(KeyUse),
) -> Result(Nil, gose.GoseError) {
  case material, use_ {
    Eddsa(..), Some(Encrypting) ->
      Error(gose.InvalidState(
        "EdDSA keys (Ed25519/Ed448) cannot be used for encryption",
      ))
    Xdh(..), Some(Signing) ->
      Error(gose.InvalidState(
        "XDH keys (X25519/X448) cannot be used for signing",
      ))
    _, _ -> Ok(Nil)
  }
}

/// Set the key ID (`kid`) metadata parameter on a key.
///
/// ## Parameters
///
/// - `key` - The JWK to update.
/// - `kid` - The key identifier string.
///
/// ## Returns
///
/// A new `Jwk` with the `kid` parameter set.
pub fn with_kid(key: Jwk, kid: String) -> Jwk {
  Jwk(..key, kid: Some(kid))
}

fn is_signing_op(op: KeyOp) -> Bool {
  case op {
    Sign | Verify -> True
    Encrypt | Decrypt | WrapKey | UnwrapKey | DeriveKey | DeriveBits -> False
  }
}

fn is_encrypting_op(op: KeyOp) -> Bool {
  case op {
    Encrypt | Decrypt | WrapKey | UnwrapKey | DeriveKey | DeriveBits -> True
    Sign | Verify -> False
  }
}

fn validate_key_use_ops(
  key_use: Option(KeyUse),
  key_ops: Option(List(KeyOp)),
) -> Result(Nil, gose.GoseError) {
  case key_use, key_ops {
    None, _ | _, None -> Ok(Nil)
    Some(Signing), Some(ops) ->
      case list.all(ops, is_signing_op) {
        True -> Ok(Nil)
        False -> Error(gose.InvalidState("key_ops incompatible with use=sig"))
      }
    Some(Encrypting), Some(ops) ->
      case list.all(ops, is_encrypting_op) {
        True -> Ok(Nil)
        False -> Error(gose.InvalidState("key_ops incompatible with use=enc"))
      }
  }
}

/// Get the algorithm (`alg`) parameter.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(Alg)` with the algorithm, or `Error(Nil)` if no algorithm was set
/// on the key.
pub fn alg(key: Jwk) -> Result(Alg, Nil) {
  option.to_result(key.alg, Nil)
}

/// Get the curve used by an EC key.
///
/// Returns an error if the key is not an EC key.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(ec.Curve)` with the EC curve, or `Error(InvalidState)` if the key
/// is not an EC key.
pub fn ec_curve(key: Jwk) -> Result(ec.Curve, gose.GoseError) {
  material_ec(key.material)
  |> result.map(fn(ec) {
    case ec {
      EcPrivate(curve:, ..) | EcPublic(curve:, ..) -> curve
    }
  })
}

/// Extract the EC public key.
///
/// Works with both EC private keys (extracts the public component)
/// and EC public keys.
///
/// Returns an error if the key is not an EC key.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(ec.PublicKey)` with the EC public key, or `Error(InvalidState)` if
/// the key is not an EC key.
pub fn ec_public_key(key: Jwk) -> Result(ec.PublicKey, gose.GoseError) {
  material_ec(key.material)
  |> result.map(fn(ec) {
    case ec {
      EcPrivate(public:, ..) -> public
      EcPublic(key: k, ..) -> k
    }
  })
}

/// Get the x and y coordinates from an EC public key.
///
/// The coordinates are returned as raw big-endian bytes, padded to
/// the coordinate size for the curve.
///
/// Returns an error if the key is not an EC key.
///
/// ## Parameters
///
/// - `key` - The EC key to extract coordinates from.
///
/// ## Returns
///
/// `Ok(#(BitArray, BitArray))` with the `(x, y)` coordinate pair, or
/// `Error(InvalidState)` if the key is not an EC key.
pub fn ec_public_key_coordinates(
  key: Jwk,
) -> Result(#(BitArray, BitArray), gose.GoseError) {
  use public <- result.try(ec_public_key(key))
  use curve <- result.try(ec_curve(key))
  utils.ec_public_key_coordinates(public, curve)
}

/// Get the curve used by an EdDSA key.
///
/// Returns an error if the key is not an EdDSA key.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(eddsa.Curve)` with the EdDSA curve, or `Error(InvalidState)` if
/// the key is not an EdDSA key.
pub fn eddsa_curve(key: Jwk) -> Result(eddsa.Curve, gose.GoseError) {
  material_eddsa(key.material)
  |> result.map(fn(eddsa) {
    case eddsa {
      EddsaPrivate(curve:, ..) | EddsaPublic(curve:, ..) -> curve
    }
  })
}

/// Extract the EdDSA public key.
///
/// Works with both EdDSA private keys (extracts the public component)
/// and EdDSA public keys.
///
/// Returns an error if the key is not an EdDSA key.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(eddsa.PublicKey)` with the EdDSA public key, or
/// `Error(InvalidState)` if the key is not an EdDSA key.
pub fn eddsa_public_key(key: Jwk) -> Result(eddsa.PublicKey, gose.GoseError) {
  material_eddsa(key.material)
  |> result.map(fn(eddsa) {
    case eddsa {
      EddsaPrivate(public:, ..) -> public
      EddsaPublic(key: k, ..) -> k
    }
  })
}

/// Get the key operations parameter.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(List(KeyOp))` with the operations, or `Error(Nil)` if no operations
/// were set on the key.
pub fn key_ops(key: Jwk) -> Result(List(KeyOp), Nil) {
  option.to_result(key.key_ops, Nil)
}

/// Get the key type (kty) for this key.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// The `KeyType` variant (`OctKeyType`, `RsaKeyType`, `EcKeyType`, or
/// `OkpKeyType`).
pub fn key_type(key: Jwk) -> KeyType {
  case key.material {
    OctetKey(..) -> OctKeyType
    Rsa(..) -> RsaKeyType
    Ec(..) -> EcKeyType
    Eddsa(..) | Xdh(..) -> OkpKeyType
  }
}

/// Get the public key use parameter.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(KeyUse)` with the use (`Signing` or `Encrypting`), or `Error(Nil)`
/// if no use was set on the key.
pub fn key_use(key: Jwk) -> Result(KeyUse, Nil) {
  option.to_result(key.key_use, Nil)
}

/// Get the key ID (kid) parameter.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(String)` with the key ID, or `Error(Nil)` if no key ID was set on
/// the key.
pub fn kid(key: Jwk) -> Result(String, Nil) {
  option.to_result(key.kid, Nil)
}

/// Get the size of an octet (symmetric) key in bytes.
///
/// Returns an error if the key is not an octet key.
///
/// ## Parameters
///
/// - `key` - The octet key to measure.
///
/// ## Returns
///
/// `Ok(Int)` with the key size in bytes, or `Error(InvalidState)` if the
/// key is not an octet key.
pub fn octet_key_size(key: Jwk) -> Result(Int, gose.GoseError) {
  case material_octet_secret(key.material) {
    Ok(secret) -> Ok(bit_array.byte_size(secret))
    Error(_) -> Error(gose.InvalidState("key is not an octet key"))
  }
}

/// Extract the RSA public key.
///
/// Works with both RSA private keys (extracts the public component)
/// and RSA public keys.
///
/// Returns an error if the key is not an RSA key.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(rsa.PublicKey)` with the RSA public key, or `Error(InvalidState)`
/// if the key is not an RSA key.
pub fn rsa_public_key(key: Jwk) -> Result(rsa.PublicKey, gose.GoseError) {
  material_rsa(key.material)
  |> result.map(fn(rsa) {
    case rsa {
      RsaPrivate(public:, ..) -> public
      RsaPublic(key: k) -> k
    }
  })
}

/// Get the curve used by an XDH key.
///
/// Returns an error if the key is not an XDH key.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(xdh.Curve)` with the XDH curve, or `Error(InvalidState)` if the
/// key is not an XDH key.
pub fn xdh_curve(key: Jwk) -> Result(xdh.Curve, gose.GoseError) {
  material_xdh(key.material)
  |> result.map(fn(xdh) {
    case xdh {
      XdhPrivate(curve:, ..) | XdhPublic(curve:, ..) -> curve
    }
  })
}

/// Extract the XDH public key (X25519/X448).
///
/// Works with both XDH private keys (extracts the public component)
/// and XDH public keys.
///
/// Returns an error if the key is not an XDH key.
///
/// ## Parameters
///
/// - `key` - The JWK to query.
///
/// ## Returns
///
/// `Ok(xdh.PublicKey)` with the XDH public key, or `Error(InvalidState)`
/// if the key is not an XDH key.
pub fn xdh_public_key(key: Jwk) -> Result(xdh.PublicKey, gose.GoseError) {
  material_xdh(key.material)
  |> result.map(fn(xdh) {
    case xdh {
      XdhPrivate(public:, ..) -> public
      XdhPublic(key: k, ..) -> k
    }
  })
}

/// Extract the public key from an asymmetric key.
///
/// For private keys, extracts the corresponding public key.
/// For public keys, returns the key unchanged.
///
/// When extracting a public key, `key_ops` are filtered to public-safe operations:
/// - `Sign` is mapped to `Verify`
/// - `Decrypt` and `UnwrapKey` are removed (private-only)
/// - Other operations are preserved
///
/// ## Parameters
///
/// - `key` - The JWK to extract the public key from.
///
/// ## Returns
///
/// `Ok(Jwk)` with the public key, or `Error(InvalidState)` if the key is
/// a symmetric octet key.
///
/// ## Example
///
/// ```gleam
/// let private_key = jwk.generate_ec(ec.P256)
/// let assert Ok(pub_key) = jwk.public_key(private_key)
/// ```
pub fn public_key(key: Jwk) -> Result(Jwk, gose.GoseError) {
  let filtered_ops =
    key.key_ops
    |> option.map(filter_public_key_ops)
    |> option.then(option.from_result)
  case key.material {
    Rsa(RsaPrivate(public:, ..)) ->
      Ok(
        Jwk(..key, material: Rsa(RsaPublic(key: public)), key_ops: filtered_ops),
      )
    Rsa(RsaPublic(..)) -> Ok(Jwk(..key, key_ops: filtered_ops))
    Ec(EcPrivate(public:, curve:, ..)) ->
      Ok(
        Jwk(
          ..key,
          material: Ec(EcPublic(key: public, curve:)),
          key_ops: filtered_ops,
        ),
      )
    Ec(EcPublic(..)) -> Ok(Jwk(..key, key_ops: filtered_ops))
    Eddsa(EddsaPrivate(public:, curve:, ..)) ->
      Ok(
        Jwk(
          ..key,
          material: Eddsa(EddsaPublic(key: public, curve:)),
          key_ops: filtered_ops,
        ),
      )
    Eddsa(EddsaPublic(..)) -> Ok(Jwk(..key, key_ops: filtered_ops))
    Xdh(XdhPrivate(public:, curve:, ..)) ->
      Ok(
        Jwk(
          ..key,
          material: Xdh(XdhPublic(key: public, curve:)),
          key_ops: filtered_ops,
        ),
      )
    Xdh(XdhPublic(..)) -> Ok(Jwk(..key, key_ops: filtered_ops))
    OctetKey(..) -> Error(gose.InvalidState("octet keys are not asymmetric"))
  }
}

fn filter_public_key_ops(ops: List(KeyOp)) -> Result(List(KeyOp), Nil) {
  case list.unique(list.filter_map(ops, map_public_key_op)) {
    [] -> Error(Nil)
    filtered -> Ok(filtered)
  }
}

fn map_public_key_op(op: KeyOp) -> Result(KeyOp, Nil) {
  case op {
    Sign -> Ok(Verify)
    Decrypt | UnwrapKey -> Error(Nil)
    Verify | Encrypt | WrapKey | DeriveKey | DeriveBits -> Ok(op)
  }
}

/// Compute the JWK Thumbprint (RFC 7638).
///
/// The thumbprint is a base64url-encoded hash of the canonical JSON
/// representation containing only the required public key members.
/// Private keys produce the same thumbprint as their corresponding public keys.
///
/// RFC 7638 specifies SHA-256 as the default hash, but allows other algorithms.
///
/// ## Parameters
///
/// - `key` - The key to compute the thumbprint for.
/// - `algorithm` - The hash algorithm to use (e.g. `hash.Sha256`).
///
/// ## Returns
///
/// `Ok(String)` with the base64url-encoded thumbprint, or
/// `Error(CryptoError)` if the hash algorithm is not supported.
///
/// ## Example
///
/// ```gleam
/// let key = jwk.generate_ec(ec.P256)
/// let assert Ok(thumbprint) = jwk.thumbprint(key, hash.Sha256)
/// ```
pub fn thumbprint(
  key: Jwk,
  algorithm: hash.HashAlgorithm,
) -> Result(String, gose.GoseError) {
  use json_str <- result.try(thumbprint_json(key))
  bit_array.from_string(json_str)
  |> crypto.hash(algorithm, _)
  |> result.replace_error(gose.CryptoError("hash algorithm not supported"))
  |> result.map(utils.encode_base64_url)
}

fn thumbprint_json(key: Jwk) -> Result(String, gose.GoseError) {
  // RFC 7638 3.2: members in lexicographic order for canonical form
  case key.material {
    Ec(EcPrivate(public:, curve:, ..)) | Ec(EcPublic(key: public, curve:)) -> {
      use #(x, y) <- result.try(utils.ec_public_key_coordinates(public, curve))
      let crv = utils.ec_curve_to_string(curve)
      let x_b64 = utils.encode_base64_url(x)
      let y_b64 = utils.encode_base64_url(y)
      Ok(
        "{\"crv\":\""
        <> crv
        <> "\",\"kty\":\"EC\",\"x\":\""
        <> x_b64
        <> "\",\"y\":\""
        <> y_b64
        <> "\"}",
      )
    }
    Rsa(RsaPrivate(public:, ..)) | Rsa(RsaPublic(key: public)) -> {
      let e =
        rsa.public_key_exponent_bytes(public)
        |> utils.strip_leading_zeros
        |> utils.encode_base64_url()
      let n =
        rsa.public_key_modulus(public)
        |> utils.strip_leading_zeros
        |> utils.encode_base64_url()
      Ok("{\"e\":\"" <> e <> "\",\"kty\":\"RSA\",\"n\":\"" <> n <> "\"}")
    }
    Eddsa(EddsaPrivate(public:, curve:, ..))
    | Eddsa(EddsaPublic(key: public, curve:)) -> {
      let crv = utils.eddsa_curve_to_string(curve)
      let x = eddsa.public_key_to_bytes(public) |> utils.encode_base64_url()
      Ok("{\"crv\":\"" <> crv <> "\",\"kty\":\"OKP\",\"x\":\"" <> x <> "\"}")
    }
    Xdh(XdhPrivate(public:, curve:, ..)) | Xdh(XdhPublic(key: public, curve:)) -> {
      let crv = utils.xdh_curve_to_string(curve)
      let x = xdh.public_key_to_bytes(public) |> utils.encode_base64_url()
      Ok("{\"crv\":\"" <> crv <> "\",\"kty\":\"OKP\",\"x\":\"" <> x <> "\"}")
    }
    OctetKey(secret:) -> {
      let k = utils.encode_base64_url(secret)
      Ok("{\"k\":\"" <> k <> "\",\"kty\":\"oct\"}")
    }
  }
}

/// Convert an algorithm (JWS or JWE) to its RFC string representation.
///
/// ## Parameters
///
/// - `alg` - The algorithm variant to convert.
///
/// ## Returns
///
/// The RFC string name (e.g. `"RS256"`, `"A128KW"`).
pub fn alg_to_string(alg: Alg) -> String {
  case alg {
    Jws(jws_alg) -> jwa.jws_alg_to_string(jws_alg)
    Jwe(jwe_alg) -> jwa.jwe_alg_to_string(jwe_alg)
  }
}

/// Serialize a JWK to DER format.
///
/// Supports RSA, EC, EdDSA, and XDH keys (both private and public).
/// Uses PKCS#8 for private keys and SPKI for public keys.
///
/// ## Parameters
///
/// - `key` - The JWK to serialize.
///
/// ## Returns
///
/// `Ok(BitArray)` with the DER-encoded key, or `Error(InvalidState)` if
/// the key is a symmetric octet key or serialization fails.
pub fn to_der(key: Jwk) -> Result(BitArray, gose.GoseError) {
  case key.material {
    Rsa(RsaPrivate(key: private, ..)) ->
      rsa.to_der(private, rsa.Pkcs8)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize RSA private key",
      ))
    Rsa(RsaPublic(key: public)) ->
      rsa.public_key_to_der(public, rsa.Spki)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize RSA public key",
      ))
    Ec(EcPrivate(key: private, ..)) ->
      ec.to_der(private)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize EC private key",
      ))
    Ec(EcPublic(key: public, ..)) ->
      ec.public_key_to_der(public)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize EC public key",
      ))
    Eddsa(EddsaPrivate(key: private, ..)) ->
      eddsa.to_der(private)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize EdDSA private key",
      ))
    Eddsa(EddsaPublic(key: public, ..)) ->
      eddsa.public_key_to_der(public)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize EdDSA public key",
      ))
    Xdh(XdhPrivate(key: private, ..)) ->
      xdh.to_der(private)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize XDH private key",
      ))
    Xdh(XdhPublic(key: public, ..)) ->
      xdh.public_key_to_der(public)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize XDH public key",
      ))
    OctetKey(..) ->
      Error(gose.InvalidState("octet keys cannot be serialized to DER"))
  }
}

/// Serialize a JWK to its JSON representation.
///
/// ## Parameters
///
/// - `key` - The JWK to serialize.
///
/// ## Returns
///
/// A `json.Json` value representing the key in JWK JSON format.
pub fn to_json(key: Jwk) -> json.Json {
  let base_fields = case key.material {
    Eddsa(EddsaPrivate(key: private, public:, curve:)) -> {
      let x_bits = eddsa.public_key_to_bytes(public)
      let d_bits = eddsa.to_bytes(private)
      [
        #("kty", json.string("OKP")),
        #("crv", json.string(utils.eddsa_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x_bits))),
        #("d", json.string(utils.encode_base64_url(d_bits))),
      ]
    }
    Eddsa(EddsaPublic(key: public, curve:)) -> {
      let x_bits = eddsa.public_key_to_bytes(public)
      [
        #("kty", json.string("OKP")),
        #("crv", json.string(utils.eddsa_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x_bits))),
      ]
    }
    OctetKey(secret:) -> [
      #("kty", json.string("oct")),
      #("k", json.string(utils.encode_base64_url(secret))),
    ]
    Rsa(RsaPrivate(key: private, ..)) -> [
      #("kty", json.string("RSA")),
      #(
        "n",
        rsa.modulus(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "e",
        rsa.public_exponent_bytes(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "d",
        rsa.private_exponent_bytes(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "p",
        rsa.prime1(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "q",
        rsa.prime2(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "dp",
        rsa.exponent1(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "dq",
        rsa.exponent2(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "qi",
        rsa.coefficient(private)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
    ]
    Rsa(RsaPublic(key: public)) -> [
      #("kty", json.string("RSA")),
      #(
        "n",
        rsa.public_key_modulus(public)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
      #(
        "e",
        rsa.public_key_exponent_bytes(public)
          |> utils.strip_leading_zeros
          |> utils.encode_base64_url()
          |> json.string,
      ),
    ]
    Ec(EcPrivate(key: private, public:, curve:)) -> {
      // Safe: all constructors validate the public key against the curve
      let assert Ok(#(x, y)) = utils.ec_public_key_coordinates(public, curve)
      let d_bits = ec.to_bytes(private)
      [
        #("kty", json.string("EC")),
        #("crv", json.string(utils.ec_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x))),
        #("y", json.string(utils.encode_base64_url(y))),
        #("d", json.string(utils.encode_base64_url(d_bits))),
      ]
    }
    Ec(EcPublic(key: public, curve:)) -> {
      // Safe: all constructors validate the public key against the curve
      let assert Ok(#(x, y)) = utils.ec_public_key_coordinates(public, curve)
      [
        #("kty", json.string("EC")),
        #("crv", json.string(utils.ec_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x))),
        #("y", json.string(utils.encode_base64_url(y))),
      ]
    }
    Xdh(XdhPrivate(key: private, public:, curve:)) -> {
      let x_bits = xdh.public_key_to_bytes(public)
      let d_bits = xdh.to_bytes(private)
      [
        #("kty", json.string("OKP")),
        #("crv", json.string(utils.xdh_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x_bits))),
        #("d", json.string(utils.encode_base64_url(d_bits))),
      ]
    }
    Xdh(XdhPublic(key: public, curve:)) -> {
      let x_bits = xdh.public_key_to_bytes(public)
      [
        #("kty", json.string("OKP")),
        #("crv", json.string(utils.xdh_curve_to_string(curve))),
        #("x", json.string(utils.encode_base64_url(x_bits))),
      ]
    }
  }

  json.object(list.append(base_fields, metadata_fields(key)))
}

fn alg_fields(alg: Option(Alg)) -> List(#(String, json.Json)) {
  case alg {
    Some(a) -> [#("alg", json.string(alg_to_string(a)))]
    None -> []
  }
}

fn key_op_to_string(op: KeyOp) -> String {
  case op {
    Sign -> "sign"
    Verify -> "verify"
    Encrypt -> "encrypt"
    Decrypt -> "decrypt"
    WrapKey -> "wrapKey"
    UnwrapKey -> "unwrapKey"
    DeriveKey -> "deriveKey"
    DeriveBits -> "deriveBits"
  }
}

fn key_ops_fields(key_ops: Option(List(KeyOp))) -> List(#(String, json.Json)) {
  case key_ops {
    Some(ops) -> [
      #(
        "key_ops",
        json.array(ops, fn(op) { json.string(key_op_to_string(op)) }),
      ),
    ]
    None -> []
  }
}

fn key_use_fields(key_use: Option(KeyUse)) -> List(#(String, json.Json)) {
  case key_use {
    Some(u) -> [#("use", json.string(key_use_to_string(u)))]
    None -> []
  }
}

fn key_use_to_string(key_use: KeyUse) -> String {
  case key_use {
    Signing -> "sig"
    Encrypting -> "enc"
  }
}

fn kid_fields(kid: Option(String)) -> List(#(String, json.Json)) {
  case kid {
    Some(k) -> [#("kid", json.string(k))]
    None -> []
  }
}

fn metadata_fields(key: Jwk) -> List(#(String, json.Json)) {
  list.flatten([
    kid_fields(key.kid),
    key_use_fields(key.key_use),
    key_ops_fields(key.key_ops),
    alg_fields(key.alg),
  ])
}

/// Export the raw bytes of a key.
///
/// Supported key types:
/// - Octet keys: returns the secret bytes
/// - EdDSA/XDH private keys: returns the private key bytes (d)
/// - EdDSA/XDH public keys: returns the public key bytes (x)
///
/// ## Parameters
///
/// - `key` - The JWK to export.
///
/// ## Returns
///
/// `Ok(BitArray)` with the raw key bytes, or `Error(InvalidState)` for RSA
/// and EC keys which have no single-value byte representation.
pub fn to_octet_bits(key: Jwk) -> Result(BitArray, gose.GoseError) {
  case key.material {
    OctetKey(secret:) -> Ok(secret)
    Eddsa(EddsaPrivate(key: private, ..)) -> Ok(eddsa.to_bytes(private))
    Eddsa(EddsaPublic(key: public, ..)) -> Ok(eddsa.public_key_to_bytes(public))
    Xdh(XdhPrivate(key: private, ..)) -> Ok(xdh.to_bytes(private))
    Xdh(XdhPublic(key: public, ..)) -> Ok(xdh.public_key_to_bytes(public))
    Rsa(..) | Ec(..) ->
      Error(gose.InvalidState("key has no single-value byte representation"))
  }
}

/// Serialize a JWK to PEM format.
///
/// Supports RSA, EC, EdDSA, and XDH keys (both private and public).
/// Uses PKCS#8 for private keys and SPKI for public keys.
///
/// ## Parameters
///
/// - `key` - The JWK to serialize.
///
/// ## Returns
///
/// `Ok(String)` with the PEM-encoded key, or `Error(InvalidState)` if the
/// key is a symmetric octet key or serialization fails.
pub fn to_pem(key: Jwk) -> Result(String, gose.GoseError) {
  case key.material {
    Rsa(RsaPrivate(key: private, ..)) ->
      rsa.to_pem(private, rsa.Pkcs8)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize RSA private key",
      ))
    Rsa(RsaPublic(key: public)) ->
      rsa.public_key_to_pem(public, rsa.Spki)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize RSA public key",
      ))
    Ec(EcPrivate(key: private, ..)) ->
      ec.to_pem(private)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize EC private key",
      ))
    Ec(EcPublic(key: public, ..)) ->
      ec.public_key_to_pem(public)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize EC public key",
      ))
    Eddsa(EddsaPrivate(key: private, ..)) ->
      eddsa.to_pem(private)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize EdDSA private key",
      ))
    Eddsa(EddsaPublic(key: public, ..)) ->
      eddsa.public_key_to_pem(public)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize EdDSA public key",
      ))
    Xdh(XdhPrivate(key: private, ..)) ->
      xdh.to_pem(private)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize XDH private key",
      ))
    Xdh(XdhPublic(key: public, ..)) ->
      xdh.public_key_to_pem(public)
      |> result.replace_error(gose.InvalidState(
        "failed to serialize XDH public key",
      ))
    OctetKey(..) ->
      Error(gose.InvalidState("octet keys cannot be serialized to PEM"))
  }
}

/// Parse an algorithm from its RFC string representation.
///
/// ## Parameters
///
/// - `s` - The RFC algorithm name (e.g. `"RS256"`, `"A128KW"`).
///
/// ## Returns
///
/// `Ok(Alg)` with the parsed algorithm, or `Error(ParseError)` if the
/// string is not a recognized algorithm name.
pub fn alg_from_string(s: String) -> Result(Alg, gose.GoseError) {
  jwa.jws_alg_from_string(s)
  |> result.map(Jws)
  |> result.lazy_or(fn() {
    jwa.jwe_alg_from_string(s)
    |> result.map(Jwe)
  })
  |> result.replace_error(gose.ParseError("unknown algorithm: " <> s))
}

fn reject_x509_params(dyn: decode.Dynamic) -> Result(Nil, gose.GoseError) {
  let x509_fields = ["x5u", "x5c", "x5t", "x5t#S256"]
  let dict_decoder = decode.dict(decode.string, decode.dynamic)
  let fields_dict =
    decode.run(dyn, dict_decoder)
    |> result.unwrap(dict.new())
  list.try_each(x509_fields, fn(field) {
    case dict.has_key(fields_dict, field) {
      True ->
        Error(gose.ParseError("unsupported X.509 JWK parameter: " <> field))
      False -> Ok(Nil)
    }
  })
}

/// Parse a JWK from a Dynamic value (decoded JSON).
@internal
pub fn from_dynamic(dyn: decode.Dynamic) -> Result(Jwk, gose.GoseError) {
  use _ <- result.try(reject_x509_params(dyn))
  let kty_decoder = decode.at(["kty"], decode.string)
  use kty <- result.try(
    decode.run(dyn, kty_decoder)
    |> result.replace_error(gose.ParseError("missing or invalid kty")),
  )
  case kty {
    "OKP" -> parse_okp_dynamic(dyn)
    "oct" -> parse_oct_dynamic(dyn)
    "RSA" -> parse_rsa_dynamic(dyn)
    "EC" -> parse_ec_dynamic(dyn)
    _ -> Error(gose.ParseError("unsupported kty: " <> kty))
  }
}

/// Parse a JWK from JSON.
///
/// ## Parameters
///
/// - `json_str` - A JSON string containing the JWK.
///
/// ## Returns
///
/// `Ok(Jwk)` with the parsed key, or `Error(ParseError)` if the JSON is
/// invalid or not a recognized JWK.
pub fn from_json(json_str: String) -> Result(Jwk, gose.GoseError) {
  use dyn <- result.try(
    json.parse(json_str, decode.dynamic)
    |> result.replace_error(gose.ParseError("invalid JSON")),
  )
  from_dynamic(dyn)
}

/// Parse a JWK from JSON provided as a `BitArray`.
///
/// ## Parameters
///
/// - `json_bits` - A `BitArray` containing the JSON-encoded JWK.
///
/// ## Returns
///
/// `Ok(Jwk)` with the parsed key, or `Error(ParseError)` if the JSON is
/// invalid or not a recognized JWK.
pub fn from_json_bits(json_bits: BitArray) -> Result(Jwk, gose.GoseError) {
  use dyn <- result.try(
    json.parse_bits(json_bits, decode.dynamic)
    |> result.replace_error(gose.ParseError("invalid JSON")),
  )
  from_dynamic(dyn)
}

/// Return a decoder for JWK values.
///
/// This lets you compose JWK decoding inside larger decode pipelines, for
/// example with `decode.field`, `decode.list`, or `json.parse`.
///
/// ## Returns
///
/// A `Decoder(Jwk)` that succeeds on valid JWK JSON objects and fails on
/// anything else.
///
/// ## Example
///
/// ```gleam
/// // Parse a JWK directly from a JSON string
/// let assert Ok(key) = json.parse(json_string, jwk.decoder())
///
/// // Use inside a larger decoder
/// use key <- decode.field("signing_key", jwk.decoder())
/// ```
pub fn decoder() -> decode.Decoder(Jwk) {
  let placeholder =
    Jwk(
      material: OctetKey(secret: <<>>),
      kid: None,
      key_use: None,
      key_ops: None,
      alg: None,
    )
  decode.new_primitive_decoder("Jwk", fn(dyn) {
    from_dynamic(dyn)
    |> result.replace_error(placeholder)
  })
}

fn key_op_from_string(s: String) -> Result(KeyOp, gose.GoseError) {
  case s {
    "sign" -> Ok(Sign)
    "verify" -> Ok(Verify)
    "encrypt" -> Ok(Encrypt)
    "decrypt" -> Ok(Decrypt)
    "wrapKey" -> Ok(WrapKey)
    "unwrapKey" -> Ok(UnwrapKey)
    "deriveKey" -> Ok(DeriveKey)
    "deriveBits" -> Ok(DeriveBits)
    _ -> Error(gose.ParseError("invalid key_ops value: " <> s))
  }
}

fn key_use_from_string(s: String) -> Result(KeyUse, gose.GoseError) {
  case s {
    "sig" -> Ok(Signing)
    "enc" -> Ok(Encrypting)
    _ -> Error(gose.ParseError("invalid use value: " <> s))
  }
}

fn parse_key_metadata(
  use_opt: Option(String),
  key_ops_opt: Option(List(String)),
  alg_opt: Option(String),
) -> Result(#(Option(KeyUse), Option(List(KeyOp)), Option(Alg)), gose.GoseError) {
  use key_use <- result.try(parse_optional(use_opt, key_use_from_string))
  use key_ops <- result.try(parse_optional(key_ops_opt, parse_key_ops))
  use alg <- result.try(parse_optional(alg_opt, alg_from_string))
  use _ <- result.try(validate_key_use_ops(key_use, key_ops))
  Ok(#(key_use, key_ops, alg))
}

fn parse_key_ops(ops: List(String)) -> Result(List(KeyOp), gose.GoseError) {
  use <- bool.guard(
    when: list.is_empty(ops),
    return: Error(gose.ParseError("key_ops must not be empty")),
  )
  use parsed <- result.try(list.try_map(ops, key_op_from_string))
  case list.unique(parsed) != parsed {
    True -> Error(gose.ParseError("key_ops must not contain duplicates"))
    False -> Ok(parsed)
  }
}

fn parse_optional(
  opt: Option(a),
  parser: fn(a) -> Result(b, gose.GoseError),
) -> Result(Option(b), gose.GoseError) {
  case opt {
    None -> Ok(None)
    Some(value) -> result.map(parser(value), Some)
  }
}

type EcDecoded {
  EcDecoded(
    crv: String,
    x: String,
    y: String,
    d: Option(String),
    kid: Option(String),
    use_: Option(String),
    key_ops: Option(List(String)),
    alg: Option(String),
  )
}

fn ec_decoder() -> decode.Decoder(EcDecoded) {
  use crv <- decode.field("crv", decode.string)
  use x <- decode.field("x", decode.string)
  use y <- decode.field("y", decode.string)
  use d <- decode.optional_field("d", None, decode.optional(decode.string))
  use kid <- decode.optional_field("kid", None, decode.optional(decode.string))
  use use_ <- decode.optional_field("use", None, decode.optional(decode.string))
  use key_ops <- decode.optional_field(
    "key_ops",
    None,
    decode.optional(decode.list(decode.string)),
  )
  use alg <- decode.optional_field("alg", None, decode.optional(decode.string))
  decode.success(EcDecoded(crv:, x:, y:, d:, kid:, use_:, key_ops:, alg:))
}

fn parse_ec_dynamic(dyn: decode.Dynamic) -> Result(Jwk, gose.GoseError) {
  use decoded <- result.try(
    decode.run(dyn, ec_decoder())
    |> result.replace_error(gose.ParseError("invalid EC JSON")),
  )
  process_ec_decoded(decoded)
}

fn process_ec_decoded(decoded: EcDecoded) -> Result(Jwk, gose.GoseError) {
  let EcDecoded(crv, x_b64, y_b64, d_opt, kid, use_opt, key_ops_opt, alg_opt) =
    decoded
  use curve <- result.try(utils.ec_curve_from_string(crv))
  use x_bits <- result.try(utils.decode_base64_url(x_b64, "x"))
  use y_bits <- result.try(utils.decode_base64_url(y_b64, "y"))
  use #(key_use, key_ops, alg) <- result.try(parse_key_metadata(
    use_opt,
    key_ops_opt,
    alg_opt,
  ))

  let coord_size = ec.coordinate_size(curve)
  use <- bool.guard(
    when: bit_array.byte_size(x_bits) != coord_size,
    return: Error(gose.ParseError(
      "EC x coordinate must be " <> int.to_string(coord_size) <> " bytes",
    )),
  )
  use <- bool.guard(
    when: bit_array.byte_size(y_bits) != coord_size,
    return: Error(gose.ParseError(
      "EC y coordinate must be " <> int.to_string(coord_size) <> " bytes",
    )),
  )
  let raw_point = bit_array.concat([<<0x04>>, x_bits, y_bits])

  case d_opt {
    Some(d_b64) -> {
      use d_bits <- result.try(utils.decode_base64_url(d_b64, "d"))
      use #(private, public) <- result.try(
        ec.from_bytes(curve, d_bits)
        |> result.replace_error(gose.ParseError("invalid EC private key bytes")),
      )

      let computed_point = ec.public_key_to_raw_point(public)
      use <- bool.guard(
        when: !crypto.constant_time_equal(computed_point, raw_point),
        return: Error(gose.ParseError("x/y do not match computed public key")),
      )
      Ok(Jwk(
        material: Ec(EcPrivate(key: private, public:, curve:)),
        kid:,
        key_use:,
        key_ops:,
        alg:,
      ))
    }
    None -> {
      use public <- result.try(
        ec.public_key_from_raw_point(curve, raw_point)
        |> result.replace_error(gose.ParseError(
          "invalid EC public key coordinates",
        )),
      )
      Ok(Jwk(
        material: Ec(EcPublic(key: public, curve:)),
        kid:,
        key_use:,
        key_ops:,
        alg:,
      ))
    }
  }
}

type OctDecoded {
  OctDecoded(
    k: String,
    kid: Option(String),
    use_: Option(String),
    key_ops: Option(List(String)),
    alg: Option(String),
  )
}

fn oct_decoder() -> decode.Decoder(OctDecoded) {
  use k <- decode.field("k", decode.string)
  use kid <- decode.optional_field("kid", None, decode.optional(decode.string))
  use use_ <- decode.optional_field("use", None, decode.optional(decode.string))
  use key_ops <- decode.optional_field(
    "key_ops",
    None,
    decode.optional(decode.list(decode.string)),
  )
  use alg <- decode.optional_field("alg", None, decode.optional(decode.string))
  decode.success(OctDecoded(k:, kid:, use_:, key_ops:, alg:))
}

fn parse_oct_dynamic(dyn: decode.Dynamic) -> Result(Jwk, gose.GoseError) {
  use decoded <- result.try(
    decode.run(dyn, oct_decoder())
    |> result.replace_error(gose.ParseError("invalid oct JSON")),
  )
  process_oct_decoded(decoded)
}

fn process_oct_decoded(decoded: OctDecoded) -> Result(Jwk, gose.GoseError) {
  let OctDecoded(k_b64, kid, use_opt, key_ops_opt, alg_opt) = decoded
  use secret <- result.try(utils.decode_base64_url(k_b64, "k"))
  use #(key_use, key_ops, alg) <- result.try(parse_key_metadata(
    use_opt,
    key_ops_opt,
    alg_opt,
  ))

  case bit_array.byte_size(secret) == 0 {
    True -> Error(gose.ParseError("oct key must not be empty"))
    False ->
      Ok(Jwk(material: OctetKey(secret:), kid:, key_use:, key_ops:, alg:))
  }
}

type OkpDecoded {
  OkpDecoded(
    crv: String,
    x: String,
    d: Option(String),
    kid: Option(String),
    use_: Option(String),
    key_ops: Option(List(String)),
    alg: Option(String),
  )
}

fn okp_decoder() -> decode.Decoder(OkpDecoded) {
  use crv <- decode.field("crv", decode.string)
  use x <- decode.field("x", decode.string)
  use d <- decode.optional_field("d", None, decode.optional(decode.string))
  use kid <- decode.optional_field("kid", None, decode.optional(decode.string))
  use use_ <- decode.optional_field("use", None, decode.optional(decode.string))
  use key_ops <- decode.optional_field(
    "key_ops",
    None,
    decode.optional(decode.list(decode.string)),
  )
  use alg <- decode.optional_field("alg", None, decode.optional(decode.string))
  decode.success(OkpDecoded(crv:, x:, d:, kid:, use_:, key_ops:, alg:))
}

fn parse_okp_dynamic(dyn: decode.Dynamic) -> Result(Jwk, gose.GoseError) {
  use decoded <- result.try(
    decode.run(dyn, okp_decoder())
    |> result.replace_error(gose.ParseError("invalid OKP JSON")),
  )
  process_okp_decoded(decoded)
}

fn process_okp_decoded(decoded: OkpDecoded) -> Result(Jwk, gose.GoseError) {
  let OkpDecoded(crv, x_b64, d_opt, kid, use_opt, key_ops_opt, alg_opt) =
    decoded

  use x_bits <- result.try(utils.decode_base64_url(x_b64, "x"))
  use #(key_use, key_ops, alg) <- result.try(parse_key_metadata(
    use_opt,
    key_ops_opt,
    alg_opt,
  ))

  case utils.eddsa_curve_from_string(crv) {
    Ok(eddsa_curve) ->
      parse_eddsa_okp_json(
        eddsa_curve,
        x_bits,
        d_opt,
        kid,
        key_use,
        key_ops,
        alg,
      )
    Error(_) ->
      case utils.xdh_curve_from_string(crv) {
        Ok(xdh_curve) ->
          parse_xdh_okp_json(
            xdh_curve,
            x_bits,
            d_opt,
            kid,
            key_use,
            key_ops,
            alg,
          )
        Error(_) -> Error(gose.ParseError("unsupported OKP curve: " <> crv))
      }
  }
}

fn build_eddsa_material(
  curve: eddsa.Curve,
  x_bits: BitArray,
  d_opt: Option(String),
) -> Result(KeyMaterial, gose.GoseError) {
  case d_opt {
    Some(d_b64) -> {
      use d_bits <- result.try(utils.decode_base64_url(d_b64, "d"))
      use #(private, public) <- result.try(
        eddsa.from_bytes(curve, d_bits)
        |> result.replace_error(gose.ParseError("invalid private key bytes")),
      )
      let computed_x = eddsa.public_key_to_bytes(public)
      use <- bool.guard(
        when: !crypto.constant_time_equal(computed_x, x_bits),
        return: Error(gose.ParseError("x does not match computed public key")),
      )
      Ok(Eddsa(EddsaPrivate(key: private, public:, curve:)))
    }
    None -> {
      use public <- result.try(
        eddsa.public_key_from_bytes(curve, x_bits)
        |> result.replace_error(gose.ParseError("invalid public key bytes")),
      )
      Ok(Eddsa(EddsaPublic(key: public, curve:)))
    }
  }
}

fn parse_eddsa_okp_json(
  curve: eddsa.Curve,
  x_bits: BitArray,
  d_opt: Option(String),
  kid: Option(String),
  key_use: Option(KeyUse),
  key_ops: Option(List(KeyOp)),
  alg: Option(Alg),
) -> Result(Jwk, gose.GoseError) {
  use material <- result.try(build_eddsa_material(curve, x_bits, d_opt))
  use _ <- result.try(validate_rfc8037_key_use(material, key_use))
  Ok(Jwk(material:, kid:, key_use:, key_ops:, alg:))
}

fn build_xdh_material(
  curve: xdh.Curve,
  x_bits: BitArray,
  d_opt: Option(String),
) -> Result(KeyMaterial, gose.GoseError) {
  case d_opt {
    Some(d_b64) -> {
      use d_bits <- result.try(utils.decode_base64_url(d_b64, "d"))
      use #(private, public) <- result.try(
        xdh.from_bytes(curve, d_bits)
        |> result.replace_error(gose.ParseError("invalid private key bytes")),
      )
      let computed_x = xdh.public_key_to_bytes(public)
      use <- bool.guard(
        when: !crypto.constant_time_equal(computed_x, x_bits),
        return: Error(gose.ParseError("x does not match computed public key")),
      )
      Ok(Xdh(XdhPrivate(key: private, public:, curve:)))
    }
    None -> {
      use public <- result.try(
        xdh.public_key_from_bytes(curve, x_bits)
        |> result.replace_error(gose.ParseError("invalid public key bytes")),
      )
      Ok(Xdh(XdhPublic(key: public, curve:)))
    }
  }
}

fn parse_xdh_okp_json(
  curve: xdh.Curve,
  x_bits: BitArray,
  d_opt: Option(String),
  kid: Option(String),
  key_use: Option(KeyUse),
  key_ops: Option(List(KeyOp)),
  alg: Option(Alg),
) -> Result(Jwk, gose.GoseError) {
  use material <- result.try(build_xdh_material(curve, x_bits, d_opt))
  use _ <- result.try(validate_rfc8037_key_use(material, key_use))
  Ok(Jwk(material:, kid:, key_use:, key_ops:, alg:))
}

fn parse_rsa_private_key_components(
  n_bits: BitArray,
  e_bits: BitArray,
  d_bits: BitArray,
  p_opt: Option(String),
  q_opt: Option(String),
  dp_opt: Option(String),
  dq_opt: Option(String),
  qi_opt: Option(String),
) -> Result(#(rsa.PrivateKey, rsa.PublicKey), gose.GoseError) {
  let crt_fields = [p_opt, q_opt, dp_opt, dq_opt, qi_opt]
  let crt_present =
    crt_fields
    |> list.filter(option.is_some)
    |> list.length
  use <- bool.guard(
    when: crt_present > 0 && crt_present < 5,
    return: Error(gose.ParseError(
      "partial CRT fields: all five (p, q, dp, dq, qi) are required if any are present",
    )),
  )

  case p_opt, q_opt, dp_opt, dq_opt, qi_opt {
    Some(p_b64), Some(q_b64), Some(dp_b64), Some(dq_b64), Some(qi_b64) -> {
      use p_bits <- result.try(utils.decode_base64_url(p_b64, "p"))
      use q_bits <- result.try(utils.decode_base64_url(q_b64, "q"))
      use dp_bits <- result.try(utils.decode_base64_url(dp_b64, "dp"))
      use dq_bits <- result.try(utils.decode_base64_url(dq_b64, "dq"))
      use qi_bits <- result.try(utils.decode_base64_url(qi_b64, "qi"))
      rsa.from_full_components(
        n_bits,
        e_bits,
        d_bits,
        p_bits,
        q_bits,
        dp_bits,
        dq_bits,
        qi_bits,
      )
      |> result.replace_error(gose.ParseError(
        "invalid RSA private key components",
      ))
    }
    _, _, _, _, _ ->
      rsa.from_components(n_bits, e_bits, d_bits)
      |> result.replace_error(gose.ParseError(
        "invalid RSA private key components",
      ))
  }
}

type RsaDecoded {
  RsaDecoded(
    n: String,
    e: String,
    d: Option(String),
    p: Option(String),
    q: Option(String),
    dp: Option(String),
    dq: Option(String),
    qi: Option(String),
    kid: Option(String),
    use_: Option(String),
    key_ops: Option(List(String)),
    alg: Option(String),
    oth: Bool,
  )
}

fn rsa_decoder() -> decode.Decoder(RsaDecoded) {
  use n <- decode.field("n", decode.string)
  use e <- decode.field("e", decode.string)
  use d <- decode.optional_field("d", None, decode.optional(decode.string))
  use p <- decode.optional_field("p", None, decode.optional(decode.string))
  use q <- decode.optional_field("q", None, decode.optional(decode.string))
  use dp <- decode.optional_field("dp", None, decode.optional(decode.string))
  use dq <- decode.optional_field("dq", None, decode.optional(decode.string))
  use qi <- decode.optional_field("qi", None, decode.optional(decode.string))
  use kid <- decode.optional_field("kid", None, decode.optional(decode.string))
  use use_ <- decode.optional_field("use", None, decode.optional(decode.string))
  use key_ops <- decode.optional_field(
    "key_ops",
    None,
    decode.optional(decode.list(decode.string)),
  )
  use alg <- decode.optional_field("alg", None, decode.optional(decode.string))
  use oth <- decode.optional_field("oth", False, decode.success(True))
  decode.success(RsaDecoded(
    n:,
    e:,
    d:,
    p:,
    q:,
    dp:,
    dq:,
    qi:,
    kid:,
    use_:,
    key_ops:,
    alg:,
    oth:,
  ))
}

fn parse_rsa_dynamic(dyn: decode.Dynamic) -> Result(Jwk, gose.GoseError) {
  use decoded <- result.try(
    decode.run(dyn, rsa_decoder())
    |> result.replace_error(gose.ParseError("invalid RSA JSON")),
  )
  process_rsa_decoded(decoded)
}

fn process_rsa_decoded(decoded: RsaDecoded) -> Result(Jwk, gose.GoseError) {
  let RsaDecoded(
    n_b64,
    e_b64,
    d_opt,
    p_opt,
    q_opt,
    dp_opt,
    dq_opt,
    qi_opt,
    kid,
    use_opt,
    key_ops_opt,
    alg_opt,
    oth,
  ) = decoded
  use <- bool.guard(
    when: oth,
    return: Error(gose.ParseError(
      "multi-prime RSA keys (oth parameter) not supported",
    )),
  )
  use n_bits <- result.try(utils.decode_base64_url(n_b64, "n"))
  use e_bits <- result.try(utils.decode_base64_url(e_b64, "e"))
  use #(key_use, key_ops, alg) <- result.try(parse_key_metadata(
    use_opt,
    key_ops_opt,
    alg_opt,
  ))

  case d_opt {
    Some(d_b64) -> {
      use d_bits <- result.try(utils.decode_base64_url(d_b64, "d"))
      use #(private, public) <- result.try(parse_rsa_private_key_components(
        n_bits,
        e_bits,
        d_bits,
        p_opt,
        q_opt,
        dp_opt,
        dq_opt,
        qi_opt,
      ))
      Ok(Jwk(
        material: Rsa(RsaPrivate(key: private, public:)),
        kid:,
        key_use:,
        key_ops:,
        alg:,
      ))
    }
    None -> {
      use public <- result.try(
        rsa.public_key_from_components(n_bits, e_bits)
        |> result.replace_error(gose.ParseError(
          "invalid RSA public key components",
        )),
      )
      Ok(Jwk(
        material: Rsa(RsaPublic(key: public)),
        kid:,
        key_use:,
        key_ops:,
        alg:,
      ))
    }
  }
}
