//// A Gleam library for JOSE (JSON Object Signing and Encryption) and
//// COSE (CBOR Object Signing and Encryption).
////
//// Core:
//// - `gose`: error type, algorithm identifiers, and key management (types,
////   generators, builders, accessors, serializers)
//// - `gose/cbor`: CBOR encoding for COSE
////
//// `gose/key`, `gose/algorithm`, `gose/jose/algorithm`, `gose/cose/key`, and
//// `gose/cose/algorithm` are deprecated shims retained for the v2.x migration
//// window. They will be removed in v3.0. New code should import `gose`,
//// `gose/jose`, and `gose/cose` directly.
////
//// JOSE:
//// - `gose/jose`: JOSE algorithm string conversion ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html))
//// - `gose/jose/jws`: JSON Web Signature ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html))
//// - `gose/jose/jws_multi`: JWS JSON Serialization for multi-signer workflows
//// - `gose/jose/jwe`: JSON Web Encryption ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html))
//// - `gose/jose/jwe_multi`: JWE JSON Serialization for multi-recipient workflows
//// - `gose/jose/jwk`: JSON Web Key serialization ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html))
//// - `gose/jose/key_set`: JWK Set ([RFC 7517 Section 5](https://www.rfc-editor.org/rfc/rfc7517.html#section-5))
//// - `gose/jose/encrypted_key`: encrypted JWK export/import
//// - `gose/jose/jwt`: JSON Web Token ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html))
//// - `gose/jose/encrypted_jwt`: encrypted JWT (JWE-based)
////
//// COSE:
//// - `gose/cose`: header parameters, the `Key` alias, COSE_Key CBOR serialization, and COSE algorithm ID mapping ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html))
//// - `gose/cose/sign1`: COSE_Sign1 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/sign`: COSE_Sign multi-signer ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/encrypt0`: COSE_Encrypt0 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/encrypt`: COSE_Encrypt multi-recipient ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/mac0`: COSE_Mac0 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
//// - `gose/cose/cwt`: CBOR Web Token ([RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html))
//// - `gose/cose/encrypted_cwt`: encrypted CWT (Encrypt0-wrapped Sign1)

import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/option.{type Option}
import gleam/result
import kryptos/crypto
import kryptos/ec
import kryptos/eddsa
import kryptos/rsa
import kryptos/xdh

/// Error type for JOSE and COSE operations.
///
/// Used by low-level JOSE/COSE primitives. The JWT and CWT layers wrap these
/// errors in their own domain-specific variants for token validation.
pub type GoseError {
  /// Parsing failed: invalid base64, malformed JSON, unexpected structure, etc.
  /// The `String` provides a human-readable description of what went wrong.
  ParseError(String)
  /// A cryptographic operation failed: signature verification, decryption,
  /// key derivation, etc. The `String` describes the failure.
  CryptoError(String)
  /// An operation was attempted in an invalid state: wrong key type for the
  /// chosen algorithm, missing required header field, etc. The `String`
  /// explains which invariant was violated.
  InvalidState(String)
  /// Signature or MAC verification failed. Intentionally carries no detail
  /// to avoid leaking information that could enable oracle attacks.
  VerificationFailed
}

/// Extract the message string from a GoseError, regardless of variant.
pub fn error_message(error: GoseError) -> String {
  case error {
    ParseError(msg) -> msg
    CryptoError(msg) -> msg
    InvalidState(msg) -> msg
    VerificationFailed -> "verification failed"
  }
}

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

/// AES key sizes.
pub type AesKeySize {
  /// 128-bit AES key
  Aes128
  /// 192-bit AES key
  Aes192
  /// 256-bit AES key
  Aes256
}

/// AES key wrapping modes.
pub type AesKwMode {
  /// AES Key Wrap (RFC 3394)
  AesKw
  /// AES-GCM Key Wrap
  AesGcmKw
}

/// ChaCha20-Poly1305 key wrapping variants.
pub type ChaCha20Kw {
  /// ChaCha20-Poly1305 Key Wrap (12-byte nonce)
  C20PKw
  /// XChaCha20-Poly1305 Key Wrap (24-byte nonce)
  XC20PKw
}

/// HMAC signing algorithm variants.
pub type HmacAlg {
  /// HMAC using SHA-256
  HmacSha256
  /// HMAC using SHA-384
  HmacSha384
  /// HMAC using SHA-512
  HmacSha512
}

/// RSA PKCS#1 v1.5 signing algorithm variants.
pub type RsaPkcs1Alg {
  /// RSA PKCSv1.5 using SHA-256
  RsaPkcs1Sha256
  /// RSA PKCSv1.5 using SHA-384
  RsaPkcs1Sha384
  /// RSA PKCSv1.5 using SHA-512
  RsaPkcs1Sha512
}

/// RSA-PSS signing algorithm variants.
pub type RsaPssAlg {
  /// RSA-PSS using SHA-256 (RSASSA-PSS)
  RsaPssSha256
  /// RSA-PSS using SHA-384 (RSASSA-PSS)
  RsaPssSha384
  /// RSA-PSS using SHA-512 (RSASSA-PSS)
  RsaPssSha512
}

/// ECDSA signing algorithm variants.
pub type EcdsaAlg {
  /// ECDSA using P-256 and SHA-256
  EcdsaP256
  /// ECDSA using P-384 and SHA-384
  EcdsaP384
  /// ECDSA using P-521 and SHA-512
  EcdsaP521
  /// ECDSA using secp256k1 and SHA-256 (RFC 8812)
  EcdsaSecp256k1
}

/// Asymmetric signature algorithms.
pub type DigitalSignatureAlg {
  /// RSA PKCS#1 v1.5 signing
  RsaPkcs1(RsaPkcs1Alg)
  /// RSA-PSS signing
  RsaPss(RsaPssAlg)
  /// ECDSA signing
  Ecdsa(EcdsaAlg)
  /// EdDSA (Ed25519 or Ed448, curve determined by key)
  Eddsa
}

/// MAC algorithms.
pub type MacAlg {
  /// HMAC-based MAC
  Hmac(HmacAlg)
}

/// Signing and MAC algorithms (union of asymmetric signatures and MACs).
pub type SigningAlg {
  /// Asymmetric digital signature algorithm
  DigitalSignature(DigitalSignatureAlg)
  /// MAC algorithm
  Mac(MacAlg)
}

/// RSA key encryption algorithm variants.
pub type RsaEncryptionAlg {
  /// RSAES PKCS1 v1.5 key encryption.
  ///
  /// **Security Warning:** Vulnerable to padding oracle attacks (Bleichenbacher).
  /// Use only for interoperability with legacy systems that require RSA1_5.
  /// Prefer `RsaOaepSha256` for new applications.
  ///
  /// **Note:** Decryption may fail on Node.js 20.x (CVE-2023-46809).
  RsaPkcs1v15
  /// RSAES OAEP using default parameters
  RsaOaepSha1
  /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
  RsaOaepSha256
}

/// ECDH-ES key agreement algorithm variants.
pub type EcdhEsAlg {
  /// ECDH-ES direct key agreement
  EcdhEsDirect
  /// ECDH-ES with AES Key Wrap
  EcdhEsAesKw(AesKeySize)
  /// ECDH-ES with ChaCha20-Poly1305 Key Wrap
  EcdhEsChaCha20Kw(ChaCha20Kw)
}

/// PBES2 key encryption algorithm variants.
pub type Pbes2Alg {
  /// PBES2 with HMAC-SHA-256 and A128KW wrapping
  Pbes2Sha256Aes128Kw
  /// PBES2 with HMAC-SHA-384 and A192KW wrapping
  Pbes2Sha384Aes192Kw
  /// PBES2 with HMAC-SHA-512 and A256KW wrapping
  Pbes2Sha512Aes256Kw
}

/// Key encryption algorithms.
pub type KeyEncryptionAlg {
  /// Direct use of a shared symmetric key
  Direct
  /// AES Key Wrap (standard or GCM mode)
  AesKeyWrap(AesKwMode, AesKeySize)
  /// ChaCha20-Poly1305 Key Wrap
  ChaCha20KeyWrap(ChaCha20Kw)
  /// RSA key encryption
  RsaEncryption(RsaEncryptionAlg)
  /// ECDH-ES key agreement
  EcdhEs(EcdhEsAlg)
  /// PBES2 password-based encryption
  Pbes2(Pbes2Alg)
}

/// Content encryption algorithms.
pub type ContentAlg {
  /// AES-GCM content encryption
  AesGcm(AesKeySize)
  /// AES-CBC with HMAC composite AEAD (CEK is double the AES key size)
  AesCbcHmac(AesKeySize)
  /// ChaCha20-Poly1305
  ChaCha20Poly1305
  /// XChaCha20-Poly1305
  XChaCha20Poly1305
}

/// Algorithm union type for the key `alg` field.
/// A key can specify either a signing algorithm or a key encryption algorithm.
pub type Alg {
  /// Signing algorithm
  SigningAlg(SigningAlg)
  /// Key encryption algorithm
  KeyEncryptionAlg(KeyEncryptionAlg)
  /// Content encryption algorithm
  ContentAlg(ContentAlg)
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
pub type KeyMaterial {
  OctetKey(secret: BitArray)
  Rsa(RsaKeyMaterial)
  Elliptic(EcKeyMaterial)
  Edwards(EddsaKeyMaterial)
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

/// A cryptographic key.
///
/// Use constructor functions like `from_octet_bits`, `from_der`,
/// `from_pem`, or `generate_*` to create keys.
pub opaque type Key(kid) {
  Key(
    material: KeyMaterial,
    kid: Option(kid),
    key_use: Option(KeyUse),
    key_ops: Option(List(KeyOp)),
    alg: Option(Alg),
  )
}

@internal
pub fn new_key(material: KeyMaterial) -> Key(kid) {
  Key(
    material:,
    kid: option.None,
    key_use: option.None,
    key_ops: option.None,
    alg: option.None,
  )
}

@internal
pub fn is_private_key(key: Key(kid)) -> Bool {
  case key.material {
    OctetKey(..) -> True
    Rsa(RsaPrivate(..)) -> True
    Rsa(RsaPublic(..)) -> False
    Elliptic(EcPrivate(..)) -> True
    Elliptic(EcPublic(..)) -> False
    Edwards(EddsaPrivate(..)) -> True
    Edwards(EddsaPublic(..)) -> False
    Xdh(XdhPrivate(..)) -> True
    Xdh(XdhPublic(..)) -> False
  }
}

@internal
pub fn material(key: Key(kid)) -> KeyMaterial {
  key.material
}

@internal
pub fn material_octet_secret(mat: KeyMaterial) -> Result(BitArray, GoseError) {
  case mat {
    OctetKey(secret:) -> Ok(secret)
    Rsa(..) | Elliptic(..) | Edwards(..) | Xdh(..) ->
      Error(InvalidState("expected octet key"))
  }
}

@internal
pub fn material_rsa(mat: KeyMaterial) -> Result(RsaKeyMaterial, GoseError) {
  case mat {
    Rsa(rsa) -> Ok(rsa)
    OctetKey(..) | Elliptic(..) | Edwards(..) | Xdh(..) ->
      Error(InvalidState("expected RSA key"))
  }
}

@internal
pub fn material_ec(mat: KeyMaterial) -> Result(EcKeyMaterial, GoseError) {
  case mat {
    Elliptic(ec) -> Ok(ec)
    OctetKey(..) | Rsa(..) | Edwards(..) | Xdh(..) ->
      Error(InvalidState("expected EC key"))
  }
}

@internal
pub fn material_eddsa(mat: KeyMaterial) -> Result(EddsaKeyMaterial, GoseError) {
  case mat {
    Edwards(eddsa) -> Ok(eddsa)
    OctetKey(..) | Rsa(..) | Elliptic(..) | Xdh(..) ->
      Error(InvalidState("expected EdDSA key"))
  }
}

@internal
pub fn material_xdh(mat: KeyMaterial) -> Result(XdhKeyMaterial, GoseError) {
  case mat {
    Xdh(xdh) -> Ok(xdh)
    OctetKey(..) | Rsa(..) | Elliptic(..) | Edwards(..) ->
      Error(InvalidState("expected XDH key"))
  }
}

/// Create a key from DER-encoded data.
///
/// Auto-detects key type (RSA, EC, EdDSA, XDH) and format (PKCS#1, PKCS#8, SPKI).
/// Supports both private and public keys.
pub fn from_der(der: BitArray) -> Result(Key(kid), GoseError) {
  parse_rsa_der(der)
  |> result.lazy_or(fn() { parse_eddsa_der(der) })
  |> result.lazy_or(fn() { parse_xdh_der(der) })
  |> result.lazy_or(fn() { parse_ec_der(der) })
  |> result.map_error(fn(_) {
    ParseError(
      "invalid DER: not a recognized RSA, EC, EdDSA, or XDH key format",
    )
  })
}

fn ec_private_key(pair: #(ec.PrivateKey, ec.PublicKey)) -> Key(kid) {
  let #(private, public) = pair
  let curve = ec.curve(private)
  new_key(Elliptic(EcPrivate(key: private, public:, curve:)))
}

fn ec_public_key_internal(public: ec.PublicKey) -> Key(kid) {
  let curve = ec.public_key_curve(public)
  new_key(Elliptic(EcPublic(key: public, curve:)))
}

fn eddsa_private_key(pair: #(eddsa.PrivateKey, eddsa.PublicKey)) -> Key(kid) {
  let #(private, public) = pair
  let curve = eddsa.curve(private)
  new_key(Edwards(EddsaPrivate(key: private, public:, curve:)))
}

fn eddsa_public_key_internal(public: eddsa.PublicKey) -> Key(kid) {
  let curve = eddsa.public_key_curve(public)
  new_key(Edwards(EddsaPublic(key: public, curve:)))
}

fn rsa_private_key_internal(pair: #(rsa.PrivateKey, rsa.PublicKey)) -> Key(kid) {
  let #(private, public) = pair
  new_key(Rsa(RsaPrivate(key: private, public:)))
}

fn rsa_public_key_internal(public: rsa.PublicKey) -> Key(kid) {
  new_key(Rsa(RsaPublic(key: public)))
}

fn xdh_private_key(pair: #(xdh.PrivateKey, xdh.PublicKey)) -> Key(kid) {
  let #(private, public) = pair
  let curve = xdh.curve(private)
  new_key(Xdh(XdhPrivate(key: private, public:, curve:)))
}

fn xdh_public_key_internal(public: xdh.PublicKey) -> Key(kid) {
  let curve = xdh.public_key_curve(public)
  new_key(Xdh(XdhPublic(key: public, curve:)))
}

fn parse_ec_der(der: BitArray) -> Result(Key(kid), Nil) {
  ec.from_der(der)
  |> result.map(ec_private_key)
  |> result.lazy_or(fn() {
    ec.public_key_from_der(der) |> result.map(ec_public_key_internal)
  })
}

fn parse_eddsa_der(der: BitArray) -> Result(Key(kid), Nil) {
  eddsa.from_der(der)
  |> result.map(eddsa_private_key)
  |> result.lazy_or(fn() {
    eddsa.public_key_from_der(der) |> result.map(eddsa_public_key_internal)
  })
}

fn parse_rsa_der(der: BitArray) -> Result(Key(kid), Nil) {
  rsa.from_der(der, rsa.Pkcs8)
  |> result.map(rsa_private_key_internal)
  |> result.lazy_or(fn() {
    rsa.from_der(der, rsa.Pkcs1) |> result.map(rsa_private_key_internal)
  })
  |> result.lazy_or(fn() {
    rsa.public_key_from_der(der, rsa.Spki)
    |> result.map(rsa_public_key_internal)
  })
  |> result.lazy_or(fn() {
    rsa.public_key_from_der(der, rsa.RsaPublicKey)
    |> result.map(rsa_public_key_internal)
  })
}

fn parse_xdh_der(der: BitArray) -> Result(Key(kid), Nil) {
  xdh.from_der(der)
  |> result.map(xdh_private_key)
  |> result.lazy_or(fn() {
    xdh.public_key_from_der(der) |> result.map(xdh_public_key_internal)
  })
}

/// Create an EdDSA key pair from raw private key bytes.
///
/// The public key is derived from the private key.
/// This is the inverse of `to_octet_bits` for EdDSA private keys.
pub fn from_eddsa_bits(
  curve: eddsa.Curve,
  private_bits private_bits: BitArray,
) -> Result(Key(kid), GoseError) {
  eddsa.from_bytes(curve, private_bits)
  |> result.map(fn(pair) {
    let #(private, public) = pair
    new_key(Edwards(EddsaPrivate(key: private, public:, curve:)))
  })
  |> result.replace_error(ParseError("invalid EdDSA private key bits"))
}

/// Create an EdDSA public key from raw bytes.
///
/// This is the inverse of `to_octet_bits` for EdDSA public keys.
pub fn from_eddsa_public_bits(
  curve: eddsa.Curve,
  public_bits public_bits: BitArray,
) -> Result(Key(kid), GoseError) {
  eddsa.public_key_from_bytes(curve, public_bits)
  |> result.map(fn(public) {
    new_key(Edwards(EddsaPublic(key: public, curve:)))
  })
  |> result.replace_error(ParseError("invalid EdDSA public key bits"))
}

/// Create a symmetric key from raw bytes.
///
/// Used for HMAC signing (HS256/384/512) and direct encryption.
/// Returns an error if the secret is empty.
///
/// ## Example
///
/// ```gleam
/// let secret = crypto.random_bytes(32)
/// let assert Ok(key) = gose.from_octet_bits(secret)
/// ```
pub fn from_octet_bits(secret: BitArray) -> Result(Key(kid), GoseError) {
  case bit_array.byte_size(secret) {
    0 -> Error(InvalidState("oct key must not be empty"))
    _ -> Ok(new_key(OctetKey(secret:)))
  }
}

/// Create a key from PEM-encoded data.
///
/// Auto-detects key type (RSA, EC, EdDSA, XDH) and format (PKCS#1, PKCS#8, SPKI).
/// Supports both private and public keys.
pub fn from_pem(pem: String) -> Result(Key(kid), GoseError) {
  parse_rsa_pem(pem)
  |> result.lazy_or(fn() { parse_eddsa_pem(pem) })
  |> result.lazy_or(fn() { parse_xdh_pem(pem) })
  |> result.lazy_or(fn() { parse_ec_pem(pem) })
  |> result.map_error(fn(_) {
    ParseError(
      "invalid PEM: not a recognized RSA, EC, EdDSA, or XDH key format",
    )
  })
}

fn parse_ec_pem(pem: String) -> Result(Key(kid), Nil) {
  ec.from_pem(pem)
  |> result.map(ec_private_key)
  |> result.lazy_or(fn() {
    ec.public_key_from_pem(pem) |> result.map(ec_public_key_internal)
  })
}

fn parse_eddsa_pem(pem: String) -> Result(Key(kid), Nil) {
  eddsa.from_pem(pem)
  |> result.map(eddsa_private_key)
  |> result.lazy_or(fn() {
    eddsa.public_key_from_pem(pem) |> result.map(eddsa_public_key_internal)
  })
}

fn parse_rsa_pem(pem: String) -> Result(Key(kid), Nil) {
  rsa.from_pem(pem, rsa.Pkcs8)
  |> result.map(rsa_private_key_internal)
  |> result.lazy_or(fn() {
    rsa.from_pem(pem, rsa.Pkcs1) |> result.map(rsa_private_key_internal)
  })
  |> result.lazy_or(fn() {
    rsa.public_key_from_pem(pem, rsa.Spki)
    |> result.map(rsa_public_key_internal)
  })
  |> result.lazy_or(fn() {
    rsa.public_key_from_pem(pem, rsa.RsaPublicKey)
    |> result.map(rsa_public_key_internal)
  })
}

fn parse_xdh_pem(pem: String) -> Result(Key(kid), Nil) {
  xdh.from_pem(pem)
  |> result.map(xdh_private_key)
  |> result.lazy_or(fn() {
    xdh.public_key_from_pem(pem) |> result.map(xdh_public_key_internal)
  })
}

/// Create an XDH key pair from raw private key bytes.
///
/// The public key is derived from the private key.
/// This is the inverse of `to_octet_bits` for XDH private keys.
pub fn from_xdh_bits(
  curve: xdh.Curve,
  private_bits private_bits: BitArray,
) -> Result(Key(kid), GoseError) {
  xdh.from_bytes(curve, private_bits)
  |> result.map(fn(pair) {
    let #(private, public) = pair
    new_key(Xdh(XdhPrivate(key: private, public:, curve:)))
  })
  |> result.replace_error(ParseError("invalid XDH private key bits"))
}

/// Create an XDH public key from raw bytes.
///
/// This is the inverse of `to_octet_bits` for XDH public keys.
pub fn from_xdh_public_bits(
  curve: xdh.Curve,
  public_bits public_bits: BitArray,
) -> Result(Key(kid), GoseError) {
  xdh.public_key_from_bytes(curve, public_bits)
  |> result.map(fn(public) { new_key(Xdh(XdhPublic(key: public, curve:))) })
  |> result.replace_error(ParseError("invalid XDH public key bits"))
}

/// Generate a new EC key pair for the given curve.
///
/// Supported curves: P256, P384, P521, Secp256k1.
pub fn generate_ec(curve: ec.Curve) -> Key(kid) {
  let #(private, public) = ec.generate_key_pair(curve)
  new_key(Elliptic(EcPrivate(key: private, public:, curve:)))
}

/// Generate a new EdDSA key pair for the given curve.
///
/// Supported curves: Ed25519, Ed448.
pub fn generate_eddsa(curve: eddsa.Curve) -> Key(kid) {
  let #(private, public) = eddsa.generate_key_pair(curve)
  new_key(Edwards(EddsaPrivate(key: private, public:, curve:)))
}

/// Generate a symmetric key for HMAC signing.
///
/// The key size is derived from the algorithm:
/// - `HmacSha256` → 32 bytes
/// - `HmacSha384` → 48 bytes
/// - `HmacSha512` → 64 bytes
pub fn generate_hmac_key(alg: HmacAlg) -> Key(kid) {
  let size = hmac_alg_key_size(alg)
  let secret = crypto.random_bytes(size)
  new_key(OctetKey(secret:))
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
pub fn generate_enc_key(enc: ContentAlg) -> Key(kid) {
  let size = content_alg_key_size(enc)
  let secret = crypto.random_bytes(size)
  new_key(OctetKey(secret:))
}

/// Generate a symmetric key for AES Key Wrap.
///
/// The key size is derived from the AES variant:
/// - `Aes128` → 16 bytes
/// - `Aes192` → 24 bytes
/// - `Aes256` → 32 bytes
pub fn generate_aes_kw_key(size: AesKeySize) -> Key(kid) {
  let byte_count = aes_key_size(size)
  let secret = crypto.random_bytes(byte_count)
  new_key(OctetKey(secret:))
}

/// Generate a symmetric key for ChaCha20-Poly1305 Key Wrap (C20PKW / XC20PKW).
///
/// Always generates a 32-byte key, as both ChaCha20 and XChaCha20 use 256-bit keys.
pub fn generate_chacha20_kw_key() -> Key(kid) {
  let secret = crypto.random_bytes(32)
  new_key(OctetKey(secret:))
}

/// Generate a new RSA key pair with the given key size in bits.
/// Common sizes are 2048, 3072, and 4096. Keys smaller than 2048
/// bits are not recommended for security.
pub fn generate_rsa(bits: Int) -> Result(Key(kid), GoseError) {
  case rsa.generate_key_pair(bits) {
    Ok(#(private, public)) ->
      Ok(new_key(Rsa(RsaPrivate(key: private, public:))))
    Error(_) -> Error(CryptoError("RSA key generation failed"))
  }
}

/// Generate a new XDH key pair for key agreement.
///
/// Supported curves: X25519, X448.
pub fn generate_xdh(curve: xdh.Curve) -> Key(kid) {
  let #(private, public) = xdh.generate_key_pair(curve)
  new_key(Xdh(XdhPrivate(key: private, public:, curve:)))
}

/// Create an EC public key from curve and x,y coordinates (big-endian bytes).
pub fn ec_public_key_from_coordinates(
  curve: ec.Curve,
  x x: BitArray,
  y y: BitArray,
) -> Result(Key(kid), GoseError) {
  ec_public_key_from_raw_coordinates(curve, x:, y:)
  |> result.map(fn(public) { new_key(Elliptic(EcPublic(key: public, curve:))) })
}

@internal
pub fn ec_public_key_from_raw_coordinates(
  curve: ec.Curve,
  x x: BitArray,
  y y: BitArray,
) -> Result(ec.PublicKey, GoseError) {
  let coord_size = ec.coordinate_size(curve)
  use <- bool.guard(
    when: bit_array.byte_size(x) != coord_size,
    return: Error(ParseError("EC x coordinate wrong length")),
  )
  use <- bool.guard(
    when: bit_array.byte_size(y) != coord_size,
    return: Error(ParseError("EC y coordinate wrong length")),
  )
  let raw_point = bit_array.concat([<<0x04>>, x, y])
  ec.public_key_from_raw_point(curve, raw_point)
  |> result.replace_error(ParseError("invalid EC coordinates"))
}

@internal
pub fn ec_raw_coordinates(
  public: ec.PublicKey,
  curve curve: ec.Curve,
) -> Result(#(BitArray, BitArray), GoseError) {
  let coord_size = ec.coordinate_size(curve)
  let raw_point = ec.public_key_to_raw_point(public)
  let expected_size = 1 + coord_size * 2
  case bit_array.byte_size(raw_point) == expected_size, raw_point {
    True, <<0x04, rest:bits>> -> {
      let error = InvalidState("invalid raw point format")
      use x <- result.try(
        bit_array.slice(rest, 0, coord_size)
        |> result.replace_error(error),
      )
      use y <- result.try(
        bit_array.slice(rest, coord_size, coord_size)
        |> result.replace_error(error),
      )
      Ok(#(x, y))
    }
    _, _ -> Error(InvalidState("invalid raw point format"))
  }
}

/// Set the algorithm (`alg`) metadata parameter on a key.
pub fn with_alg(key: Key(kid), alg: Alg) -> Key(kid) {
  Key(..key, alg: option.Some(alg))
}

/// Set the key operations parameter.
///
/// Per RFC 7517, the values should be consistent with `key_use` if both are present:
/// - `Signing` use implies `Sign` and/or `Verify` operations
/// - `Encrypting` use implies `Encrypt`, `Decrypt`, `WrapKey`, `UnwrapKey`, `DeriveKey`, `DeriveBits`
///
/// Returns an error if the list is empty, contains duplicates, or is
/// incompatible with the key's existing `key_use`.
pub fn with_key_ops(
  key: Key(kid),
  ops: List(KeyOp),
) -> Result(Key(kid), GoseError) {
  case ops {
    [] -> Error(InvalidState("key_ops must not be empty"))
    _ -> {
      use <- bool.guard(
        when: list.unique(ops) != ops,
        return: Error(InvalidState("key_ops must not contain duplicates")),
      )
      validate_key_use_ops(key.key_use, option.Some(ops))
      |> result.replace(Key(..key, key_ops: option.Some(ops)))
    }
  }
}

/// Set the public key use parameter.
///
/// Returns an error if the key already has `key_ops` that are incompatible with
/// the specified use, or if the use is incompatible with the key type per RFC
/// 8037 (EdDSA keys can only be used for signing, XDH keys can only be used for
/// encryption).
pub fn with_key_use(key: Key(kid), use_: KeyUse) -> Result(Key(kid), GoseError) {
  use _ <- result.try(validate_key_use_ops(option.Some(use_), key.key_ops))
  use _ <- result.try(validate_rfc8037_key_use(key.material, option.Some(use_)))
  Ok(Key(..key, key_use: option.Some(use_)))
}

/// Validate key use against RFC 8037 curve restrictions.
/// - EdDSA keys (Ed25519/Ed448): only `sig` allowed
/// - XDH keys (X25519/X448): only `enc` allowed
fn validate_rfc8037_key_use(
  material: KeyMaterial,
  use_: Option(KeyUse),
) -> Result(Nil, GoseError) {
  case material, use_ {
    Edwards(..), option.Some(Encrypting) ->
      Error(InvalidState(
        "EdDSA keys (Ed25519/Ed448) cannot be used for encryption",
      ))
    Xdh(..), option.Some(Signing) ->
      Error(InvalidState("XDH keys (X25519/X448) cannot be used for signing"))
    _, _ -> Ok(Nil)
  }
}

/// Set the key ID (`kid`) metadata parameter on a key.
pub fn with_kid(key: Key(a), kid: String) -> Key(String) {
  Key(..key, kid: option.Some(kid))
}

/// Set the key ID (`kid`) metadata parameter on a key using raw bytes.
///
/// In COSE (RFC 9052), kid is a bstr that may contain arbitrary bytes.
/// For JWK interoperability where kid is a JSON string, use `with_kid`.
pub fn with_kid_bits(key: Key(a), kid: BitArray) -> Key(BitArray) {
  Key(..key, kid: option.Some(kid))
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

@internal
pub fn validate_key_use_ops(
  key_use: Option(KeyUse),
  key_ops: Option(List(KeyOp)),
) -> Result(Nil, GoseError) {
  case key_use, key_ops {
    option.None, _ | _, option.None -> Ok(Nil)
    option.Some(Signing), option.Some(ops) ->
      case list.all(ops, is_signing_op) {
        True -> Ok(Nil)
        False -> Error(InvalidState("key_ops incompatible with use=sig"))
      }
    option.Some(Encrypting), option.Some(ops) ->
      case list.all(ops, is_encrypting_op) {
        True -> Ok(Nil)
        False -> Error(InvalidState("key_ops incompatible with use=enc"))
      }
  }
}

/// Get the algorithm (`alg`) parameter.
pub fn alg(key: Key(kid)) -> Result(Alg, Nil) {
  option.to_result(key.alg, Nil)
}

/// Get the curve used by an EC key.
///
/// Returns an error if the key is not an EC key.
pub fn ec_curve(key: Key(kid)) -> Result(ec.Curve, GoseError) {
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
pub fn ec_public_key(key: Key(kid)) -> Result(ec.PublicKey, GoseError) {
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
pub fn ec_public_key_coordinates(
  key: Key(kid),
) -> Result(#(BitArray, BitArray), GoseError) {
  use public <- result.try(ec_public_key(key))
  use curve <- result.try(ec_curve(key))
  ec_raw_coordinates(public, curve:)
}

/// Get the curve used by an EdDSA key.
///
/// Returns an error if the key is not an EdDSA key.
pub fn eddsa_curve(key: Key(kid)) -> Result(eddsa.Curve, GoseError) {
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
pub fn eddsa_public_key(key: Key(kid)) -> Result(eddsa.PublicKey, GoseError) {
  material_eddsa(key.material)
  |> result.map(fn(eddsa) {
    case eddsa {
      EddsaPrivate(public:, ..) -> public
      EddsaPublic(key: k, ..) -> k
    }
  })
}

/// Get the key operations parameter.
pub fn key_ops(key: Key(kid)) -> Result(List(KeyOp), Nil) {
  option.to_result(key.key_ops, Nil)
}

/// Get the key type (kty) for this key.
pub fn key_type(key: Key(kid)) -> KeyType {
  case key.material {
    OctetKey(..) -> OctKeyType
    Rsa(..) -> RsaKeyType
    Elliptic(..) -> EcKeyType
    Edwards(..) | Xdh(..) -> OkpKeyType
  }
}

/// Get the public key use parameter.
pub fn key_use(key: Key(kid)) -> Result(KeyUse, Nil) {
  option.to_result(key.key_use, Nil)
}

/// Get the key ID (kid) parameter.
///
/// The return type depends on the key's kid type parameter:
/// - `Key(String)` (from JWK) → `Result(String, Nil)`
/// - `Key(BitArray)` (from COSE) → `Result(BitArray, Nil)`
pub fn kid(key: Key(kid)) -> Result(kid, Nil) {
  option.to_result(key.kid, Nil)
}

/// Get the size of an octet (symmetric) key in bytes.
///
/// Returns an error if the key is not an octet key.
pub fn octet_key_size(key: Key(kid)) -> Result(Int, GoseError) {
  case material_octet_secret(key.material) {
    Ok(secret) -> Ok(bit_array.byte_size(secret))
    Error(_) -> Error(InvalidState("key is not an octet key"))
  }
}

/// Extract the RSA public key.
///
/// Works with both RSA private keys (extracts the public component)
/// and RSA public keys.
///
/// Returns an error if the key is not an RSA key.
pub fn rsa_public_key(key: Key(kid)) -> Result(rsa.PublicKey, GoseError) {
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
pub fn xdh_curve(key: Key(kid)) -> Result(xdh.Curve, GoseError) {
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
pub fn xdh_public_key(key: Key(kid)) -> Result(xdh.PublicKey, GoseError) {
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
/// Returns an error for symmetric octet keys.
///
/// When extracting a public key, `key_ops` are filtered to public-safe operations:
/// - `Sign` is mapped to `Verify`
/// - `Decrypt` and `UnwrapKey` are removed (private-only)
/// - Other operations are preserved
///
/// ## Example
///
/// ```gleam
/// let private_key = gose.generate_ec(ec.P256)
/// let assert Ok(pub_key) = gose.public_key(private_key)
/// ```
pub fn public_key(key: Key(kid)) -> Result(Key(kid), GoseError) {
  let filtered_ops =
    key.key_ops
    |> option.map(filter_public_key_ops)
    |> option.then(option.from_result)
  case key.material {
    Rsa(RsaPrivate(public:, ..)) ->
      Ok(
        Key(..key, material: Rsa(RsaPublic(key: public)), key_ops: filtered_ops),
      )
    Rsa(RsaPublic(..)) -> Ok(Key(..key, key_ops: filtered_ops))
    Elliptic(EcPrivate(public:, curve:, ..)) ->
      Ok(
        Key(
          ..key,
          material: Elliptic(EcPublic(key: public, curve:)),
          key_ops: filtered_ops,
        ),
      )
    Elliptic(EcPublic(..)) -> Ok(Key(..key, key_ops: filtered_ops))
    Edwards(EddsaPrivate(public:, curve:, ..)) ->
      Ok(
        Key(
          ..key,
          material: Edwards(EddsaPublic(key: public, curve:)),
          key_ops: filtered_ops,
        ),
      )
    Edwards(EddsaPublic(..)) -> Ok(Key(..key, key_ops: filtered_ops))
    Xdh(XdhPrivate(public:, curve:, ..)) ->
      Ok(
        Key(
          ..key,
          material: Xdh(XdhPublic(key: public, curve:)),
          key_ops: filtered_ops,
        ),
      )
    Xdh(XdhPublic(..)) -> Ok(Key(..key, key_ops: filtered_ops))
    OctetKey(..) -> Error(InvalidState("octet keys are not asymmetric"))
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

/// Serialize a key to DER format.
///
/// Supports RSA, EC, EdDSA, and XDH keys (both private and public).
/// Uses PKCS#8 for private keys and SPKI for public keys.
pub fn to_der(key: Key(kid)) -> Result(BitArray, GoseError) {
  case key.material {
    Rsa(RsaPrivate(key: private, ..)) ->
      rsa.to_der(private, rsa.Pkcs8)
      |> result.replace_error(InvalidState(
        "failed to serialize RSA private key",
      ))
    Rsa(RsaPublic(key: public)) ->
      rsa.public_key_to_der(public, rsa.Spki)
      |> result.replace_error(InvalidState("failed to serialize RSA public key"))
    Elliptic(EcPrivate(key: private, ..)) ->
      ec.to_der(private)
      |> result.replace_error(InvalidState("failed to serialize EC private key"))
    Elliptic(EcPublic(key: public, ..)) ->
      ec.public_key_to_der(public)
      |> result.replace_error(InvalidState("failed to serialize EC public key"))
    Edwards(EddsaPrivate(key: private, ..)) ->
      eddsa.to_der(private)
      |> result.replace_error(InvalidState(
        "failed to serialize EdDSA private key",
      ))
    Edwards(EddsaPublic(key: public, ..)) ->
      eddsa.public_key_to_der(public)
      |> result.replace_error(InvalidState(
        "failed to serialize EdDSA public key",
      ))
    Xdh(XdhPrivate(key: private, ..)) ->
      xdh.to_der(private)
      |> result.replace_error(InvalidState(
        "failed to serialize XDH private key",
      ))
    Xdh(XdhPublic(key: public, ..)) ->
      xdh.public_key_to_der(public)
      |> result.replace_error(InvalidState("failed to serialize XDH public key"))
    OctetKey(..) ->
      Error(InvalidState("octet keys cannot be serialized to DER"))
  }
}

/// Export the raw bytes of a key.
///
/// Supported key types:
/// - Octet keys: returns the secret bytes
/// - EdDSA/XDH private keys: returns the private key bytes (d)
/// - EdDSA/XDH public keys: returns the public key bytes (x)
pub fn to_octet_bits(key: Key(kid)) -> Result(BitArray, GoseError) {
  case key.material {
    OctetKey(secret:) -> Ok(secret)
    Edwards(EddsaPrivate(key: private, ..)) -> Ok(eddsa.to_bytes(private))
    Edwards(EddsaPublic(key: public, ..)) ->
      Ok(eddsa.public_key_to_bytes(public))
    Xdh(XdhPrivate(key: private, ..)) -> Ok(xdh.to_bytes(private))
    Xdh(XdhPublic(key: public, ..)) -> Ok(xdh.public_key_to_bytes(public))
    Rsa(..) | Elliptic(..) ->
      Error(InvalidState("key has no single-value byte representation"))
  }
}

/// Serialize a key to PEM format.
///
/// Supports RSA, EC, EdDSA, and XDH keys (both private and public).
/// Uses PKCS#8 for private keys and SPKI for public keys.
pub fn to_pem(key: Key(kid)) -> Result(String, GoseError) {
  case key.material {
    Rsa(RsaPrivate(key: private, ..)) ->
      rsa.to_pem(private, rsa.Pkcs8)
      |> result.replace_error(InvalidState(
        "failed to serialize RSA private key",
      ))
    Rsa(RsaPublic(key: public)) ->
      rsa.public_key_to_pem(public, rsa.Spki)
      |> result.replace_error(InvalidState("failed to serialize RSA public key"))
    Elliptic(EcPrivate(key: private, ..)) ->
      ec.to_pem(private)
      |> result.replace_error(InvalidState("failed to serialize EC private key"))
    Elliptic(EcPublic(key: public, ..)) ->
      ec.public_key_to_pem(public)
      |> result.replace_error(InvalidState("failed to serialize EC public key"))
    Edwards(EddsaPrivate(key: private, ..)) ->
      eddsa.to_pem(private)
      |> result.replace_error(InvalidState(
        "failed to serialize EdDSA private key",
      ))
    Edwards(EddsaPublic(key: public, ..)) ->
      eddsa.public_key_to_pem(public)
      |> result.replace_error(InvalidState(
        "failed to serialize EdDSA public key",
      ))
    Xdh(XdhPrivate(key: private, ..)) ->
      xdh.to_pem(private)
      |> result.replace_error(InvalidState(
        "failed to serialize XDH private key",
      ))
    Xdh(XdhPublic(key: public, ..)) ->
      xdh.public_key_to_pem(public)
      |> result.replace_error(InvalidState("failed to serialize XDH public key"))
    OctetKey(..) ->
      Error(InvalidState("octet keys cannot be serialized to PEM"))
  }
}

@internal
pub fn build(
  material material: KeyMaterial,
  kid kid: Option(kid),
  key_use key_use: Option(KeyUse),
  key_ops key_ops: Option(List(KeyOp)),
  alg alg: Option(Alg),
) -> Key(kid) {
  Key(material:, kid:, key_use:, key_ops:, alg:)
}

@internal
pub fn validate_rfc8037_key_use_public(
  material: KeyMaterial,
  use_: Option(KeyUse),
) -> Result(Nil, GoseError) {
  validate_rfc8037_key_use(material, use_)
}

@internal
pub fn aes_key_size(size: AesKeySize) -> Int {
  case size {
    Aes128 -> 16
    Aes192 -> 24
    Aes256 -> 32
  }
}

@internal
pub fn hmac_alg_key_size(alg: HmacAlg) -> Int {
  case alg {
    HmacSha256 -> 32
    HmacSha384 -> 48
    HmacSha512 -> 64
  }
}

@internal
pub fn content_alg_key_size(enc: ContentAlg) -> Int {
  case enc {
    AesGcm(size) -> aes_key_size(size)
    AesCbcHmac(size) -> aes_key_size(size) * 2
    ChaCha20Poly1305 -> 32
    XChaCha20Poly1305 -> 32
  }
}

@internal
pub fn chacha20_kw_nonce_size(variant: ChaCha20Kw) -> Int {
  case variant {
    C20PKw -> 12
    XC20PKw -> 24
  }
}
