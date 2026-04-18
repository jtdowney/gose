//// Cryptographic algorithm definitions for signing and encryption.

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
