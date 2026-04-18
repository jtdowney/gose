# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-04-18

### Added

- Key management API promoted to the top-level `gose` module. All types
  (`Key`, `KeyUse`, `KeyOp`, `Alg`, `KeyType`) and functions
  (`from_der`, `from_pem`, `generate_ec`, `with_kid`, `to_pem`, and the
  rest of the former `gose/key` surface) are now available directly on
  `gose`.
- Algorithm identifier types (`AesKeySize`, `HmacAlg`, `EcdsaAlg`,
  `SigningAlg`, `KeyEncryptionAlg`, `ContentAlg`, and the rest of the
  former `gose/algorithm` surface) promoted to `gose`.
- New `gose/jose` module hosting the JOSE algorithm string conversions
  (`signing_alg_to_string`, `signing_alg_from_string`,
  `key_encryption_alg_to_string`, `key_encryption_alg_from_string`,
  `content_alg_to_string`, `content_alg_from_string`).
- COSE algorithm integer conversions (`signature_alg_to_int`,
  `signature_alg_from_int`, `mac_alg_to_int`, `mac_alg_from_int`,
  `signing_alg_to_int`, `signing_alg_from_int`,
  `key_encryption_alg_to_int`, `key_encryption_alg_from_int`,
  `content_alg_to_int`, `content_alg_from_int`) added to `gose/cose`.
- `gose/cose.Key` (alias for `gose.Key(BitArray)`) as the canonical
  home for the COSE-flavored key alias.
- `gose/cose.key_to_cbor`, `key_from_cbor`, `key_to_cbor_map`, and
  `key_from_cbor_map` for COSE_Key serialization. These replace the
  like-named functions on `gose/cose/key`.

### Changed

- Renamed the internal `KeyMaterial` constructors `Ec(_)` to
  `Elliptic(_)` and `Eddsa(_)` to `Edwards(_)` to free the `Ec` and
  `Eddsa` names for the public `KeyType` and `DigitalSignatureAlg`
  constructors on `gose`. `KeyMaterial` is `@internal`, so this only
  affects callers that depend on package-internal pattern matches
  against `KeyMaterial` variants.

### Deprecated

- `gose/key`, `gose/algorithm`, `gose/jose/algorithm`, `gose/cose/key`,
  and `gose/cose/algorithm` are now `@deprecated` shims and will be
  removed in v3.0. The shims preserve module paths for function calls
  and type annotations only. **Constructor call sites must migrate
  immediately.** Gleam type aliases do not re-export constructors, so
  references such as `key.Signing`, `key.SigningAlg(_)`,
  `algorithm.Mac(_)`, or `algorithm.Aes128` stop compiling in this
  release even though the old module paths still resolve. See
  `docs/MIGRATION.md` for the per-module rewrite tables.

## [2.0.0] - 2026-04-17

### Added

#### COSE (RFC 9052 / 9053)

- COSE_Sign1 single-signer messages (`gose/cose/sign1`)
- COSE_Sign multi-signer messages (`gose/cose/sign`)
- COSE_Encrypt0 single-recipient messages (`gose/cose/encrypt0`)
- COSE_Encrypt multi-recipient messages (`gose/cose/encrypt`)
- COSE_Mac0 messages (`gose/cose/mac0`)
- COSE_Key serialization (`gose/cose/key`)
- COSE algorithm identifiers (`gose/cose/algorithm`)
- CBOR Web Token, RFC 8392 (`gose/cose/cwt`)
- Encrypt0-wrapped CWT (`gose/cose/encrypted_cwt`)
- CBOR encoder/decoder used by the COSE stack (`gose/cbor`)

#### JOSE

- JWS JSON Serialization for multi-signer workflows (`gose/jose/jws_multi`)
- JWE JSON Serialization for multi-recipient workflows (`gose/jose/jwe_multi`)

### Changed

This is a major release; every item in this section is a breaking change.

- JOSE modules moved under the `gose/jose/` namespace (`gose/jws` to
  `gose/jose/jws`, `gose/jwe` to `gose/jose/jwe`, `gose/jwt` to
  `gose/jose/jwt`, `gose/encrypted_jwt` to `gose/jose/encrypted_jwt`)
- `gose/jwa` split into `gose/algorithm` (shared algorithm identifiers)
  and `gose/jose/algorithm` (JOSE string conversions)
- `gose/jwk` split into `gose/key` (key material and generation) and
  `gose/jose/jwk` (JWK JSON serialization, algorithm string conversion,
  RFC 7638 thumbprints)
- `gose/encrypted_jwk` renamed to `gose/jose/encrypted_key`
- `gose/jwk_set` renamed to `gose/jose/key_set`
- `gose.GoseError` gains a `VerificationFailed` variant. Signature and
  MAC verification failures now return this variant instead of a
  `CryptoError` with a descriptive string.
- `jws.verify` and `jws.verify_detached` now return
  `Result(Nil, GoseError)` instead of the previous verified-JWS value
- `jwt.sign` and `cwt.sign` now take labeled arguments
  (`alg:`, `key:`, `options:`)
- `cose/cwt.CwtError` gains an `InvalidSignature` variant. Signature
  verification failures on a structurally valid CWT now return
  `InvalidSignature` instead of `MalformedToken("signature verification failed")`,
  matching `jose/jwt.JwtError`.

[2.1.0]: https://github.com/jtdowney/gose/releases/tag/v2.1.0
[2.0.0]: https://github.com/jtdowney/gose/releases/tag/v2.0.0

## [1.2.0] - 2026-03-08

### Added

- Key type validation for JWE paths, ensuring keys match expected algorithm families

## [1.1.0] - 2026-02-27

### Added

- `decoder()` functions for JWK and JWK Set types for use with `gleam_json` dynamic decoding

## [1.0.0] - 2026-02-27

### Added

#### JWK (RFC 7517)

- Symmetric, RSA, EC (P-256, P-384, P-521, secp256k1), EdDSA (Ed25519, Ed448), and XDH (X25519, X448) key types
- Import/export: PEM, DER, JSON, and raw bytes
- Key generation for all supported types
- Key metadata: `kid`, `alg`, `use`, `key_ops`
- Public key extraction and JWK Thumbprint (RFC 7638)
- JWK Set with lenient and strict parsing modes

#### JWS (RFC 7515)

- HMAC (HS256, HS384, HS512)
- RSA PKCS#1 v1.5 (RS256, RS384, RS512) and RSA-PSS (PS256, PS384, PS512)
- ECDSA (ES256, ES384, ES512, ES256K) and EdDSA
- Compact, JSON Flattened, and JSON General serialization
- Detached and unencoded payloads (RFC 7797)
- Algorithm-pinned verification with multi-key support

#### JWE (RFC 7516)

- Direct, AES Key Wrap, AES-GCM Key Wrap, RSA, ECDH-ES, and PBES2 key management
- AES-GCM, AES-CBC-HMAC, ChaCha20-Poly1305, and XChaCha20-Poly1305 content encryption
- Non-standard ChaCha20 key wrap variants (C20PKW, XC20PKW, ECDH-ES+C20PKW, ECDH-ES+XC20PKW)
- Compact, JSON Flattened, and JSON General serialization
- Additional Authenticated Data and unprotected header support
- Algorithm-pinned decryption with multi-key and password-based support

#### JWT (RFC 7519)

- Registered claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) and custom claims
- Configurable validation: expiration, not-before, issuer, audience, max token age, and custom `jti` validator
- Structured `JwtError` variants for actionable error handling

#### Encrypted JWT and JWK

- Encrypt/decrypt JWTs using any supported JWE algorithm
- Key-based and password-based (PBES2) JWT encryption
- Encrypted JWK storage with key-based and password-based protection

[1.2.0]: https://github.com/jtdowney/gose/releases/tag/v1.2.0
[1.1.0]: https://github.com/jtdowney/gose/releases/tag/v1.1.0
[1.0.0]: https://github.com/jtdowney/gose/releases/tag/v1.0.0
