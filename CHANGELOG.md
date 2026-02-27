# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/jtdowney/gose/releases/tag/v1.0.0
