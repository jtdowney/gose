# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.y   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

To report a security vulnerability, please use [GitHub Security Advisories](https://github.com/jtdowney/gose/security/advisories/new).

**Please do not report security vulnerabilities through public GitHub issues.**

When reporting, include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

You can expect an initial response within 48 hours. We will work with you to understand the issue and coordinate disclosure.

## Security Model

gose is a JOSE (JSON Object Signing and Encryption) library that delegates all cryptographic primitives to [kryptos](https://github.com/jtdowney/kryptos), which in turn uses platform-native implementations:

- **Erlang target**: OTP `:crypto` and `:public_key` modules (OpenSSL/LibreSSL)
- **JavaScript target**: Node.js `crypto` module (OpenSSL)

gose does not implement any cryptographic primitives itself. Security of the underlying operations depends on kryptos and the platform implementations being correct and up to date.

### Compile-Time Safety via Phantom Types

gose uses phantom types to prevent common misuse at compile time:

- **JWS**: `Jws(Unsigned)` cannot be serialized; only `Jws(Signed)` can
- **JWE**: `Jwe(Unencrypted, ...)` cannot be serialized; only `Jwe(Encrypted, ...)` can
- **JWT**: Claims are only accessible from `Jwt(Verified)`, not `Jwt(Unverified)`
- **JWE algorithm families**: Phantom types restrict builder methods to their correct algorithm family (e.g., `with_apu` only compiles for ECDH-ES, not Direct)

### Algorithm Pinning

All verifier and decryptor constructors require the caller to specify the expected algorithm up front. The library rejects tokens whose header algorithm does not match, preventing algorithm confusion attacks where an attacker substitutes a weaker algorithm (e.g., replacing RS256 with HS256).

### Key Validation

Before signing, verification, encryption, or decryption, gose validates:

- **Key type**: The key type matches the algorithm (e.g., RSA keys for RS256, EC keys for ES256)
- **Key use** (`use`): If set, must be appropriate for the operation (`sig` for signing, `enc` for encryption)
- **Key operations** (`key_ops`): If set, must include the required operation (e.g., `sign`, `verify`, `wrapKey`)
- **Key algorithm** (`alg`): If set on the key, must match the requested algorithm

### JWT Claim Validation

`verify_and_validate` enforces standard JWT claims:

- **`exp`**: Token must not be expired (required by default)
- **`nbf`**: Token must not be used before the not-before time
- **`iss`**: If an expected issuer is configured, it must match
- **`aud`**: If an expected audience is configured, the token must include it

## Algorithm Guidance

### Recommended Algorithms

| Use Case               | Recommended                                         |
| ---------------------- | --------------------------------------------------- |
| JWS Signing            | EdDSA, ES256/ES384/ES512, PS256/PS384/PS512         |
| JWE Key Encryption     | ECDH-ES, ECDH-ES+A128KW/A192KW/A256KW, RSA-OAEP-256 |
| JWE Content Encryption | A256GCM, A256CBC-HS512                              |
| Password-Based         | PBES2-HS512+A256KW                                  |
| Symmetric Key Wrap     | A256KW, A256GCMKW                                   |
| Direct Symmetric       | dir (with A256GCM or A256CBC-HS512)                 |

### Legacy Algorithms (Use with Caution)

The following are supported for interoperability with existing systems but are not recommended for new applications:

- **RSA PKCS#1 v1.5 signing (RS256/RS384/RS512)**: Less robust than PSS; prefer PS256/PS384/PS512
- **RSA PKCS#1 v1.5 key encryption (RSA1_5)**: Vulnerable to padding oracle attacks (Bleichenbacher); prefer RSA-OAEP or RSA-OAEP-256

## Runtime Requirements

### Node.js

**Recommended: Node.js 22 or later**

Node.js 20.x has a known vulnerability ([CVE-2023-46809](https://nvd.nist.gov/vuln/detail/CVE-2023-46809)) affecting RSA PKCS#1 v1.5 decryption (Marvin attack). The underlying kryptos library disables PKCS#1 v1.5 decryption on affected versions.

### Erlang/OTP

Use a currently supported OTP version with up-to-date OpenSSL/LibreSSL.
