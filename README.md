# gose

[![Package Version](https://img.shields.io/hexpm/v/gose)](https://hex.pm/packages/gose)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gose/)

A Gleam implementation of JOSE (JSON Object Signing and Encryption) standards:

- **JWS** ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)) - JSON Web Signature
- **JWE** ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)) - JSON Web Encryption
- **JWK** ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) - JSON Web Key
- **JWA** ([RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)) - JSON Web Algorithms
- **JWT** ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)) - JSON Web Token

## Project Goals

- Type-Safe by Design - types enforce correct API usage at compile time. Unsigned JWS can't be serialized, unverified JWT claims can't be trusted.
- Algorithm Pinning - JWT/JWS/JWE require explicit algorithm declaration, preventing algorithm confusion attacks common in other JOSE libraries. It trades off verbosity for security.
- Invalid States Are Unconstructable - Keys and tokens are validated at construction time. If you have a `Jwk`, it's valid.

## Installation

```sh
gleam add gose
```

## Platform support

- Erlang/OTP 27+
- Node.js 22+

Browser JavaScript is not supported.

## Supported Algorithms

All algorithms below apply to both raw JWS/JWE operations and JWT signing and encryption.

### JWS Signing

| Family          | Algorithms                                                      |
| --------------- | --------------------------------------------------------------- |
| HMAC            | HS256, HS384, HS512                                             |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512                                             |
| RSA-PSS         | PS256, PS384, PS512                                             |
| ECDSA           | ES256 (P-256), ES384 (P-384), ES512 (P-521), ES256K (secp256k1) |
| EdDSA           | Ed25519, Ed448                                                  |

### JWE Key Management

| Family            | Algorithms                                                                               |
| ----------------- | ---------------------------------------------------------------------------------------- |
| Direct            | dir                                                                                      |
| AES Key Wrap      | A128KW, A192KW, A256KW                                                                   |
| AES-GCM Key Wrap  | A128GCMKW, A192GCMKW, A256GCMKW                                                          |
| ChaCha20 Key Wrap | C20PKW, XC20PKW                                                                          |
| RSA               | RSA1_5, RSA-OAEP, RSA-OAEP-256                                                           |
| ECDH-ES           | ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW, ECDH-ES+C20PKW, ECDH-ES+XC20PKW |
| PBES2             | PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW                               |

### JWE Content Encryption

| Family         | Algorithms                                           |
| -------------- | ---------------------------------------------------- |
| AES-GCM        | A128GCM, A192GCM, A256GCM                            |
| AES-CBC + HMAC | A128CBC-HS256, A192CBC-HS384, A256CBC-HS512          |
| ChaCha20       | C20P (ChaCha20-Poly1305), XC20P (XChaCha20-Poly1305) |

## Quick Start

### JWT - Creating and Verifying Tokens

```gleam
import gleam/dynamic/decode
import gleam/option.{None}
import gleam/time/duration
import gleam/time/timestamp
import gose/jwa
import gose/jwk
import gose/jwt

pub fn main() {
  // Generate a symmetric key for HS256
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let now = timestamp.system_time()

  // Create claims
  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_issuer("my-app")
    |> jwt.with_expiration(timestamp.add(now, duration.hours(1)))

  // Sign the JWT
  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)

  // Serialize to compact format
  let token = jwt.serialize(signed)

  // Verify and validate
  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

  // Decode verified claims
  let decoder = decode.field("sub", decode.string, decode.success)
  let assert Ok("user123") = jwt.decode(verified, decoder)
}
```

### JWS - Signing Data

```gleam
import gose/jwa
import gose/jwk
import gose/jws
import kryptos/eddsa

pub fn main() {
  // Generate an Ed25519 key
  let key = jwk.generate_eddsa(eddsa.Ed25519)
  let payload = <<"hello world":utf8>>

  // Create and sign
  let assert Ok(signed) =
    jws.new(jwa.JwsEddsa)
    |> jws.sign(key, payload)

  // Serialize to compact format
  let assert Ok(token) = jws.serialize_compact(signed)

  // Parse and verify using a Verifier
  let assert Ok(parsed) = jws.parse_compact(token)
  let assert Ok(verifier) = jws.verifier(jwa.JwsEddsa, [key])
  let assert Ok(True) = jws.verify(verifier, parsed)
}
```

### JWE - Encrypting Data

```gleam
import gose/jwa
import gose/jwe
import gose/jwk

pub fn main() {
  // Generate a 256-bit key for direct encryption with AES-256-GCM
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let plaintext = <<"sensitive data":utf8>>

  // Encrypt using direct key encryption
  let assert Ok(encrypted) =
    jwe.new_direct(jwa.AesGcm(jwa.Aes256))
    |> jwe.encrypt(key, plaintext)

  // Serialize to compact format
  let assert Ok(token) = jwe.serialize_compact(encrypted)

  // Parse and decrypt with algorithm pinning
  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) = jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), [key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  // decrypted == <<"sensitive data":utf8>>
}
```

## Error Handling

The library uses a two-tier error design:

**`GoseError`** — used by JOSE primitives (JWS, JWE, JWK):

| Variant        | When It Occurs                                                                 |
| -------------- | ------------------------------------------------------------------------------ |
| `ParseError`   | Invalid base64 encoding, malformed JSON, wrong token format                    |
| `CryptoError`  | Signature verification failure, decryption failure, key derivation error       |
| `InvalidState` | Wrong key type for algorithm, missing required header, incompatible parameters |

**`JwtError`** — used by JWT and encrypted JWT modules:

| Variant                | When It Occurs                                                                         |
| ---------------------- | -------------------------------------------------------------------------------------- |
| `TokenExpired`         | Token's `exp` claim is in the past                                                     |
| `TokenNotYetValid`     | Token's `nbf` claim is in the future                                                   |
| `IssuerMismatch`       | Token's `iss` doesn't match expected issuer                                            |
| `AudienceMismatch`     | Token's `aud` doesn't match expected audience                                          |
| `InvalidSignature`     | JWS signature verification failed                                                      |
| `DecryptionFailed`     | JWE decryption failed                                                                  |
| `JoseError(GoseError)` | Underlying JOSE operation failed (key validation, signing, etc.)                       |
| ...                    | See [`JwtError`](https://hexdocs.pm/gose/gose/jwt.html#JwtError) type for all variants |

## Limitations

- X.509 certificate parameters not supported - JWKs containing X.509 certificate chain parameters (`x5u`, `x5c`, `x5t`, `x5t#S256`) are rejected with a parse error. Certificate-based key validation must be performed outside this library.

## Documentation

Full API documentation is available at [hexdocs.pm/gose](https://hexdocs.pm/gose/).
