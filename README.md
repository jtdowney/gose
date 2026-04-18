# gose

[![Package Version](https://img.shields.io/hexpm/v/gose)](https://hex.pm/packages/gose)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gose/)

A Gleam implementation of JOSE (JSON Object Signing and Encryption) and COSE (CBOR Object Signing and Encryption) standards:

**JOSE:**

- **JWS** ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)) - JSON Web Signature
- **JWE** ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516)) - JSON Web Encryption
- **JWK** ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)) - JSON Web Key (including JWK Sets)
- **JWA** ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)) - JSON Web Algorithms
- **JWT** ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)) - JSON Web Token

**COSE:**

- **COSE_Sign1** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) - Single-signer signing
- **COSE_Sign** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) - Multi-signer signing
- **COSE_Encrypt0** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) - Symmetric encryption
- **COSE_Encrypt** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) - Multi-recipient encryption
- **COSE_Mac0** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) - Message authentication
- **COSE_Key** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) - Key serialization
- **CWT** ([RFC 8392](https://www.rfc-editor.org/rfc/rfc8392)) - CBOR Web Token

## Project Goals

- Type-Safe by Design - types enforce correct API usage at compile time. Unsigned payloads (JWS, etc) can't be serialized, unverified JWT/CWT claims can't be trusted.
- Algorithm Pinning - require explicit algorithm declaration, preventing algorithm confusion attacks common in other libraries. It trades off verbosity for security.
- Invalid States Are Unconstructable - Keys and tokens are validated at construction time. If you have a `Key`, it's valid.

## Should you use this?

My professional opinion as a long-time security engineering practitioner is that you should basically never use these algorithms in a greenfield system. This library was created for the purpose of integrating with existing systems that already use these standards (like ACME or Webauthn).

## Installation

```sh
gleam add gose
```

Some examples below import `kryptos` directly for key generation; add it with `gleam add kryptos` if needed.

## Platform support

- Erlang/OTP 27+
- Node.js 22+

Browser JavaScript is not supported.

## Supported Algorithms

### Signing (JWS, COSE_Sign1, and COSE_Sign)

| Family          | Algorithms                                                      |
| --------------- | --------------------------------------------------------------- |
| HMAC            | HS256, HS384, HS512                                             |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512                                             |
| RSA-PSS         | PS256, PS384, PS512                                             |
| ECDSA           | ES256 (P-256), ES384 (P-384), ES512 (P-521), ES256K (secp256k1) |
| EdDSA           | Ed25519, Ed448                                                  |

### MAC (COSE_Mac0)

| Family | Algorithms          |
| ------ | ------------------- |
| HMAC   | HS256, HS384, HS512 |

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

### Content Encryption (JWE and COSE_Encrypt0)

| Family         | Algorithms                                             |
| -------------- | ------------------------------------------------------ |
| AES-GCM        | A128GCM, A192GCM, A256GCM                              |
| AES-CBC + HMAC | A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (JWE only) |
| ChaCha20       | C20P (ChaCha20-Poly1305), XC20P (XChaCha20-Poly1305)   |

## Quick Start

### JWT

```gleam
import gleam/dynamic/decode
import gleam/time/duration
import gleam/time/timestamp
import gose
import gose/jose/jwt

pub fn main() {
  let signing_key = gose.generate_hmac_key(gose.HmacSha256)
  let now = timestamp.system_time()

  let claims =
    jwt.claims()
    |> jwt.with_subject("user123")
    |> jwt.with_issuer("my-app")
    |> jwt.with_expiration(timestamp.add(now, duration.hours(1)))

  let assert Ok(signed) =
    jwt.sign(gose.Mac(gose.Hmac(gose.HmacSha256)), claims:, key: signing_key)
  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(gose.Mac(gose.Hmac(gose.HmacSha256)), keys: [signing_key], options: jwt.default_validation())
  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

  let decoder = decode.field("sub", decode.string, decode.success)
  let assert Ok("user123") = jwt.decode(verified, using: decoder)
}
```

### JWE

```gleam
import gose
import gose/jose/jwe

pub fn main() {
  let encryption_key = gose.generate_enc_key(gose.AesGcm(gose.Aes256))
  let plaintext = <<"sensitive data":utf8>>

  let assert Ok(encrypted) =
    jwe.new_direct(gose.AesGcm(gose.Aes256))
    |> jwe.encrypt(key: encryption_key, plaintext:)

  let assert Ok(token) = jwe.serialize_compact(encrypted)

  let assert Ok(parsed) = jwe.parse_compact(token)
  let assert Ok(decryptor) = jwe.key_decryptor(gose.Direct, gose.AesGcm(gose.Aes256), keys: [encryption_key])
  let assert Ok(decrypted) = jwe.decrypt(decryptor, parsed)
  assert decrypted == <<"sensitive data":utf8>>
}
```

### COSE_Sign1

```gleam
import gose
import gose/cose/sign1
import kryptos/ec

pub fn main() {
  let signing_key = gose.generate_ec(ec.P256)
  let payload = <<"hello COSE":utf8>>

  let assert Ok(signed) =
    sign1.new(gose.Ecdsa(gose.EcdsaP256))
    |> sign1.sign(signing_key, payload)
  let data = sign1.serialize(signed)

  let assert Ok(parsed) = sign1.parse(data)
  let assert Ok(verifier) =
    sign1.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(Nil) = sign1.verify(verifier, parsed)
  assert sign1.payload(parsed) == Ok(payload)
}
```

### CWT

```gleam
import gleam/time/duration
import gleam/time/timestamp
import gose
import gose/cose/cwt
import kryptos/ec

pub fn main() {
  let signing_key = gose.generate_ec(ec.P256)
  let now = timestamp.system_time()

  let claims =
    cwt.new()
    |> cwt.with_subject("user123")
    |> cwt.with_issuer("my-app")
    |> cwt.with_expiration(timestamp.add(now, duration.hours(1)))

  let assert Ok(token) =
    cwt.sign(claims, alg: gose.Ecdsa(gose.EcdsaP256), key: signing_key)

  let assert Ok(verifier) =
    cwt.verifier(gose.Ecdsa(gose.EcdsaP256), keys: [signing_key])
  let assert Ok(verified) = cwt.verify_and_validate(verifier, token:, now:)
  let verified_claims = cwt.verified_claims(verified)
  let assert Ok(subject) = cwt.subject(verified_claims)
  assert subject == "user123"
}
```

## Error Handling

The library uses a two-tier error design:

**`GoseError`** used by JOSE primitives (JWS, JWE, JWK):

| Variant              | When It Occurs                                                                 |
| -------------------- | ------------------------------------------------------------------------------ |
| `ParseError`         | Invalid base64 encoding, malformed JSON, wrong token format                    |
| `CryptoError`        | Decryption failure, key derivation error                                       |
| `InvalidState`       | Wrong key type for algorithm, missing required header, incompatible parameters |
| `VerificationFailed` | Signature or MAC verification failed (intentionally opaque)                    |

**`JwtError`** used by JWT and encrypted JWT modules:

| Variant                | When It Occurs                                                                              |
| ---------------------- | ------------------------------------------------------------------------------------------- |
| `TokenExpired`         | Token's `exp` claim is in the past                                                          |
| `TokenNotYetValid`     | Token's `nbf` claim is in the future                                                        |
| `IssuerMismatch`       | Token's `iss` doesn't match expected issuer                                                 |
| `AudienceMismatch`     | Token's `aud` doesn't match expected audience                                               |
| `InvalidSignature`     | JWS signature verification failed                                                           |
| `DecryptionFailed`     | JWE decryption failed                                                                       |
| `JoseError(GoseError)` | Underlying JOSE operation failed (key validation, signing, etc.)                            |
| ...                    | See [`JwtError`](https://hexdocs.pm/gose/gose/jose/jwt.html#JwtError) type for all variants |

**`CwtError`** used by CWT and encrypted CWT modules:

| Variant                | When It Occurs                                                   |
| ---------------------- | ---------------------------------------------------------------- |
| `TokenExpired`         | Token's `exp` claim is in the past                               |
| `TokenNotYetValid`     | Token's `nbf` claim is in the future                             |
| `IssuerMismatch`       | Token's `iss` doesn't match expected issuer                      |
| `AudienceMismatch`     | Token's `aud` doesn't match expected audience                    |
| `MissingExpiration`    | Token lacks a required `exp` claim                               |
| `InvalidClaim`         | Claim value is invalid (empty audience list, etc.)               |
| `InvalidSignature`     | COSE_Sign1 signature verification failed                         |
| `MalformedToken`       | CBOR structure or claim types are invalid                        |
| `DecryptionFailed`     | COSE decryption failed                                           |
| `CoseError(GoseError)` | Underlying COSE operation failed (key validation, signing, etc.) |

## Limitations

- X.509 certificate parameters not supported - JWKs containing X.509 certificate chain parameters (`x5u`, `x5c`, `x5t`, `x5t#S256`) are rejected with a parse error. Certificate-based key validation must be performed outside this library.
- JWE compression (`zip`) not supported - compressed JWEs are rejected. See [JOSE vulnerability](https://www.rfc-editor.org/rfc/rfc8725#section-3.6) notes.
- COSE_Mac (multiparty) not supported - only COSE_Mac0 (single-recipient) is implemented.

## Documentation

Full API documentation is available at [hexdocs.pm/gose](https://hexdocs.pm/gose/).
