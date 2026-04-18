# Migrating from gose v1 to v2

gose v2 adds COSE support and reorganizes the module structure. The JOSE API is functionally the same, but modules moved and some types were renamed.

This guide covers JOSE migration. v2 also adds COSE ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) / [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053)) support, which has no v1 equivalent. See the README's COSE section and the modules under `gose/cose/`: `sign1`, `sign`, `encrypt0`, `encrypt`, `mac0`, `cwt`, `encrypted_cwt`, `key`.

## Quick checklist

1. Update imports (modules moved under `gose/jose/`)
2. Replace `gose/jwa` with `gose/algorithm`
3. Replace `gose/jwk` with `gose/key` (key management) and `gose/jose/jwk` (JSON serialization)
4. Update algorithm constructors (`JwsHmac(...)` becomes `Mac(Hmac(...))`)
5. Update type annotations (`Jwk` becomes `Key(String)`)

## Import changes

| v1                          | v2                                                     |
| --------------------------- | ------------------------------------------------------ |
| `import gose/jwa`           | `import gose/algorithm` (algorithm types) + `import gose/jose/algorithm` (JOSE string conversions) |
| `import gose/jwk`           | `import gose/key`                                      |
| (none)                      | `import gose/jose/jwk` (JWK JSON, alg string conversions, thumbprints) |
| `import gose/jws`           | `import gose/jose/jws`                                 |
| `import gose/jwe`           | `import gose/jose/jwe`                                 |
| `import gose/jwt`           | `import gose/jose/jwt`                                 |
| `import gose/jwk_set`       | `import gose/jose/key_set`                             |
| `import gose/encrypted_jwk` | `import gose/jose/encrypted_key`                       |
| `import gose/encrypted_jwt` | `import gose/jose/encrypted_jwt`                       |
| (none)                      | `import gose/jose/jws_multi` (multi-signature JWS)     |
| (none)                      | `import gose/jose/jwe_multi` (multi-recipient JWE)     |

## Key management split

In v1, `gose/jwk` handled everything: key creation, metadata, and JSON serialization. In v2 this is split:

- `gose/key` for key creation, generation, metadata, DER/PEM import/export
- `gose/jose/jwk` for JWK JSON serialization (`to_json`, `from_json`), JWK `alg` string conversions (`alg_to_string`, `alg_from_string`), and JWK thumbprints (`thumbprint`)

```gleam
// v1
import gose/jwk

let k = jwk.generate_ec(ec.P256) |> jwk.with_kid("my-key")
let json = jwk.to_json(k) |> json.to_string()
let assert Ok(parsed) = jwk.from_json(json_string)

// v2
import gose/key
import gose/jose/jwk

let k = key.generate_ec(ec.P256) |> key.with_kid("my-key")
let json = jwk.to_json(k) |> json.to_string()
let assert Ok(parsed) = jwk.from_json(json_string)
```

`thumbprint`, `alg_to_string`, and `alg_from_string` moved with JSON serialization. They now live on `gose/jose/jwk`:

```gleam
// v1
import gose/jwk

let assert Ok(tp) = jwk.thumbprint(k, hash.Sha256)

// v2
import gose/jose/jwk

let assert Ok(tp) = jwk.thumbprint(k, hash.Sha256)
```

### Type rename

The key type changed from `jwk.Jwk` to `key.Key(String)`. The type parameter is the key ID type: `String` for JWK, `BitArray` for COSE keys.

```gleam
// v1
fn my_function(k: jwk.Jwk) -> ...

// v2
fn my_function(k: key.Key(String)) -> ...
```

Supporting types (`KeyUse`, `KeyOp`, `KeyType`) moved from `gose/jwk` to `gose/key` with the same names and constructors.

### Alg type

The `Alg` type on keys changed its constructor names:

```gleam
// v1
jwk.Jws(jwa.JwsHmac(jwa.HmacSha256))
jwk.Jwe(jwa.JweDirect)

// v2
key.SigningAlg(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)))
key.KeyEncryptionAlg(algorithm.Direct)
key.ContentAlg(algorithm.AesGcm(algorithm.Aes256))  // new in v2
```

## Algorithm changes

`gose/jwa` is removed. Its types now live in `gose/algorithm` with a more granular hierarchy.

### Signing algorithms

`jwa.JwsAlg` becomes `algorithm.SigningAlg`, which separates digital signatures from MACs:

```gleam
// v1                                    // v2
jwa.JwsHmac(jwa.HmacSha256)             algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256))
jwa.JwsRsaPkcs1(jwa.RsaPkcs1Sha256)     algorithm.DigitalSignature(algorithm.RsaPkcs1(algorithm.RsaPkcs1Sha256))
jwa.JwsRsaPss(jwa.RsaPssSha256)         algorithm.DigitalSignature(algorithm.RsaPss(algorithm.RsaPssSha256))
jwa.JwsEcdsa(jwa.EcdsaP256)             algorithm.DigitalSignature(algorithm.Ecdsa(algorithm.EcdsaP256))
jwa.JwsEddsa                            algorithm.DigitalSignature(algorithm.Eddsa)
```

The leaf types (`HmacAlg`, `RsaPkcs1Alg`, `RsaPssAlg`, `EcdsaAlg`, `AesKeySize`) kept the same constructors. Only the wrapping changed.

### Key encryption algorithms

`jwa.JweAlg` becomes `algorithm.KeyEncryptionAlg`:

```gleam
// v1                                              // v2
jwa.JweDirect                                      algorithm.Direct
jwa.JweAesKeyWrap(jwa.AesKw, jwa.Aes128)           algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes128)
jwa.JweAesKeyWrap(jwa.AesGcmKw, jwa.Aes256)        algorithm.AesKeyWrap(algorithm.AesGcmKw, algorithm.Aes256)
jwa.JweChaCha20KeyWrap(jwa.C20PKw)                 algorithm.ChaCha20KeyWrap(algorithm.C20PKw)
jwa.JweRsa(jwa.RsaOaepSha256)                      algorithm.RsaEncryption(algorithm.RsaOaepSha256)
jwa.JweEcdhEs(jwa.EcdhEsDirect)                    algorithm.EcdhEs(algorithm.EcdhEsDirect)
jwa.JweEcdhEs(jwa.EcdhEsAesKw(jwa.Aes128))         algorithm.EcdhEs(algorithm.EcdhEsAesKw(algorithm.Aes128))
jwa.JwePbes2(jwa.Pbes2Sha256Aes128Kw)              algorithm.Pbes2(algorithm.Pbes2Sha256Aes128Kw)
```

### Content encryption algorithms

`jwa.Enc` becomes `algorithm.ContentAlg`:

```gleam
// v1                      // v2
jwa.AesGcm(jwa.Aes256)     algorithm.AesGcm(algorithm.Aes256)
jwa.AesCbcHmac(jwa.Aes256) algorithm.AesCbcHmac(algorithm.Aes256)
jwa.ChaCha20Poly1305       algorithm.ChaCha20Poly1305
jwa.XChaCha20Poly1305      algorithm.XChaCha20Poly1305
```

### Conversion functions

JOSE string conversions move to `gose/jose/algorithm`:

| v1                        | v2                                              |
| ------------------------- | ----------------------------------------------- |
| `jwa.jws_alg_to_string`   | `jose/algorithm.signing_alg_to_string`          |
| `jwa.jws_alg_from_string` | `jose/algorithm.signing_alg_from_string`        |
| `jwa.jwe_alg_to_string`   | `jose/algorithm.key_encryption_alg_to_string`   |
| `jwa.jwe_alg_from_string` | `jose/algorithm.key_encryption_alg_from_string` |
| `jwa.enc_to_string`       | `jose/algorithm.content_alg_to_string`          |
| `jwa.enc_from_string`     | `jose/algorithm.content_alg_from_string`        |

The v1 raw size helpers (`jwa.aes_key_size_in_bytes`,
`jwa.hmac_alg_octet_key_size`, `jwa.enc_octet_key_size`,
`jwa.chacha20_kw_nonce_size`) are no longer part of the public API. Use the
`gose/key.generate_*` helpers to produce keys of the correct size for each
algorithm variant.

## End-to-end examples

### JWT signing and verification

v2 adds `claims:` and `key:` labels to `jwt.sign` (positional in v1).

```gleam
// v1
import gose/jwa
import gose/jwk
import gose/jwt

let k = jwk.generate_hmac_key(jwa.HmacSha256)
let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, k)
let token = jwt.serialize(signed)

let assert Ok(verifier) = jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), keys: [k], options: jwt.default_validation())
let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

// v2
import gose/algorithm
import gose/key
import gose/jose/jwt

let k = key.generate_hmac_key(algorithm.HmacSha256)
let assert Ok(signed) = jwt.sign(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)), claims: claims, key: k)
let token = jwt.serialize(signed)

let assert Ok(verifier) = jwt.verifier(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)), keys: [k], options: jwt.default_validation())
let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)
```

### JWS signing

```gleam
// v1
import gose/jwa
import gose/jwk
import gose/jws

let k = jwk.generate_eddsa(eddsa.Ed25519)
let assert Ok(signed) = jws.new(jwa.JwsEddsa) |> jws.sign(key: k, payload: payload)
let assert Ok(verifier) = jws.verifier(jwa.JwsEddsa, keys: [k])

// v2
import gose/algorithm
import gose/key
import gose/jose/jws

let k = key.generate_eddsa(eddsa.Ed25519)
let assert Ok(signed) = jws.new(algorithm.DigitalSignature(algorithm.Eddsa)) |> jws.sign(key: k, payload: payload)
let assert Ok(verifier) = jws.verifier(algorithm.DigitalSignature(algorithm.Eddsa), keys: [k])
```

### JWE encryption

```gleam
// v1
import gose/jwa
import gose/jwk
import gose/jwe

let k = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
let assert Ok(encrypted) = jwe.new_direct(jwa.AesGcm(jwa.Aes256)) |> jwe.encrypt(key: k, plaintext: plaintext)
let assert Ok(decryptor) = jwe.key_decryptor(jwa.JweDirect, jwa.AesGcm(jwa.Aes256), keys: [k])

// v2
import gose/algorithm
import gose/key
import gose/jose/jwe

let k = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
let assert Ok(encrypted) = jwe.new_direct(algorithm.AesGcm(algorithm.Aes256)) |> jwe.encrypt(key: k, plaintext: plaintext)
let assert Ok(decryptor) = jwe.key_decryptor(algorithm.Direct, algorithm.AesGcm(algorithm.Aes256), keys: [k])
```

### JWK Set

```gleam
// v1
import gose/jwk
import gose/jwk_set

let set = jwk_set.from_list([key1, key2])
let assert Ok(k) = jwk_set.get(set, "my-kid")

// v2
import gose/key
import gose/jose/key_set

let set = key_set.from_list([key1, key2])
let assert Ok(k) = key_set.get(set, kid: "my-kid")
```

### Encrypted key (formerly encrypted JWK)

Renamed from `encrypted_jwk` to `encrypted_key`. Same API: `decrypt` takes a `jwe.Decryptor`, `encrypt_with_key`/`encrypt_with_password` handle export.

```gleam
// v1
import gose/encrypted_jwk
import gose/jwa
import gose/jwe

let decryptor = jwe.password_decryptor(jwa.Pbes2Sha256Aes128Kw, jwa.AesGcm(jwa.Aes256), password: "secret")
let assert Ok(k) = encrypted_jwk.decrypt(decryptor, encrypted_token)
let assert Ok(exported) = encrypted_jwk.encrypt_with_password(k, alg: jwa.Pbes2Sha256Aes128Kw, enc: jwa.AesGcm(jwa.Aes256), password: "secret")

// v2
import gose/algorithm
import gose/jose/encrypted_key
import gose/jose/jwe

let decryptor = jwe.password_decryptor(algorithm.Pbes2Sha256Aes128Kw, algorithm.AesGcm(algorithm.Aes256), password: "secret")
let assert Ok(k) = encrypted_key.decrypt(decryptor, encrypted_token)
let assert Ok(exported) = encrypted_key.encrypt_with_password(k, alg: algorithm.Pbes2Sha256Aes128Kw, enc: algorithm.AesGcm(algorithm.Aes256), password: "secret")
```

## Verification return type

All `verify` functions on JWS, COSE_Sign1, COSE_Sign, and COSE_Mac0 now return `Result(Nil, GoseError)` instead of `Result(Bool, GoseError)`. Verification failure is now an error, not a boolean.

A new `VerificationFailed` variant was added to `GoseError`.

```gleam
// v1
let assert Ok(True) = jws.verify(verifier, parsed)
let assert Ok(True) = sign1.verify(verifier, parsed)
let assert Ok(True) = mac0.verify(verifier, parsed)

// v2
let assert Ok(Nil) = jws.verify(verifier, parsed)
let assert Ok(Nil) = sign1.verify(verifier, parsed)
let assert Ok(Nil) = mac0.verify(verifier, parsed)
```

Handling verification failure:

```gleam
// v1
case jws.verify(verifier, parsed) {
  Ok(True) -> // valid
  Ok(False) -> // invalid signature
  Error(err) -> // operational error
}

// v2
case jws.verify(verifier, parsed) {
  Ok(Nil) -> // valid
  Error(gose.VerificationFailed) -> // invalid signature
  Error(err) -> // operational error
}
```

**JWT and CWT are unaffected.** `jwt.verify_and_validate` still returns `Result(Jwt(Verified), JwtError)` and `cwt.verify_and_validate` still returns `Result(Cwt(Verified), CwtError)`.

## Unchanged

- `gose.GoseError` variants `ParseError`, `CryptoError`, `InvalidState` (unchanged; `VerificationFailed` was added)
- `jwt.JwtError` and its variants
- JWT claims builder (`jwt.claims()`, `jwt.with_subject()`, etc.)
- JWS phantom types (`Unsigned`, `Signed`, `Built`, `Parsed`)
- JWE phantom types and family-specific builders
- Serialization/parsing functions (`serialize_compact`, `parse_compact`, `serialize_json_flattened`, etc.)
- Algorithm pinning behavior
- Platform support (Erlang, Node.js)
- Dependencies (`kryptos`, `gleam_json`, `gleam_stdlib`, `gleam_time`)
