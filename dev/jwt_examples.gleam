import gleam/dynamic/decode
import gleam/int
import gleam/io
import gleam/json
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import gose/encrypted_jwt
import gose/jwa
import gose/jwk
import gose/jwt
import kryptos/ec

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("JWT (JSON Web Token) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  create_and_sign_jwt()
  verify_jwt()
  custom_claims()
  key_rotation()
  validation_options()

  io.println("")
  io.println(string.repeat("=", 60))
  io.println("Encrypted JWT (JWE-based) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  encrypt_jwt_direct()
  encrypt_jwt_aes_kw()
  encrypt_jwt_ecdh()
  encrypt_jwt_password()
  encrypted_jwt_custom_claims()

  io.println(string.repeat("=", 60))
  io.println("All JWT examples completed!")
  io.println(string.repeat("=", 60))
}

fn create_and_sign_jwt() {
  io.println("--- Create and Sign JWT ---")

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_issuer("gose-example")
    |> jwt.with_subject("user-123")
    |> jwt.with_audience("my-api")
    |> jwt.with_issued_at(now)
    |> jwt.with_expiration(exp)
    |> jwt.with_jwt_id("unique-token-id-001")

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)

  let token = jwt.serialize(signed)

  io.println("Signed JWT:")
  io.println(token)

  let decoder = {
    use iss <- decode.field("iss", decode.string)
    use sub <- decode.field("sub", decode.string)
    decode.success(#(iss, sub))
  }
  let assert Ok(#(iss, sub)) = jwt.decode(signed, decoder)
  io.println("Issuer: " <> iss)
  io.println("Subject: " <> sub)
  io.println("")
}

fn verify_jwt() {
  io.println("--- Verify JWT ---")

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_issuer("gose-example")
    |> jwt.with_subject("user-456")
    |> jwt.with_expiration(exp)

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)

  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())

  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

  let decoder = decode.field("sub", decode.string, decode.success)
  let assert Ok(sub) = jwt.decode(verified, decoder)
  io.println("Verified JWT for subject: " <> sub)
  io.println("")
}

fn custom_claims() {
  io.println("--- Custom Claims ---")

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let assert Ok(claims) =
    jwt.claims()
    |> jwt.with_subject("user-789")
    |> jwt.with_expiration(exp)
    |> jwt.with_claim("role", json.string("admin"))

  let assert Ok(claims) =
    jwt.with_claim(
      claims,
      "permissions",
      json.preprocessed_array([
        json.string("read"),
        json.string("write"),
        json.string("delete"),
      ]),
    )

  let assert Ok(claims) = jwt.with_claim(claims, "org_id", json.int(42))

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)

  let token = jwt.serialize(signed)

  let decoder = {
    use sub <- decode.field("sub", decode.string)
    use role <- decode.field("role", decode.string)
    use org_id <- decode.field("org_id", decode.int)
    decode.success(#(sub, role, org_id))
  }

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], jwt.default_validation())
  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)
  let assert Ok(#(sub, role, org_id)) = jwt.decode(verified, decoder)

  io.println("Decoded custom claims:")
  io.println("  Subject: " <> sub)
  io.println("  Role: " <> role)
  io.println("  Org ID: " <> int.to_string(org_id))
  io.println("")
}

fn key_rotation() {
  io.println("--- Key Rotation with Multiple Keys ---")

  let old_key = jwk.generate_hmac_key(jwa.HmacSha256)
  let old_key = jwk.with_kid(old_key, "key-v1")

  let new_key = jwk.generate_hmac_key(jwa.HmacSha256)
  let new_key = jwk.with_kid(new_key, "key-v2")

  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("rotating-user")
    |> jwt.with_expiration(exp)

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, old_key)

  let token = jwt.serialize(signed)

  let assert Ok(verifier) =
    jwt.verifier(
      jwa.JwsHmac(jwa.HmacSha256),
      [new_key, old_key],
      jwt.default_validation(),
    )

  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

  let assert Ok(kid) = jwt.kid(verified)
  io.println("Verified token with kid: " <> kid)
  io.println("(Verifier tried key-v2 first, then matched key-v1)")
  io.println("")
}

fn validation_options() {
  io.println("--- Validation Options (Issuer/Audience) ---")

  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_issuer("trusted-issuer")
    |> jwt.with_audience("my-service")
    |> jwt.with_subject("validated-user")
    |> jwt.with_expiration(exp)

  let assert Ok(signed) = jwt.sign(jwa.JwsHmac(jwa.HmacSha256), claims, key)

  let token = jwt.serialize(signed)

  let options =
    jwt.JwtValidationOptions(
      issuer: Some("trusted-issuer"),
      audience: Some("my-service"),
      clock_skew: 60,
      require_exp: True,
      max_token_age: None,
      jti_validator: None,
      kid_policy: jwt.NoKidRequirement,
    )

  let assert Ok(verifier) =
    jwt.verifier(jwa.JwsHmac(jwa.HmacSha256), [key], options)
  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

  let decoder = {
    use iss <- decode.field("iss", decode.string)
    use aud <- decode.field("aud", decode.string)
    decode.success(#(iss, aud))
  }
  let assert Ok(#(iss, aud)) = jwt.decode(verified, decoder)
  io.println("Validation passed:")
  io.println("  Issuer: " <> iss <> " (matched)")
  io.println("  Audience: " <> aud <> " (matched)")
  io.println("")
}

// ============================================================================
// Encrypted JWT Examples
// ============================================================================

fn encrypt_jwt_direct() {
  io.println("--- Encrypted JWT (Direct Key) ---")

  // Generate a 256-bit key for AES-256-GCM
  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  // Create claims (same as signed JWTs)
  let claims =
    jwt.claims()
    |> jwt.with_issuer("gose-example")
    |> jwt.with_subject("encrypted-user-123")
    |> jwt.with_audience("secure-api")
    |> jwt.with_expiration(exp)

  // Encrypt the JWT using direct key encryption
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      jwa.JweDirect,
      jwa.AesGcm(jwa.Aes256),
      key,
    )

  let token = encrypted_jwt.serialize(encrypted)
  io.println("Encrypted JWT (dir + A256GCM):")
  io.println(string.slice(token, 0, 80) <> "...")

  // Decrypt and validate
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      jwa.JweDirect,
      jwa.AesGcm(jwa.Aes256),
      [key],
      jwt.default_validation(),
    )

  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)

  let decoder = decode.field("sub", decode.string, decode.success)
  let assert Ok(sub) = encrypted_jwt.decode(verified, decoder)
  io.println("Decrypted subject: " <> sub)
  io.println("")
}

fn encrypt_jwt_aes_kw() {
  io.println("--- Encrypted JWT (AES Key Wrap) ---")

  // Generate a 256-bit key for A256KW
  let key = jwk.generate_aes_kw_key(jwa.Aes256)
  let key = jwk.with_kid(key, "kw-key-1")
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("aes-kw-user")
    |> jwt.with_expiration(exp)

  // Encrypt using AES-256 Key Wrap with AES-256-GCM content encryption
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      jwa.JweAesKeyWrap(jwa.AesKw, jwa.Aes256),
      jwa.AesGcm(jwa.Aes256),
      key,
    )

  let token = encrypted_jwt.serialize(encrypted)
  io.println("Encrypted JWT (A256KW + A256GCM):")
  io.println(string.slice(token, 0, 80) <> "...")

  let jwe_alg = encrypted_jwt.alg(encrypted)
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      jwe_alg,
      jwa.AesGcm(jwa.Aes256),
      [key],
      jwt.default_validation(),
    )

  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  let assert Ok(kid) = encrypted_jwt.kid(verified)
  io.println("Decrypted successfully, kid: " <> kid)
  io.println("")
}

fn encrypt_jwt_ecdh() {
  io.println("--- Encrypted JWT (ECDH-ES) ---")

  // Generate an EC key for ECDH-ES
  let ec_key = jwk.generate_ec(ec.P256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("ecdh-user")
    |> jwt.with_issuer("ec-issuer")
    |> jwt.with_expiration(exp)

  // Encrypt using ECDH-ES direct key agreement
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      jwa.JweEcdhEs(jwa.EcdhEsDirect),
      jwa.AesGcm(jwa.Aes256),
      ec_key,
    )

  let token = encrypted_jwt.serialize(encrypted)
  io.println("Encrypted JWT (ECDH-ES + A256GCM):")
  io.println(string.slice(token, 0, 80) <> "...")

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      jwa.JweEcdhEs(jwa.EcdhEsDirect),
      jwa.AesGcm(jwa.Aes256),
      [ec_key],
      jwt.default_validation(),
    )

  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)

  let decoder = {
    use sub <- decode.field("sub", decode.string)
    use iss <- decode.field("iss", decode.string)
    decode.success(#(sub, iss))
  }
  let assert Ok(#(sub, iss)) = encrypted_jwt.decode(verified, decoder)
  io.println("Decrypted - Subject: " <> sub <> ", Issuer: " <> iss)
  io.println("")
}

fn encrypt_jwt_password() {
  io.println("--- Encrypted JWT (Password-based) ---")

  let password = "my-secure-password-123"
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("password-protected-user")
    |> jwt.with_expiration(exp)

  // Encrypt using PBES2 password-based encryption
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_password(
      claims,
      jwa.Pbes2Sha256Aes128Kw,
      jwa.AesGcm(jwa.Aes128),
      password,
      kid: None,
    )

  let token = encrypted_jwt.serialize(encrypted)
  io.println("Encrypted JWT (PBES2-HS256+A128KW + A128GCM):")
  io.println(string.slice(token, 0, 80) <> "...")

  let decryptor =
    encrypted_jwt.password_decryptor(
      jwa.Pbes2Sha256Aes128Kw,
      jwa.AesGcm(jwa.Aes128),
      password,
      jwt.default_validation(),
    )

  let assert Ok(verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)

  let decoder = decode.field("sub", decode.string, decode.success)
  let assert Ok(sub) = encrypted_jwt.decode(verified, decoder)
  io.println("Decrypted with password - Subject: " <> sub)
  io.println("")
}

fn encrypted_jwt_custom_claims() {
  io.println("--- Encrypted JWT with Custom Claims ---")

  let key = jwk.generate_enc_key(jwa.AesGcm(jwa.Aes256))
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  // Create claims with custom fields
  let assert Ok(claims) =
    jwt.claims()
    |> jwt.with_subject("admin-user")
    |> jwt.with_expiration(exp)
    |> jwt.with_claim("role", json.string("superadmin"))

  let assert Ok(claims) =
    jwt.with_claim(
      claims,
      "permissions",
      json.preprocessed_array([
        json.string("users:read"),
        json.string("users:write"),
        json.string("admin:all"),
      ]),
    )

  let assert Ok(claims) = jwt.with_claim(claims, "tenant_id", json.int(12_345))

  // Encrypt the JWT
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      jwa.JweDirect,
      jwa.AesGcm(jwa.Aes256),
      key,
    )

  let token = encrypted_jwt.serialize(encrypted)

  // Decrypt and decode custom claims
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      jwa.JweDirect,
      jwa.AesGcm(jwa.Aes256),
      [key],
      jwt.default_validation(),
    )

  let decoder = {
    use sub <- decode.field("sub", decode.string)
    use role <- decode.field("role", decode.string)
    use tenant_id <- decode.field("tenant_id", decode.int)
    use permissions <- decode.field("permissions", decode.list(decode.string))
    decode.success(#(sub, role, tenant_id, permissions))
  }

  let assert Ok(#(sub, role, tenant_id, permissions)) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
    |> result.try(encrypted_jwt.decode(_, decoder))

  io.println("Decrypted custom claims:")
  io.println("  Subject: " <> sub)
  io.println("  Role: " <> role)
  io.println("  Tenant ID: " <> int.to_string(tenant_id))
  io.println("  Permissions: " <> string.join(permissions, ", "))
  io.println("")
}
