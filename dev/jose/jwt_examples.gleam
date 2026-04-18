import gleam/dynamic/decode
import gleam/int
import gleam/io
import gleam/json
import gleam/option
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import gose/algorithm
import gose/jose/encrypted_jwt
import gose/jose/jwt
import gose/key
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
  encrypted_jwt_peek_headers()
  dangerous_escape_hatches()

  io.println(string.repeat("=", 60))
  io.println("All JWT examples completed!")
  io.println(string.repeat("=", 60))
}

fn create_and_sign_jwt() {
  io.println("--- Create and Sign JWT ---")

  let key = key.generate_hmac_key(algorithm.HmacSha256)
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

  // Sign
  let assert Ok(signed) =
    jwt.sign(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)), claims, key)

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

  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_issuer("gose-example")
    |> jwt.with_subject("user-456")
    |> jwt.with_expiration(exp)

  // Sign
  let assert Ok(signed) =
    jwt.sign(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)), claims, key)

  let token = jwt.serialize(signed)

  // Verify
  let assert Ok(verifier) =
    jwt.verifier(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      [key],
      jwt.default_validation(),
    )

  let assert Ok(verified) = jwt.verify_and_validate(verifier, token, now)

  let decoder = decode.field("sub", decode.string, decode.success)
  let assert Ok(sub) = jwt.decode(verified, decoder)
  io.println("Verified JWT for subject: " <> sub)
  io.println("")
}

fn custom_claims() {
  io.println("--- Custom Claims ---")

  let key = key.generate_hmac_key(algorithm.HmacSha256)
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

  // Sign
  let assert Ok(signed) =
    jwt.sign(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)), claims, key)

  let token = jwt.serialize(signed)

  let decoder = {
    use sub <- decode.field("sub", decode.string)
    use role <- decode.field("role", decode.string)
    use org_id <- decode.field("org_id", decode.int)
    decode.success(#(sub, role, org_id))
  }

  // Verify
  let assert Ok(verifier) =
    jwt.verifier(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      [key],
      jwt.default_validation(),
    )
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

  let old_key = key.generate_hmac_key(algorithm.HmacSha256)
  let old_key = key.with_kid(old_key, "key-v1")

  let new_key = key.generate_hmac_key(algorithm.HmacSha256)
  let new_key = key.with_kid(new_key, "key-v2")

  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("rotating-user")
    |> jwt.with_expiration(exp)

  // Sign
  let assert Ok(signed) =
    jwt.sign(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      claims,
      old_key,
    )

  let token = jwt.serialize(signed)

  // Verify
  let assert Ok(verifier) =
    jwt.verifier(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
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

  let key = key.generate_hmac_key(algorithm.HmacSha256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_issuer("trusted-issuer")
    |> jwt.with_audience("my-service")
    |> jwt.with_subject("validated-user")
    |> jwt.with_expiration(exp)

  // Sign
  let assert Ok(signed) =
    jwt.sign(algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)), claims, key)

  let token = jwt.serialize(signed)

  // Verify
  let options =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      issuer: option.Some("trusted-issuer"),
      audience: option.Some("my-service"),
    )

  let assert Ok(verifier) =
    jwt.verifier(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      [key],
      options,
    )
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

fn encrypt_jwt_direct() {
  io.println("--- Encrypted JWT (Direct Key) ---")

  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_issuer("gose-example")
    |> jwt.with_subject("encrypted-user-123")
    |> jwt.with_audience("secure-api")
    |> jwt.with_expiration(exp)

  // Encrypt
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )

  let token = encrypted_jwt.serialize(encrypted)
  io.println("Encrypted JWT (dir + A256GCM):")
  io.println(string.slice(token, 0, 80) <> "...")

  // Decrypt and validate
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
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

  let wrap_key = key.generate_aes_kw_key(algorithm.Aes256)
  let wrap_key = key.with_kid(wrap_key, "kw-key-1")
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("aes-kw-user")
    |> jwt.with_expiration(exp)

  // Encrypt
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.AesKeyWrap(algorithm.AesKw, algorithm.Aes256),
      algorithm.AesGcm(algorithm.Aes256),
      wrap_key,
    )

  let token = encrypted_jwt.serialize(encrypted)
  io.println("Encrypted JWT (A256KW + A256GCM):")
  io.println(string.slice(token, 0, 80) <> "...")

  // Decrypt and validate
  let jwe_alg = encrypted_jwt.alg(encrypted)
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      jwe_alg,
      algorithm.AesGcm(algorithm.Aes256),
      [wrap_key],
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

  let ec_key = key.generate_ec(ec.P256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("ecdh-user")
    |> jwt.with_issuer("ec-issuer")
    |> jwt.with_expiration(exp)

  // Encrypt
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      algorithm.AesGcm(algorithm.Aes256),
      ec_key,
    )

  let token = encrypted_jwt.serialize(encrypted)
  io.println("Encrypted JWT (ECDH-ES + A256GCM):")
  io.println(string.slice(token, 0, 80) <> "...")

  // Decrypt and validate
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.EcdhEs(algorithm.EcdhEsDirect),
      algorithm.AesGcm(algorithm.Aes256),
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

  // Encrypt
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_password(
      claims,
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes128),
      password,
      kid: option.None,
    )

  let token = encrypted_jwt.serialize(encrypted)
  io.println("Encrypted JWT (PBES2-HS256+A128KW + A128GCM):")
  io.println(string.slice(token, 0, 80) <> "...")

  // Decrypt and validate
  let decryptor =
    encrypted_jwt.password_decryptor(
      algorithm.Pbes2Sha256Aes128Kw,
      algorithm.AesGcm(algorithm.Aes128),
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

  let key = key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

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

  // Encrypt
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
      key,
    )

  let token = encrypted_jwt.serialize(encrypted)

  // Decrypt and validate
  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      algorithm.Direct,
      algorithm.AesGcm(algorithm.Aes256),
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

fn encrypted_jwt_peek_headers() {
  io.println("--- Peek Encrypted JWT Headers (kid-based decryptor routing) ---")

  let encryption_key =
    key.generate_enc_key(algorithm.AesGcm(algorithm.Aes256))
    |> key.with_kid("kek-2025")
  let now = timestamp.system_time()

  let claims = jwt.claims() |> jwt.with_subject("user-123")
  let assert Ok(encrypted) =
    encrypted_jwt.encrypt_with_key(
      claims,
      alg: algorithm.Direct,
      enc: algorithm.AesGcm(algorithm.Aes256),
      key: encryption_key,
    )
  let token = encrypted_jwt.serialize(encrypted)

  let assert Ok(peeked) = encrypted_jwt.peek_headers(token)
  io.println("alg before decryption: " <> string.inspect(peeked.alg))
  io.println("enc before decryption: " <> string.inspect(peeked.enc))
  io.println("kid: " <> string.inspect(peeked.kid))

  let assert Ok(decryptor) =
    encrypted_jwt.key_decryptor(
      alg: algorithm.Direct,
      enc: algorithm.AesGcm(algorithm.Aes256),
      keys: [encryption_key],
      options: jwt.default_validation(),
    )
  let assert Ok(_verified) =
    encrypted_jwt.decrypt_and_validate(decryptor, token, now)
  io.println("")
}

fn dangerous_escape_hatches() {
  io.println("--- Dangerous Escape Hatches (use only after authorization) ---")

  let k = key.generate_hmac_key(algorithm.HmacSha256)
  let now = timestamp.system_time()
  let past = timestamp.add(now, duration.hours(-1))

  let claims =
    jwt.claims()
    |> jwt.with_subject("user-42")
    |> jwt.with_expiration(past)
  let assert Ok(signed) =
    jwt.sign(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      claims:,
      key: k,
    )
  let token = jwt.serialize(signed)

  // Inspect claims BEFORE any verification happens. Never trust these values
  // until verify_and_validate succeeds.
  let assert Ok(unverified) = jwt.parse(token)
  let subject_decoder = {
    use sub <- decode.field("sub", decode.string)
    decode.success(sub)
  }
  let assert Ok(untrusted_sub) =
    jwt.dangerously_decode_unverified(unverified, using: subject_decoder)
  io.println("Untrusted subject preview: " <> untrusted_sub)

  // Verify signature but skip claim validation (e.g. to inspect an expired token).
  let assert Ok(verifier) =
    jwt.verifier(
      algorithm.Mac(algorithm.Hmac(algorithm.HmacSha256)),
      keys: [k],
      options: jwt.default_validation(),
    )
  let assert Ok(verified_expired) =
    jwt.verify_and_dangerously_skip_validation(verifier, token)
  let _ = verified_expired
  io.println("Signature verified even though token is expired")
  io.println("")
}
