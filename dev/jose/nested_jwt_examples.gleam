import gleam/bit_array
import gleam/dynamic/decode
import gleam/io
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import gose
import gose/jose/jwe
import gose/jose/jwt
import kryptos/ec
import kryptos/eddsa

/// Nested JWTs provide both integrity and confidentiality
/// by signing a JWT first, then encrypting the entire signed token.
///
/// The existing gose primitives compose cleanly for this pattern:
/// 1. Create claims and sign with jwt.sign() -> Jwt(Verified)
/// 2. Serialize the signed JWT -> String
/// 3. Encrypt as JWE payload with cty: "JWT" header
///
/// On the receiving side:
/// 1. Parse and decrypt the outer JWE
/// 2. Extract the inner JWT string
/// 3. Verify the inner JWT signature and validate claims
pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("Nested JWT Examples (Sign-then-Encrypt)")
  io.println(string.repeat("=", 60))
  io.println("")

  nested_jwt_symmetric()
  nested_jwt_asymmetric()
  nested_jwt_different_keys()

  io.println(string.repeat("=", 60))
  io.println("All nested JWT examples completed!")
  io.println(string.repeat("=", 60))
}

fn nested_jwt_symmetric() {
  io.println("--- Nested JWT (Symmetric Keys) ---")
  io.println("Sign with HS256, encrypt with dir + A256GCM")
  io.println("")

  let signing_key = gose.generate_hmac_key(gose.HmacSha256)
  let encryption_key = gose.generate_enc_key(gose.AesGcm(gose.Aes256))
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  // Sign the inner JWT
  let claims =
    jwt.claims()
    |> jwt.with_issuer("auth-server")
    |> jwt.with_subject("user-123")
    |> jwt.with_audience("api-gateway")
    |> jwt.with_issued_at(now)
    |> jwt.with_expiration(exp)

  let assert Ok(signed_jwt) =
    jwt.sign(
      gose.Mac(gose.Hmac(gose.HmacSha256)),
      claims,
      signing_key,
    )
  let inner_token = jwt.serialize(signed_jwt)
  io.println("Inner signed JWT created")

  // Encrypt as JWE — cty: "JWT" signals the payload is itself a JWT
  let assert Ok(nested_token) =
    jwe.new_direct(gose.AesGcm(gose.Aes256))
    |> jwe.with_cty("JWT")
    |> jwe.encrypt(encryption_key, bit_array.from_string(inner_token))
    |> result.try(jwe.serialize_compact)

  io.println("Outer JWE created with cty: JWT")
  io.println("Nested token: " <> nested_token)
  io.println("")

  // Decrypt the outer JWE
  let assert Ok(parsed_jwe) = jwe.parse_compact(nested_token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(gose.Direct, gose.AesGcm(gose.Aes256), [
      encryption_key,
    ])
  let assert Ok(inner_bits) = jwe.decrypt(decryptor, parsed_jwe)
  let assert Ok(decrypted_inner_token) = bit_array.to_string(inner_bits)

  io.println("Outer JWE decrypted")

  // Verify the inner JWT
  let assert Ok(verifier) =
    jwt.verifier(
      gose.Mac(gose.Hmac(gose.HmacSha256)),
      [signing_key],
      jwt.default_validation(),
    )
  let assert Ok(verified_jwt) =
    jwt.verify_and_validate(verifier, decrypted_inner_token, now)

  let decoder = {
    use sub <- decode.field("sub", decode.string)
    use iss <- decode.field("iss", decode.string)
    decode.success(#(sub, iss))
  }
  let assert Ok(#(sub, iss)) = jwt.decode(verified_jwt, decoder)

  io.println("Inner JWT verified")
  io.println("  Subject: " <> sub)
  io.println("  Issuer: " <> iss)
  io.println("")
}

fn nested_jwt_asymmetric() {
  io.println("--- Nested JWT (Asymmetric Keys) ---")
  io.println("Sign with ES256 (P-256), encrypt with ECDH-ES + A256GCM")
  io.println("")

  let sender_signing_key = gose.generate_ec(ec.P256)
  let assert Ok(sender_public_key) = gose.public_key(sender_signing_key)

  let recipient_encryption_key = gose.generate_ec(ec.P256)
  let assert Ok(recipient_public_key) =
    gose.public_key(recipient_encryption_key)

  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  // Sender: sign the inner JWT
  let claims =
    jwt.claims()
    |> jwt.with_issuer("identity-provider")
    |> jwt.with_subject("user-456")
    |> jwt.with_expiration(exp)

  let assert Ok(signed_jwt) =
    jwt.sign(
      gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)),
      claims,
      sender_signing_key,
    )
  let inner_token = jwt.serialize(signed_jwt)
  io.println("Sender: Signed JWT with private key")

  // Sender: encrypt to recipient's public key
  let apu = <<"identity-provider":utf8>>
  let apv = <<"api-gateway":utf8>>

  let assert Ok(nested_token) =
    jwe.new_ecdh_es(gose.EcdhEsDirect, gose.AesGcm(gose.Aes256))
    |> jwe.with_cty("JWT")
    |> jwe.with_apu(apu)
    |> jwe.with_apv(apv)
    |> jwe.encrypt(recipient_public_key, bit_array.from_string(inner_token))
    |> result.try(jwe.serialize_compact)

  io.println("Sender: Encrypted to recipient's public key (with apu/apv)")
  io.println("Nested token: " <> nested_token)
  io.println("")

  // Recipient: decrypt with private key
  let assert Ok(parsed_jwe) = jwe.parse_compact(nested_token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      gose.EcdhEs(gose.EcdhEsDirect),
      gose.AesGcm(gose.Aes256),
      [
        recipient_encryption_key,
      ],
    )
  let assert Ok(inner_bits) = jwe.decrypt(decryptor, parsed_jwe)
  let assert Ok(decrypted_inner_token) = bit_array.to_string(inner_bits)

  io.println("Recipient: Decrypted with private key")

  // Recipient: verify with sender's public key
  let assert Ok(verifier) =
    jwt.verifier(
      gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)),
      [sender_public_key],
      jwt.default_validation(),
    )
  let assert Ok(verified_jwt) =
    jwt.verify_and_validate(verifier, decrypted_inner_token, now)

  let decoder = decode.field("sub", decode.string, decode.success)
  let assert Ok(sub) = jwt.decode(verified_jwt, decoder)

  io.println("Recipient: Verified signature with sender's public key")
  io.println("  Subject: " <> sub)
  io.println("")
}

fn nested_jwt_different_keys() {
  io.println("--- Nested JWT (Different Key Types) ---")
  io.println("Sign with EdDSA (Ed25519), encrypt with AES-256-KW + A256GCM")
  io.println("")

  let signing_key = gose.generate_eddsa(eddsa.Ed25519)
  let encryption_key = gose.generate_aes_kw_key(gose.Aes256)
  let now = timestamp.system_time()
  let exp = timestamp.add(now, duration.hours(1))

  // Sign the inner JWT
  let claims =
    jwt.claims()
    |> jwt.with_issuer("secure-service")
    |> jwt.with_subject("user-789")
    |> jwt.with_expiration(exp)

  let assert Ok(signed_jwt) =
    jwt.sign(gose.DigitalSignature(gose.Eddsa), claims, signing_key)
  let inner_token = jwt.serialize(signed_jwt)
  io.println("Inner JWT signed with EdDSA")

  // Encrypt as JWE
  let assert Ok(nested_token) =
    jwe.new_aes_kw(gose.Aes256, gose.AesGcm(gose.Aes256))
    |> jwe.with_cty("JWT")
    |> jwe.encrypt(encryption_key, bit_array.from_string(inner_token))
    |> result.try(jwe.serialize_compact)

  io.println("Outer JWE encrypted with A256KW")
  io.println("Nested token: " <> nested_token)
  io.println("")

  // Decrypt the outer JWE
  let assert Ok(parsed_jwe) = jwe.parse_compact(nested_token)
  let assert Ok(decryptor) =
    jwe.key_decryptor(
      gose.AesKeyWrap(gose.AesKw, gose.Aes256),
      gose.AesGcm(gose.Aes256),
      [
        encryption_key,
      ],
    )
  let assert Ok(inner_bits) = jwe.decrypt(decryptor, parsed_jwe)
  let assert Ok(decrypted_inner_token) = bit_array.to_string(inner_bits)

  io.println("Outer JWE decrypted")

  // Verify the inner JWT
  let assert Ok(verifier) =
    jwt.verifier(
      gose.DigitalSignature(gose.Eddsa),
      [signing_key],
      jwt.default_validation(),
    )
  let assert Ok(verified_jwt) =
    jwt.verify_and_validate(verifier, decrypted_inner_token, now)

  let decoder = decode.field("sub", decode.string, decode.success)
  let assert Ok(sub) = jwt.decode(verified_jwt, decoder)

  io.println("Inner JWT verified with EdDSA")
  io.println("  Subject: " <> sub)
  io.println("")
}
