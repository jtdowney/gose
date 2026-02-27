import gleam/dynamic/decode
import gleam/time/duration
import gleam/time/timestamp.{type Timestamp}
import gose/jwk
import gose/jwt

pub fn fixed_timestamp() -> Timestamp {
  timestamp.from_unix_seconds(1_700_000_000)
}

pub fn hmac_key() -> jwk.Jwk {
  let assert Ok(key) =
    jwk.from_octet_bits(<<"test-secret-key-32-bytes-long!!!":utf8>>)
  key
}

pub fn default_claims_with_exp() -> jwt.Claims {
  let now = fixed_timestamp()
  let exp = timestamp.add(now, duration.hours(1))
  jwt.claims()
  |> jwt.with_subject("user123")
  |> jwt.with_expiration(exp)
}

pub fn expired_claims() -> jwt.Claims {
  let now = fixed_timestamp()
  jwt.claims()
  |> jwt.with_subject("user123")
  |> jwt.with_expiration(timestamp.add(now, duration.hours(-1)))
}

pub fn not_yet_valid_claims() -> jwt.Claims {
  let now = fixed_timestamp()
  jwt.claims()
  |> jwt.with_subject("user123")
  |> jwt.with_not_before(timestamp.add(now, duration.hours(1)))
  |> jwt.with_expiration(timestamp.add(now, duration.hours(2)))
}

pub fn claims_with_issuer(issuer: String) -> jwt.Claims {
  default_claims_with_exp() |> jwt.with_issuer(issuer)
}

pub fn claims_without_exp() -> jwt.Claims {
  jwt.claims() |> jwt.with_subject("user123")
}

pub fn sub_decoder() -> decode.Decoder(String) {
  decode.field("sub", decode.string, decode.success)
}
