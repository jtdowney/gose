import gleam/int
import gleam/io
import gleam/json
import gleam/list
import gleam/string
import gose
import gose/jose/key_set
import kryptos/ec

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("JWK Set Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  create_and_serialize()
  parse_and_lookup()
  filter_keys()
  strict_parsing()

  io.println(string.repeat("=", 60))
  io.println("All JWK Set examples completed!")
  io.println(string.repeat("=", 60))
}

fn create_and_serialize() {
  io.println("--- Create and Serialize ---")

  let k1 =
    gose.generate_hmac_key(gose.HmacSha256)
    |> gose.with_kid("hmac-1")
  let k2 =
    gose.generate_ec(ec.P256)
    |> gose.with_kid("ec-1")

  let set = key_set.from_list([k1, k2])

  let json_str = key_set.to_json(set) |> json.to_string
  io.println("JWK Set JSON:")
  io.println(json_str)
  io.println("")
}

fn parse_and_lookup() {
  io.println("--- Parse and Lookup ---")

  let k1 =
    gose.generate_hmac_key(gose.HmacSha256)
    |> gose.with_kid("signing-key")
  let k2 =
    gose.generate_ec(ec.P256)
    |> gose.with_kid("verification-key")

  let set = key_set.from_list([k1, k2])

  // Serialize
  let json_str = key_set.to_json(set) |> json.to_string

  // Parse
  let assert Ok(parsed) = key_set.from_json(json_str)
  let assert Ok(found) = key_set.get(parsed, kid: "signing-key")
  let assert Ok(kid) = gose.kid(found)
  io.println("Found key: " <> kid)

  let assert Error(Nil) = key_set.get(parsed, kid: "nonexistent")
  io.println("Missing key lookup correctly returns Error")
  io.println("")
}

fn filter_keys() {
  io.println("--- Filter and Modify ---")

  let assert Ok(k1) =
    gose.generate_hmac_key(gose.HmacSha256)
    |> gose.with_kid("hmac-a")
    |> gose.with_key_use(gose.Signing)
  let assert Ok(k2) =
    gose.generate_ec(ec.P256)
    |> gose.with_kid("ec-b")
    |> gose.with_key_use(gose.Encrypting)
  let assert Ok(k3) =
    gose.generate_hmac_key(gose.HmacSha384)
    |> gose.with_kid("hmac-c")
    |> gose.with_key_use(gose.Signing)

  let set = key_set.from_list([k1, k2, k3])

  let signing_keys =
    key_set.filter(set, fn(k) { gose.key_use(k) == Ok(gose.Signing) })
  let count =
    signing_keys
    |> key_set.to_list
    |> list.length
  io.println("Signing keys: " <> int.to_string(count))

  let updated = key_set.delete(set, kid: "ec-b")
  let remaining =
    updated
    |> key_set.to_list
    |> list.length
  io.println("After delete: " <> int.to_string(remaining) <> " keys")
  io.println("")
}

fn strict_parsing() {
  io.println("--- Strict Parsing (reject unknown keys) ---")

  let well_formed =
    json.object([
      #(
        "keys",
        json.preprocessed_array([
          json.object([
            #("kty", json.string("oct")),
            #("k", json.string("AQIDBAUGBwgJCgsMDQ4PEA")),
            #("kid", json.string("octet-1")),
          ]),
        ]),
      ),
    ])
    |> json.to_string
  let assert Ok(set) = key_set.from_json_strict(well_formed)
  let count = set |> key_set.to_list |> list.length
  io.println("Strictly parsed: " <> int.to_string(count) <> " keys")

  let malformed =
    json.object([
      #(
        "keys",
        json.preprocessed_array([
          json.object([#("kty", json.string("unknown-type"))]),
        ]),
      ),
    ])
    |> json.to_string
  let assert Error(_) = key_set.from_json_strict(malformed)
  io.println("Strict parser rejected unknown key type")
  io.println("")
}
