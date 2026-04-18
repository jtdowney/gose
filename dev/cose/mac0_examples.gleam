import gleam/bit_array
import gleam/io
import gleam/string
import gose
import gose/cose/mac0

pub fn main() {
  io.println(string.repeat("=", 60))
  io.println("COSE_Mac0 (Single-Recipient MAC) Examples")
  io.println(string.repeat("=", 60))
  io.println("")

  hmac_mac()
  serialize_and_parse()
  aad()

  io.println(string.repeat("=", 60))
  io.println("All COSE_Mac0 examples completed!")
  io.println(string.repeat("=", 60))
}

fn hmac_mac() {
  io.println("--- HMAC-SHA256 MAC ---")

  let mac_key = gose.generate_hmac_key(gose.HmacSha256)
  let payload = <<"Hello, MAC0!":utf8>>

  // Tag
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha256))
    |> mac0.tag(mac_key, payload)

  // Verify
  let assert Ok(verifier) =
    mac0.verifier(gose.Hmac(gose.HmacSha256), keys: [mac_key])
  let assert Ok(Nil) = mac0.verify(verifier, tagged)
  io.println("MAC computed and verified successfully")
  io.println("")
}

fn serialize_and_parse() {
  io.println("--- Serialize and Parse (Tagged CBOR) ---")

  let mac_key = gose.generate_hmac_key(gose.HmacSha384)
  let payload = <<"Serialized MAC0 message":utf8>>

  // Tag
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha384))
    |> mac0.tag(mac_key, payload)

  let data = mac0.serialize_tagged(tagged)
  io.println("Tagged COSE_Mac0 (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Verify
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(verifier) =
    mac0.verifier(gose.Hmac(gose.HmacSha384), keys: [mac_key])
  let assert Ok(Nil) = mac0.verify(verifier, parsed)
  io.println("Parsed and verified successfully")
  io.println("")
}

fn aad() {
  io.println("--- External AAD ---")

  let mac_key = gose.generate_hmac_key(gose.HmacSha512)
  let payload = <<"Protected payload":utf8>>
  let aad = <<"application-context":utf8>>

  // Tag
  let assert Ok(tagged) =
    mac0.new(gose.Hmac(gose.HmacSha512))
    |> mac0.with_aad(aad:)
    |> mac0.tag(mac_key, payload)

  let data = mac0.serialize(tagged)
  io.println("COSE_Mac0 with external AAD (base64):")
  io.println(bit_array.base64_encode(data, True))

  // Verify
  let assert Ok(parsed) = mac0.parse(data)
  let assert Ok(verifier) =
    mac0.verifier(gose.Hmac(gose.HmacSha512), keys: [mac_key])
  let assert Ok(Nil) = mac0.verify_with_aad(verifier, parsed, aad)
  io.println("Verified with matching external AAD")
  io.println("")
}
