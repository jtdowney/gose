import birdie
import gleam/bit_array
import gleam/json
import gleam/list
import gose
import gose/jwa
import gose/jwk
import gose/jwk_set
import kryptos/ec
import kryptos/eddsa
import qcheck

fn generator_jwk() -> qcheck.Generator(jwk.Jwk) {
  qcheck.from_generators(qcheck.return(jwk.generate_hmac_key(jwa.HmacSha256)), [
    qcheck.return(jwk.generate_hmac_key(jwa.HmacSha384)),
    qcheck.return(jwk.generate_hmac_key(jwa.HmacSha512)),
    qcheck.return(jwk.generate_ec(ec.P256)),
    qcheck.return(jwk.generate_eddsa(eddsa.Ed25519)),
  ])
}

fn generator_jwk_with_kid() -> qcheck.Generator(jwk.Jwk) {
  use key <- qcheck.then(generator_jwk())
  use kid <- qcheck.map(qcheck.non_empty_string())
  jwk.with_kid(key, kid)
}

fn generator_jwk_list() -> qcheck.Generator(List(jwk.Jwk)) {
  qcheck.generic_list(generator_jwk(), qcheck.bounded_int(0, 5))
}

fn generator_jwk_list_with_kids() -> qcheck.Generator(List(jwk.Jwk)) {
  qcheck.generic_list(generator_jwk_with_kid(), qcheck.bounded_int(0, 5))
}

pub fn new_creates_empty_set_test() {
  let set = jwk_set.new()
  assert jwk_set.to_list(set) == []
}

pub fn from_list_preserves_keys_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_ec(ec.P256)
  let keys = [key1, key2]
  let set = jwk_set.from_list(keys)
  assert list.length(jwk_set.to_list(set)) == 2
}

pub fn empty_set_roundtrip_test() {
  let set = jwk_set.new()
  let json_val = jwk_set.to_json(set)
  let assert Ok(parsed) = jwk_set.from_json(json.to_string(json_val))
  assert jwk_set.to_list(parsed) == []
}

pub fn single_key_roundtrip_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let set = jwk_set.from_list([key])
  let json_val = jwk_set.to_json(set)
  let assert Ok(parsed) = jwk_set.from_json(json.to_string(json_val))
  assert list.length(jwk_set.to_list(parsed)) == 1
}

pub fn multiple_key_types_roundtrip_test() {
  let oct_key = jwk.generate_hmac_key(jwa.HmacSha256)
  let ec_key = jwk.generate_ec(ec.P256)
  let ed_key = jwk.generate_eddsa(eddsa.Ed25519)
  let set =
    jwk_set.from_list([
      oct_key,
      ec_key,
      ed_key,
    ])
  let json_val = jwk_set.to_json(set)
  let assert Ok(parsed) = jwk_set.from_json(json.to_string(json_val))
  assert list.length(jwk_set.to_list(parsed)) == 3
}

pub fn property_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generator_jwk_list(),
    fn(keys) {
      let set = jwk_set.from_list(keys)
      let json_val = jwk_set.to_json(set)
      let assert Ok(parsed) = jwk_set.from_json(json.to_string(json_val))
      assert list.length(jwk_set.to_list(parsed)) == list.length(keys)
    },
  )
}

pub fn empty_set_json_snapshot_test() {
  let set = jwk_set.new()
  let json_val = jwk_set.to_json(set)
  json.to_string(json_val)
  |> birdie.snap("empty JWK Set JSON")
}

pub fn single_octet_key_set_snapshot_test() {
  let assert Ok(key) = jwk.from_octet_bits(<<"test-secret":utf8>>)
  let key = jwk.with_kid(key, "key-1")
  let set = jwk_set.from_list([key])
  let json_val = jwk_set.to_json(set)
  json.to_string(json_val)
  |> birdie.snap("JWK Set with single octet key")
}

pub fn multiple_keys_set_snapshot_test() {
  let assert Ok(key1) = jwk.from_octet_bits(<<"secret-one":utf8>>)
  let key1 = jwk.with_kid(key1, "oct-key")
  let assert Ok(key2) = jwk.from_octet_bits(<<"secret-two":utf8>>)
  let key2 = jwk.with_kid(key2, "oct-key-2")
  let set = jwk_set.from_list([key1, key2])
  let json_val = jwk_set.to_json(set)
  json.to_string(json_val)
  |> birdie.snap("JWK Set with multiple keys")
}

pub fn missing_keys_field_test() {
  let json_str = json.object([]) |> json.to_string
  assert jwk_set.from_json(json_str)
    == Error(gose.ParseError("missing or invalid keys array"))
}

pub fn keys_not_array_test() {
  let json_str =
    json.object([#("keys", json.string("not-an-array"))]) |> json.to_string
  assert jwk_set.from_json(json_str)
    == Error(gose.ParseError("missing or invalid keys array"))
}

pub fn keys_null_test() {
  let json_str = json.object([#("keys", json.null())]) |> json.to_string
  assert jwk_set.from_json(json_str)
    == Error(gose.ParseError("missing or invalid keys array"))
}

pub fn invalid_jwk_in_array_skipped_test() {
  let json_str =
    json.object([
      #(
        "keys",
        json.preprocessed_array([
          json.object([#("kty", json.string("invalid"))]),
        ]),
      ),
    ])
    |> json.to_string
  let assert Ok(set) = jwk_set.from_json(json_str)
  assert jwk_set.to_list(set) == []
}

pub fn invalid_json_test() {
  let json_str = "not valid json"
  assert jwk_set.from_json(json_str)
    == Error(gose.ParseError("missing or invalid keys array"))
}

pub fn malformed_key_in_array_skipped_test() {
  let json_str =
    json.object([
      #(
        "keys",
        json.preprocessed_array([json.object([#("kty", json.string("oct"))])]),
      ),
    ])
    |> json.to_string
  let assert Ok(set) = jwk_set.from_json(json_str)
  assert jwk_set.to_list(set) == []
}

pub fn mixed_valid_invalid_keys_test() {
  let json_str =
    json.object([
      #(
        "keys",
        json.preprocessed_array([
          json.object([
            #("kty", json.string("oct")),
            #("k", json.string("dGVzdA")),
          ]),
          json.object([#("kty", json.string("unknown"))]),
          json.object([
            #("kty", json.string("oct")),
            #("k", json.string("c2VjcmV0")),
          ]),
        ]),
      ),
    ])
    |> json.to_string
  let assert Ok(set) = jwk_set.from_json(json_str)
  assert list.length(jwk_set.to_list(set)) == 2
}

pub fn get_existing_key_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "key-1")
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2, "key-2")
  let set = jwk_set.from_list([key1, key2])

  let assert Ok(found) = jwk_set.get(set, "key-1")
  assert jwk.kid(found) == Ok("key-1")

  let assert Ok(found2) = jwk_set.get(set, "key-2")
  assert jwk.kid(found2) == Ok("key-2")
}

pub fn get_missing_key_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let key = jwk.with_kid(key, "key-1")
  let set = jwk_set.from_list([key])
  assert jwk_set.get(set, "nonexistent") == Error(Nil)
}

pub fn get_key_without_kid_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let set = jwk_set.from_list([key])
  assert jwk_set.get(set, "any-kid") == Error(Nil)
}

pub fn get_from_empty_set_test() {
  let set = jwk_set.new()
  assert jwk_set.get(set, "any-kid") == Error(Nil)
}

pub fn property_get_finds_inserted_keys_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generator_jwk_list_with_kids(),
    fn(keys) {
      let set = jwk_set.from_list(keys)
      list.each(keys, fn(key) {
        case jwk.kid(key) {
          Ok(kid) -> {
            let assert Ok(_found) = jwk_set.get(set, kid)
            Nil
          }
          Error(_) -> Nil
        }
      })
    },
  )
}

pub fn insert_to_empty_set_test() {
  let set = jwk_set.new()
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let updated = jwk_set.insert(set, key)
  assert list.length(jwk_set.to_list(updated)) == 1
}

pub fn insert_multiple_keys_test() {
  let set = jwk_set.new()
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_ec(ec.P256)
  let updated =
    set
    |> jwk_set.insert(key1)
    |> jwk_set.insert(key2)
  assert list.length(jwk_set.to_list(updated)) == 2
}

pub fn insert_preserves_order_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "first")
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2, "second")

  let set =
    jwk_set.new()
    |> jwk_set.insert(key1)
    |> jwk_set.insert(key2)

  let keys = jwk_set.to_list(set)
  let assert [first, second] = keys
  assert jwk.kid(first) == Ok("second")
  assert jwk.kid(second) == Ok("first")
}

pub fn insert_duplicate_kid_shadows_older_key_test() {
  let old_key =
    jwk.generate_hmac_key(jwa.HmacSha256)
    |> jwk.with_kid("same-kid")
  let new_key =
    jwk.generate_hmac_key(jwa.HmacSha384)
    |> jwk.with_kid("same-kid")

  let set =
    jwk_set.new()
    |> jwk_set.insert(old_key)
    |> jwk_set.insert(new_key)

  assert list.length(jwk_set.to_list(set)) == 2

  let assert Ok(found) = jwk_set.get(set, "same-kid")
  assert jwk.alg(found) == jwk.alg(new_key)
}

pub fn remove_existing_key_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "key-1")
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2, "key-2")
  let set = jwk_set.from_list([key1, key2])

  let updated = jwk_set.delete(set, "key-1")
  assert list.length(jwk_set.to_list(updated)) == 1
  assert jwk_set.get(updated, "key-1") == Error(Nil)
  let assert Ok(_) = jwk_set.get(updated, "key-2")
}

pub fn remove_nonexistent_key_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let key = jwk.with_kid(key, "key-1")
  let set = jwk_set.from_list([key])

  let updated = jwk_set.delete(set, "nonexistent")
  assert list.length(jwk_set.to_list(updated)) == 1
}

pub fn remove_from_empty_set_test() {
  let set = jwk_set.new()
  let updated = jwk_set.delete(set, "any-kid")
  assert jwk_set.to_list(updated) == []
}

pub fn remove_preserves_keys_without_kid_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2, "key-2")
  let set = jwk_set.from_list([key1, key2])

  let updated = jwk_set.delete(set, "key-2")
  assert list.length(jwk_set.to_list(updated)) == 1
}

pub fn ignores_unknown_top_level_members_test() {
  let json_str =
    json.object([
      #(
        "keys",
        json.preprocessed_array([
          json.object([
            #("kty", json.string("oct")),
            #("k", json.string("dGVzdA")),
          ]),
        ]),
      ),
      #("unknown_field", json.string("ignored")),
    ])
    |> json.to_string
  let assert Ok(set) = jwk_set.from_json(json_str)
  assert list.length(jwk_set.to_list(set)) == 1
}

pub fn first_empty_set_test() {
  let set = jwk_set.new()
  assert jwk_set.first(set) == Error(Nil)
}

pub fn first_single_key_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let key = jwk.with_kid(key, "only-key")
  let set = jwk_set.from_list([key])
  let assert Ok(found) = jwk_set.first(set)
  assert jwk.kid(found) == Ok("only-key")
}

pub fn first_multiple_keys_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key1 = jwk.with_kid(key1, "first-key")
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.with_kid(key2, "second-key")
  let set = jwk_set.from_list([key1, key2])
  let assert Ok(found) = jwk_set.first(set)
  assert jwk.kid(found) == Ok("first-key")
}

pub fn filter_by_key_type_test() {
  let oct_key = jwk.generate_hmac_key(jwa.HmacSha256)
  let ec_key = jwk.generate_ec(ec.P256)
  let set = jwk_set.from_list([oct_key, ec_key])

  let oct_only =
    jwk_set.filter(set, fn(key) { jwk.key_type(key) == jwk.OctKeyType })
  assert list.length(jwk_set.to_list(oct_only)) == 1
  let assert Ok(found) = jwk_set.first(oct_only)
  assert jwk.key_type(found) == jwk.OctKeyType

  let ec_only =
    jwk_set.filter(set, fn(key) { jwk.key_type(key) == jwk.EcKeyType })
  assert list.length(jwk_set.to_list(ec_only)) == 1
  let assert Ok(found_ec) = jwk_set.first(ec_only)
  assert jwk.key_type(found_ec) == jwk.EcKeyType
}

pub fn filter_by_use_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key1) = jwk.with_key_use(key1, jwk.Signing)
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key2) = jwk.with_key_use(key2, jwk.Encrypting)
  let key3 = jwk.generate_hmac_key(jwa.HmacSha256)
  let assert Ok(key3) = jwk.with_key_use(key3, jwk.Signing)
  let set = jwk_set.from_list([key1, key2, key3])

  let sig_only =
    jwk_set.filter(set, fn(key) { jwk.key_use(key) == Ok(jwk.Signing) })
  assert list.length(jwk_set.to_list(sig_only)) == 2

  let enc_only =
    jwk_set.filter(set, fn(key) { jwk.key_use(key) == Ok(jwk.Encrypting) })
  assert list.length(jwk_set.to_list(enc_only)) == 1
}

pub fn filter_empty_result_test() {
  let key = jwk.generate_hmac_key(jwa.HmacSha256)
  let set = jwk_set.from_list([key])
  let filtered = jwk_set.filter(set, fn(_) { False })
  assert jwk_set.to_list(filtered) == []
}

pub fn filter_all_match_test() {
  let key1 = jwk.generate_hmac_key(jwa.HmacSha256)
  let key2 = jwk.generate_hmac_key(jwa.HmacSha256)
  let set = jwk_set.from_list([key1, key2])
  let filtered = jwk_set.filter(set, fn(_) { True })
  assert list.length(jwk_set.to_list(filtered)) == 2
}

pub fn filter_empty_set_test() {
  let set = jwk_set.new()
  let filtered = jwk_set.filter(set, fn(_) { True })
  assert jwk_set.to_list(filtered) == []
}

pub fn from_json_strict_valid_keys_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generator_jwk_list(),
    fn(keys) {
      let set = jwk_set.from_list(keys)
      let json_val = jwk_set.to_json(set)
      let assert Ok(parsed) = jwk_set.from_json_strict(json.to_string(json_val))
      assert list.length(jwk_set.to_list(parsed)) == list.length(keys)
    },
  )
}

pub fn from_json_strict_empty_keys_succeeds_test() {
  let json_str =
    json.object([#("keys", json.preprocessed_array([]))])
    |> json.to_string
  let assert Ok(set) = jwk_set.from_json_strict(json_str)
  assert jwk_set.to_list(set) == []
}

pub fn from_json_strict_invalid_key_fails_with_index_test() {
  let json_str =
    json.object([
      #(
        "keys",
        json.preprocessed_array([
          json.object([
            #("kty", json.string("oct")),
            #("k", json.string("dGVzdA")),
          ]),
          json.object([#("kty", json.string("invalid"))]),
          json.object([
            #("kty", json.string("oct")),
            #("k", json.string("c2VjcmV0")),
          ]),
        ]),
      ),
    ])
    |> json.to_string
  assert jwk_set.from_json_strict(json_str)
    == Error(gose.ParseError("invalid key at index 1: unsupported kty: invalid"))
}

pub fn from_json_strict_first_key_invalid_includes_index_0_test() {
  let json_str =
    json.object([
      #(
        "keys",
        json.preprocessed_array([
          json.object([#("kty", json.string("unknown"))]),
        ]),
      ),
    ])
    |> json.to_string
  assert jwk_set.from_json_strict(json_str)
    == Error(gose.ParseError("invalid key at index 0: unsupported kty: unknown"))
}

pub fn from_json_strict_missing_required_field_includes_reason_test() {
  let json_str =
    json.object([
      #(
        "keys",
        json.preprocessed_array([json.object([#("kty", json.string("oct"))])]),
      ),
    ])
    |> json.to_string
  assert jwk_set.from_json_strict(json_str)
    == Error(gose.ParseError("invalid key at index 0: invalid oct JSON"))
}

pub fn from_json_bits_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generator_jwk_list(),
    fn(keys) {
      let set = jwk_set.from_list(keys)
      let json_bits =
        jwk_set.to_json(set)
        |> json.to_string
        |> bit_array.from_string
      let assert Ok(parsed) = jwk_set.from_json_bits(json_bits)
      assert list.length(jwk_set.to_list(parsed)) == list.length(keys)
    },
  )
}

pub fn from_json_bits_invalid_json_test() {
  assert jwk_set.from_json_bits(<<"not valid json":utf8>>)
    == Error(gose.ParseError("missing or invalid keys array"))
}

pub fn from_json_bits_non_utf8_test() {
  assert jwk_set.from_json_bits(<<0xFF, 0xFE>>)
    == Error(gose.ParseError("missing or invalid keys array"))
}

pub fn from_json_bits_missing_keys_test() {
  let json_bits = json.object([]) |> json.to_string |> bit_array.from_string
  assert jwk_set.from_json_bits(json_bits)
    == Error(gose.ParseError("missing or invalid keys array"))
}

pub fn from_json_bits_invalid_key_skipped_test() {
  let json_bits =
    json.object([
      #(
        "keys",
        json.preprocessed_array([
          json.object([#("kty", json.string("unknown"))]),
          json.object([
            #("kty", json.string("oct")),
            #("k", json.string("dGVzdA")),
          ]),
        ]),
      ),
    ])
    |> json.to_string
    |> bit_array.from_string
  let assert Ok(set) = jwk_set.from_json_bits(json_bits)
  assert list.length(jwk_set.to_list(set)) == 1
}

pub fn from_json_strict_bits_invalid_key_fails_with_index_test() {
  let json_bits =
    json.object([
      #(
        "keys",
        json.preprocessed_array([
          json.object([
            #("kty", json.string("oct")),
            #("k", json.string("dGVzdA")),
          ]),
          json.object([#("kty", json.string("invalid"))]),
        ]),
      ),
    ])
    |> json.to_string
    |> bit_array.from_string
  assert jwk_set.from_json_strict_bits(json_bits)
    == Error(gose.ParseError("invalid key at index 1: unsupported kty: invalid"))
}

pub fn from_json_strict_bits_invalid_json_test() {
  assert jwk_set.from_json_strict_bits(<<"not json":utf8>>)
    == Error(gose.ParseError("missing or invalid keys array"))
}

pub fn to_json_from_json_strict_preserves_metadata_test() {
  let key =
    jwk.generate_hmac_key(jwa.HmacSha256)
    |> jwk.with_kid("my-key-id")
    |> jwk.with_alg(jwk.Jws(jwa.JwsHmac(jwa.HmacSha256)))
  let assert Ok(key) = jwk.with_key_use(key, jwk.Signing)
  let assert Ok(key) = jwk.with_key_ops(key, [jwk.Sign, jwk.Verify])

  let set = jwk_set.from_list([key])
  let json_str = jwk_set.to_json(set) |> json.to_string
  let assert Ok(parsed) = jwk_set.from_json_strict(json_str)

  let assert Ok(parsed_key) = jwk_set.first(parsed)
  assert jwk.kid(parsed_key) == Ok("my-key-id")
  assert jwk.key_use(parsed_key) == Ok(jwk.Signing)
  assert jwk.key_ops(parsed_key) == Ok([jwk.Sign, jwk.Verify])
  assert jwk.alg(parsed_key) == Ok(jwk.Jws(jwa.JwsHmac(jwa.HmacSha256)))
}

pub fn from_json_strict_bits_non_utf8_test() {
  assert jwk_set.from_json_strict_bits(<<0xFF, 0xFE>>)
    == Error(gose.ParseError("missing or invalid keys array"))
}

pub fn from_json_strict_bits_roundtrip_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(25),
    generator_jwk_list(),
    fn(keys) {
      let set = jwk_set.from_list(keys)
      let json_bits =
        jwk_set.to_json(set)
        |> json.to_string
        |> bit_array.from_string
      let assert Ok(parsed) = jwk_set.from_json_strict_bits(json_bits)
      assert list.length(jwk_set.to_list(parsed)) == list.length(keys)
    },
  )
}
