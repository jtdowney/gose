# Move `gose/key` Public Surface into `gose`

Date: 2026-04-17
Target release: v2.1.0 (shim), v3.0.0 (removal)

## Goal

Make `gose` the canonical module for the `Key` type and all key
management functions. Turn `gose/key` into a thin deprecated shim that
ships once in v2.1 to give callers a grace window, then disappears in
v3.0.

## Motivation

`gose.gleam` is currently a 60-line module holding only `GoseError`
plus `error_message`. The `Key` type and ~40 public functions that
operate on it live one namespace down at `gose/key`. Promoting `Key`
to the top-level module elevates it to match its status as the core
value of the library, while `gose/jose/jwk` and `gose/cose/key` remain
format-specific serializers.

## Non-goals

- No signature changes to any moved function; pure relocation.
- No changes to `gose/jose/jwk` or `gose/cose/key`.
- No user-facing error semantics change.

## Approach

### Target state

**`gose.gleam` (grows from ~60 to ~1100 lines):**

- Keeps `GoseError` and `error_message`.
- Absorbs everything currently public in `gose/key.gleam`:
  - Public constructor types: `KeyUse`, `KeyOp`, `Alg`, `KeyType`.
  - Opaque type: `Key(kid)`.
  - `@internal pub` items used by other modules in the package:
    `RsaKeyMaterial`, `EcKeyMaterial`, `EddsaKeyMaterial`,
    `XdhKeyMaterial`, `KeyMaterial`, `new_key`, `is_private_key`,
    `material`, `material_octet_secret`, `material_rsa`, `material_ec`,
    `material_eddsa`, `material_xdh`, `build`, `validate_key_use_ops`,
    `validate_rfc8037_key_use_public`.
  - All ~40 public functions: `from_der`, `from_pem`, `from_octet_bits`,
    `from_eddsa_bits`, `from_eddsa_public_bits`, `from_xdh_bits`,
    `from_xdh_public_bits`, `generate_ec`, `generate_eddsa`,
    `generate_hmac_key`, `generate_enc_key`, `generate_aes_kw_key`,
    `generate_chacha20_kw_key`, `generate_rsa`, `generate_xdh`,
    `ec_public_key_from_coordinates`, `with_alg`, `with_key_ops`,
    `with_key_use`, `with_kid`, `with_kid_bits`, `alg`, `ec_curve`,
    `ec_public_key`, `ec_public_key_coordinates`, `eddsa_curve`,
    `eddsa_public_key`, `key_ops`, `key_type`, `key_use`, `kid`,
    `octet_key_size`, `rsa_public_key`, `xdh_curve`, `xdh_public_key`,
    `public_key`, `to_der`, `to_octet_bits`, `to_pem`.

**`gose/key.gleam` (shrinks from ~1036 to ~150 lines, all `@deprecated`):**

- Module doc comment notes the file is deprecated, points readers to
  `gose`, and calls out that constructor types (`KeyUse`, `KeyOp`,
  `Alg`, `KeyType`) must be re-imported (type aliases can't re-export
  constructors).
- Type re-exports as aliases with `@deprecated`:
  ```gleam
  @deprecated("use gose.Key")
  pub type Key(kid) = gose.Key(kid)

  @deprecated("use gose.KeyUse (constructors must be re-imported: gose.Signing, gose.Encrypting)")
  pub type KeyUse = gose.KeyUse

  @deprecated("use gose.KeyOp (constructors must be re-imported)")
  pub type KeyOp = gose.KeyOp

  @deprecated("use gose.Alg (constructors must be re-imported: gose.SigningAlg, gose.KeyEncryptionAlg, gose.ContentAlg)")
  pub type Alg = gose.Alg

  @deprecated("use gose.KeyType")
  pub type KeyType = gose.KeyType
  ```
- Function re-exports as thin wrappers with `@deprecated`:
  ```gleam
  @deprecated("use gose.generate_ec")
  pub fn generate_ec(curve: ec.Curve) -> Key(kid) {
    gose.generate_ec(curve)
  }
  ```
  Applied to all ~40 public functions.
- `@internal` items are **not** re-exported. Internal callers
  (`gose/internal/*`, `gose/jose/*`, `gose/cose/*`) are updated to
  import from `gose` directly in the same change.

### Internal importer migration

Every file that currently does `import gose/key` gets updated to
`import gose` with `key.Foo` references rewritten to `gose.Foo`.

Source files (~15): `gose/internal/cose_structure`,
`gose/internal/key_helpers`, `gose/internal/key_encryption`,
`gose/internal/signing`, `gose/internal/key_extract`,
`gose/jose/jwe`, `gose/jose/jwe_multi`, `gose/jose/jws`,
`gose/jose/jws_multi`, `gose/jose/jwk`, `gose/jose/jwt`,
`gose/jose/encrypted_key`, `gose/jose/encrypted_jwt`,
`gose/jose/key_set`, `gose/cose/key`, `gose/cose/sign1`,
`gose/cose/sign`, `gose/cose/mac0`, `gose/cose/encrypt0`,
`gose/cose/encrypt`, `gose/cose/cwt`, `gose/cose/encrypted_cwt`.

Test files (~20) under `test/gose/**`.

The rewrite is mechanical but needs care:
- Parameters named `key: Key(kid)` are shadowed by the old `key`
  module alias. After the rewrite, `key.foo()` calls become
  `gose.foo()`, and the `key` identifier becomes the variable. Any
  place that relied on the alias/variable distinction must be
  resolved manually.
- `gleam format --check` and `gleam check` after each directory
  catches stragglers.

### Test suite move

`test/gose/key_test.gleam` (the existing ~1000-line suite) moves to
`test/gose_test.gleam` and is rewritten to exercise `gose.*`.

A new minimal `test/gose/key_test.gleam` (~50 lines) stays behind to
cover the shim surface: one representative call per category
(`key.from_pem`, `key.from_der`, `key.from_octet_bits`, `key.generate_ec`,
`key.with_kid`, `key.public_key`, `key.to_pem`) confirming the shim
delegates correctly. This is the only module that intentionally emits
deprecation warnings; `gleam check` on the rest of the tree must be
warning-free.

### Error handling

No change. Every function either already returns `Result(_, GoseError)`
or is infallible; the shim wrappers pass through unchanged.

### Release plan

- **v2.1.0 (this work):** `gose.*` canonical API available,
  `gose/key` shimmed with `@deprecated`. Semver minor — no breaking
  changes; callers using `gose/key` compile with warnings.
- **v3.0.0 (future):** delete `src/gose/key.gleam` and the shim test
  file. Breaking change.

### Documentation updates in this change

- **`CHANGELOG.md`** — v2.1.0 entry:
  - Added: canonical key API at `gose` (previously `gose/key`).
  - Deprecated: entire `gose/key` module; slated for removal in v3.0.
- **`docs/MIGRATION.md`** — new top-level section
  *"Preparing for v3: move from `gose/key` to `gose`"* appended after
  the current v1→v2 content. Contents:
  - Framing: v2.1 deprecates `gose/key`, v3.0 removes it.
  - Import change: `import gose/key` → `import gose` (and note that
    `import gose as key` keeps diffs minimal for callers who prefer
    it).
  - Table of constructor re-imports users must do (type aliases
    don't re-export constructors): `key.Signing` → `gose.Signing`,
    `key.Encrypting` → `gose.Encrypting`, `key.Sign`/`Verify`/
    `Encrypt`/`Decrypt`/`WrapKey`/`UnwrapKey`/`DeriveKey`/`DeriveBits`
    → `gose.*`, `key.SigningAlg`/`KeyEncryptionAlg`/`ContentAlg` →
    `gose.*`, `key.Rsa`/`Ec`/`Eddsa`/`Xdh`/`Octet` → `gose.*` for the
    `KeyType` variants.
  - Table of type annotations: `key.Key(String)` → `gose.Key(String)`,
    `key.KeyUse` → `gose.KeyUse`, `key.KeyOp` → `gose.KeyOp`,
    `key.Alg` → `gose.Alg`, `key.KeyType` → `gose.KeyType`.
  - Short before/after snippet with `generate_ec` + `with_kid` + an
    accessor.
  - Note that the v1→v2 instructions earlier in the doc still deliver
    callers to v2.1; the v2.1→v3 rename is a separate, additive pass.
- **`README.md`** — audit for any snippet that imports `gose/key`;
  update to `gose` and add a one-line note that `gose/key` is the
  deprecated spelling.
- **Module-level doc in `src/gose.gleam`** — update the `gose/key`
  bullet in the intro list to describe the new home. The same bullet
  in the shim carries a deprecation note.

## Verification

- `gleam format --check src test` clean.
- `gleam check` clean except for deprecation warnings originating
  only from `test/gose/key_test.gleam`. Any other deprecation
  warning is a missed internal importer.
- `gleam test` all green.
- Manual spot-check: `grep -rn "gose/key" src` returns only
  `src/gose/key.gleam` itself.

## Risks

- **Large single commit.** The move touches ~45 files. Splitting
  into multiple commits (move + shim; internal importers; tests;
  docs) reduces review load and keeps `gleam test` green at each
  step. Recommend the split.
- **Constructor pattern-matching break.** Callers doing
  `case k { key.Signing -> ... }` see a compile error, not a warning,
  because type aliases don't re-export constructors. The
  `@deprecated` message on the type alias is the primary mitigation;
  `MIGRATION.md` is the secondary. Acceptable because the break is
  loud and the fix is mechanical.
- **Parameter/alias name collision.** The old code uses `key` both
  as a module alias and as a parameter name. Automated rewrite must
  distinguish the two. Mitigation: rewrite per-file with
  `gleam check` after each.

## Out of scope

- Renaming `gose/cose/key` or `gose/jose/jwk`.
- Any change to `GoseError` or `error_message`.
- Multi-release deprecation (rejected in favor of single-release
  shim).
- Permanent shim (rejected in favor of clean removal in v3.0).
