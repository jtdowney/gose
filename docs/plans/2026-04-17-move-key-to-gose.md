# Move `gose/key` Public Surface into `gose` — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Relocate the full public surface of `src/gose/key.gleam`
into `src/gose.gleam`, leaving `src/gose/key.gleam` as a thin
`@deprecated` shim, so v2.1 ships a grace window and v3.0 can delete
the shim.

**Architecture:** Atomic move in one commit (same opaque `Key` type
can't be defined in both modules simultaneously). Three commits
total: code move + internal importer updates; test suite reorg;
docs. Existing test suite acts as the regression net — no new
behavior, so no new TDD cycle per function.

**Tech Stack:** Gleam 1.15.4, `kryptos`, `gleam_json`, `gleam_time`.

**Design doc:** `docs/plans/2026-04-17-move-key-to-gose-design.md`
(read this first — it enumerates every moved item and the
constructor-alias constraint).

---

## Pre-work

### Task 0: Baseline green build

**Step 1:** Confirm working tree is clean.
Run: `git status`
Expected: clean on `main`.

**Step 2:** Confirm tests pass before any changes.
Run: `gleam format --check src test && gleam check && gleam test`
Expected: all green.

**Step 3:** Capture the `gose/key` importer list for verification
later.
Run: `grep -rln "gose/key" src test | sort > /tmp/gose-key-importers.txt && wc -l /tmp/gose-key-importers.txt`
Expected: ~45 files listed.

---

## Stage 1 — Move code into `gose.gleam` and rewrite `gose/key.gleam` as shim

### Task 1: Write the new `gose.gleam`

**Files:**
- Modify: `src/gose.gleam` (grows to ~1100 lines)

**Step 1:** Read the entire current `src/gose/key.gleam` to capture
exact content (imports, types, functions, private helpers,
`@internal` annotations).

**Step 2:** Read the current `src/gose.gleam` (60 lines — the
`GoseError` module).

**Step 3:** Compose the new `src/gose.gleam` with this layout:

1. Top-of-file `////` module doc (keep the existing library-level
   intro; update the `gose/key` bullet to say *deprecated, use the
   items in this module*).
2. All imports currently in both files (dedupe). Note: no import of
   `gose` itself (the module cannot import itself).
3. `GoseError` + `error_message` (existing).
4. Public constructor types: `KeyUse`, `KeyOp`, `Alg`, `KeyType`
   (exact content from `gose/key.gleam`).
5. `@internal` types: `RsaKeyMaterial`, `EcKeyMaterial`,
   `EddsaKeyMaterial`, `XdhKeyMaterial`, `KeyMaterial`.
6. Opaque `Key(kid)` type and its `@internal` accessors (`new_key`,
   `is_private_key`, `material`, `material_octet_secret`,
   `material_rsa`, `material_ec`, `material_eddsa`, `material_xdh`).
7. Public builders: `from_der`, `from_pem`, `from_octet_bits`,
   `from_eddsa_bits`, `from_eddsa_public_bits`, `from_xdh_bits`,
   `from_xdh_public_bits`, `ec_public_key_from_coordinates`.
8. Generators: `generate_ec`, `generate_eddsa`, `generate_hmac_key`,
   `generate_enc_key`, `generate_aes_kw_key`,
   `generate_chacha20_kw_key`, `generate_rsa`, `generate_xdh`.
9. Fluent builders: `with_alg`, `with_key_ops`, `with_key_use`,
   `with_kid`, `with_kid_bits`.
10. Accessors: `alg`, `ec_curve`, `ec_public_key`,
    `ec_public_key_coordinates`, `eddsa_curve`, `eddsa_public_key`,
    `key_ops`, `key_type`, `key_use`, `kid`, `octet_key_size`,
    `rsa_public_key`, `xdh_curve`, `xdh_public_key`, `public_key`.
11. Serializers: `to_der`, `to_pem`, `to_octet_bits`.
12. Private helpers that back the above (`parse_rsa_der`,
    `parse_eddsa_der`, `parse_xdh_der`, `parse_ec_der`,
    `ec_private_key`, `ec_public_key_internal`,
    `eddsa_private_key`, `eddsa_public_key_internal`, etc. — every
    non-`pub` function currently in `gose/key.gleam`).
13. `@internal` trailing helpers: `build`, `validate_key_use_ops`,
    `validate_rfc8037_key_use_public`.

Inside the moved code, replace every `gose.GoseError`/`gose.ParseError`/
`gose.CryptoError`/`gose.InvalidState`/`gose.VerificationFailed` with
the bare names (`GoseError`, `ParseError`, …) because they now live
in the same module.

**Step 4:** `gleam format src/gose.gleam` — let the formatter settle
the file.

**Step 5:** Do **not** run `gleam check` yet — `gose/key.gleam`
still defines the same opaque type, so the project won't compile
until Task 2 lands. Task 1 and Task 2 are a single edit pair; only
check after Task 3.

---

### Task 2: Rewrite `src/gose/key.gleam` as the deprecated shim

**Files:**
- Modify: `src/gose/key.gleam` (shrinks to ~150 lines)

**Step 1:** Replace the entire file with the shim. Structure:

```gleam
//// Deprecated: use the `gose` module instead.
////
//// This module re-exports the key API from `gose` for the v2.x
//// migration window. It will be removed in v3.0. New code should
//// import `gose` directly.
////
//// The constructors of `KeyUse`, `KeyOp`, `Alg`, and `KeyType` are
//// not re-exported here (Gleam type aliases do not re-export
//// constructors). Callers that pattern-match on these types must
//// update to `gose.Signing`, `gose.SigningAlg(_)`, etc.

import gleam/option.{type Option}
import gose
import gose/algorithm
import kryptos/ec
import kryptos/eddsa
import kryptos/rsa
import kryptos/xdh

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

@deprecated("use gose.from_der")
pub fn from_der(der: BitArray) -> Result(Key(kid), gose.GoseError) {
  gose.from_der(der)
}

// …continue one thin wrapper per public function in gose/key:
// from_pem, from_octet_bits, from_eddsa_bits, from_eddsa_public_bits,
// from_xdh_bits, from_xdh_public_bits, ec_public_key_from_coordinates,
// generate_ec, generate_eddsa, generate_hmac_key, generate_enc_key,
// generate_aes_kw_key, generate_chacha20_kw_key, generate_rsa,
// generate_xdh, with_alg, with_key_ops, with_key_use, with_kid,
// with_kid_bits, alg, ec_curve, ec_public_key,
// ec_public_key_coordinates, eddsa_curve, eddsa_public_key, key_ops,
// key_type, key_use, kid, octet_key_size, rsa_public_key, xdh_curve,
// xdh_public_key, public_key, to_der, to_pem, to_octet_bits.
```

Every `pub fn` gets an `@deprecated("use gose.<name>")` attribute
and a one-line body that calls through to `gose.<name>` with the
same arguments.

**Note:** `@internal` items are **not** re-exported. Internal
callers will move to `gose` directly in Task 3.

**Step 2:** `gleam format src/gose/key.gleam`.

**Step 3:** Still don't run `gleam check` — Task 3 must land first.

---

### Task 3: Update internal src importers

**Files:**
- Modify all files returned by:
  `grep -l "import gose/key" src/gose/internal src/gose/jose src/gose/cose`

Expected list (~22 files): `gose/internal/cose_structure`,
`gose/internal/key_helpers`, `gose/internal/key_encryption`,
`gose/internal/signing`, `gose/internal/key_extract`,
`gose/jose/jwe`, `gose/jose/jwe_multi`, `gose/jose/jws`,
`gose/jose/jws_multi`, `gose/jose/jwk`, `gose/jose/jwt`,
`gose/jose/encrypted_key`, `gose/jose/encrypted_jwt`,
`gose/jose/key_set`, `gose/cose/key`, `gose/cose/sign1`,
`gose/cose/sign`, `gose/cose/mac0`, `gose/cose/encrypt0`,
`gose/cose/encrypt`, `gose/cose/cwt`, `gose/cose/encrypted_cwt`.

**Step 1:** For each file:
1. Remove `import gose/key` (or `import gose/key as <alias>`).
2. If `gose` is not already imported, add `import gose`.
3. Replace every `key.X` where `key` was the module alias with
   `gose.X`.
4. Watch for parameter/local bindings named `key: Key(kid)` —
   those should now be `key: gose.Key(kid)` for the type
   annotation, but the local identifier `key` stays the same; any
   `key.foo()` *call* where `key` was the module alias becomes
   `gose.foo()`, while `key.material_field` (record access on the
   parameter) stays unchanged.

**Concrete heuristic for the alias/parameter ambiguity:** module-
aliased `key.Foo` is capitalized (`key.Signing`, `key.SigningAlg`,
`key.KeyType`) or matches a function name (`key.from_pem`,
`key.generate_ec`). Record access is always on a lowercase field
name. Walk the file and classify each `key.<ident>` before
rewriting.

**Step 2:** `gleam format src`.

**Step 3:** Run: `gleam check`
Expected: clean, **zero deprecation warnings** (src is entirely on
the new paths; only the shim file itself contains `@deprecated`
declarations which don't warn on their own definition).

If deprecation warnings appear, find the missed file and fix it.

**Step 4:** Run: `gleam test`
Expected: all green. The tests still import `gose/key` — they'll
show deprecation warnings, but the behavior is correct.

**Step 5:** Commit.

```bash
git add src/gose.gleam src/gose/key.gleam src/gose/internal src/gose/jose src/gose/cose
git commit -m "refactor: move Key API from gose/key to gose"
```

Commit body:

```
Promote the key management API (types, opaque Key(kid), generators,
builders, accessors, serializers) from gose/key into gose. gose/key
is kept as a thin @deprecated shim for the v2.1 migration window;
it will be removed in v3.0.

Internal importers under gose/internal, gose/jose, and gose/cose
are updated to import gose directly so the src tree is free of
self-inflicted deprecation warnings.
```

---

## Stage 2 — Reorganize tests

### Task 4: Move the key test suite to `test/gose_test.gleam`

**Files:**
- Create: `test/gose_test.gleam` (from the content of
  `test/gose/key_test.gleam`, with imports updated)
- Delete: `test/gose/key_test.gleam` (replaced in Task 5 with a
  minimal shim test)

**Step 1:** Copy `test/gose/key_test.gleam` to `test/gose_test.gleam`.

**Step 2:** Edit the new `test/gose_test.gleam`:
1. Change `import gose/key` → `import gose`.
2. Replace all `key.X` (module-qualified) calls with `gose.X`.
3. Keep any `gose.GoseError`/`gose.ParseError`/etc. as-is.

**Step 3:** Delete the old `test/gose/key_test.gleam`.

**Step 4:** Run: `gleam format test`.

**Step 5:** Run: `gleam test`
Expected: all green, no deprecation warnings yet (no file imports
`gose/key`).

---

### Task 5: Add minimal shim coverage

**Files:**
- Create: `test/gose/key_test.gleam` (~60 lines)

**Step 1:** Write a small test file that exercises the deprecated
shim so we catch any regression where a wrapper forgets to delegate
correctly.

```gleam
// Intentionally uses the deprecated gose/key module so regressions
// in the shim surface here and nowhere else. Deprecation warnings
// from this file are expected.

import gleam/option
import gose
import gose/algorithm
@target(erlang)
import gose/key
@target(javascript)
import gose/key
import kryptos/ec
import kryptos/eddsa
import unitest

pub fn from_octet_bits_delegates_test() {
  let assert Ok(k) = key.from_octet_bits(<<"secret":utf8>>)
  assert gose.key_type(k) == gose.OctKeyType
}

pub fn generate_ec_delegates_test() {
  let k = key.generate_ec(ec.P256)
  assert gose.key_type(k) == gose.EcKeyType
}

pub fn generate_eddsa_delegates_test() {
  let k = key.generate_eddsa(eddsa.Ed25519)
  assert gose.key_type(k) == gose.OkpKeyType
}

pub fn generate_hmac_key_delegates_test() {
  let k = key.generate_hmac_key(algorithm.HmacSha256)
  assert gose.key_type(k) == gose.OctKeyType
}

pub fn with_kid_delegates_test() {
  let k =
    key.generate_ec(ec.P256)
    |> key.with_kid("kid-1")

  assert gose.kid(k) == Ok("kid-1")
}

pub fn to_pem_roundtrip_delegates_test() {
  let original = key.generate_ec(ec.P256)
  let assert Ok(pem) = key.to_pem(original)
  let assert Ok(restored) = key.from_pem(pem)

  assert gose.key_type(restored) == gose.EcKeyType
}
```

Remove the `@target` duplicates once you confirm they aren't
needed; they're only there as a reminder if the project segregates
test builds. The real check is: pick one representative per shim
category (builder, generator, fluent, accessor, serializer
roundtrip).

**Step 2:** Run: `gleam format test/gose/key_test.gleam`.

**Step 3:** Run: `gleam test`
Expected: all green, with deprecation warnings appearing **only**
from `test/gose/key_test.gleam` (one per `key.<call>`).

If warnings appear elsewhere, find the lingering importer.

**Step 4:** Verify scope of deprecation warnings:
Run: `gleam test 2>&1 | grep -E "warning|deprecated" | grep -v "gose/key_test"`
Expected: empty output (no warnings outside the shim test).

**Step 5:** Commit.

```bash
git add test
git commit -m "test: move key tests to gose_test, add shim coverage"
```

Body:

```
The bulk of the key test suite now lives at test/gose_test.gleam
and exercises the canonical gose.* API. A small replacement at
test/gose/key_test.gleam covers the gose/key shim so we catch any
wrapper that forgets to delegate. That file is the only place in
the project that intentionally emits deprecation warnings.
```

---

## Stage 3 — Documentation

### Task 6: Update `CHANGELOG.md`

**Files:**
- Modify: `CHANGELOG.md`

**Step 1:** Insert a new `## [2.1.0] - YYYY-MM-DD` section above the
existing `## [2.0.0] - 2026-04-17` block. Use the real release date
when cutting, or leave `YYYY-MM-DD` as a placeholder if this ships
with a later version bump.

```markdown
## [2.1.0] - YYYY-MM-DD

### Added

- Key management API promoted to the top-level `gose` module. All
  types (`Key`, `KeyUse`, `KeyOp`, `Alg`, `KeyType`) and functions
  (`from_der`, `from_pem`, `generate_ec`, `with_kid`, `to_pem`, …)
  that previously lived in `gose/key` are now available directly on
  `gose`.

### Deprecated

- `gose/key` — every public item carries `@deprecated` and delegates
  to the corresponding `gose` function. The module will be removed
  in v3.0. Callers that pattern-match on the constructors of
  `KeyUse`, `KeyOp`, `Alg`, or `KeyType` must re-import them from
  `gose` (Gleam type aliases do not re-export constructors). See
  `docs/MIGRATION.md`.
```

**Step 2:** No commit yet — batch with docs in Task 9.

---

### Task 7: Update `docs/MIGRATION.md`

**Files:**
- Modify: `docs/MIGRATION.md`

**Step 1:** Append a new top-level section at the end of the file.

```markdown
## Preparing for v3: move from `gose/key` to `gose`

v2.1 deprecates `gose/key`; v3.0 removes it. The key API moved to
the top-level `gose` module. This migration is additive — v1→v2
callers following the instructions above land on v2.1 and can run
this second pass in one sweep.

### Import change

```gleam
// v2.0
import gose/key

let k = key.generate_ec(ec.P256) |> key.with_kid("my-key")

// v2.1 / v3
import gose

let k = gose.generate_ec(ec.P256) |> gose.with_kid("my-key")
```

If you want to minimize diffs in a large codebase, `import gose as key`
keeps the `key.` call sites unchanged for functions (but not for
constructor types — see below).

### Constructor re-imports

Gleam type aliases re-export the type but not the constructors, so
these must be updated even if you keep a `key` alias:

| v2.0                             | v2.1 / v3                        |
| -------------------------------- | -------------------------------- |
| `key.Signing`, `key.Encrypting`  | `gose.Signing`, `gose.Encrypting` |
| `key.Sign`, `key.Verify`, …      | `gose.Sign`, `gose.Verify`, …    |
| `key.SigningAlg(_)`              | `gose.SigningAlg(_)`             |
| `key.KeyEncryptionAlg(_)`        | `gose.KeyEncryptionAlg(_)`       |
| `key.ContentAlg(_)`              | `gose.ContentAlg(_)`             |
| `key.OctKeyType`, `key.RsaKeyType`, `key.EcKeyType`, `key.OkpKeyType` | `gose.OctKeyType`, … |

### Type annotation changes

| v2.0               | v2.1 / v3         |
| ------------------ | ----------------- |
| `key.Key(String)`  | `gose.Key(String)` |
| `key.KeyUse`       | `gose.KeyUse`     |
| `key.KeyOp`        | `gose.KeyOp`      |
| `key.Alg`          | `gose.Alg`        |
| `key.KeyType`      | `gose.KeyType`    |

### End-to-end example

```gleam
// v2.0
import gose/key
import kryptos/ec

fn build_signer(kid: String) -> key.Key(String) {
  key.generate_ec(ec.P256)
  |> key.with_kid(kid)
  |> key.with_key_use(key.Signing)
}

// v2.1 / v3
import gose
import kryptos/ec

fn build_signer(kid: String) -> gose.Key(String) {
  gose.generate_ec(ec.P256)
  |> gose.with_kid(kid)
  |> gose.with_key_use(gose.Signing)
}
```
```

**Step 2:** No commit yet — batch with docs in Task 9.

---

### Task 8: Update `README.md` and `src/gose.gleam` module doc

**Files:**
- Modify: `README.md`
- Modify: `src/gose.gleam` (top-of-file `////` doc)

**Step 1:** In `README.md`:
1. Find every code snippet that does `import gose/key` and update
   to `import gose` with call sites rewritten to `gose.*`.
2. Add a one-line note near the first mention of keys, e.g. *"The
   `gose/key` module is a deprecated alias retained for v2.x
   migration; new code should use `gose` directly."*

Run: `grep -n "gose/key\|key\." README.md` to find hits.

**Step 2:** In `src/gose.gleam`:
1. Update the `/// - gose/key: key management` bullet in the intro
   list to describe the new location: `/// - gose: key management
   (was gose/key, which is now a deprecated alias)`.
2. Ensure the module doc still mentions the error type and key
   management together.

**Step 3:** In `src/gose/key.gleam`, confirm the module doc already
reflects the deprecation (it should from Task 2).

**Step 4:** Run: `gleam format src`.

**Step 5:** Run: `gleam check`
Expected: clean.

---

### Task 9: Commit the docs

**Step 1:** Stage and commit:

```bash
git add CHANGELOG.md docs/MIGRATION.md README.md src/gose.gleam
git commit -m "docs: document gose/key deprecation and v3 migration"
```

Body:

```
CHANGELOG gains a v2.1.0 entry noting the Added/Deprecated pair.
MIGRATION.md gets a "Preparing for v3" section covering the import
change, constructor re-imports, type annotation updates, and an
end-to-end example. README snippets switch to the gose.* API with
a note that gose/key is the deprecated spelling.
```

---

## Verification

### Task 10: Final green check

**Step 1:** Run the full verification battery:

```bash
gleam format --check src test
gleam check
gleam test
```

Expected:
- Formatter clean.
- `gleam check` clean.
- `gleam test` all green.
- Deprecation warnings appear **only** from
  `test/gose/key_test.gleam`. Any other source emitting a
  deprecation warning is a missed importer.

**Step 2:** Confirm `gose/key` is the only internal reference:

```bash
grep -rln "gose/key" src test
```

Expected output (exactly these files):
- `src/gose/key.gleam` (the shim itself)
- `test/gose/key_test.gleam` (shim coverage)

Any other file means an importer was missed in Task 3 or Task 4.

**Step 3:** Spot-check the deprecation messages by reading a random
compile output:

```bash
gleam test 2>&1 | head -30
```

You should see a cluster of warnings like `gose/key.from_octet_bits
is deprecated — use gose.from_octet_bits`, all sourced from
`test/gose/key_test.gleam`.

**Step 4:** `git log --oneline -4` should show:

```
<hash> docs: document gose/key deprecation and v3 migration
<hash> test: move key tests to gose_test, add shim coverage
<hash> refactor: move Key API from gose/key to gose
<hash> docs: add design for moving gose/key into gose
```

---

## Risks and rollback

- If Task 1/2/3 don't land cleanly as a trio, revert the single
  refactor commit (`git revert HEAD`) — the design doc is
  independent and stays.
- If internal importer rewrite breaks a subtle parameter/alias
  interaction, `gleam check` flags it immediately; fix in-place
  before committing.
- If a `@deprecated` message typo slips through, fix it in a
  follow-up commit; the library is still correct.
