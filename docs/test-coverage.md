# test-coverage.md — digital.vasic.normalize (round-258)

Symbol → test ledger for the Normalize submodule. Every exported and
documented internal symbol is cross-referenced to (a) the unit test
that exercises it, and (b) the multi-locale Challenge that exercises
it against real bilingual stego inputs.

Round-258 deep-doc enrichment co-maintained with `README.md`, the
multi-locale fixture at `tests/fixtures/normalize/payloads.json`, the
bilingual Challenge runner at `challenges/runner/main.go`, and the
paired-mutation gate at `challenges/scripts/normalize_describe_challenge.sh`.

> Verbatim 2026-05-19 operator mandate: *"all existing tests and Challenges
> do work in anti-bluff manner - they MUST confirm that all tested codebase
> really works as expected! We had been in position that all tests do
> execute with success and all Challenges as well, but in reality the most
> of the features does not work and can't be used! This MUST NOT be the
> case and execution of tests and Challenges MUST guarantee the quality,
> the completition and full usability by end users of the product!"*

## Exported symbols (package `normalize`)

| Symbol | File | Unit test | Challenge section |
|--------|------|-----------|-------------------|
| `NormalizedInput` (type) | `normalize.go` | every test in `normalize_test.go` returns/inspects one | `[normalize][*]` (every section) |
| `Normalize` (func) | `normalize.go` | every `TestNormalize_*` | `[normalize][nfkc]`, `[homoglyph]`, `[zerowidth]`, `[leet]`, `[rot13]`, `[base64]`, `[whitespace]`, `[charsplit]`, `[reverse]`, `[combined]` per locale |
| `NormalizedInput.AnyMatch` (method) | `normalize.go` | `TestNormalize_AnyMatch` | `[anymatch]` (per locale) |

## Internal helpers (package-private, contract-documented)

These are not exported but are exercised end-to-end through `Normalize`
and one of them (`rot13`, `reverseString`) is asserted directly in
unit tests. They are listed here so the paired-mutation Challenge can
cross-reference them and detect ledger drift.

| Symbol | File | Exercised via |
|--------|------|---------------|
| `stripZeroWidth` | `normalize.go` | `TestNormalize_StripZeroWidth`; runner `[zerowidth]` per locale |
| `deleetSpeak` | `normalize.go` | `TestNormalize_DeleetSpeak`; runner `[leet][en]` |
| `foldHomoglyphs` | `normalize.go` | `TestNormalize_FoldHomoglyphs`, `TestNormalize_Variants_CombinedAttack`; runner `[homoglyph]` per locale that documents one |
| `rot13` | `normalize.go` | `TestNormalize_ROT13_Reversible` (direct assertion); runner `[rot13][en]` (ROT13 only touches ASCII letters by contract — non-ASCII locales document the no-op) |
| `tryDecodeBase64` | `normalize.go` | `TestNormalize_Base64_PlausibleText`, `TestNormalize_Base64_RejectsImplausible`; runner `[base64]` per locale |
| `padBase64` | `normalize.go` | covered indirectly through `TestNormalize_Base64_PlausibleText` |
| `isPlausibleText` | `normalize.go` | `TestNormalize_Base64_RejectsImplausible` |
| `collapseWhitespace` | `normalize.go` | `TestNormalize_CollapseWhitespace`; runner `[whitespace]` per locale |
| `collapseCharacterSplit` | `normalize.go` | `TestNormalize_CollapseCharacterSplit`; runner `[charsplit]` per locale |
| `isAlphaNum` | `normalize.go` | covered indirectly through `TestNormalize_CollapseCharacterSplit` |
| `isSeparator` | `normalize.go` | covered indirectly through `TestNormalize_CollapseCharacterSplit` |
| `reverseString` | `normalize.go` | `TestNormalize_ReverseString` (direct UTF-8 safety assertion); runner `[reverse]` per locale |
| `leetMap` (var) | `normalize.go` | `TestNormalize_DeleetSpeak` |
| `homoglyphMap` (var) | `normalize.go` | `TestNormalize_FoldHomoglyphs` |
| `b64RE` (var) | `normalize.go` | `TestNormalize_Base64_*` |
| `collapseWhitespaceRE` (var) | `normalize.go` | `TestNormalize_CollapseWhitespace` |

## Behavioural invariants (asserted at runtime)

| Invariant | Unit test | Challenge section |
|-----------|-----------|-------------------|
| `Variants[0] == Original` | `TestNormalize_OriginalAlwaysFirst` | runner `[invariant][first-is-original]` per locale |
| `Variants` has no duplicates | `TestNormalize_DeduplicatesVariants` | runner `[invariant][unique]` per locale |
| Empty input → empty `Variants` | `TestNormalize_EmptyString` | runner `[invariant][empty]` |
| ROT13 is self-inverse on ASCII | `TestNormalize_ROT13_Reversible` | runner `[rot13][en]` |
| `reverseString` is UTF-8 safe (rune-aware) | `TestNormalize_ReverseString` (`"日本" ↔ "本日"`) | runner `[reverse][ja]` |
| Combined stego (homoglyph + ZW + leet) reveals "ignore" + " all " | `TestNormalize_Variants_CombinedAttack` | runner `[combined][en]` |
| `AnyMatch` finds folded form, misses literal absent | `TestNormalize_AnyMatch` | runner `[anymatch]` per locale |
| Base64 decode plausibility-gated (≥4 bytes, ≥80% printable) | `TestNormalize_Base64_PlausibleText`, `TestNormalize_Base64_RejectsImplausible` | runner `[base64]` per locale |
| No NUL bytes in any variant | `TestNormalize_Base64_PlausibleText` | runner `[invariant][no-nul]` per locale |

## Multi-locale stego matrix

The fixture at `tests/fixtures/normalize/payloads.json` carries 5
locales: `en`, `sr`, `ja`, `ar`, `zh-CN`. Each locale ships a tuple
of inputs designed to exercise the documented transforms:

- **NFKC fullwidth** — same word in fullwidth form per locale that has one.
- **Zero-width insertion** — ZWSP/ZWJ injected between every other rune.
- **Homoglyph** — Cyrillic look-alikes for Latin scripts; documented
  no-op for scripts not covered by the conservative `homoglyphMap`.
- **Leet** — digit-for-letter substitutions; documented no-op for
  non-Latin scripts.
- **ROT13** — ASCII letters only (documented no-op for non-Latin scripts).
- **Base64** — natural-language payload base64-encoded per locale,
  with a `decoded_min_substring` assertion the runner checks.
- **Whitespace explosion** — tab/space/newline runs that must collapse
  to a single space.
- **Character-split** — hyphen/dot-separated forms of the locale's
  ignore-prompt sentinel.
- **Reverse** — full sentence reversed; runner asserts the reverse
  reveals the original.

## Test execution

```bash
# Unit floor (race-enabled, no cache)
GOMAXPROCS=2 nice -n 19 ionice -c 3 go test -count=1 -p 1 -race ./...

# Multi-locale runner (real Normalize on bilingual fixtures)
go run ./challenges/runner -fixtures tests/fixtures/normalize/payloads.json

# Paired-mutation describe gate
bash challenges/scripts/normalize_describe_challenge.sh
bash challenges/scripts/normalize_describe_challenge.sh --anti-bluff-mutate  # exit 99 expected
```
