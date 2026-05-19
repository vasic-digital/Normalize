# digital.vasic.normalize

Adversarial-input canonicalisation for defensive LLM guardrail pipelines.

Produces multiple canonical "variants" of a prompt so pattern detectors
can scan ALL encoded / obfuscated forms — base64, leet-speak, homoglyph,
Unicode normalization (NFKC), zero-width stripping, ROT13, whitespace
collapse, character-split collapse, and string reversal.

## Round-258 deep-doc enrichment

This README, the symbol→test ledger at `docs/test-coverage.md`, the
multi-locale fixture at `tests/fixtures/normalize/payloads.json`, and
the bilingual Challenge runner at `challenges/runner/main.go` are
co-maintained so every claim below is exercised by real executed code
on every commit. See `challenges/scripts/normalize_describe_challenge.sh`
for the paired-mutation gate that enforces it.

## API surface

| Symbol | Kind | Purpose |
|--------|------|---------|
| `NormalizedInput` | type | `{Original string, Variants []string}` — output of `Normalize`. |
| `Normalize(s string) NormalizedInput` | func | Returns deduplicated variants (Original first). |
| `NormalizedInput.AnyMatch(fn func(string) bool) bool` | method | True iff `fn` matches any variant. |

All transforms are pure functions; no I/O, no goroutines, no global
state. Safe for use in concurrent guardrail pipelines.

## Transforms

`Normalize(s)` produces a `NormalizedInput{Original, Variants}` where
`Variants` contains (deduplicated, original first):

1. Original input
2. NFKC Unicode normalization (fullwidth / compatibility folds)
3. Zero-width stripped (ZWJ U+200D, ZWSP U+200B, ZWNJ U+200C,
   word-joiner U+2060, BOM U+FEFF)
4. Zero-width stripped + NFKC (composed)
5. Leet-speak de-leet (`1gn0r3` → `ignore`; `@`/`!`/`$` → `a`/`i`/`s`)
6. Homoglyph fold (Cyrillic + Greek capital look-alikes → ASCII;
   conservative table — see `homoglyphMap` in `normalize.go`)
7. ROT13 round-trip (self-inverse; non-letters preserved)
8. Base64 decode (regex `[A-Za-z0-9+/]{16,}={0,2}`, plausibility-gated:
   ≥4 bytes, ≥80% printable runes)
9. Whitespace collapsed (any run of whitespace → single ASCII space)
10. Character-split collapsed (`i-g-n-o-r-e` → `ignore`;
    single separator between two alphanumerics is removed)
11. String reversed (rune-aware UTF-8 safe)
12. Combined: homoglyph fold + NFKC + zero-width strip
13. Combined, lowercased

## Usage

```go
import "digital.vasic.normalize"

ni := normalize.Normalize(userPrompt)
if ni.AnyMatch(func(v string) bool {
    return dangerousRegex.MatchString(v)
}) {
    // block
}
```

## Anti-bluff guarantees (Article XI §11.9 + CONST-035 + CONST-050(B))

Round-258 strengthens this submodule's claim-to-execution mapping. The
following invariants are enforced by `normalize_test.go` and the
multi-locale runner at `challenges/runner/main.go`:

- **No metadata-only / grep-only PASS.** Every Challenge PASS line is
  preceded by the locale code, the transform exercised, and a positive
  assertion (substring containment, rune count, length delta, etc.)
  computed from the actual returned `Variants` slice.
- **Bilingual stego coverage.** The fixture at
  `tests/fixtures/normalize/payloads.json` ships 5 locales (en, sr,
  ja, ar, zh-CN) of NFKC-fullwidth, homoglyph-Cyrillic, zero-width,
  leet, ROT13, base64, character-split, and reversed inputs — every
  attack class re-tested in every language to catch regressions
  where a transform silently breaks for non-Latin scripts.
- **Real `Normalize` exerciser.** The runner calls the real public API
  on every payload, asserts every documented variant appears (or
  documents why it cannot — e.g. ROT13 of Cyrillic is a no-op by
  contract since ROT13 only touches ASCII letters), and exits non-zero
  on any failure.
- **Paired-mutation Challenge.** The describe Challenge supports
  `--anti-bluff-mutate`: it plants a deliberate symbol-rename in the
  ledger (`Normalize` → `Bogus_MUTATED`), reruns validation, and
  asserts the gate FAILS with exit 99. This proves the gate actually
  catches ledger-vs-source drift instead of rubber-stamping it.
- **Failure surface preserved.** A test that previously passed but
  whose underlying invariant has been weakened (e.g. transform now
  returns the original on non-ASCII input without raising) is a
  bluff — the runner asserts positive evidence per transform per
  locale, not absence-of-error.

> Verbatim 2026-05-19 operator mandate: *"all existing tests and
> Challenges do work in anti-bluff manner - they MUST confirm that
> all tested codebase really works as expected! We had been in
> position that all tests do execute with success and all Challenges
> as well, but in reality the most of the features does not work
> and can't be used! This MUST NOT be the case and execution of
> tests and Challenges MUST guarantee the quality, the completition
> and full usability by end users of the product!"*

## Defensive-use policy

This module is intentionally read-only for offensive consumers. It
produces variants; it does NOT produce attack payloads. Integrating
this into any red-team or bypass tooling violates the stated use case.

## Tests

```bash
# Unit tests (race-enabled, single-pass, no cache)
GOMAXPROCS=2 nice -n 19 ionice -c 3 go test -count=1 -p 1 -race ./...

# Round-258 multi-locale Challenge runner (real Normalize exerciser)
go run ./challenges/runner -fixtures tests/fixtures/normalize/payloads.json

# Round-258 paired-mutation describe gate
bash challenges/scripts/normalize_describe_challenge.sh
bash challenges/scripts/normalize_describe_challenge.sh --anti-bluff-mutate  # exit 99 = good
```

Expected: all gates exit 0 (PASS) on a clean tree; the `--anti-bluff-mutate`
run exits 99 (proving the gate would catch a drift).

## License

Apache-2.0
