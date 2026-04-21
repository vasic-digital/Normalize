# digital.vasic.normalize

Adversarial-input canonicalisation for defensive LLM guardrail pipelines.

Produces multiple canonical "variants" of a prompt so pattern detectors
can scan ALL encoded / obfuscated forms -- base64, leet-speak, homoglyph,
Unicode normalization (NFKC), zero-width stripping, ROT13, whitespace
collapse, reversal.

## Transforms

`Normalize(s)` produces a `NormalizedInput{Original, Variants}` where
`Variants` contains (deduplicated, original first):

1. Original input
2. NFKC Unicode normalization (fullwidth / compatibility folds)
3. Zero-width stripped (ZWJ/ZWSP/ZWNJ/BOM/word-joiner)
4. Zero-width stripped + NFKC
5. Leet-speak de-leet (`1gn0r3` -> `ignore`)
6. Homoglyph fold (Cyrillic / Greek look-alikes to ASCII)
7. ROT13 round-trip
8. Base64 decode (plausibility-gated)
9. Whitespace collapsed
10. Character-split collapsed (`i-g-n-o-r-e` -> `ignore`)
11. String reversed
12. Combined (homoglyph + NFKC + zero-width strip)
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

## Defensive-use policy

This module is intentionally read-only for offensive consumers. It
produces variants; it does NOT produce attack payloads. Integrating
this into any red-team or bypass tooling violates the stated use case.

## Tests

```bash
GOMAXPROCS=2 nice -n 19 ionice -c 3 go test -count=1 -p 1 -race ./...
```

## License

Apache-2.0
