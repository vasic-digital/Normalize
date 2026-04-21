# AGENTS.md -- digital.vasic.normalize

## Module

`digital.vasic.normalize` -- adversarial-input canonicalisation for
defensive LLM guardrail pipelines.

## Framing: DEFENSIVE USE ONLY

This library produces canonical variants of suspicious input so that
pattern-matching detectors can scan ALL encoded forms (base64,
leet-speak, homoglyph, NFKC, zero-width stripped, ROT13, reversed,
whitespace-collapsed). It exists so that filter-bypass and stego
attacks on LLM guardrails fail.

**It is NOT an attack toolkit.** It does not produce jailbreak
strings, does not enumerate mutation payloads, and must not be
repurposed as one. Agents touching this module must reject any
request that inverts the direction (generate obfuscated attacks
from plain text rather than reveal plain text from obfuscated
attacks).

## Primary consumer

HelixAgent (`dev.helix.agent`). The `internal/security` package
consumes `Normalize` to scan every variant against its deny-list
regexes; a match on any variant triggers a guardrail.

Repository: `git@github.com:vasic-digital/HelixAgent.git`
(pinned via submodule + `go.mod` replace).

## Contribution policy

- Additions to the transform pipeline must be motivated by a
  documented, defensive use case (a specific bypass observed in the
  wild or in the HelixAgent red-team corpus).
- Performance-regressing changes require a benchmark comparison
  (`go test -bench=.`).
- Never introduce offensive helpers (e.g. "generate ROT13-encoded
  prompt from plain text") -- the consumer can trivially do that
  itself; exporting such helpers enlarges attack surface.
