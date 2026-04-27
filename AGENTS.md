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

<!-- BEGIN host-power-management addendum (CONST-033) -->

## Host Power Management — Hard Ban (CONST-033)

**You may NOT, under any circumstance, generate or execute code that
sends the host to suspend, hibernate, hybrid-sleep, poweroff, halt,
reboot, or any other power-state transition.** This rule applies to:

- Every shell command you run via the Bash tool.
- Every script, container entry point, systemd unit, or test you write
  or modify.
- Every CLI suggestion, snippet, or example you emit.

**Forbidden invocations** (non-exhaustive — see CONST-033 in
`CONSTITUTION.md` for the full list):

- `systemctl suspend|hibernate|hybrid-sleep|poweroff|halt|reboot|kexec`
- `loginctl suspend|hibernate|hybrid-sleep|poweroff|halt|reboot`
- `pm-suspend`, `pm-hibernate`, `shutdown -h|-r|-P|now`
- `dbus-send` / `busctl` calls to `org.freedesktop.login1.Manager.Suspend|Hibernate|PowerOff|Reboot|HybridSleep|SuspendThenHibernate`
- `gsettings set ... sleep-inactive-{ac,battery}-type` to anything but `'nothing'` or `'blank'`

The host runs mission-critical parallel CLI agents and container
workloads. Auto-suspend has caused historical data loss (2026-04-26
18:23:43 incident). The host is hardened (sleep targets masked) but
this hard ban applies to ALL code shipped from this repo so that no
future host or container is exposed.

**Defence:** every project ships
`scripts/host-power-management/check-no-suspend-calls.sh` (static
scanner) and
`challenges/scripts/no_suspend_calls_challenge.sh` (challenge wrapper).
Both MUST be wired into the project's CI / `run_all_challenges.sh`.

**Full background:** `docs/HOST_POWER_MANAGEMENT.md` and `CONSTITUTION.md` (CONST-033).

<!-- END host-power-management addendum (CONST-033) -->

