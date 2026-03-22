# Craig's Guardrails — protec / smartcard-diagnostic
# Read before every response. No exceptions.

## Code Block Rules — ABSOLUTE

Terminal blocks contain ONLY bash commands. Nothing else. No labels, no
explanations, no comments inside the block.

Explanatory text goes outside code blocks, in plain prose, BEFORE the block
it refers to.

Never put instructions, confirmations, or narration inside a code block.

## Formatting

Plain prose for explanations and instructions.

Terminal block for commands Craig runs on his machine.

Inline code (backticks) for filenames, identifiers, and short snippets inside
prose.

No other block types are used for commands or file paths.

## Repo and Branch Rules

Repo: github.com/ThinGuy/protec

Working branch: claude/snap-diagnostic-B4ClC

All work lives on that branch. Never push to main.

Claude writes files in the container and produces a patch. Craig applies the
patch, reviews, and pushes from his machine.

Craig does the terminal work. Claude does the file work.

Snap builds happen on Craig's side only. Claude never runs snapcraft.

## Local Path

Craig's repo lives at ~/Desktop/protec.

All terminal blocks must cd ~/Desktop/protec first.

## Naming — Active and Retired

Active project names:
- Ngikhona — endpoint snap (kiosk / thin client)
- Sawubona — management backend
- Community — project codename
- smartcard-diagnostic — the snap being fixed in this project
- ProTEC — the broader toolset (protec.py + smartcard-diagnostic)

Retired names — never use again:
- FrameCube, Frame, cUbE, rUbE

## Remediation Phase Rules

The five-phase plan in guardrails-protec.md is the sequence. Do not skip ahead.

Phases 0–3 work under confinement: devmode and grade: devel. Do not flip
either until Phase 3 checkpoint passes.

Phase 4 (confinement: strict) begins only after all Phase 3 tests pass on
physical hardware.

Phase 5 (shared pcscd snap) begins only after Phase 4 is clean.

No work on Sawubona until Ngikhona M3 is complete.

## Hard Rules

Read every file before touching it. No edits from memory.

Explain root cause before applying any fix.

Lock call contracts before writing callers.

One layer at a time. Test before moving to next layer.

Never invent PCSC API call signatures, D-Bus interface contracts, Wayfire
config keys, or FreeRDP flags. Look them up or ask.

No bundling pcscd inside any consumer snap — ever.

grade: devel on all snaps until the smoke test suite passes on real hardware.

## D-Bus Contracts — Locked

These are the only valid signatures for com.canonical.SmartCardMonitor.
Do not change them without updating both sides (Python daemon + Dart client)
in the same commit.

  GetCardInfo()       → a{ss}   keys: type, atr, certs
  GetCardInfoJson()   → s       full JSON for nested data
  GetHealthStatus()   → s       JSON
  GetCertificateExpiry() → s    JSON
  RunQuickTest()      → s       JSON
  ReaderPresent()     → b
  CardPresent()       → b

  Signals:
  CardInserted(b)
  CardRemoved(b)
  ReaderStatusChanged(s)
  HealthStatusChanged(s)

  Bus: system (never session)
  Object path: /com/canonical/SmartCardMonitor
  Interface:   com.canonical.SmartCardMonitor
