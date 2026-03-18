# ProTEC Project Status

## Last Updated
2026-03-18

## Current Phase
Phase 1: Smart Card Diagnostic Tool - Foundation

## Repository Information
Repository: https://github.com/ThinGuy/protec
Working Branch: claude/snap-smartcard
Protected Branches: main (never commit directly)

## Naming Convention
CRITICAL - Must follow everywhere:
- Use: "smartcard" or "smart card"
- Use: "PIV card" for Personal Identity Verification
- Avoid: DoD, CAC, military references (except in testing docs)
- Target: Government and Enterprise PKI deployments
- Branding: Professional, vendor-neutral, internationally applicable

## Project Components
1. protec.py - Standalone automation script (existing)
2. smartcard-diagnostic/ - GUI diagnostic tool (new)
3. ubuntu-pro-integration/ - Pro Client service (future)

## Completed Tasks
- [x] ProTEC automation script
- [x] ProTEC documentation
- [x] CLAUDE.md initialization
- [x] Smartcard diagnostic tool foundation

## In Progress
- [ ] Repository structure for diagnostic tool

## Guardrails
CRITICAL - READ BEFORE EVERY TASK:
1. Always read CLAUDE.md before making any changes
2. Never commit to main branch
3. Only commit to: claude/snap-smartcard
4. Never mix prompts with terminal commands in responses
5. Always provide full code blocks - never ask user to edit
6. Update CLAUDE.md after every task completion
7. Preserve existing ProTEC files - do not modify unless instructed
8. All new code goes in smartcard-diagnostic/ subdirectory
9. Use "smartcard" terminology - avoid DoD/CAC/military references
10. Target professional government/enterprise market

## Known Issues
None yet

## Next Steps
1. Create smartcard-diagnostic/ directory structure
2. Create snapcraft.yaml
3. Implement D-Bus service
4. Create Flutter project structure

## Dependencies Status
Existing ProTEC dependencies: installed
New snap dependencies: not yet installed
- Flutter SDK: Required
- Python 3: Required (already present)
- snapcraft: Required

## Testing Status
ProTEC script: tested
Smartcard diagnostic: no tests yet
