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
CRITICAL:
- Use: "smartcard" or "smart card"
- Use: "PIV card" for Personal Identity Verification
- Avoid: DoD, CAC, military references (except testing docs)
- Target: Government and Enterprise PKI deployments

## Project Components
1. protec.py - Standalone automation script (existing)
2. smartcard-diagnostic/ - GUI diagnostic tool (new)
3. ubuntu-pro-integration/ - Pro Client service (future)

## Completed Tasks
- [x] ProTEC automation script
- [x] ProTEC documentation
- [x] CLAUDE.md initialization
- [x] Directory structure creation
- [x] Initial file scaffolding

## In Progress
- [ ] Implement D-Bus monitor service

## Guardrails
READ BEFORE EVERY TASK:
1. Always read CLAUDE.md before making changes
2. Never commit to main branch
3. Only commit to: claude/snap-smartcard
4. Never mix prompts with terminal commands
5. Always provide full code blocks
6. Update CLAUDE.md after task completion
7. Preserve existing ProTEC files
8. All new code in smartcard-diagnostic/
9. Use "smartcard" terminology
10. Target professional market

## Known Issues
None

## Next Steps
1. Implement D-Bus monitor service
2. Create Flutter UI
3. Implement diagnostic scripts
4. Add tests

## Dependencies Status
- Python 3: Present
- Flutter SDK: Not installed
- snapcraft: Not installed

## Testing Status
ProTEC: tested
Smartcard diagnostic: no tests yet
