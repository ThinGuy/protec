# ProTEC Project Status

## Last Updated
2026-03-23

## Current Phase
Phase 1: Smart Card Diagnostic Tool - CODE COMPLETE - Ready for user build and test

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
- [x] Implement D-Bus monitor service
- [x] smartcard_monitor.py implementation
- [x] D-Bus service file
- [x] Detection shell scripts
- [x] Implement Flutter home screen UI
- [x] Card info, test result, health status models
- [x] D-Bus client service
- [x] Smart card service with detection
- [x] Status card and card info widgets (Yaru themed)
- [x] Home screen with Canonical UI guidelines
- [x] Yaru theme integration
- [x] .gitignore file
- [x] Testing documentation
- [x] Build instructions
- [x] D-Bus monitor service implementation
- [x] Flutter UI with Yaru theme
- [x] D-Bus client integration
- [x] Status state machine (gray/blue/green/red rules)
- [x] Models, services, widgets
- [x] Snap configuration
- [x] Documentation
- [x] YubiKey provisioning script with safety warnings
- [x] Interactive YubiKey testing menu
- [x] Multiple smart card personality support (PIV, PIV-I, Enterprise, DoD CAC)
- [x] Serial number and certificate verification for data protection
- [x] Updated testing documentation with provisioning guide
- [x] Flutter Linux desktop support initialized

## In Progress
- [ ] Awaiting user build/test feedback

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
- flutter-stable extension not available in snapcraft (fixed: switched to flutter plugin with manual override-build)
- core24 requires 'platforms' instead of 'architectures' (fixed: changed to platforms syntax)
- pip packages (pygobject, dbus-python) fail to compile in strict confinement (fixed: switched to Ubuntu archive packages python3-dbus, python3-gi)
- All Python dependencies now from Ubuntu archives for Canonical supportability
- CMAKE_INSTALL_PREFIX defaulted to /usr/local requiring root (fixed: relative DESTINATION paths + CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT guard)
- native_assets/linux/ install rule failed when directory absent (fixed: guarded with install(CODE ...) + if(EXISTS) check)
- CMakeLists.txt referenced main.cc at linux/ root but flutter create puts them in linux/runner/ (fixed: moved sources to runner/, created runner/CMakeLists.txt, parent uses add_subdirectory(runner))
- runner/my_application.cc includes "flutter/generated_plugin_registrant.h" but compiler searched from runner/ not linux/ (fixed: added target_include_directories for CMAKE_SOURCE_DIR in runner/CMakeLists.txt)
- snap run fails with "Couldn't open libEGL.so.1" (fixed: stage libegl1 dispatch loader only — not mesa/GL libs which shadow host drivers; added $SNAP_LIBRARY_PATH to LD_LIBRARY_PATH so dispatch loader finds host Mesa via opengl plug)

## Next Steps
1. User will retry snap build
2. Create remaining Flutter screens
3. Add tests

## User Action Required
User will run commands from BUILD_AND_TEST.md and report:
1. Build success/failure
2. Snap install success/failure
3. D-Bus service status
4. Application launch status
5. Any errors encountered

## Dependencies Status
- Python 3: Present
- Flutter SDK: Not installed
- snapcraft: Not installed

## Testing Status
ProTEC: tested
Smartcard diagnostic: code complete, awaiting user build test
