# Smart Card Diagnostic Tool Specification

## Purpose

Provide a professional GUI-based diagnostic tool for smart card operations on Ubuntu systems, packaged as a snap for easy distribution and security confinement. Designed for government and enterprise PKI deployments.

## Components

### 1. Flutter GUI Application
- Material Design 3 interface with Ubuntu theming
- Four main views: Home (status overview), Diagnostics (test suite), Support Bundle, Settings
- Communicates with backend daemon via D-Bus
- Responsive layout for desktop use

### 2. D-Bus Monitoring Daemon
- Python-based service running as snap daemon
- Polls for smart card reader and card events
- Exposes status via D-Bus methods and signals
- Enables real-time UI updates

### 3. Diagnostic Scripts
- Shell scripts for reader detection, card identification, FIPS validation
- Bundle generation for support cases
- Can be used standalone or invoked by the daemon

## Snap Confinement

### Required Interfaces
- `raw-usb` - Access to USB smart card readers
- `hardware-observe` - Hardware detection
- `desktop` / `wayland` / `x11` - GUI display
- `opengl` - Flutter rendering
- `network` - Certificate validation (OCSP/CRL)

### Security Model
- Strict confinement ensures the tool cannot access files outside its scope
- D-Bus service scoped to session bus
- No root access required for diagnostics (unlike ProTEC configuration)

## Target Market

### Primary
- Government PKI deployments (federal, state, local)
- Enterprise organizations using PIV or PIV-I cards

### Secondary
- IT administrators managing smart card infrastructure
- Help desk teams diagnosing smart card issues

## Integration with ProTEC
- Diagnostic tool reads system state; ProTEC modifies it
- Diagnostic results inform ProTEC configuration decisions
- Shared understanding of card types, readers, and FIPS requirements

## Naming Convention
- Product name: "Smart Card Diagnostic Tool"
- Snap name: `smartcard-diagnostic`
- Use "PIV" for Personal Identity Verification references
- Use "smart card" (two words) in prose, "smartcard" in identifiers
- Minimize DoD/CAC references; use only in testing documentation
