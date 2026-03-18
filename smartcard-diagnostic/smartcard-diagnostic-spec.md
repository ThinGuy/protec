# Smart Card Diagnostic Tool Specification

## Purpose

Professional GUI-based diagnostic tool for smart card operations on Ubuntu systems,
packaged as a snap for easy distribution and security confinement. Designed for
government and enterprise PKI deployments.

## Architecture

### Components

1. **Flutter GUI Application**
   - Material Design 3 interface
   - Four screens: Home, Diagnostics, Support Bundle, Settings
   - Communicates with backend daemon via D-Bus

2. **D-Bus Monitoring Daemon**
   - Python-based service running as snap daemon
   - Polls for smart card reader and card events
   - Exposes status via D-Bus methods and signals

3. **Diagnostic Scripts**
   - Reader detection, card identification, FIPS validation
   - Support bundle generation
   - Standalone or daemon-invoked

### Snap Confinement

Required interfaces:
- `raw-usb` - USB smart card readers
- `hardware-observe` - Hardware detection
- `desktop` / `wayland` / `x11` - GUI display
- `opengl` - Flutter rendering
- `network` - Certificate validation (OCSP/CRL)

### D-Bus Interface

Service: `com.canonical.SmartCardMonitor`

Methods:
- `GetReaderStatus()` -> JSON string
- `GetCardStatus()` -> JSON string
- `Refresh()` -> boolean

Signals:
- `ReaderChanged(status: string)`
- `CardChanged(status: string)`

## Target Market

- Government PKI deployments (federal, state, local)
- Enterprise organizations using PIV or PIV-I cards
- IT administrators managing smart card infrastructure

## Naming Convention

- Product: "Smart Card Diagnostic Tool"
- Snap: `smartcard-diagnostic`
- Use "PIV" for Personal Identity Verification
- Use "smart card" in prose, "smartcard" in identifiers
- DoD/CAC references only in testing documentation

## Security Model

- Strict snap confinement
- D-Bus service on session bus
- No root access required for diagnostics
- No telemetry or data collection
- Support bundles require explicit user approval

## Integration with ProTEC

- Diagnostic tool reads system state; ProTEC modifies it
- Diagnostic results inform configuration decisions
- Shared understanding of card types, readers, FIPS requirements
