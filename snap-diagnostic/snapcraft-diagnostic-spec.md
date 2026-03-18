# Snapcraft Diagnostic Tool Specification

## Purpose
Provide a comprehensive GUI-based diagnostic tool for smart card operations on Ubuntu systems, packaged as a snap for easy distribution and security confinement.

## Components

### 1. Flutter GUI Application
- Material Design 3 interface with Ubuntu theming
- Five main views: Reader Status, Card Info, FIPS Validation, Certificate Bundle, Monitor
- Communicates with backend daemon via D-Bus

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

## Integration with ProTEC
- Diagnostic tool reads system state; ProTEC modifies it
- Diagnostic results inform ProTEC configuration decisions
- Shared understanding of card types, readers, and FIPS requirements
