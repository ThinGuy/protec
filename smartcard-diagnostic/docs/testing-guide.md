# Testing Guide

## Overview

This guide covers testing the Smart Card Diagnostic Tool with various card types and configurations.

## Test Environment Setup

### Prerequisites
- Ubuntu 22.04 LTS or newer
- `pcscd` service installed and running
- At least one supported smart card reader
- Test smart card (PIV-compatible)

### Quick Setup
```bash
sudo apt install pcscd pcsc-tools opensc
sudo systemctl enable --now pcscd
```

## Testing with YubiKey (PIV Mode)

YubiKey 5 Series devices support PIV and are ideal for development testing.

### Setup
```bash
# Install YubiKey manager
sudo apt install yubikey-manager

# Verify PIV is enabled
ykman info
ykman piv info
```

### Generate Test Certificates
```bash
# Generate a self-signed certificate for testing
ykman piv keys generate --algorithm RSA2048 9a /tmp/test-pub.pem
ykman piv certificates generate --subject "CN=Test User" 9a /tmp/test-pub.pem
```

## Testing with DoD Common Access Cards

For organizations with access to DoD CAC cards, these can be used for integration testing. Note that CAC cards are one specific implementation of PIV-compatible smart cards.

### CAC-Specific Tests
1. Reader detection with CAC middleware
2. PIV application selection on CAC
3. Certificate extraction and validation
4. PIN verification (use test cards only)

## Running Unit Tests
```bash
cd smartcard-diagnostic
# Flutter tests
flutter test

# Python daemon tests
cd daemon
python -m pytest ../test/unit/
```

## Running Integration Tests

Integration tests require a connected reader and card.

```bash
cd smartcard-diagnostic
# With hardware connected
flutter test test/integration/
```

## Test Matrix

| Test | PIV Card | YubiKey | Enterprise Card |
|------|----------|---------|-----------------|
| Reader Detection | Pass | Pass | Pass |
| ATR Reading | Pass | Pass | Pass |
| PIV App Select | Pass | Pass | Varies |
| Certificate Read | Pass | Pass | Varies |
| FIPS Validation | System | System | System |
