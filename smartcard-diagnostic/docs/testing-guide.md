# Testing Guide

## Test Environment Setup

### Prerequisites
- Ubuntu 22.04 LTS or newer
- `pcscd` service installed and running
- Supported smart card reader
- Test smart card (PIV-compatible)

### Quick Setup
```bash
sudo apt install pcscd pcsc-tools opensc
sudo systemctl enable --now pcscd
```

## Testing with YubiKey (PIV Mode)

YubiKey 5 Series devices support PIV and are ideal for development testing.

```bash
sudo apt install yubikey-manager
ykman info
ykman piv info
```

## Testing with DoD Common Access Cards

For organizations with access to DoD CAC cards, these can be used for
integration testing. CAC cards are one implementation of PIV-compatible
smart cards.

## Running Tests

### Unit Tests
```bash
cd smartcard-diagnostic
flutter test
```

### Integration Tests
Requires connected reader and card:
```bash
flutter test test/integration/
```

### Daemon Tests
```bash
cd daemon
python -m pytest ../test/unit/
```
