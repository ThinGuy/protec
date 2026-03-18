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

## Testing the D-Bus Service

### Start the Monitor Daemon
```bash
cd smartcard-diagnostic
python3 daemon/smartcard_monitor.py
```

### Query D-Bus Methods
```bash
# Check reader
dbus-send --session --print-reply \
  --dest=com.canonical.SmartCardMonitor \
  /com/canonical/SmartCardMonitor \
  com.canonical.SmartCardMonitor.ReaderPresent

# Check card
dbus-send --session --print-reply \
  --dest=com.canonical.SmartCardMonitor \
  /com/canonical/SmartCardMonitor \
  com.canonical.SmartCardMonitor.CardPresent

# Get card info
dbus-send --session --print-reply \
  --dest=com.canonical.SmartCardMonitor \
  /com/canonical/SmartCardMonitor \
  com.canonical.SmartCardMonitor.GetCardInfo

# Get health status
dbus-send --session --print-reply \
  --dest=com.canonical.SmartCardMonitor \
  /com/canonical/SmartCardMonitor \
  com.canonical.SmartCardMonitor.GetHealthStatus

# Get certificate expiry
dbus-send --session --print-reply \
  --dest=com.canonical.SmartCardMonitor \
  /com/canonical/SmartCardMonitor \
  com.canonical.SmartCardMonitor.GetCertificateExpiry

# Run quick test
dbus-send --session --print-reply \
  --dest=com.canonical.SmartCardMonitor \
  /com/canonical/SmartCardMonitor \
  com.canonical.SmartCardMonitor.RunQuickTest
```

### Monitor D-Bus Signals
In one terminal, watch for card insertion/removal signals:
```bash
dbus-monitor --session \
  "type='signal',interface='com.canonical.SmartCardMonitor'"
```

In another terminal, insert/remove card and observe signals.

## Testing the Flutter UI

### Launch Application
```bash
smartcard-diagnostic
```

### Test Cases

#### Test 1: No Reader Connected
**Expected**: Gray status, "Waiting for reader..." message

#### Test 2: Reader Connected, No Card
**Expected**: Gray status, "Waiting for card..." message
**Action**: Click "Insert Card" button
**Expected**: Blue "Detecting..." then Red error "No card detected"

#### Test 3: Card Inserted
**Expected**: Automatic detection within 2 seconds, green status with card info

#### Test 4: Card Removed
**Expected**: Status changes to gray "Waiting for card..." within 2 seconds

#### Test 5: Unreadable Card
**Action**: Insert non-PIV card (or damaged card)
**Expected**: Red error "Unable to read card" with troubleshooting suggestions

## Testing with YubiKey

### Setup YubiKey for Testing
```bash
# Install YubiKey Manager
sudo apt install yubikey-manager

# Reset PIV applet (WARNING: erases existing keys)
ykman piv reset

# Generate test certificate
ykman piv generate-key 9a public_key.pem
ykman piv generate-certificate --subject "CN=Test User" 9a public_key.pem
```

### Verify YubiKey Detection
```bash
# Should show YubiKey as reader
opensc-tool -l

# Should show certificate
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O
```

## Testing with DoD Common Access Cards

For organizations with access to DoD CAC cards, these can be used for
integration testing. CAC cards are one implementation of PIV-compatible
smart cards.

## Common Issues

### Issue: D-Bus Service Not Starting
**Check logs**:
```bash
journalctl --user -u snap.smartcard-diagnostic.monitor.service -f
```

**Restart service**:
```bash
snap restart smartcard-diagnostic.monitor
```

### Issue: Reader Not Detected
**Check pcscd**:
```bash
systemctl status pcscd
```

**Restart pcscd**:
```bash
sudo systemctl restart pcscd
```

**Check USB permissions**:
```bash
ls -l /dev/bus/usb/*/*
```

### Issue: Flutter App Won't Launch
**Check snap logs**:
```bash
snap logs smartcard-diagnostic -n=100
```

**Try running from command line to see errors**:
```bash
/snap/smartcard-diagnostic/current/smartcard-diagnostic
```

## Development Testing

### Run Flutter App Without Snap
Requires D-Bus service to be running:
```bash
cd smartcard-diagnostic
flutter run -d linux
```

### Run Unit Tests
```bash
flutter test
```

### Code Coverage
```bash
flutter test --coverage
genhtml coverage/lcov.info -o coverage/html
```

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

## Performance Testing

### Monitor Resource Usage
```bash
# CPU and memory
top -p $(pgrep -f smartcard-diagnostic)

# D-Bus messages
dbus-monitor --session | grep SmartCardMonitor
```

### Expected Resource Usage
- Memory: ~50-100 MB
- CPU: <5% idle, <15% during detection
- D-Bus polls: Every 2 seconds

## Snap Store Testing

Before publishing to snap store:

1. Test on clean Ubuntu 22.04 VM
2. Test on clean Ubuntu 24.04 VM
3. Test on Ubuntu Core device (if available)
4. Verify all interfaces connect automatically
5. Test upgrades from previous version
