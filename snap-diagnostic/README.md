# Smart Card Diagnostic Tool (Snap)

A GUI diagnostic application for comprehensive smart card testing and monitoring on Ubuntu systems.

## Overview

This snap provides:
- **Real-time reader detection** - Automatically detect connected smart card readers
- **Card identification** - Read ATR and identify inserted cards
- **FIPS validation** - Verify FIPS 140-2/140-3 compliance status
- **Certificate bundle generation** - Create diagnostic bundles for support
- **D-Bus monitoring service** - Background daemon for card insert/remove events

## Architecture

```
snap-diagnostic/
├── snap/snapcraft.yaml      # Snap packaging configuration
├── lib/                     # Flutter GUI application
│   ├── main.dart            # App entry point
│   ├── screens/             # UI screens
│   ├── services/            # D-Bus client, backend services
│   ├── widgets/             # Reusable UI components
│   └── models/              # Data models
├── daemon/                  # D-Bus monitoring service
│   ├── smartcard_monitor.py # Monitor daemon
│   ├── requirements.txt     # Python dependencies
│   └── com.canonical.SmartCardMonitor.service
├── scripts/                 # Shell-based diagnostic tools
│   ├── detect_reader.sh     # Reader detection
│   ├── detect_card.sh       # Card detection
│   ├── validate_fips.sh     # FIPS validation
│   └── generate_bundle.sh   # Diagnostic bundle generator
└── test/                    # Test suites
    ├── unit/
    └── integration/
```

## Prerequisites

- Ubuntu 22.04 LTS or newer
- Flutter SDK (for development)
- Python 3.10+ (for daemon)
- `pcscd` service running
- Smart card reader (for testing)

## Development

### Building the snap

```bash
cd snap-diagnostic
snapcraft
```

### Running the daemon standalone

```bash
cd daemon
pip install -r requirements.txt
python smartcard_monitor.py
```

### Running diagnostic scripts

```bash
bash scripts/detect_reader.sh
bash scripts/detect_card.sh
bash scripts/validate_fips.sh
bash scripts/generate_bundle.sh /tmp
```

## D-Bus Interface

The monitoring daemon exposes the following D-Bus interface:

- **Service**: `com.canonical.SmartCardMonitor`
- **Methods**:
  - `GetReaderStatus()` → JSON string with reader information
  - `GetCardStatus()` → JSON string with card information
  - `Refresh()` → Force status update
- **Signals**:
  - `ReaderChanged(status)` → Emitted when reader state changes
  - `CardChanged(status)` → Emitted when card state changes

## Related

- [ProTEC automation script](../protec.py) - Standalone CAC configuration tool
- [ProTEC documentation](../ProTEC.md) - Comprehensive setup guide
