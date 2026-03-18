# Smart Card Diagnostic Tool

Professional diagnostic and monitoring application for government and enterprise smart card deployments.

## Supported Card Types

- PIV (Personal Identity Verification) cards
- PIV-I (Interoperable) cards
- Government-issued smart cards
- Enterprise PKI cards

## Features

- Real-time smart card reader and card detection
- Comprehensive diagnostic test suite
- FIPS 140-2/140-3 compliance validation
- Certificate validation and expiry monitoring
- Transparent support bundle generation
- Ubuntu Desktop and Ubuntu Core support

## Installation

```bash
sudo snap install smartcard-diagnostic
```

## Usage

Launch the application:
```bash
smartcard-diagnostic
```

Monitor service status:
```bash
snap services smartcard-diagnostic
```

## Supported Systems

### Tested Cards
- U.S. Government PIV cards
- DoD Common Access Cards (testing only)
- Commercial PIV-compatible cards

### Tested Readers
See [docs/supported-cards.md](docs/supported-cards.md) for compatibility list.

## Privacy

This application collects no telemetry. Support bundles require explicit user approval and contain no sensitive data (no PINs, passwords, or private keys).

## Building from Source

```bash
cd smartcard-diagnostic
snapcraft
sudo snap install --dangerous smartcard-diagnostic_*.snap
```

## Development

See [smartcard-diagnostic-spec.md](smartcard-diagnostic-spec.md) for full specification.

## License

GPL v3

## Support

For issues, please visit: https://github.com/ThinGuy/protec/issues
