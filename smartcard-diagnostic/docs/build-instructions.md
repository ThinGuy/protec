# Build Instructions

## Local Development Build

### Prerequisites
```bash
# Install Flutter
sudo snap install flutter --classic

# Install snapcraft
sudo snap install snapcraft --classic

# Install multipass (for clean builds)
sudo snap install multipass
```

### Build Steps
```bash
cd protec/smartcard-diagnostic

# Clean previous builds
snapcraft clean

# Build snap
snapcraft

# Output: smartcard-diagnostic_2.0.0_amd64.snap
```

### Install Locally
```bash
sudo snap install --dangerous smartcard-diagnostic_2.0.0_amd64.snap
```

## Clean Build (Recommended)

Use multipass for isolated build environment:
```bash
snapcraft --use-lxd
```

## Build for Multiple Architectures

### AMD64 (default)
```bash
snapcraft
```

### ARM64 (for thin clients)
```bash
snapcraft --target-arch=arm64
```

## Troubleshooting Build Issues

### Issue: Flutter Plugin Errors
```bash
cd smartcard-diagnostic
flutter pub get
flutter pub upgrade
cd ..
snapcraft clean
snapcraft
```

### Issue: Python Dependencies
```bash
# Verify requirements.txt is correct
cat daemon/requirements.txt

# Test Python dependencies locally
python3 -m venv test-env
source test-env/bin/activate
pip install -r daemon/requirements.txt
python daemon/smartcard_monitor.py
deactivate
```

### Issue: Missing System Packages

Edit `snap/snapcraft.yaml` and ensure all required packages in `system-dependencies` part.

## Snap Store Publishing

### 1. Register Name
```bash
snapcraft register smartcard-diagnostic
```

### 2. Build for Release
```bash
snapcraft --use-lxd
```

### 3. Upload to Edge Channel (Testing)
```bash
snapcraft upload smartcard-diagnostic_2.0.0_amd64.snap --release=edge
```

### 4. Test from Edge
```bash
sudo snap install smartcard-diagnostic --edge
```

### 5. Promote to Stable
```bash
snapcraft release smartcard-diagnostic 1 stable
```

## CI/CD Integration

Example GitHub Actions workflow (`.github/workflows/snap.yml`):
```yaml
name: Build Snap

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build snap
        uses: snapcore/action-build@v1
        with:
          path: smartcard-diagnostic

      - name: Upload snap artifact
        uses: actions/upload-artifact@v3
        with:
          name: snap
          path: smartcard-diagnostic/*.snap
```
