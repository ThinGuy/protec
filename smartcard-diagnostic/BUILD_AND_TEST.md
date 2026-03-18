# Build and Test Commands

## Build Command

```bash
cd ~/path/to/protec/smartcard-diagnostic && \
git branch --show-current && \
git pull && \
snapcraft clean --use-lxd && \
snapcraft pack --use-lxd 2>&1 | tail -5
```

Expected output: `smartcard-diagnostic_2.0.0_amd64.snap`

## Install and Test Commands

```bash
sudo snap set system snapshots.automatic.retention=no && \
sudo snap remove smartcard-diagnostic 2>/dev/null || true && \
sudo snap install --dangerous ./smartcard-diagnostic_2.0.0_amd64.snap && \
sleep 5 && \
sudo snap connect smartcard-diagnostic:raw-usb && \
sudo snap connect smartcard-diagnostic:hardware-observe && \
snap services smartcard-diagnostic && \
sleep 3 && \
systemctl --user status snap.smartcard-diagnostic.monitor.service
```

## Test D-Bus Service

```bash
dbus-send --session --print-reply \
  --dest=com.canonical.SmartCardMonitor \
  /com/canonical/SmartCardMonitor \
  com.canonical.SmartCardMonitor.ReaderPresent
```

Expected: `boolean true` or `boolean false` (depending on reader presence)

## Launch Application

```bash
smartcard-diagnostic
```

Expected: Flutter app window opens with "Waiting for card..." status

## Check Logs

```bash
# D-Bus monitor service logs
journalctl --user -u snap.smartcard-diagnostic.monitor.service -n 50

# Application logs
snap logs smartcard-diagnostic -n 50
```

## Cleanup (if needed)

```bash
sudo snap remove smartcard-diagnostic
```
