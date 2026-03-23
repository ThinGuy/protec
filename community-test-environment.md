# Project Community — Test Environment Guide

## Physical Hardware — Ngikhona Test Target

Minimum spec for Wayfire + wf-cube with GLES 3.2:

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | Intel 8th gen+ or AMD Ryzen 3000+ with integrated graphics | Intel 12th gen+ NUC |
| RAM | 8GB | 16GB |
| Storage | 32GB SSD | 64GB SSD |
| GPU | Intel UHD 620/630 or AMD Vega integrated (GLES 3.2 required) | Intel UHD 770 |
| OS | Ubuntu 24.04 LTS bare metal | Ubuntu 24.04 LTS bare metal |

### Recommended Hardware

| Device | Price | Notes |
|--------|-------|-------|
| Intel NUC 12/13 Pro | ~$300 refurb | Intel UHD graphics, full GLES 3.2 |
| Beelink EQ12 | ~$150 | Intel N100, works well |
| MINISFORUM UM350 | ~$180 | AMD Ryzen 5 3550H, Vega 8 integrated |

> Your Lemur Pro's integrated GPU works for snap build and test but is not ideal as a kiosk display target.

### SmartCard Readers

Any CCID-compliant USB reader works. Recommended options:

| Reader | Price | Notes |
|--------|-------|-------|
| Identiv uTrust 3700F | ~$25 | Reliable, widely tested |
| YubiKey 5 NFC (PIV applet) | ~$50 | Good for dev testing |
| ACS ACR122U | ~$30 | Works, NFC capable |

---

## VM Setup — Sawubona + Integration Testing

### Prerequisites (host machine)

```bash
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virtinst
sudo usermod -aG kvm,libvirt $USER
```

Log out and back in for group membership to take effect.

### Ngikhona Test VM (with virgl 3D acceleration)

```bash
virt-install \
  --name ngikhona-test \
  --ram 4096 \
  --vcpus 4 \
  --cpu host \
  --os-variant ubuntu24.04 \
  --disk path=/var/lib/libvirt/images/ngikhona-test.qcow2,size=32,format=qcow2,bus=virtio \
  --network bridge=virbr0,model=virtio \
  --graphics spice,listen=none,gl.enable=yes \
  --video virtio,accel3d=yes \
  --channel spicevmc \
  --cdrom /path/to/ubuntu-24.04-live-server-amd64.iso \
  --boot uefi \
  --noautoconsole
```

### Sawubona Test VM (backend only — no GPU needed)

```bash
virt-install \
  --name sawubona-test \
  --ram 2048 \
  --vcpus 2 \
  --cpu host \
  --os-variant ubuntu24.04 \
  --disk path=/var/lib/libvirt/images/sawubona-test.qcow2,size=20,format=qcow2,bus=virtio \
  --network bridge=virbr0,model=virtio \
  --graphics none \
  --console pty,target_type=serial \
  --cdrom /path/to/ubuntu-24.04-live-server-amd64.iso \
  --boot uefi \
  --noautoconsole
```

### Verify virgl 3D acceleration inside Ngikhona VM

```bash
sudo apt install -y mesa-utils
glxinfo | grep "OpenGL renderer"
```

Expected output contains `virgl`. If you see `llvmpipe`, 3D acceleration is not working — verify that your host has `virglrenderer` installed and the SPICE display is configured with `listen=none` and GL enabled.

### SmartCard USB passthrough to VM

Find your reader's USB vendor and product IDs:

```bash
lsusb
```

Create a file `usb-smartcard.xml`:

```xml
<hostdev mode='subsystem' type='usb' managed='yes'>
  <source>
    <vendor id='0x<VENDOR_ID>'/>
    <product id='0x<PRODUCT_ID>'/>
  </source>
</hostdev>
```

Attach to the running VM:

```bash
virsh attach-device ngikhona-test --file usb-smartcard.xml --live
```

---

## Hardware Testing Checklist

| Test | VM | Physical | Notes |
|------|----|----------|-------|
| Sawubona backend + API | ✅ | ✅ | |
| React dashboard | ✅ | ✅ | |
| WireGuard tunnel | ✅ | ✅ | |
| mDNS discovery | ✅ bridged | ✅ | Requires bridged network in VM |
| Snap install + confinement | ✅ | ✅ | |
| Wayfire + wf-cube | ⚠️ virgl only | ✅ | virgl works but may be slow |
| Plymouth boot theme | ❌ | ✅ | Only visible on bare metal boot |
| SmartCard PIN overlay | ⚠️ USB passthrough | ✅ | USB passthrough required in VM |
| window-rules workspace pinning | ⚠️ virgl only | ✅ | Verify app_id values on hardware |
| Keyboard exclusive mode (PIN overlay) | ⚠️ verify | ✅ | Test under strict confinement |

---

## Outstanding TODOs Before Hardware Testing

These are code TODOs that must be resolved on hardware:

1. **WireGuard tun device creation** — both `ngikhona/cmd/agent/main.go:113` and `sawubona/internal/pairing/pairing.go:addWGPeer` assume the WireGuard interface exists. On bare metal: `sudo modprobe wireguard && sudo ip link add wg-sawubona type wireguard`. For the snap, add `network-control` plug to snapcraft.yaml.

2. **window-rules workspace pinning** — `ngikhona/wayfire/wayfire.ini` has the `[window-rules]` section commented out. Verify the following `app_id` values on real hardware with `lswt`, then uncomment:
   - `xfreerdp3` → workspace 0
   - `remote-viewer` → workspace 1
   - `chromium-browser` → workspace 2
   - `hollywood` → workspace 3

3. **Keyboard exclusive mode** — `GTK_LAYER_SHELL_KEYBOARD_MODE_EXCLUSIVE` in `ngikhona/bin/ngikhona-pin-overlay`. Verify input grab works under strict snap confinement with the `wayland` plug connected.

4. **pcscd snap connection** — one-time manual step after install:
   ```bash
   snap connect ngikhona:pcsc-socket pcscd:pcsc-socket
   ```
   Verify socket path resolves at `$SNAP_DATA/pcsc/run/pcscd.comm`.

5. **Plymouth PNGs** — run `build.sh` before snap build:
   ```bash
   cd ngikhona/branding/plymouth && bash build.sh
   ```
   Verify `rsvg-convert` and `imagemagick` are available in the snapcraft build environment.

6. **npm audit vulnerabilities** — 2 moderate severity vulnerabilities in the React dashboard. Run `npm audit fix` in `sawubona/web/dashboard/` before any production build.

---

## Network Layout (recommended for testing)

```
Host machine (your Lemur Pro)
├── virbr0 (192.168.122.0/24) — libvirt bridge
│   ├── sawubona-test VM (192.168.122.x) — Sawubona backend + dashboard
│   └── ngikhona-test VM (192.168.122.y) — Ngikhona snap
│
└── WireGuard tunnel (10.100.0.0/24)
    ├── sawubona-test: 10.100.0.1 (server)
    └── ngikhona-test: 10.100.0.2 (first endpoint)
```

mDNS (`_ngikhona._udp`) works over the `virbr0` bridge as long as both VMs are on the same bridge network.
