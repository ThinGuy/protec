#!/usr/bin/env python3
"""Smart Card Monitor D-Bus Service.

Monitors smart card reader and card events, exposing status
information over D-Bus for the Flutter GUI application.

Uses opensc-tool and pkcs11-tool for hardware detection.
Designed for government and enterprise PKI deployments.
Supports PIV and other standard smart card types.

Security: Only reads public card data. No PINs, passwords,
or private keys are ever accessed or stored.
"""

import json
import logging
import os
import signal
import subprocess
import sys
from datetime import datetime

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

# D-Bus constants
DBUS_BUS_NAME = "com.canonical.SmartCardMonitor"
DBUS_OBJECT_PATH = "/com/canonical/SmartCardMonitor"
DBUS_INTERFACE = "com.canonical.SmartCardMonitor"

# Polling interval in seconds
POLL_INTERVAL = 2

# Subprocess timeout in seconds
CMD_TIMEOUT = 2

# Configure logging for journald
logging.basicConfig(
    level=logging.INFO,
    format="%(name)s: %(levelname)s: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("smartcard-monitor")


def _run_cmd(cmd, timeout=CMD_TIMEOUT):
    """Run a shell command with timeout and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        log.warning("Command timed out after %ds: %s", timeout, " ".join(cmd))
        return -1, "", "timeout"
    except FileNotFoundError:
        log.warning("Command not found: %s", cmd[0])
        return -1, "", "not_found"
    except Exception as exc:
        log.error("Command failed: %s: %s", " ".join(cmd), exc)
        return -1, "", str(exc)


def _detect_reader():
    """Detect smart card reader using opensc-tool.

    Returns dict with reader status information.
    """
    rc, stdout, stderr = _run_cmd(["opensc-tool", "-l"])
    if rc != 0:
        if "No smart card readers found" in stderr or "No smart card readers found" in stdout:
            return {"detected": False, "count": 0, "readers": []}
        return {"detected": False, "count": 0, "readers": [], "error": stderr or "opensc-tool failed"}

    readers = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # opensc-tool -l outputs lines like: "# 0  Reader Name"
        # or "Detected readers (pcsc)" header lines
        if line.lower().startswith("detected reader"):
            continue
        # Parse reader entries: lines starting with a number or "Nr."
        if line.startswith("Nr."):
            continue
        # Typical format: " 0  Identiv SCR3310v2.0 00 00"
        parts = line.split(None, 1)
        if parts and parts[0].isdigit() and len(parts) > 1:
            reader_name = parts[1].strip()
            readers.append(reader_name)

    if readers:
        return {"detected": True, "count": len(readers), "readers": readers}

    # Fallback: if we got output but couldn't parse reader names
    if stdout and "No smart card readers found" not in stdout:
        return {"detected": True, "count": 1, "readers": ["Unknown Reader"]}

    return {"detected": False, "count": 0, "readers": []}


def _detect_card():
    """Detect smart card presence using opensc-tool.

    Returns dict with card presence information.
    """
    rc, stdout, stderr = _run_cmd(["opensc-tool", "-l"])
    if rc != 0:
        return {"present": False}

    # Look for "Card present" or "Card flags" in output
    for line in stdout.splitlines():
        if "Card present" in line:
            return {"present": True}

    # Try opensc-tool -n for card name/ATR
    rc, stdout, stderr = _run_cmd(["opensc-tool", "-n"])
    if rc == 0 and stdout:
        return {"present": True, "name": stdout.strip()}

    return {"present": False}


def _get_card_info():
    """Extract public card information using pkcs11-tool.

    Only reads public data - never accesses PINs or private keys.
    Returns dict with card details.
    """
    info = {"type": "unknown", "atr": "", "certificates": [], "objects": []}

    # Get ATR
    rc, stdout, _ = _run_cmd(["opensc-tool", "-a"])
    if rc == 0 and stdout:
        info["atr"] = stdout.strip()

    # Get card name
    rc, stdout, _ = _run_cmd(["opensc-tool", "-n"])
    if rc == 0 and stdout:
        info["type"] = stdout.strip()

    # List public objects via pkcs11-tool (no PIN required)
    rc, stdout, _ = _run_cmd(["pkcs11-tool", "--list-objects", "--type", "cert"])
    if rc == 0 and stdout:
        current_cert = {}
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Certificate Object"):
                if current_cert:
                    info["certificates"].append(current_cert)
                current_cert = {"type": "certificate"}
            elif ":" in line and current_cert is not None:
                key, _, value = line.partition(":")
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                current_cert[key] = value
        if current_cert:
            info["certificates"].append(current_cert)

    # List public key objects
    rc, stdout, _ = _run_cmd(["pkcs11-tool", "--list-objects", "--type", "pubkey"])
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Public Key Object"):
                info["objects"].append({"type": "public_key"})

    return info


def _get_certificate_expiry():
    """Check certificate expiry dates from the smart card.

    Uses pkcs15-tool to read certificate info without needing PIN.
    Returns dict with expiry information.
    """
    expiry_info = {"certificates": [], "earliest_expiry": None, "status": "unknown"}

    rc, stdout, _ = _run_cmd(["pkcs15-tool", "--list-certificates"])
    if rc != 0:
        return expiry_info

    certs = []
    current = {}
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("X.509 Certificate"):
            if current:
                certs.append(current)
            current = {}
        elif ":" in line and current is not None:
            key, _, value = line.partition(":")
            current[key.strip()] = value.strip()
    if current:
        certs.append(current)

    expiry_info["certificates"] = certs
    expiry_info["status"] = "ok" if certs else "no_certificates"
    return expiry_info


def _run_quick_test():
    """Run a quick diagnostic test suite.

    Returns dict with test results.
    """
    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tests": [],
        "passed": 0,
        "failed": 0,
        "total": 0,
    }

    # Test 1: pcscd running
    rc, _, _ = _run_cmd(["systemctl", "is-active", "pcscd.socket"])
    pcscd_active = rc == 0
    if not pcscd_active:
        rc, _, _ = _run_cmd(["systemctl", "is-active", "pcscd.service"])
        pcscd_active = rc == 0
    results["tests"].append({
        "name": "pcscd_service",
        "description": "PC/SC daemon is running",
        "passed": pcscd_active,
    })

    # Test 2: Reader detection
    reader_info = _detect_reader()
    reader_found = reader_info.get("detected", False)
    results["tests"].append({
        "name": "reader_detection",
        "description": "Smart card reader detected",
        "passed": reader_found,
        "details": reader_info,
    })

    # Test 3: Card detection (only if reader present)
    if reader_found:
        card_info = _detect_card()
        card_present = card_info.get("present", False)
        results["tests"].append({
            "name": "card_detection",
            "description": "Smart card detected in reader",
            "passed": card_present,
        })

        # Test 4: Card readable (only if card present)
        if card_present:
            info = _get_card_info()
            card_readable = info.get("type", "unknown") != "unknown"
            results["tests"].append({
                "name": "card_readable",
                "description": "Card type identified",
                "passed": card_readable,
                "details": {"type": info.get("type", "unknown")},
            })

    # Test 5: FIPS mode check
    fips_enabled = False
    fips_path = "/proc/sys/crypto/fips_enabled"
    try:
        if os.path.exists(fips_path):
            with open(fips_path) as f:
                fips_enabled = f.read().strip() == "1"
    except OSError:
        pass
    results["tests"].append({
        "name": "fips_mode",
        "description": "FIPS mode status",
        "passed": True,  # Informational, not a pass/fail
        "details": {"fips_enabled": fips_enabled},
    })

    # Tally results
    for test in results["tests"]:
        results["total"] += 1
        if test["passed"]:
            results["passed"] += 1
        else:
            results["failed"] += 1

    return results


class SmartCardMonitorService(dbus.service.Object):
    """D-Bus service for monitoring smart card readers and cards.

    Exposes methods for querying card/reader status and signals
    for real-time event notification. Uses opensc-tool and pkcs11-tool
    for hardware interaction.
    """

    def __init__(self, bus_name):
        super().__init__(bus_name, DBUS_OBJECT_PATH)
        self._reader_present = False
        self._card_present = False
        self._health_status = "unknown"
        self._reader_info = {}
        self._card_info = {}
        log.info("SmartCardMonitorService initialized")

    # ── D-Bus Methods ──

    @dbus.service.method(DBUS_INTERFACE, out_signature="b")
    def ReaderPresent(self):
        """Return whether a smart card reader is connected."""
        return self._reader_present

    @dbus.service.method(DBUS_INTERFACE, out_signature="b")
    def CardPresent(self):
        """Return whether a smart card is inserted."""
        return self._card_present

    @dbus.service.method(DBUS_INTERFACE, out_signature="s")
    def GetCardInfo(self):
        """Return public card information as JSON.

        Only returns public data - no PINs or private keys.
        """
        if not self._card_present:
            return json.dumps({"error": "no_card", "present": False})
        try:
            info = _get_card_info()
            return json.dumps(info)
        except Exception as exc:
            log.error("GetCardInfo failed: %s", exc)
            return json.dumps({"error": str(exc)})

    @dbus.service.method(DBUS_INTERFACE, out_signature="s")
    def GetHealthStatus(self):
        """Return overall health status as JSON.

        Status values:
        - "unknown": No reader detected
        - "healthy": Reader present, card readable
        - "warning": Card present but unreadable, or reader error
        """
        return json.dumps({
            "status": self._health_status,
            "reader_present": self._reader_present,
            "card_present": self._card_present,
            "reader_info": self._reader_info,
        })

    @dbus.service.method(DBUS_INTERFACE, out_signature="s")
    def GetCertificateExpiry(self):
        """Return certificate expiry information as JSON."""
        if not self._card_present:
            return json.dumps({"error": "no_card", "certificates": []})
        try:
            expiry = _get_certificate_expiry()
            return json.dumps(expiry)
        except Exception as exc:
            log.error("GetCertificateExpiry failed: %s", exc)
            return json.dumps({"error": str(exc), "certificates": []})

    @dbus.service.method(DBUS_INTERFACE, out_signature="s")
    def RunQuickTest(self):
        """Run a quick diagnostic test and return results as JSON."""
        try:
            results = _run_quick_test()
            return json.dumps(results)
        except Exception as exc:
            log.error("RunQuickTest failed: %s", exc)
            return json.dumps({"error": str(exc), "tests": []})

    # ── D-Bus Signals ──

    @dbus.service.signal(DBUS_INTERFACE, signature="b")
    def CardInserted(self, present):
        """Emitted when a smart card is inserted."""
        log.info("Signal: CardInserted")

    @dbus.service.signal(DBUS_INTERFACE, signature="b")
    def CardRemoved(self, present):
        """Emitted when a smart card is removed."""
        log.info("Signal: CardRemoved")

    @dbus.service.signal(DBUS_INTERFACE, signature="s")
    def ReaderStatusChanged(self, status):
        """Emitted when reader connection status changes."""
        log.info("Signal: ReaderStatusChanged -> %s", status)

    @dbus.service.signal(DBUS_INTERFACE, signature="s")
    def HealthStatusChanged(self, status):
        """Emitted when overall health status changes."""
        log.info("Signal: HealthStatusChanged -> %s", status)

    # ── Polling Logic ──

    def poll(self):
        """Poll for reader and card status changes.

        Called every POLL_INTERVAL seconds via GLib.timeout_add_seconds().
        Returns True to keep the timeout active.
        """
        old_reader = self._reader_present
        old_card = self._card_present
        old_health = self._health_status

        # Detect reader
        reader_info = _detect_reader()
        self._reader_info = reader_info
        self._reader_present = reader_info.get("detected", False)

        # Detect card (only if reader present)
        if self._reader_present:
            card_info = _detect_card()
            self._card_present = card_info.get("present", False)
        else:
            self._card_present = False

        # Determine health status
        if not self._reader_present:
            self._health_status = "unknown"
        elif self._card_present:
            # Try to read card to confirm it's accessible
            info = _get_card_info()
            if info.get("type", "unknown") != "unknown":
                self._health_status = "healthy"
            else:
                self._health_status = "warning"
        else:
            # Reader present but no card
            self._health_status = "healthy"

        # Emit signals on state changes
        if old_reader != self._reader_present:
            status = "connected" if self._reader_present else "disconnected"
            self.ReaderStatusChanged(status)
            log.info("Reader status changed: %s", status)

        if old_card != self._card_present:
            if self._card_present:
                self.CardInserted(True)
                log.info("Card inserted")
            else:
                self.CardRemoved(False)
                log.info("Card removed")

        if old_health != self._health_status:
            self.HealthStatusChanged(self._health_status)
            log.info("Health status changed: %s -> %s", old_health, self._health_status)

        # Return True to keep the GLib timeout active
        return True


def main():
    """Start the D-Bus smart card monitor service."""
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    session_bus = dbus.SessionBus()
    bus_name = dbus.service.BusName(DBUS_BUS_NAME, session_bus)
    monitor = SmartCardMonitorService(bus_name)

    # Set up polling via GLib main loop
    GLib.timeout_add_seconds(POLL_INTERVAL, monitor.poll)

    # Run initial poll immediately
    monitor.poll()

    loop = GLib.MainLoop()

    def shutdown(signum, _frame):
        signame = signal.Signals(signum).name
        log.info("Received %s, shutting down", signame)
        loop.quit()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    log.info("Smart Card Monitor service started on %s", DBUS_BUS_NAME)
    log.info("Polling every %d seconds", POLL_INTERVAL)

    try:
        loop.run()
    except KeyboardInterrupt:
        log.info("Keyboard interrupt, shutting down")
        loop.quit()

    log.info("Smart Card Monitor service stopped")


if __name__ == "__main__":
    main()
