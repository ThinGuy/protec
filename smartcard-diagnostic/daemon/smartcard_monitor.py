#!/usr/bin/env python3
"""Smart Card Monitor D-Bus Service.

Monitors smart card reader and card events, exposing status
information over D-Bus for the Flutter GUI application.

Designed for government and enterprise PKI deployments.
Supports PIV and other standard smart card types.
"""

import signal
import sys
import threading
import time
from typing import Optional

# D-Bus interface name
DBUS_INTERFACE = "com.canonical.SmartCardMonitor"
DBUS_PATH = "/com/canonical/SmartCardMonitor"

try:
    from pydbus import SessionBus
    from pydbus.generic import signal as dbus_signal
    from gi.repository import GLib
except ImportError:
    print("Error: pydbus and PyGObject are required.", file=sys.stderr)
    print("Install with: pip install pydbus PyGObject", file=sys.stderr)
    sys.exit(1)

try:
    from smartcard.System import readers
    from smartcard.Exceptions import NoReadersException
    HAS_PYSCARD = True
except ImportError:
    HAS_PYSCARD = False
    print("Warning: pyscard not available. Using stub detection.", file=sys.stderr)


class SmartCardMonitor:
    """D-Bus service for monitoring smart card readers and cards."""

    dbus = f"""
    <node>
      <interface name='{DBUS_INTERFACE}'>
        <method name='GetReaderStatus'>
          <arg type='s' name='response' direction='out'/>
        </method>
        <method name='GetCardStatus'>
          <arg type='s' name='response' direction='out'/>
        </method>
        <method name='Refresh'>
          <arg type='b' name='success' direction='out'/>
        </method>
        <signal name='ReaderChanged'>
          <arg type='s' name='status'/>
        </signal>
        <signal name='CardChanged'>
          <arg type='s' name='status'/>
        </signal>
      </interface>
    </node>
    """

    ReaderChanged = dbus_signal()
    CardChanged = dbus_signal()

    def __init__(self):
        self._reader_status: str = "unknown"
        self._card_status: str = "unknown"
        self._running = True

    def GetReaderStatus(self) -> str:
        """Return current reader status as JSON string."""
        return self._reader_status

    def GetCardStatus(self) -> str:
        """Return current card status as JSON string."""
        return self._card_status

    def Refresh(self) -> bool:
        """Force a status refresh."""
        self._update_status()
        return True

    def _update_status(self):
        """Poll for reader and card status changes."""
        old_reader = self._reader_status
        old_card = self._card_status

        if HAS_PYSCARD:
            try:
                reader_list = readers()
                if reader_list:
                    self._reader_status = (
                        f'{{"detected": true, "count": {len(reader_list)}, '
                        f'"readers": {[str(r) for r in reader_list]}}}'
                    )
                    # Try to connect to first reader
                    try:
                        connection = reader_list[0].createConnection()
                        connection.connect()
                        atr = connection.getATR()
                        atr_hex = " ".join(f"{b:02X}" for b in atr)
                        self._card_status = f'{{"inserted": true, "atr": "{atr_hex}"}}'
                        connection.disconnect()
                    except Exception:
                        self._card_status = '{"inserted": false}'
                else:
                    self._reader_status = '{"detected": false, "count": 0, "readers": []}'
                    self._card_status = '{"inserted": false}'
            except NoReadersException:
                self._reader_status = '{"detected": false, "count": 0, "readers": []}'
                self._card_status = '{"inserted": false}'
        else:
            self._reader_status = '{"detected": false, "error": "pyscard not installed"}'
            self._card_status = '{"inserted": false, "error": "pyscard not installed"}'

        if old_reader != self._reader_status:
            self.ReaderChanged(self._reader_status)
        if old_card != self._card_status:
            self.CardChanged(self._card_status)

    def run_monitor(self, interval: float = 2.0):
        """Run the polling loop in a background thread."""
        def poll():
            while self._running:
                self._update_status()
                time.sleep(interval)
        thread = threading.Thread(target=poll, daemon=True)
        thread.start()

    def stop(self):
        """Stop the monitor."""
        self._running = False


def main():
    """Start the D-Bus smart card monitor service."""
    monitor = SmartCardMonitor()

    loop = GLib.MainLoop()
    bus = SessionBus()
    bus.publish(DBUS_INTERFACE, monitor)

    monitor.run_monitor()

    def shutdown(signum, frame):
        monitor.stop()
        loop.quit()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print(f"Smart Card Monitor service started on {DBUS_INTERFACE}")
    try:
        loop.run()
    except KeyboardInterrupt:
        monitor.stop()
        loop.quit()


if __name__ == "__main__":
    main()
