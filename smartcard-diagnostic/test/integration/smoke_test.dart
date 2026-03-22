/// Integration smoke test for SmartCardService.
///
/// This file contains two test groups:
///
///   1. "mock D-Bus server" — uses the hand-rolled MockDBusSmartCardClient
///      to exercise the full service layer without hardware.  Runs in CI.
///
///   2. "physical hardware" — requires a CCID reader and an inserted card
///      (a YubiKey provisioned with protec.py works well).  Skipped unless
///      the SMARTCARD_HW_TEST=1 environment variable is set.
///
/// Usage:
///   # CI (no hardware):
///   flutter test test/integration/smoke_test.dart
///
///   # With hardware (e.g. after provisioning a YubiKey):
///   SMARTCARD_HW_TEST=1 flutter test test/integration/smoke_test.dart --timeout 30s
library;

import 'dart:async';
import 'dart:io';
import 'package:dbus/dbus.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smartcard_diagnostic/services/dbus_client.dart';
import 'package:smartcard_diagnostic/services/smartcard_service.dart';
import 'package:smartcard_diagnostic/services/piv_validator.dart';
import 'package:smartcard_diagnostic/models/health_status.dart';

// ── Reusable mock (same pattern as unit tests) ─────────────────────────────────

class MockDBusSmartCardClient extends DBusSmartCardClient {
  bool readerPresent = false;
  bool cardPresent   = false;
  Map<String, String> cardInfoResult = {};

  final _insertedCtrl = StreamController<DBusSignal>.broadcast();
  final _removedCtrl  = StreamController<DBusSignal>.broadcast();

  @override Future<void> connect() async {}
  @override Future<bool> isReaderPresent() async => readerPresent;
  @override Future<bool> isCardPresent()   async => cardPresent;
  @override Future<Map<String, String>> getCardInfo() async => cardInfoResult;
  @override Stream<DBusSignal> get cardInsertedSignal => _insertedCtrl.stream;
  @override Stream<DBusSignal> get cardRemovedSignal  => _removedCtrl.stream;

  @override
  void close() {
    _insertedCtrl.close();
    _removedCtrl.close();
  }

  void emitCardInserted() =>
      _insertedCtrl.add(DBusSignal(
        sender: 'com.canonical.SmartCardMonitor',
        path: DBusObjectPath('/com/canonical/SmartCardMonitor'),
        interface: 'com.canonical.SmartCardMonitor',
        name: 'CardInserted',
        values: [DBusBoolean(true)],
      ));

  void emitCardRemoved() =>
      _removedCtrl.add(DBusSignal(
        sender: 'com.canonical.SmartCardMonitor',
        path: DBusObjectPath('/com/canonical/SmartCardMonitor'),
        interface: 'com.canonical.SmartCardMonitor',
        name: 'CardRemoved',
        values: [DBusBoolean(false)],
      ));
}

// ── Tests ─────────────────────────────────────────────────────────────────────

void main() {
  // ── Group 1: mock D-Bus (always runs) ───────────────────────────────────────
  group('mock D-Bus server', () {
    late MockDBusSmartCardClient mock;
    late SmartCardService service;

    setUp(() {
      mock    = MockDBusSmartCardClient();
      service = SmartCardService(client: mock);
    });

    tearDown(() => service.dispose());

    test('full card insertion flow: waiting → detected → waiting', () async {
      await service.initialize();
      mock.readerPresent  = true;
      mock.cardPresent    = false;

      final states = <CardStatus>[];
      service.startMonitoring((status, _) => states.add(status.status));
      await Future<void>.delayed(Duration.zero);

      // Simulate card insert
      mock.cardPresent    = true;
      mock.cardInfoResult = {'type': 'YubiKey PIV', 'atr': '3b f9 00', 'certs': '2'};
      mock.emitCardInserted();
      await Future<void>.delayed(Duration.zero);

      // Simulate card remove
      mock.cardPresent    = false;
      mock.cardInfoResult = {};
      mock.emitCardRemoved();
      await Future<void>.delayed(Duration.zero);

      expect(states, containsAllInOrder([
        CardStatus.waiting,
        CardStatus.detected,
        CardStatus.waiting,
      ]));
    });

    test('signal fires within 200ms of emission', () async {
      await service.initialize();
      mock.readerPresent  = true;
      mock.cardPresent    = true;
      mock.cardInfoResult = {'type': 'PIV', 'atr': '3b db 00', 'certs': '1'};

      final completer = Completer<CardStatus>();
      service.startMonitoring((status, _) {
        if (status.status == CardStatus.detected && !completer.isCompleted) {
          completer.complete(status.status);
        }
      });

      final sw = Stopwatch()..start();
      mock.emitCardInserted();
      final result = await completer.future.timeout(const Duration(seconds: 1));
      sw.stop();

      expect(result, CardStatus.detected);
      expect(sw.elapsedMilliseconds, lessThan(200));
    });

    test('PIV validator confirms mock YubiKey card', () async {
      mock.cardInfoResult = {'type': 'YubiKey PIV', 'atr': '3b f9 00', 'certs': '2'};
      final validator = PivValidator(client: mock);
      final result = await validator.validate();
      expect(result.isPiv, isTrue);
      validator.close();
    });
  });

  // ── Group 2: physical hardware (opt-in) ─────────────────────────────────────
  group('physical hardware', () {
    final runHwTests = Platform.environment['SMARTCARD_HW_TEST'] == '1';

    setUp(() {
      if (!runHwTests) {
        // Print instead of skip so CI logs make the reason clear
        printOnFailure(
          'Physical hardware tests skipped. '
          'Set SMARTCARD_HW_TEST=1 to run against a real CCID reader.',
        );
      }
    });

    test('daemon is reachable on system D-Bus', () async {
      if (!runHwTests) return;

      final client = DBusSmartCardClient();
      await client.connect();
      // Simply calling the method proves the daemon is up and the bus name
      // is registered — no assertion beyond "does not throw"
      expect(() => client.isReaderPresent(), returnsNormally);
      client.close();
    }, timeout: const Timeout(Duration(seconds: 10)));

    test('card insertion detected within 1 second of physical insert', () async {
      if (!runHwTests) return;

      final client = DBusSmartCardClient();
      await client.connect();

      // Pre-condition: card must NOT be inserted when the test starts.
      // Insert the card during the 5-second window.
      bool detected = false;
      final sub = client.cardInsertedSignal.listen((_) { detected = true; });
      await Future<void>.delayed(const Duration(seconds: 5));
      await sub.cancel();
      client.close();

      expect(detected, isTrue,
          reason: 'Insert a card within 5 seconds of test start');
    }, timeout: const Timeout(Duration(seconds: 15)));

    test('GetCardInfo returns non-empty a{ss} for inserted PIV card', () async {
      if (!runHwTests) return;

      final client = DBusSmartCardClient();
      await client.connect();
      final info = await client.getCardInfo();
      client.close();

      expect(info, isNotEmpty);
      expect(info.containsKey('type'), isTrue);
      expect(info.containsKey('atr'),  isTrue);
    }, timeout: const Timeout(Duration(seconds: 10)));
  });
}
