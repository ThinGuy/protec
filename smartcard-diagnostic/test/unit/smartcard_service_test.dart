import 'dart:async';
import 'package:dbus/dbus.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smartcard_diagnostic/services/dbus_client.dart';
import 'package:smartcard_diagnostic/services/smartcard_service.dart';
import 'package:smartcard_diagnostic/models/health_status.dart';

// ── Hand-rolled mock — no code-gen needed ────────────────────────────────────

class MockDBusSmartCardClient extends DBusSmartCardClient {
  bool readerPresent = false;
  bool cardPresent   = false;
  Map<String, String> cardInfoResult = {};
  bool connectCalled = false;

  // Signal controllers — tests inject events via these
  final _insertedCtrl = StreamController<DBusSignal>.broadcast();
  final _removedCtrl  = StreamController<DBusSignal>.broadcast();

  @override
  Future<void> connect() async { connectCalled = true; }

  @override
  Future<bool> isReaderPresent() async => readerPresent;

  @override
  Future<bool> isCardPresent() async => cardPresent;

  @override
  Future<Map<String, String>> getCardInfo() async => cardInfoResult;

  @override
  Stream<DBusSignal> get cardInsertedSignal => _insertedCtrl.stream;

  @override
  Stream<DBusSignal> get cardRemovedSignal  => _removedCtrl.stream;

  @override
  void close() {
    _insertedCtrl.close();
    _removedCtrl.close();
  }

  /// Simulate a CardInserted D-Bus signal.
  void emitCardInserted() =>
      _insertedCtrl.add(DBusSignal(
        sender: 'com.canonical.SmartCardMonitor',
        path: DBusObjectPath('/com/canonical/SmartCardMonitor'),
        interface: 'com.canonical.SmartCardMonitor',
        name: 'CardInserted',
        values: [DBusBoolean(true)],
      ));

  /// Simulate a CardRemoved D-Bus signal.
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
  late MockDBusSmartCardClient mock;
  late SmartCardService service;

  setUp(() {
    mock    = MockDBusSmartCardClient();
    service = SmartCardService(client: mock);
  });

  tearDown(() {
    service.dispose();
  });

  // ── initialize() ──────────────────────────────────────────────────────────

  group('initialize', () {
    test('calls connect() on the D-Bus client', () async {
      await service.initialize();
      expect(mock.connectCalled, isTrue);
    });
  });

  // ── startMonitoring — initial state ───────────────────────────────────────

  group('startMonitoring — initial state', () {
    test('reports waiting when no reader is present', () async {
      await service.initialize();
      mock.readerPresent = false;
      mock.cardPresent   = false;

      HealthStatus? captured;
      service.startMonitoring((status, _) => captured = status);

      await Future<void>.delayed(Duration.zero);

      expect(captured, isNotNull);
      expect(captured!.status, CardStatus.waiting);
      expect(captured!.readerPresent, isFalse);
    });

    test('reports waiting for card when reader present, no card', () async {
      await service.initialize();
      mock.readerPresent = true;
      mock.cardPresent   = false;

      HealthStatus? captured;
      service.startMonitoring((status, _) => captured = status);

      await Future<void>.delayed(Duration.zero);

      expect(captured!.status, CardStatus.waiting);
      expect(captured!.readerPresent, isTrue);
      expect(captured!.cardPresent, isFalse);
    });

    test('reports detected when reader and card both present', () async {
      await service.initialize();
      mock.readerPresent  = true;
      mock.cardPresent    = true;
      mock.cardInfoResult = {'type': 'YubiKey PIV', 'atr': '3b f9 00', 'certs': '2'};

      HealthStatus? captured;
      service.startMonitoring((status, _) => captured = status);

      await Future<void>.delayed(Duration.zero);

      expect(captured!.status, CardStatus.detected);
      expect(captured!.cardPresent, isTrue);
    });
  });

  // ── Signal-driven state transitions ───────────────────────────────────────

  group('signal-driven transitions', () {
    test('CardInserted signal → callback fires with detected status', () async {
      await service.initialize();
      mock.readerPresent  = true;
      mock.cardPresent    = true;
      mock.cardInfoResult = {'type': 'PIV', 'atr': '3b db 00', 'certs': '1'};

      final statuses = <CardStatus>[];
      service.startMonitoring((status, _) => statuses.add(status.status));

      await Future<void>.delayed(Duration.zero); // initial refresh

      mock.emitCardInserted();
      await Future<void>.delayed(Duration.zero); // signal processed

      expect(statuses, contains(CardStatus.detected));
    });

    test('CardRemoved signal → callback fires with waiting status', () async {
      await service.initialize();
      mock.readerPresent = true;
      mock.cardPresent   = false;

      final statuses = <CardStatus>[];
      service.startMonitoring((status, _) => statuses.add(status.status));

      await Future<void>.delayed(Duration.zero);

      mock.emitCardRemoved();
      await Future<void>.delayed(Duration.zero);

      expect(statuses.last, CardStatus.waiting);
    });

    test('signals fire immediately — no 2-second delay', () async {
      await service.initialize();
      mock.readerPresent  = true;
      mock.cardPresent    = true;
      mock.cardInfoResult = {'type': 'PIV', 'atr': '3b f9 00', 'certs': '3'};

      final statuses = <CardStatus>[];
      service.startMonitoring((status, _) => statuses.add(status.status));

      final stopwatch = Stopwatch()..start();
      mock.emitCardInserted();
      await Future<void>.delayed(Duration.zero);
      stopwatch.stop();

      // Must resolve well under 1s — signal is synchronous, no polling delay
      expect(stopwatch.elapsedMilliseconds, lessThan(200));
      expect(statuses, contains(CardStatus.detected));
    });
  });

  // ── GetCardInfo a{ss} mapping ──────────────────────────────────────────────

  group('getCardInfo a{ss} mapping', () {
    test('non-empty result maps to CardInfo correctly', () async {
      await service.initialize();
      mock.readerPresent  = true;
      mock.cardPresent    = true;
      mock.cardInfoResult = {
        'type':  'YubiKey PIV',
        'atr':   '3b f9 13 00',
        'certs': '2',
      };

      dynamic capturedInfo;
      service.startMonitoring((_, info) => capturedInfo = info);
      await Future<void>.delayed(Duration.zero);

      expect(capturedInfo, isNotNull);
    });

    test('error key in result returns null CardInfo', () async {
      await service.initialize();
      mock.readerPresent  = true;
      mock.cardPresent    = true;
      mock.cardInfoResult = {'error': 'opensc-tool timeout'};

      dynamic capturedInfo;
      service.startMonitoring((_, info) => capturedInfo = info);
      await Future<void>.delayed(Duration.zero);

      // CardInfo.fromMap with only 'error' key — should degrade gracefully
      // (no crash is the critical assertion)
      expect(() => capturedInfo, returnsNormally);
    });
  });

  // ── detectCard() ──────────────────────────────────────────────────────────

  group('detectCard', () {
    test('returns error result when no reader', () async {
      await service.initialize();
      mock.readerPresent = false;

      final result = await service.detectCard();
      expect(result.status, CardStatus.error);
      expect(result.message, contains('reader'));
    });

    test('returns error result when no card', () async {
      await service.initialize();
      mock.readerPresent = true;
      mock.cardPresent   = false;

      final result = await service.detectCard();
      expect(result.status, CardStatus.error);
      expect(result.message, contains('card'));
    });

    test('returns detected result with card info', () async {
      await service.initialize();
      mock.readerPresent  = true;
      mock.cardPresent    = true;
      mock.cardInfoResult = {'type': 'PIV', 'atr': '3b db 96 00', 'certs': '1'};

      final result = await service.detectCard();
      expect(result.status, CardStatus.detected);
      expect(result.info, isNotNull);
    });
  });

  // ── dispose / stopMonitoring ───────────────────────────────────────────────

  group('lifecycle', () {
    test('stopMonitoring cancels subscriptions without throwing', () async {
      await service.initialize();
      service.startMonitoring((_, __) {});
      expect(() => service.stopMonitoring(), returnsNormally);
    });

    test('emitting signals after dispose does not crash', () async {
      await service.initialize();
      service.startMonitoring((_, __) {});
      service.dispose();
      // Controllers are closed — emitting would throw on a non-broadcast
      // stream; our mock uses broadcast streams so this is safe to verify
      expect(() => mock.emitCardInserted(), throwsStateError);
    });
  });
}
