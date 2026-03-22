import 'dart:async';
import '../models/card_info.dart';
import '../models/health_status.dart';
import 'dbus_client.dart';

class SmartCardService {
  final DBusSmartCardClient _dbusClient;

  /// [client] is optional — production code omits it and gets the real
  /// DBusSmartCardClient.  Tests pass a mock subclass.
  SmartCardService({DBusSmartCardClient? client})
      : _dbusClient = client ?? DBusSmartCardClient();

  // Signal subscriptions — cancelled in dispose()
  StreamSubscription<dynamic>? _insertedSub;
  StreamSubscription<dynamic>? _removedSub;

  // Optional slow health-check timer (30s) — keeps UI in sync if a
  // signal is ever missed.  NOT a replacement for signal-driven updates.
  Timer? _healthTimer;

  Future<void> initialize() async {
    await _dbusClient.connect();
  }

  void startMonitoring(Function(HealthStatus, CardInfo?) callback) {
    // ── Signal-driven updates (instant, zero polling overhead) ──────────
    _insertedSub = _dbusClient.cardInsertedSignal.listen((_) async {
      final info = await _fetchCardInfo();
      callback(
        HealthStatus(
          status: CardStatus.detected,
          readerPresent: true,
          cardPresent: true,
          message: 'Card detected',
        ),
        info,
      );
    });

    _removedSub = _dbusClient.cardRemovedSignal.listen((_) {
      callback(
        HealthStatus(
          status: CardStatus.waiting,
          readerPresent: true,
          cardPresent: false,
          message: 'Waiting for card...',
        ),
        null,
      );
    });

    // ── Slow health-check (30s) — catches missed events / reader unplug ─
    _healthTimer = Timer.periodic(const Duration(seconds: 30), (_) async {
      await _refreshStatus(callback);
    });

    // ── Initial state ────────────────────────────────────────────────────
    _refreshStatus(callback);
  }

  Future<void> _refreshStatus(Function(HealthStatus, CardInfo?) callback) async {
    try {
      final readerPresent = await _dbusClient.isReaderPresent();
      final cardPresent = readerPresent && await _dbusClient.isCardPresent();

      CardStatus status;
      String message;
      CardInfo? info;

      if (!readerPresent) {
        status = CardStatus.waiting;
        message = 'Waiting for reader...';
      } else if (!cardPresent) {
        status = CardStatus.waiting;
        message = 'Waiting for card...';
      } else {
        status = CardStatus.detected;
        message = 'Card detected';
        info = await _fetchCardInfo();
      }

      callback(
        HealthStatus(
          status: status,
          readerPresent: readerPresent,
          cardPresent: cardPresent,
          message: message,
        ),
        info,
      );
    } catch (e) {
      callback(
        HealthStatus(
          status: CardStatus.waiting,
          readerPresent: false,
          cardPresent: false,
          message: 'Monitoring...',
        ),
        null,
      );
    }
  }

  Future<CardInfo?> _fetchCardInfo() async {
    try {
      final cardInfoMap = await _dbusClient.getCardInfo();
      return cardInfoMap.isNotEmpty ? CardInfo.fromMap(cardInfoMap) : null;
    } catch (_) {
      return null;
    }
  }

  Future<DetectionResult> detectCard() async {
    try {
      final readerPresent = await _dbusClient.isReaderPresent();

      if (!readerPresent) {
        return DetectionResult(
          status: CardStatus.error,
          message: 'No reader detected',
          errorDetails: 'Please connect a smart card reader',
        );
      }

      final cardPresent = await _dbusClient.isCardPresent();

      if (!cardPresent) {
        return DetectionResult(
          status: CardStatus.error,
          message: 'No card detected',
          errorDetails: 'Please insert a smart card into the reader',
        );
      }

      final cardInfoMap = await _dbusClient.getCardInfo();

      if (cardInfoMap.isEmpty) {
        return DetectionResult(
          status: CardStatus.error,
          message: 'Unable to read card',
          errorDetails: 'Card may be damaged, locked, or unsupported',
        );
      }

      final info = CardInfo.fromMap(cardInfoMap);

      return DetectionResult(
        status: CardStatus.detected,
        message: 'Card detected successfully',
        info: info,
      );
    } catch (e) {
      return DetectionResult(
        status: CardStatus.error,
        message: 'Detection failed',
        errorDetails: e.toString(),
      );
    }
  }

  void stopMonitoring() {
    _insertedSub?.cancel();
    _removedSub?.cancel();
    _healthTimer?.cancel();
    _insertedSub = null;
    _removedSub = null;
    _healthTimer = null;
  }

  void dispose() {
    stopMonitoring();
    _dbusClient.close();
  }
}

class DetectionResult {
  final CardStatus status;
  final String message;
  final CardInfo? info;
  final String? errorDetails;

  DetectionResult({
    required this.status,
    required this.message,
    this.info,
    this.errorDetails,
  });
}
