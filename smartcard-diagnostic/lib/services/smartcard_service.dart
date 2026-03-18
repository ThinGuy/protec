import 'dart:async';
import '../models/card_info.dart';
import '../models/health_status.dart';
import 'dbus_client.dart';

class SmartCardService {
  final DBusSmartCardClient _dbusClient = DBusSmartCardClient();
  Timer? _pollTimer;

  Future<void> initialize() async {
    await _dbusClient.connect();
  }

  void startMonitoring(Function(HealthStatus, CardInfo?) callback) {
    _pollTimer = Timer.periodic(const Duration(seconds: 2), (timer) async {
      try {
        final readerPresent = await _dbusClient.isReaderPresent();
        final cardPresent = await _dbusClient.isCardPresent();

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
          final cardInfoMap = await _dbusClient.getCardInfo();
          info = CardInfo.fromMap(cardInfoMap);
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
    });
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
    _pollTimer?.cancel();
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
