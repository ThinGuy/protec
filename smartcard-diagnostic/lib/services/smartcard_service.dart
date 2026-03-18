/// Service layer for smart card operations.
///
/// Provides a unified API for the Flutter UI to interact with
/// smart card readers and cards via the D-Bus monitoring daemon.
class SmartCardService {
  SmartCardService._();
  static final instance = SmartCardService._();

  /// Check if a smart card reader is connected.
  Future<ReaderStatus> getReaderStatus() async {
    // TODO: Implement via D-Bus client
    return ReaderStatus(detected: false, readerCount: 0, readers: []);
  }

  /// Check if a smart card is inserted.
  Future<CardStatus> getCardStatus() async {
    // TODO: Implement via D-Bus client
    return CardStatus(inserted: false);
  }

  /// Run the full diagnostic test suite.
  Future<List<DiagnosticResult>> runDiagnostics() async {
    // TODO: Implement via D-Bus client
    return [];
  }

  /// Generate a support bundle.
  Future<String> generateSupportBundle(String outputPath) async {
    // TODO: Implement via D-Bus client
    return '';
  }
}

class ReaderStatus {
  final bool detected;
  final int readerCount;
  final List<String> readers;

  ReaderStatus({
    required this.detected,
    required this.readerCount,
    required this.readers,
  });
}

class CardStatus {
  final bool inserted;
  final String? atr;
  final String? cardName;

  CardStatus({
    required this.inserted,
    this.atr,
    this.cardName,
  });
}

class DiagnosticResult {
  final String testName;
  final bool passed;
  final String message;

  DiagnosticResult({
    required this.testName,
    required this.passed,
    required this.message,
  });
}
