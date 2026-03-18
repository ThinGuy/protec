enum CardStatus {
  waiting,      // Gray - waiting for user to click Insert Card
  detecting,    // Blue - actively detecting
  detected,     // Green - card found and working
  error,        // Red - detection failed after user tried
}

class HealthStatus {
  final CardStatus status;
  final bool readerPresent;
  final bool cardPresent;
  final String message;
  final String? errorDetails;

  HealthStatus({
    required this.status,
    required this.readerPresent,
    required this.cardPresent,
    required this.message,
    this.errorDetails,
  });
}
