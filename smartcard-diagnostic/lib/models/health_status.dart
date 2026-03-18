/// Overall health status of the smart card environment.
class HealthStatus {
  final bool readerDetected;
  final bool cardInserted;
  final bool pivApplicationPresent;
  final bool fipsCompliant;
  final bool certificatesValid;
  final DateTime lastChecked;

  HealthStatus({
    required this.readerDetected,
    required this.cardInserted,
    required this.pivApplicationPresent,
    required this.fipsCompliant,
    required this.certificatesValid,
    DateTime? lastChecked,
  }) : lastChecked = lastChecked ?? DateTime.now();

  HealthLevel get level {
    if (!readerDetected) return HealthLevel.error;
    if (!cardInserted) return HealthLevel.warning;
    if (!pivApplicationPresent || !certificatesValid) return HealthLevel.warning;
    if (!fipsCompliant) return HealthLevel.info;
    return HealthLevel.good;
  }

  String get summary {
    switch (level) {
      case HealthLevel.good:
        return 'All systems operational';
      case HealthLevel.info:
        return 'Functional with recommendations';
      case HealthLevel.warning:
        return 'Attention required';
      case HealthLevel.error:
        return 'Reader or card not detected';
    }
  }
}

enum HealthLevel {
  good,
  info,
  warning,
  error,
}
