enum TestStatus {
  pending,
  running,
  passed,
  warning,
  failed,
}

class TestResult {
  final String name;
  final String description;
  final TestStatus status;
  final String details;
  final DateTime? timestamp;

  TestResult({
    required this.name,
    required this.description,
    required this.status,
    this.details = '',
    this.timestamp,
  });
}
