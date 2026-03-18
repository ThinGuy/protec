/// Represents the result of a single diagnostic test.
class TestResult {
  final String testId;
  final String testName;
  final TestOutcome outcome;
  final String message;
  final Duration duration;
  final DateTime timestamp;

  TestResult({
    required this.testId,
    required this.testName,
    required this.outcome,
    required this.message,
    required this.duration,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  bool get passed => outcome == TestOutcome.passed;
}

enum TestOutcome {
  passed,
  failed,
  skipped,
  error,
}
