import 'package:flutter/material.dart';

enum TestState { pending, running, passed, failed }

class TestResultWidget extends StatelessWidget {
  final String testName;
  final String description;
  final TestState state;
  final String? detail;

  const TestResultWidget({
    super.key,
    required this.testName,
    required this.description,
    this.state = TestState.pending,
    this.detail,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        leading: _buildIcon(),
        title: Text(testName),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(description),
            if (detail != null) ...[
              const SizedBox(height: 4),
              Text(
                detail!,
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildIcon() {
    switch (state) {
      case TestState.pending:
        return const Icon(Icons.circle_outlined, color: Colors.grey);
      case TestState.running:
        return const SizedBox(
          width: 24,
          height: 24,
          child: CircularProgressIndicator(strokeWidth: 2),
        );
      case TestState.passed:
        return const Icon(Icons.check_circle, color: Colors.green);
      case TestState.failed:
        return const Icon(Icons.error, color: Colors.red);
    }
  }
}
