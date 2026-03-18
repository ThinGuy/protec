import 'package:flutter/material.dart';
import '../widgets/test_result_widget.dart';

class DiagnosticsScreen extends StatefulWidget {
  const DiagnosticsScreen({super.key});

  @override
  State<DiagnosticsScreen> createState() => _DiagnosticsScreenState();
}

class _DiagnosticsScreenState extends State<DiagnosticsScreen> {
  bool _isRunning = false;

  void _runDiagnostics() {
    setState(() {
      _isRunning = true;
    });
    // TODO: Implement diagnostic test execution via D-Bus service
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Diagnostics'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Smart Card Test Suite',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            Text(
              'Run comprehensive diagnostics on your smart card reader and card.',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: _isRunning ? null : _runDiagnostics,
              icon: _isRunning
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.play_arrow),
              label: Text(_isRunning ? 'Running...' : 'Run All Tests'),
            ),
            const SizedBox(height: 24),
            Expanded(
              child: ListView(
                children: const [
                  TestResultWidget(
                    testName: 'Reader Detection',
                    description: 'Verify smart card reader is connected and recognized',
                  ),
                  TestResultWidget(
                    testName: 'Card Communication',
                    description: 'Test ATR retrieval and basic card communication',
                  ),
                  TestResultWidget(
                    testName: 'PIV Application',
                    description: 'Verify PIV application is present and accessible',
                  ),
                  TestResultWidget(
                    testName: 'Certificate Validation',
                    description: 'Check certificate chain and expiry dates',
                  ),
                  TestResultWidget(
                    testName: 'FIPS Compliance',
                    description: 'Validate FIPS 140-2/140-3 cryptographic module status',
                  ),
                  TestResultWidget(
                    testName: 'PKCS#11 Module',
                    description: 'Verify PKCS#11 module loading and slot detection',
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
