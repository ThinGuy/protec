import 'package:flutter/material.dart';
import '../widgets/progress_indicator.dart' as app_progress;

class SupportBundleScreen extends StatefulWidget {
  const SupportBundleScreen({super.key});

  @override
  State<SupportBundleScreen> createState() => _SupportBundleScreenState();
}

class _SupportBundleScreenState extends State<SupportBundleScreen> {
  bool _isGenerating = false;
  String? _bundlePath;

  void _generateBundle() {
    setState(() {
      _isGenerating = true;
      _bundlePath = null;
    });
    // TODO: Implement bundle generation via D-Bus service
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Support Bundle'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Generate Support Bundle',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            Text(
              'Create a diagnostic bundle for support analysis. '
              'The bundle contains system information, reader status, and card '
              'diagnostics. No sensitive data (PINs, passwords, or private keys) '
              'is included.',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 8),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Row(
                  children: [
                    Icon(Icons.privacy_tip,
                        color: Theme.of(context).colorScheme.primary),
                    const SizedBox(width: 12),
                    const Expanded(
                      child: Text(
                        'Privacy: Bundle contents are shown for review before saving. '
                        'No data is transmitted automatically.',
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            if (_isGenerating) const app_progress.BundleProgressIndicator(),
            if (_bundlePath != null)
              Card(
                color: Theme.of(context).colorScheme.primaryContainer,
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('Bundle saved to:'),
                      const SizedBox(height: 4),
                      SelectableText(
                        _bundlePath!,
                        style: const TextStyle(fontFamily: 'monospace'),
                      ),
                    ],
                  ),
                ),
              ),
            const Spacer(),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: _isGenerating ? null : _generateBundle,
                icon: _isGenerating
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.folder_zip),
                label: Text(
                    _isGenerating ? 'Generating...' : 'Generate Bundle'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
