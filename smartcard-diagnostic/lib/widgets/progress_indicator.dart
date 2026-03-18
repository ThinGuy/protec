import 'package:flutter/material.dart';

class BundleProgressIndicator extends StatelessWidget {
  const BundleProgressIndicator({super.key});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Generating Bundle...',
                style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 12),
            const LinearProgressIndicator(),
            const SizedBox(height: 12),
            const _StepItem(label: 'Collecting system information'),
            const _StepItem(label: 'Reading reader status'),
            const _StepItem(label: 'Reading card information'),
            const _StepItem(label: 'Checking FIPS status'),
            const _StepItem(label: 'Listing installed packages'),
            const _StepItem(label: 'Creating archive'),
          ],
        ),
      ),
    );
  }
}

class _StepItem extends StatelessWidget {
  final String label;
  const _StepItem({required this.label});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2.0),
      child: Row(
        children: [
          const SizedBox(
            width: 16,
            height: 16,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
          const SizedBox(width: 8),
          Text(label, style: Theme.of(context).textTheme.bodySmall),
        ],
      ),
    );
  }
}
