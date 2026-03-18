import 'package:flutter/material.dart';

class StatusCard extends StatelessWidget {
  final String title;
  final IconData icon;
  final String status;
  final bool isLoading;
  final Color? statusColor;

  const StatusCard({
    super.key,
    required this.title,
    required this.icon,
    required this.status,
    this.isLoading = false,
    this.statusColor,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Row(
          children: [
            Icon(icon, size: 32, color: Theme.of(context).colorScheme.primary),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title,
                      style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 4),
                  isLoading
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : Text(
                          status,
                          style: TextStyle(color: statusColor),
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
