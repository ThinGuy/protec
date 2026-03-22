import 'package:flutter/material.dart';

class StatusCard extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String message;
  final bool isAnimated;

  const StatusCard({
    Key? key,
    required this.icon,
    required this.color,
    required this.message,
    this.isAnimated = false,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(24.0),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          isAnimated
              ? SizedBox(
                  width: 64,
                  height: 64,
                  child: CircularProgressIndicator(
                    strokeWidth: 6,
                    color: color,
                  ),
                )
              : Icon(
                  icon,
                  size: 64,
                  color: color,
                ),
          const SizedBox(height: 16),
          Text(
            message,
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              color: color,
              fontWeight: FontWeight.w500,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}
