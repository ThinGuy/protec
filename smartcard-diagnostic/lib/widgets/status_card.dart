import 'package:flutter/material.dart';
import 'package:yaru/yaru.dart';

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
    return YaruBanner(
      padding: const EdgeInsets.all(24.0),
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
