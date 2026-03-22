import 'package:flutter/material.dart';
import '../models/card_info.dart';

class CardInfoDisplay extends StatelessWidget {
  final CardInfo cardInfo;

  const CardInfoDisplay({
    Key? key,
    required this.cardInfo,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    const successColor = Color(0xFF0E8420);
    return Container(
      padding: const EdgeInsets.all(16.0),
      decoration: BoxDecoration(
        color: const Color(0xFFD5F5E3),
        border: Border.all(color: successColor.withOpacity(0.4)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.check_circle_outline, color: successColor),
              const SizedBox(width: 8),
              Text(
                'Card Information',
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  color: successColor,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          _buildInfoRow(context, 'Label', cardInfo.label),
          _buildInfoRow(context, 'Manufacturer', cardInfo.manufacturer),
          _buildInfoRow(context, 'Model', cardInfo.model),
          if (cardInfo.serial.isNotEmpty)
            _buildInfoRow(context, 'Serial', cardInfo.serial),
          if (cardInfo.certificateSubject.isNotEmpty)
            _buildInfoRow(context, 'Certificate', cardInfo.certificateSubject),
          if (cardInfo.certificateExpiry.isNotEmpty)
            _buildInfoRow(context, 'Expires', cardInfo.certificateExpiry),
        ],
      ),
    );
  }

  Widget _buildInfoRow(BuildContext context, String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              '$label:',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
          ),
        ],
      ),
    );
  }
}
