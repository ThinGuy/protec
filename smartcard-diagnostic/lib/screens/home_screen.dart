import 'package:flutter/material.dart';
import '../widgets/status_card.dart';
import '../widgets/card_info_display.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Smart Card Diagnostic'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: const SingleChildScrollView(
        padding: EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            StatusCard(
              title: 'Reader Status',
              icon: Icons.usb,
              status: 'Checking...',
              isLoading: true,
            ),
            SizedBox(height: 16),
            StatusCard(
              title: 'Card Status',
              icon: Icons.credit_card,
              status: 'Checking...',
              isLoading: true,
            ),
            SizedBox(height: 16),
            StatusCard(
              title: 'FIPS Compliance',
              icon: Icons.security,
              status: 'Checking...',
              isLoading: true,
            ),
            SizedBox(height: 24),
            CardInfoDisplay(),
          ],
        ),
      ),
    );
  }
}
