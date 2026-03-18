import 'package:flutter/material.dart';

void main() {
  runApp(const SmartCardDiagnosticApp());
}

class SmartCardDiagnosticApp extends StatelessWidget {
  const SmartCardDiagnosticApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Smart Card Diagnostic',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFFE95420), // Ubuntu orange
        ),
        useMaterial3: true,
      ),
      home: const DiagnosticHomePage(),
    );
  }
}

class DiagnosticHomePage extends StatefulWidget {
  const DiagnosticHomePage({super.key});

  @override
  State<DiagnosticHomePage> createState() => _DiagnosticHomePageState();
}

class _DiagnosticHomePageState extends State<DiagnosticHomePage> {
  int _selectedIndex = 0;

  static const List<String> _pageTitles = [
    'Reader Status',
    'Card Info',
    'FIPS Validation',
    'Certificate Bundle',
    'Monitor',
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_pageTitles[_selectedIndex]),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Center(
        child: Text(
          '${_pageTitles[_selectedIndex]} - Coming Soon',
          style: Theme.of(context).textTheme.headlineMedium,
        ),
      ),
      navigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (int index) {
          setState(() {
            _selectedIndex = index;
          });
        },
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.usb),
            label: 'Reader',
          ),
          NavigationDestination(
            icon: Icon(Icons.credit_card),
            label: 'Card',
          ),
          NavigationDestination(
            icon: Icon(Icons.verified_user),
            label: 'FIPS',
          ),
          NavigationDestination(
            icon: Icon(Icons.folder_zip),
            label: 'Bundle',
          ),
          NavigationDestination(
            icon: Icon(Icons.monitor_heart),
            label: 'Monitor',
          ),
        ],
      ),
    );
  }
}
