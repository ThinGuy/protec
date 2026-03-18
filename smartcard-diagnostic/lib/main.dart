import 'package:flutter/material.dart';
import 'screens/home_screen.dart';

void main() {
  runApp(const SmartCardDiagnosticApp());
}

class SmartCardDiagnosticApp extends StatelessWidget {
  const SmartCardDiagnosticApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Smart Card Diagnostic',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const HomeScreen(),
    );
  }
}
