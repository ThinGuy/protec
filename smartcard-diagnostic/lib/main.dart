import 'package:flutter/material.dart';
import 'screens/home_screen.dart';

// Canonical brand colors
const _canonicalOrange  = Color(0xFFE95420);
const _canonicalAubergine = Color(0xFF772953);

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const SmartCardDiagnosticApp());
}

class SmartCardDiagnosticApp extends StatelessWidget {
  const SmartCardDiagnosticApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Smart Card Diagnostic',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: _canonicalOrange,
          primary: _canonicalOrange,
          secondary: _canonicalAubergine,
        ),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: _canonicalOrange,
          primary: _canonicalOrange,
          secondary: _canonicalAubergine,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      debugShowCheckedModeBanner: false,
      home: const HomeScreen(),
    );
  }
}
