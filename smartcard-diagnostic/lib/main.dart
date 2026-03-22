import 'package:flutter/material.dart';
import 'package:yaru/yaru.dart';
import 'screens/home_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const SmartCardDiagnosticApp());
}

class SmartCardDiagnosticApp extends StatelessWidget {
  const SmartCardDiagnosticApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return YaruTheme(
      builder: (context, yaru, child) {
        return MaterialApp(
          title: 'Smart Card Diagnostic',
          theme: yaru.theme,
          darkTheme: yaru.darkTheme,
          highContrastTheme: yaruHighContrastLight,
          highContrastDarkTheme: yaruHighContrastDark,
          debugShowCheckedModeBanner: false,
          home: const HomeScreen(),
        );
      },
    );
  }
}
