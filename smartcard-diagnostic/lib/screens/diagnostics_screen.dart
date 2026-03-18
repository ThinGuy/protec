import 'package:flutter/material.dart';

class DiagnosticsScreen extends StatelessWidget {
  const DiagnosticsScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Diagnostics'),
      ),
      body: const Center(
        child: Text('Diagnostics Screen'),
      ),
    );
  }
}
