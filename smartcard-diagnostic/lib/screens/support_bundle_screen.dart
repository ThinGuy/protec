import 'package:flutter/material.dart';

class SupportBundleScreen extends StatelessWidget {
  const SupportBundleScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Support Bundle'),
      ),
      body: const Center(
        child: Text('Support Bundle Screen'),
      ),
    );
  }
}
