import 'package:flutter/material.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _autoRefresh = true;
  int _refreshInterval = 2;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: ListView(
        children: [
          const _SectionHeader(title: 'Monitoring'),
          SwitchListTile(
            title: const Text('Auto-refresh'),
            subtitle: const Text('Automatically poll for reader and card changes'),
            value: _autoRefresh,
            onChanged: (value) {
              setState(() {
                _autoRefresh = value;
              });
            },
          ),
          ListTile(
            title: const Text('Refresh interval'),
            subtitle: Text('$_refreshInterval seconds'),
            trailing: DropdownButton<int>(
              value: _refreshInterval,
              items: const [
                DropdownMenuItem(value: 1, child: Text('1s')),
                DropdownMenuItem(value: 2, child: Text('2s')),
                DropdownMenuItem(value: 5, child: Text('5s')),
                DropdownMenuItem(value: 10, child: Text('10s')),
              ],
              onChanged: (value) {
                if (value != null) {
                  setState(() {
                    _refreshInterval = value;
                  });
                }
              },
            ),
          ),
          const Divider(),
          const _SectionHeader(title: 'About'),
          const ListTile(
            title: Text('Smart Card Diagnostic Tool'),
            subtitle: Text('Version 0.1.0'),
          ),
          const ListTile(
            title: Text('License'),
            subtitle: Text('GNU General Public License v3.0'),
          ),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  final String title;
  const _SectionHeader({required this.title});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      child: Text(
        title,
        style: Theme.of(context).textTheme.titleSmall?.copyWith(
              color: Theme.of(context).colorScheme.primary,
            ),
      ),
    );
  }
}
