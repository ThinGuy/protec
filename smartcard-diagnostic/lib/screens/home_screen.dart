import 'package:flutter/material.dart';
import '../models/card_info.dart';
import '../models/health_status.dart';
import '../services/smartcard_service.dart';
import '../widgets/status_card.dart';
import '../widgets/card_info_display.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({Key? key}) : super(key: key);

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final SmartCardService _service = SmartCardService();

  CardStatus _status = CardStatus.waiting;
  CardInfo? _cardInfo;
  String _message = 'Waiting for card...';
  String _errorDetails = '';
  bool _isDetecting = false;

  @override
  void initState() {
    super.initState();
    _initializeService();
  }

  Future<void> _initializeService() async {
    await _service.initialize();
    _service.startMonitoring(_onStatusChanged);
  }

  void _onStatusChanged(HealthStatus health, CardInfo? info) {
    if (!_isDetecting) {
      setState(() {
        _status = health.status;
        _cardInfo = info;
        _message = health.message;
      });
    }
  }

  Future<void> _detectCard() async {
    setState(() {
      _isDetecting = true;
      _status = CardStatus.detecting;
      _message = 'Detecting card...';
      _errorDetails = '';
    });

    final result = await _service.detectCard();

    setState(() {
      _status = result.status;
      _cardInfo = result.info;
      _message = result.message;
      _errorDetails = result.errorDetails ?? '';
      _isDetecting = false;
    });
  }

  @override
  void dispose() {
    _service.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Smart Card Diagnostic'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            onPressed: () {},
            tooltip: 'Settings',
          ),
        ],
      ),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 600),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                _buildStatusDisplay(),
                const SizedBox(height: 32),
                if (_status == CardStatus.waiting || _status == CardStatus.error)
                  _buildInsertCardButton(),
                if (_status == CardStatus.detected && _cardInfo != null)
                  CardInfoDisplay(cardInfo: _cardInfo!),
                if (_status == CardStatus.error)
                  _buildErrorDisplay(),
                const SizedBox(height: 48),
                _buildActionButtons(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildStatusDisplay() {
    IconData icon;
    Color color;
    String displayMessage;
    bool animated = false;

    switch (_status) {
      case CardStatus.waiting:
        icon = Icons.info_outline;
        color = const Color(0xFF757575);
        displayMessage = _message;
        break;
      case CardStatus.detecting:
        icon = Icons.sync;
        color = Colors.blue;
        displayMessage = _message;
        animated = true;
        break;
      case CardStatus.detected:
        icon = Icons.check_circle_outline;
        color = const Color(0xFF0E8420);
        displayMessage = _message;
        break;
      case CardStatus.error:
        icon = Icons.error_outline;
        color = const Color(0xFFC7162B);
        displayMessage = _message;
        break;
    }

    return StatusCard(
      icon: icon,
      color: color,
      message: displayMessage,
      isAnimated: animated,
    );
  }

  Widget _buildInsertCardButton() {
    return ElevatedButton.icon(
      onPressed: _isDetecting ? null : _detectCard,
      icon: _isDetecting
          ? const SizedBox(
              width: 20,
              height: 20,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.credit_card_outlined),
      label: Text(_isDetecting ? 'Detecting...' : 'Insert Card'),
      style: ElevatedButton.styleFrom(
        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
      ),
    );
  }

  Widget _buildErrorDisplay() {
    const errorColor = Color(0xFFC7162B);
    return Container(
      padding: const EdgeInsets.all(16.0),
      decoration: BoxDecoration(
        color: const Color(0xFFFADBD8),
        border: Border.all(color: errorColor.withOpacity(0.4)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.error_outline, color: errorColor),
              const SizedBox(width: 8),
              Text(
                'Error Details',
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  color: errorColor,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            _errorDetails.isEmpty ? 'Unknown error' : _errorDetails,
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 12),
          Text(
            'Possible causes:',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 4),
          ...['Card not fully inserted',
            'Reader malfunction',
            'Card locked (too many PIN attempts)',
            'Unsupported card type',
          ].map((text) => Padding(
            padding: const EdgeInsets.only(left: 8.0, bottom: 2.0),
            child: Text(
              '\u2022 $text',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          )),
          const SizedBox(height: 16),
          Wrap(
            spacing: 8,
            children: [
              TextButton.icon(
                onPressed: _detectCard,
                icon: const Icon(Icons.refresh),
                label: const Text('Retry'),
              ),
              TextButton.icon(
                onPressed: () {},
                icon: const Icon(Icons.folder_open_outlined),
                label: const Text('View Logs'),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildActionButtons() {
    return Wrap(
      spacing: 16,
      runSpacing: 16,
      alignment: WrapAlignment.center,
      children: [
        OutlinedButton.icon(
          onPressed: () {},
          icon: const Icon(Icons.search),
          label: const Text('Run Full Diagnostics'),
        ),
        OutlinedButton.icon(
          onPressed: () {},
          icon: const Icon(Icons.save_alt),
          label: const Text('Generate Support Bundle'),
        ),
      ],
    );
  }
}
