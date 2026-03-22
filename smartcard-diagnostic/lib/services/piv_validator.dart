/// PIV application and certificate validator.
///
/// Validates a smart card against the NIST SP 800-73 PIV standard by
/// examining the card type string and ATR returned by the D-Bus daemon's
/// GetCardInfo() method.  No PIN or private-key access is required.
library;

import 'dbus_client.dart';

// ── Result types ────────────────────────────────────────────────────────────

enum PivStatus {
  /// Card is a conformant PIV credential.
  valid,

  /// Card is present but does not appear to be PIV.
  invalid,

  /// Card is present but type/ATR could not be determined.
  unknown,

  /// No card is inserted.
  noCard,

  /// D-Bus call failed.
  error,
}

class PivValidationResult {
  final PivStatus status;
  final String? cardType;
  final String? atr;
  final String? message;

  const PivValidationResult({
    required this.status,
    this.cardType,
    this.atr,
    this.message,
  });

  bool get isPiv => status == PivStatus.valid;

  @override
  String toString() =>
      'PivValidationResult(status: $status, type: $cardType, atr: $atr)';
}

// ── Known PIV identifiers ───────────────────────────────────────────────────

/// Substrings found in opensc-tool -n output for known PIV card types.
const _pivTypeKeywords = <String>[
  'piv',
  'personal identity verification',
  'yubikey',   // YubiKey ships a PIV applet
  'nitrokey',  // Nitrokey 3 PIV
  'gemalto',   // Gemalto IDPrime PIV
  'identiv',   // Identiv PIV
  'ueid',      // DoD UEID cards
  'cac',       // Common Access Card (PIV-compatible)
];

/// Known PIV ATR prefixes (hex, lower-case, space-separated bytes).
/// ATRs for NIST SP 800-73 cards begin with 3B or 3F followed by
/// specific historical bytes.  This list covers the most common
/// government-issued and commercial PIV tokens.
const _pivAtrPrefixes = <String>[
  '3b db',  // NIST reference PIV / CAC family
  '3b 7d',  // Gemalto IDPrime
  '3b f9',  // Yubico YubiKey 5 PIV
  '3b fc',  // Identiv SCR PIV
  '3b 8c',  // Nitrokey 3 PIV
];

// ── Validator ───────────────────────────────────────────────────────────────

class PivValidator {
  final DBusSmartCardClient _client;

  PivValidator({DBusSmartCardClient? client})
      : _client = client ?? DBusSmartCardClient();

  /// Connect the underlying D-Bus client.  Call once before [validate].
  Future<void> connect() => _client.connect();

  /// Validate the currently inserted card.
  ///
  /// Calls GetCardInfo() (a{ss}) and checks the returned [type] and [atr]
  /// fields against known PIV identifiers.  No PIN is required.
  Future<PivValidationResult> validate() async {
    try {
      final info = await _client.getCardInfo();

      if (info.isEmpty) {
        return const PivValidationResult(
          status: PivStatus.noCard,
          message: 'No card inserted or daemon returned empty info.',
        );
      }

      if (info.containsKey('error')) {
        return PivValidationResult(
          status: PivStatus.error,
          message: info['error'],
        );
      }

      final cardType = info['type'] ?? '';
      final atr      = info['atr']  ?? '';

      if (_isPiv(cardType, atr)) {
        return PivValidationResult(
          status: PivStatus.valid,
          cardType: cardType,
          atr: atr,
          message: 'Card identified as PIV-compatible.',
        );
      }

      if (cardType.isEmpty && atr.isEmpty) {
        return PivValidationResult(
          status: PivStatus.unknown,
          cardType: cardType,
          atr: atr,
          message:
              'Card type and ATR unavailable — cannot determine PIV status.',
        );
      }

      return PivValidationResult(
        status: PivStatus.invalid,
        cardType: cardType,
        atr: atr,
        message: 'Card does not match known PIV type or ATR patterns.',
      );
    } catch (e) {
      return PivValidationResult(
        status: PivStatus.error,
        message: 'D-Bus call failed: $e',
      );
    }
  }

  void close() => _client.close();
}

// ── Private helpers ─────────────────────────────────────────────────────────

bool _isPiv(String cardType, String atr) {
  final typeLower = cardType.toLowerCase();
  final atrLower  = atr.toLowerCase();

  for (final kw in _pivTypeKeywords) {
    if (typeLower.contains(kw)) return true;
  }
  for (final prefix in _pivAtrPrefixes) {
    if (atrLower.startsWith(prefix)) return true;
  }

  return false;
}
