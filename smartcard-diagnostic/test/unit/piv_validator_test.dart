import 'package:flutter_test/flutter_test.dart';
import 'package:smartcard_diagnostic/services/dbus_client.dart';
import 'package:smartcard_diagnostic/services/piv_validator.dart';

// ── Minimal mock ──────────────────────────────────────────────────────────────

class MockDBusClientForPiv extends DBusSmartCardClient {
  Map<String, String> response = {};

  @override
  Future<void> connect() async {}

  @override
  Future<Map<String, String>> getCardInfo() async => response;

  @override
  void close() {}
}

// ── Tests ──────────────────────────────────────────────────────────────────────

void main() {
  late MockDBusClientForPiv mock;
  late PivValidator validator;

  setUp(() {
    mock      = MockDBusClientForPiv();
    validator = PivValidator(client: mock);
  });

  tearDown(() => validator.close());

  group('PivValidator — type keyword matching', () {
    for (final entry in {
      'YubiKey 5 NFC (PIV)':         true,
      'Personal Identity Verification': true,
      'CAC (Common Access Card)':     true,
      'Gemalto IDPrime MD':           true,
      'Mifare DESFire EV1':           false,
      'EMV Visa Credit':              false,
      'Unknown':                      false,
    }.entries) {
      test('type="${entry.key}" → isPiv=${entry.value}', () async {
        mock.response = {'type': entry.key, 'atr': ''};
        final result = await validator.validate();
        expect(result.isPiv, entry.value,
            reason: 'Expected isPiv=${entry.value} for type "${entry.key}"');
      });
    }
  });

  group('PivValidator — ATR prefix matching', () {
    for (final entry in {
      '3b db 96 00 80 1f 03 00 31 c0 64 00': true,   // CAC/PIV family
      '3b f9 13 00 00 81 31 fe 45 59 75 62': true,   // YubiKey 5 PIV
      '3b 7d 11 00 00 31 80 71 8e 64 86 d6': true,   // Gemalto IDPrime
      '3b 9f 96 81 31 fe 45 00 00':          false,  // non-PIV
      '3f 6f 00 00 00 00 00':                false,  // generic ISO
      '':                                    false,
    }.entries) {
      test('atr prefix "${entry.key.split(' ').take(2).join(' ')}" → isPiv=${entry.value}', () async {
        mock.response = {'type': '', 'atr': entry.key};
        final result = await validator.validate();
        expect(result.isPiv, entry.value,
            reason: 'ATR "${entry.key}"');
      });
    }
  });

  group('PivValidator — edge cases', () {
    test('empty map → noCard status', () async {
      mock.response = {};
      final result = await validator.validate();
      expect(result.status, PivStatus.noCard);
    });

    test('error key in map → error status', () async {
      mock.response = {'error': 'GetCardInfo failed: timeout'};
      final result = await validator.validate();
      expect(result.status, PivStatus.error);
    });

    test('type and atr both empty → unknown status', () async {
      mock.response = {'type': '', 'atr': '', 'certs': '0'};
      final result = await validator.validate();
      expect(result.status, PivStatus.unknown);
    });

    test('non-PIV card → invalid status', () async {
      mock.response = {'type': 'EMV Visa', 'atr': '3f 6f 00', 'certs': '0'};
      final result = await validator.validate();
      expect(result.status, PivStatus.invalid);
    });

    test('result carries cardType and atr on success', () async {
      mock.response = {'type': 'YubiKey PIV', 'atr': '3b f9 00', 'certs': '2'};
      final result = await validator.validate();
      expect(result.cardType, 'YubiKey PIV');
      expect(result.atr, '3b f9 00');
    });
  });
}
