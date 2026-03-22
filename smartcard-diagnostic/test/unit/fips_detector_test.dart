import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:smartcard_diagnostic/services/fips_detector.dart';

// ── Tests ──────────────────────────────────────────────────────────────────────
//
// FipsDetector._checkKernelFips() reads a file path that we can redirect
// in tests by passing fipsEnabledPath to the constructor.
//
// FipsDetector._checkCardFips() calls pkcs15-tool.  On the CI / build
// host there is no smart card, so the Process.run() call will either
// fail to find the binary or return a non-zero exit code.  Both outcomes
// result in cardFipsCapable=false, which is the correct safe default.
// We therefore only directly exercise the kernel-flag branch here.

void main() {
  late Directory tempDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('fips_test_');
  });

  tearDown(() {
    tempDir.deleteSync(recursive: true);
  });

  // ── Kernel FIPS flag ───────────────────────────────────────────────────────

  group('kernel FIPS flag', () {
    test('kernelFipsEnabled=true when file contains "1"', () async {
      final f = File('${tempDir.path}/fips_enabled')..writeAsStringSync('1\n');
      final detector = FipsDetector(fipsEnabledPath: f.path);
      final result = await detector.detect();
      expect(result.kernelFipsEnabled, isTrue);
    });

    test('kernelFipsEnabled=false when file contains "0"', () async {
      final f = File('${tempDir.path}/fips_enabled')..writeAsStringSync('0\n');
      final detector = FipsDetector(fipsEnabledPath: f.path);
      final result = await detector.detect();
      expect(result.kernelFipsEnabled, isFalse);
    });

    test('kernelFipsEnabled=false when file does not exist', () async {
      final detector = FipsDetector(
          fipsEnabledPath: '${tempDir.path}/nonexistent');
      final result = await detector.detect();
      expect(result.kernelFipsEnabled, isFalse);
    });

    test('kernelFipsEnabled=false when file is empty', () async {
      final f = File('${tempDir.path}/fips_enabled')..writeAsStringSync('');
      final detector = FipsDetector(fipsEnabledPath: f.path);
      final result = await detector.detect();
      expect(result.kernelFipsEnabled, isFalse);
    });
  });

  // ── Level computation ──────────────────────────────────────────────────────

  group('level computation (kernel=false, card varies)', () {
    // On the test host pkcs15-tool is absent → cardFipsCapable=false always.
    // We can still verify the nonFips path deterministically.
    test('level is nonFips when kernel off and no card tool', () async {
      final f = File('${tempDir.path}/fips_enabled')..writeAsStringSync('0');
      final detector = FipsDetector(fipsEnabledPath: f.path);
      final result = await detector.detect();
      // cardFipsCapable may be false (no tool on test host)
      if (!result.cardFipsCapable) {
        expect(result.level, FipsLevel.nonFips);
      }
    });

    test('level is kernelOnly when kernel on and no card tool', () async {
      final f = File('${tempDir.path}/fips_enabled')..writeAsStringSync('1');
      final detector = FipsDetector(fipsEnabledPath: f.path);
      final result = await detector.detect();
      if (!result.cardFipsCapable) {
        expect(result.level, FipsLevel.kernelOnly);
      }
    });
  });

  // ── isFullyFipsCompliant ───────────────────────────────────────────────────

  group('isFullyFipsCompliant', () {
    test('false when kernel is off', () async {
      final f = File('${tempDir.path}/fips_enabled')..writeAsStringSync('0');
      final detector = FipsDetector(fipsEnabledPath: f.path);
      final result = await detector.detect();
      if (!result.cardFipsCapable) {
        expect(result.isFullyFipsCompliant, isFalse);
      }
    });
  });
}
