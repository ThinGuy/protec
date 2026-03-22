/// FIPS 140-2/140-3 compliance detector.
///
/// Combines two independent checks:
///   1. Kernel FIPS mode   — /proc/sys/crypto/fips_enabled
///   2. Card FIPS token    — pkcs15-tool --list-keys output flags
///
/// Neither check requires a PIN or private-key access.
library;

import 'dart:io';

// ── Result types ────────────────────────────────────────────────────────────

enum FipsLevel {
  /// Kernel reports FIPS enabled AND card token advertises FIPS capability.
  fips140_2,

  /// Kernel FIPS enabled; card FIPS status indeterminate or not checked.
  kernelOnly,

  /// Card advertises FIPS capability; kernel FIPS mode is off.
  tokenOnly,

  /// Neither kernel FIPS mode nor card FIPS flags detected.
  nonFips,

  /// Detection could not be completed (tools missing, permission error, etc.).
  indeterminate,
}

class FipsDetectionResult {
  final FipsLevel level;
  final bool kernelFipsEnabled;
  final bool cardFipsCapable;
  final String? message;

  const FipsDetectionResult({
    required this.level,
    required this.kernelFipsEnabled,
    required this.cardFipsCapable,
    this.message,
  });

  /// True when both kernel and card are operating in a FIPS mode.
  bool get isFullyFipsCompliant =>
      kernelFipsEnabled && cardFipsCapable;

  @override
  String toString() => 'FipsDetectionResult('
      'level: $level, '
      'kernel: $kernelFipsEnabled, '
      'card: $cardFipsCapable)';
}

// ── FIPS keyword patterns in pkcs15-tool output ──────────────────────────────

/// Tokens that indicate FIPS mode in pkcs15-tool --list-keys output.
const _fipsKeywords = <String>[
  'fips',
  'fips-140',
  'fips140',
];

// ── Detector ────────────────────────────────────────────────────────────────

class FipsDetector {
  /// Path to the kernel FIPS flag — can be overridden in tests.
  final String fipsEnabledPath;

  FipsDetector({this.fipsEnabledPath = '/proc/sys/crypto/fips_enabled'});

  /// Run both kernel and card FIPS checks.
  Future<FipsDetectionResult> detect() async {
    final kernelFips = await _checkKernelFips();
    final cardFips   = await _checkCardFips();

    final level = _computeLevel(kernelFips, cardFips);

    return FipsDetectionResult(
      level: level,
      kernelFipsEnabled: kernelFips,
      cardFipsCapable:   cardFips,
      message: _message(level),
    );
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  Future<bool> _checkKernelFips() async {
    try {
      final file = File(fipsEnabledPath);
      if (!file.existsSync()) return false;
      final content = await file.readAsString();
      return content.trim() == '1';
    } catch (_) {
      return false;
    }
  }

  Future<bool> _checkCardFips() async {
    try {
      final result = await Process.run(
        'pkcs15-tool',
        ['--list-keys'],
        stdoutEncoding: const SystemEncoding(),
        stderrEncoding: const SystemEncoding(),
      );

      if (result.exitCode != 0) return false;

      final output = (result.stdout as String).toLowerCase();
      for (final kw in _fipsKeywords) {
        if (output.contains(kw)) return true;
      }
      return false;
    } catch (_) {
      // pkcs15-tool not found or no card — not an error, just indeterminate
      return false;
    }
  }

  FipsLevel _computeLevel(bool kernel, bool card) {
    if (kernel && card)  return FipsLevel.fips140_2;
    if (kernel && !card) return FipsLevel.kernelOnly;
    if (!kernel && card) return FipsLevel.tokenOnly;
    return FipsLevel.nonFips;
  }

  String _message(FipsLevel level) {
    switch (level) {
      case FipsLevel.fips140_2:
        return 'Kernel FIPS mode enabled; card token reports FIPS capability.';
      case FipsLevel.kernelOnly:
        return 'Kernel FIPS mode enabled; card FIPS capability not confirmed.';
      case FipsLevel.tokenOnly:
        return 'Card token reports FIPS capability; kernel FIPS mode is off.';
      case FipsLevel.nonFips:
        return 'No FIPS indicators detected on kernel or card.';
      case FipsLevel.indeterminate:
        return 'FIPS detection incomplete — check tool availability.';
    }
  }
}
