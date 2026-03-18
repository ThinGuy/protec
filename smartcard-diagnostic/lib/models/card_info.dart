/// Represents information about an inserted smart card.
class CardInfo {
  final String atr;
  final String? cardName;
  final CardType cardType;
  final bool hasPivApplication;
  final List<String> certificates;

  CardInfo({
    required this.atr,
    this.cardName,
    this.cardType = CardType.unknown,
    this.hasPivApplication = false,
    this.certificates = const [],
  });

  factory CardInfo.fromJson(Map<String, dynamic> json) {
    return CardInfo(
      atr: json['atr'] as String? ?? '',
      cardName: json['card_name'] as String?,
      hasPivApplication: json['has_piv'] as bool? ?? false,
    );
  }
}

enum CardType {
  piv,
  pivI,
  enterprise,
  unknown,
}
