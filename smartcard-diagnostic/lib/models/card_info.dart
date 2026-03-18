class CardInfo {
  final String label;
  final String manufacturer;
  final String model;
  final String serial;
  final String certificateSubject;
  final String certificateExpiry;

  CardInfo({
    required this.label,
    required this.manufacturer,
    required this.model,
    required this.serial,
    this.certificateSubject = '',
    this.certificateExpiry = '',
  });

  factory CardInfo.fromMap(Map<String, String> map) {
    return CardInfo(
      label: map['label'] ?? 'Unknown',
      manufacturer: map['manufacturer'] ?? 'Unknown',
      model: map['model'] ?? 'Unknown',
      serial: map['serial'] ?? 'Unknown',
      certificateSubject: map['certificate_subject'] ?? '',
      certificateExpiry: map['certificate_expiry'] ?? '',
    );
  }

  Map<String, String> toMap() {
    return {
      'label': label,
      'manufacturer': manufacturer,
      'model': model,
      'serial': serial,
      'certificate_subject': certificateSubject,
      'certificate_expiry': certificateExpiry,
    };
  }
}
