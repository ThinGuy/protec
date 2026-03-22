import 'package:dbus/dbus.dart';

class DBusSmartCardClient {
  final DBusClient _systemBus = DBusClient.system();
  DBusRemoteObject? _remoteObject;

  static const String busName = 'com.canonical.SmartCardMonitor';
  static const String objectPath = '/com/canonical/SmartCardMonitor';
  static const String interface = 'com.canonical.SmartCardMonitor';

  Future<void> connect() async {
    _remoteObject = DBusRemoteObject(
      _systemBus,
      name: busName,
      path: DBusObjectPath(objectPath),
    );
  }

  Future<bool> isReaderPresent() async {
    final result = await _remoteObject!.callMethod(
      interface,
      'ReaderPresent',
      [],
      replySignature: DBusSignature('b'),
    );
    return result.returnValues[0].asBoolean();
  }

  Future<bool> isCardPresent() async {
    final result = await _remoteObject!.callMethod(
      interface,
      'CardPresent',
      [],
      replySignature: DBusSignature('b'),
    );
    return result.returnValues[0].asBoolean();
  }

  /// Returns a flat string dict (a{ss}) with keys: type, atr, certs.
  /// For full nested card data use getCardInfoJson().
  Future<Map<String, String>> getCardInfo() async {
    final result = await _remoteObject!.callMethod(
      interface,
      'GetCardInfo',
      [],
      replySignature: DBusSignature('a{ss}'),
    );

    final dbusDict = result.returnValues[0].asStringVariantDict();
    return dbusDict.map((key, value) => MapEntry(key, value.asString()));
  }

  /// Returns full card information as a JSON string.
  Future<String> getCardInfoJson() async {
    final result = await _remoteObject!.callMethod(
      interface,
      'GetCardInfoJson',
      [],
      replySignature: DBusSignature('s'),
    );
    return result.returnValues[0].asString();
  }

  Future<String> getHealthStatus() async {
    final result = await _remoteObject!.callMethod(
      interface,
      'GetHealthStatus',
      [],
      replySignature: DBusSignature('s'),
    );
    return result.returnValues[0].asString();
  }

  Future<String> getCertificateExpiry() async {
    final result = await _remoteObject!.callMethod(
      interface,
      'GetCertificateExpiry',
      [],
      replySignature: DBusSignature('s'),
    );
    return result.returnValues[0].asString();
  }

  Stream<DBusSignal> get cardInsertedSignal {
    return DBusSignalStream(
      _systemBus,
      sender: busName,
      path: DBusObjectPath(objectPath),
      interface: interface,
      name: 'CardInserted',
    );
  }

  Stream<DBusSignal> get cardRemovedSignal {
    return DBusSignalStream(
      _systemBus,
      sender: busName,
      path: DBusObjectPath(objectPath),
      interface: interface,
      name: 'CardRemoved',
    );
  }

  void close() {
    _systemBus.close();
  }
}
