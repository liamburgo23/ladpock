import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const storage = FlutterSecureStorage();

Future<void> saveToken(String token) async {
  await storage.write(key: 'auth_token', value: token);
}
