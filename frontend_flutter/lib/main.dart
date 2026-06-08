import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

void main() {
  runApp(const SololaApp());
}

/// Application principale : thème, couleur personnalisable et mode sombre.
class SololaApp extends StatefulWidget {
  const SololaApp({super.key});

  @override
  State<SololaApp> createState() => _SololaAppState();
}

class _SololaAppState extends State<SololaApp> {
  Color seedColor = const Color(0xFF2563EB);
  bool darkMode = false;

  @override
  void initState() {
    super.initState();
    restoreTheme();
  }

  Future<void> restoreTheme() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      seedColor = Color(prefs.getInt('solola_theme_color') ?? 0xFF2563EB);
      darkMode = prefs.getBool('solola_dark_mode') ?? false;
    });
  }

  Future<void> changeColor(Color color) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt('solola_theme_color', color.value);
    setState(() => seedColor = color);
  }

  Future<void> changeDarkMode(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('solola_dark_mode', value);
    setState(() => darkMode = value);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Solola',
      debugShowCheckedModeBanner: false,
      themeMode: darkMode ? ThemeMode.dark : ThemeMode.light,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: seedColor),
        scaffoldBackgroundColor: const Color(0xFFF3F7FF),
        cardTheme: const CardThemeData(elevation: 0),
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: seedColor, brightness: Brightness.dark),
      ),
      home: RootPage(
        darkMode: darkMode,
        onDarkModeChanged: changeDarkMode,
        onColorChanged: changeColor,
      ),
    );
  }
}

/// Client HTTP pour communiquer avec le backend FastAPI.
class ApiClient {
  String baseUrl;
  String? token;

  ApiClient({required this.baseUrl, required this.token});

  Uri uri(String path) => Uri.parse('$baseUrl$path');

  Map<String, String> headers({bool json = true}) {
    return {
      if (json) 'Content-Type': 'application/json',
      if (token != null) 'Authorization': 'Bearer $token',
    };
  }

  String websocketUrl() {
    return '${baseUrl.replaceFirst('http://', 'ws://').replaceFirst('https://', 'wss://')}/ws?token=${Uri.encodeComponent(token ?? '')}';
  }

  String fileUrl(dynamic path) {
    final value = '${path ?? ''}';
    if (value.isEmpty) return '';
    if (value.startsWith('http')) return value;
    return '$baseUrl$value';
  }

  Future<dynamic> get(String path) async {
    return decode(await http.get(uri(path), headers: headers(json: false)));
  }

  Future<dynamic> post(String path, Map<String, dynamic> body) async {
    return decode(await http.post(uri(path), headers: headers(), body: jsonEncode(body)));
  }

  Future<dynamic> patch(String path, Map<String, dynamic> body) async {
    return decode(await http.patch(uri(path), headers: headers(), body: jsonEncode(body)));
  }

  Future<dynamic> delete(String path) async {
    return decode(await http.delete(uri(path), headers: headers(json: false)));
  }

  Future<dynamic> upload(String path, PlatformFile file, {Map<String, String>? fields}) async {
    final request = http.MultipartRequest('POST', uri(path));

    if (token != null) {
      request.headers['Authorization'] = 'Bearer $token';
    }

    request.fields.addAll(fields ?? {});

    if (file.bytes != null) {
      request.files.add(http.MultipartFile.fromBytes('upload', file.bytes!, filename: file.name));
    } else if (file.path != null) {
      request.files.add(await http.MultipartFile.fromPath('upload', file.path!, filename: file.name));
    } else {
      throw Exception('Fichier invalide.');
    }

    return decode(await http.Response.fromStream(await request.send()));
  }

  dynamic decode(http.Response response) {
    dynamic data;
    try {
      data = response.body.isEmpty ? null : jsonDecode(response.body);
    } catch (_) {
      data = response.body;
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final detail = data is Map ? data['detail'] : data;
      throw Exception(friendlyError('$detail', response.statusCode));
    }

    return data;
  }

  String friendlyError(String message, int statusCode) {
    if (statusCode == 401) return 'Session expirée ou accès refusé.';
    if (statusCode == 403) return 'Action refusée : droits insuffisants.';
    if (statusCode == 404) return 'Élément introuvable.';
    if (statusCode == 413) return 'Fichier trop lourd.';
    if (message.contains('XMLHttpRequest') ||
        message.contains('Connection') ||
        message.contains('Failed host lookup') ||
        message.contains('SocketException')) {
      return 'Impossible de joindre le backend. Vérifie que FastAPI tourne sur http://localhost:8000 et que tu utilises le bon dossier backend.';
    }
    return message.isEmpty ? 'Erreur HTTP $statusCode' : message;
  }
}

/// Chiffrement local avec PIN : AES-GCM + PBKDF2.
/// Le PIN n'est jamais envoyé au backend.
class PinCrypto {
  static final Pbkdf2 _pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 200000,
    bits: 256,
  );

  static final AesGcm _aes = AesGcm.with256bits();

  static Uint8List randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(List<int>.generate(length, (_) => random.nextInt(256)));
  }

  static Future<Map<String, dynamic>> encryptText({
    required String clearText,
    required String pin,
    required String hint,
    required String mode,
  }) async {
    final salt = randomBytes(16);
    final nonce = randomBytes(12);

    final key = await _pbkdf2.deriveKey(
      secretKey: SecretKey(utf8.encode(pin)),
      nonce: salt,
    );

    final secretBox = await _aes.encrypt(
      utf8.encode(clearText),
      secretKey: key,
      nonce: nonce,
    );

    final payload = <int>[...secretBox.cipherText, ...secretBox.mac.bytes];

    return {
      'encrypted': true,
      'mode': mode,
      'algorithm': 'AES-GCM',
      'kdf': 'PBKDF2',
      'iterations': 200000,
      'hint': hint,
      'salt': base64Encode(salt),
      'iv': base64Encode(nonce),
      'ciphertext': base64Encode(payload),
    };
  }

  static Future<String> decryptText({
    required Map<String, dynamic> payload,
    required String pin,
  }) async {
    final salt = base64Decode('${payload['salt']}');
    final nonce = base64Decode('${payload['iv']}');
    final encrypted = base64Decode('${payload['ciphertext']}');

    if (encrypted.length < 17) {
      throw Exception('Message chiffré invalide.');
    }

    final cipherText = encrypted.sublist(0, encrypted.length - 16);
    final macBytes = encrypted.sublist(encrypted.length - 16);

    final key = await _pbkdf2.deriveKey(
      secretKey: SecretKey(utf8.encode(pin)),
      nonce: salt,
    );

    final clearBytes = await _aes.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(macBytes)),
      secretKey: key,
    );

    return utf8.decode(clearBytes);
  }
}

enum AppSection {
  chats,
  status,
  groups,
  secure,
  settings,
  help,
}

/// Page racine : restaure la session, affiche login ou application.
class RootPage extends StatefulWidget {
  final bool darkMode;
  final Future<void> Function(bool) onDarkModeChanged;
  final Future<void> Function(Color) onColorChanged;

  const RootPage({
    super.key,
    required this.darkMode,
    required this.onDarkModeChanged,
    required this.onColorChanged,
  });

  @override
  State<RootPage> createState() => _RootPageState();
}

class _RootPageState extends State<RootPage> {
  late ApiClient api;
  Map<String, dynamic>? user;
  String logoUrl = '';
  bool loading = true;

  @override
  void initState() {
    super.initState();
    restoreSession();
  }

  Future<void> restoreSession() async {
    final prefs = await SharedPreferences.getInstance();
    final apiUrl = prefs.getString('solola_api_url') ?? 'http://localhost:8000';
    final token = prefs.getString('solola_token');
    final userJson = prefs.getString('solola_user');
    logoUrl = prefs.getString('solola_logo_url') ?? '';

    api = ApiClient(baseUrl: apiUrl, token: token);

    if (userJson != null && token != null) {
      user = Map<String, dynamic>.from(jsonDecode(userJson));
    }

    setState(() => loading = false);
  }

  Future<void> setApiUrl(String value) async {
    final prefs = await SharedPreferences.getInstance();
    final clean = value.trim().isEmpty ? 'http://localhost:8000' : value.trim();
    await prefs.setString('solola_api_url', clean);
    api.baseUrl = clean;
  }

  Future<void> setLogoUrl(String value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('solola_logo_url', value.trim());
    setState(() => logoUrl = value.trim());
  }

  Future<void> setAuthenticatedUser(String token, Map<String, dynamic> nextUser) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('solola_token', token);
    await prefs.setString('solola_user', jsonEncode(nextUser));

    api.token = token;
    setState(() => user = nextUser);
  }

  Future<void> updateUser(Map<String, dynamic> nextUser) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('solola_user', jsonEncode(nextUser));
    setState(() => user = nextUser);
  }

  Future<void> logout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('solola_token');
    await prefs.remove('solola_user');

    api.token = null;
    setState(() => user = null);
  }

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    if (user == null) {
      return AuthPage(
        api: api,
        logoUrl: logoUrl,
        onLogoChanged: setLogoUrl,
        onApiChanged: setApiUrl,
        onAuthenticated: setAuthenticatedUser,
      );
    }

    return HomePage(
      api: api,
      user: user!,
      logoUrl: logoUrl,
      onLogoChanged: setLogoUrl,
      updateUser: updateUser,
      logout: logout,
      darkMode: widget.darkMode,
      onDarkModeChanged: widget.onDarkModeChanged,
      onColorChanged: widget.onColorChanged,
      onApiChanged: setApiUrl,
    );
  }
}

/// Logo réutilisable de Solola.
/// Il utilise l'asset local `assets/images/solola_logo.png`.
class SololaLogo extends StatelessWidget {
  final String logoUrl;
  final double size;
  final bool showText;

  const SololaLogo({
    super.key,
    required this.logoUrl,
    this.size = 64,
    this.showText = false,
  });

  @override
  Widget build(BuildContext context) {
    final logo = Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(size * 0.22),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF2563EB).withOpacity(0.28),
            blurRadius: 26,
            offset: const Offset(0, 12),
          ),
        ],
      ),
      clipBehavior: Clip.antiAlias,
      child: logoUrl.trim().isNotEmpty
          ? Image.network(
              logoUrl.trim(),
              fit: BoxFit.cover,
              errorBuilder: (_, __, ___) => Image.asset('assets/images/solola_logo.png', fit: BoxFit.cover),
            )
          : Image.asset('assets/images/solola_logo.png', fit: BoxFit.cover),
    );

    if (!showText) return logo;

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        logo,
        const SizedBox(height: 16),
        const Text(
          'SOLOLA',
          style: TextStyle(
            fontSize: 42,
            fontWeight: FontWeight.w900,
            letterSpacing: 2.5,
            color: Colors.white,
          ),
        ),
        const SizedBox(height: 6),
        const Text(
          'COMMUNIQUER • CONNECTER • PARTAGER',
          textAlign: TextAlign.center,
          style: TextStyle(
            fontSize: 12,
            letterSpacing: 2.0,
            fontWeight: FontWeight.w800,
            color: Color(0xFFEAF4FF),
          ),
        ),
      ],
    );
  }
}

/// Page de connexion / inscription OTP gratuite.
class AuthPage extends StatefulWidget {
  final ApiClient api;
  final String logoUrl;
  final Future<void> Function(String) onLogoChanged;
  final Future<void> Function(String) onApiChanged;
  final Future<void> Function(String, Map<String, dynamic>) onAuthenticated;

  const AuthPage({
    super.key,
    required this.api,
    required this.logoUrl,
    required this.onLogoChanged,
    required this.onApiChanged,
    required this.onAuthenticated,
  });

  @override
  State<AuthPage> createState() => _AuthPageState();
}

class _AuthPageState extends State<AuthPage> {
  final phoneCtrl = TextEditingController();
  final codeCtrl = TextEditingController();
  final pseudoCtrl = TextEditingController();

  bool codeSent = false;
  bool isNewUser = false;
  bool busy = false;
  String demoCode = '';
  String? error;

  @override
  void dispose() {
    phoneCtrl.dispose();
    codeCtrl.dispose();
    pseudoCtrl.dispose();
    super.dispose();
  }

  Future<void> requestCode() async {
    setState(() {
      busy = true;
      error = null;
    });

    try {
      final phone = phoneCtrl.text.trim();
      if (phone.isEmpty) throw Exception('Entre ton numéro de téléphone.');

      await widget.onApiChanged(widget.api.baseUrl);

      final data = await widget.api.post('/auth/otp/start', {
        'phone_number': phone,
      });

      setState(() {
        codeSent = true;
        isNewUser = data['is_new_user'] == true;
        demoCode = '${data['dev_code'] ?? ''}';
      });
    } catch (e) {
      setState(() => error = '$e'.replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> verifyCode() async {
    setState(() {
      busy = true;
      error = null;
    });

    try {
      final phone = phoneCtrl.text.trim();
      final code = codeCtrl.text.trim();

      if (phone.isEmpty || code.isEmpty) {
        throw Exception('Numéro et code obligatoires.');
      }

      if (isNewUser && pseudoCtrl.text.trim().isEmpty) {
        throw Exception('Entre ton nom de profil.');
      }

      final data = await widget.api.post('/auth/otp/verify', {
        'phone_number': phone,
        'code': code,
        'pseudo': pseudoCtrl.text.trim(),
      });

      await widget.onAuthenticated(
        '${data['access_token']}',
        Map<String, dynamic>.from(data['user']),
      );
    } catch (e) {
      setState(() => error = '$e'.replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  void changeNumber() {
    setState(() {
      codeSent = false;
      isNewUser = false;
      demoCode = '';
      error = null;
      codeCtrl.clear();
    });
  }

  @override
  Widget build(BuildContext context) {
    final title = codeSent ? 'Vérifie ton numéro' : 'Bienvenue sur Solola';
    final subtitle = codeSent
        ? 'Entre le code de vérification pour continuer.'
        : 'Entre ton numéro pour créer ou ouvrir ton compte.';

    return Scaffold(
      body: Container(
        width: double.infinity,
        height: double.infinity,
        decoration: const BoxDecoration(
          gradient: RadialGradient(
            center: Alignment(-0.62, -0.55),
            radius: 1.35,
            colors: [
              Color(0xFF043448),
              Color(0xFF061126),
              Color(0xFF160B34),
              Color(0xFF070817),
            ],
            stops: [0.0, 0.34, 0.68, 1.0],
          ),
        ),
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(22),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 580),
              child: Container(
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(34),
                  border: Border.all(color: Colors.white.withOpacity(0.16)),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withOpacity(0.30),
                      blurRadius: 52,
                      offset: const Offset(0, 26),
                    ),
                  ],
                ),
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(34, 36, 34, 30),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Center(child: SololaLogo(logoUrl: widget.logoUrl, size: 138, showText: true)),
                      const SizedBox(height: 28),
                      Text(
                        title,
                        textAlign: TextAlign.center,
                        style: const TextStyle(fontSize: 30, fontWeight: FontWeight.w900, color: Colors.white),
                      ),
                      const SizedBox(height: 10),
                      Text(
                        subtitle,
                        textAlign: TextAlign.center,
                        style: const TextStyle(color: Color(0xFFD7E5F7), fontSize: 16, height: 1.35),
                      ),
                      const SizedBox(height: 28),
                      if (!codeSent) ...[
                        _DarkInput(
                          controller: phoneCtrl,
                          label: 'Numéro de téléphone',
                          icon: Icons.phone_outlined,
                          keyboardType: TextInputType.phone,
                        ),
                        const SizedBox(height: 16),
                        _PrimaryGradientButton(
                          text: 'Continuer',
                          loading: busy,
                          onPressed: busy ? null : requestCode,
                        ),
                      ] else ...[
                        Align(
                          alignment: Alignment.centerLeft,
                          child: TextButton.icon(
                            onPressed: busy ? null : changeNumber,
                            icon: const Icon(Icons.arrow_back, color: Color(0xFF80DFFF)),
                            label: Text(phoneCtrl.text.trim(), style: const TextStyle(color: Color(0xFF80DFFF), fontWeight: FontWeight.w800)),
                          ),
                        ),
                        if (isNewUser)
                          _DarkInput(controller: pseudoCtrl, label: 'Nom de profil', icon: Icons.person_outline),
                        const SizedBox(height: 12),
                        _DarkInput(
                          controller: codeCtrl,
                          label: 'Code de vérification',
                          icon: Icons.verified_user_outlined,
                          keyboardType: TextInputType.number,
                        ),
                        if (demoCode.isNotEmpty) ...[
                          const SizedBox(height: 14),
                          Container(
                            padding: const EdgeInsets.all(14),
                            decoration: BoxDecoration(
                              gradient: const LinearGradient(colors: [Color(0x3322D3EE), Color(0x334F46E5)]),
                              borderRadius: BorderRadius.circular(18),
                              border: Border.all(color: Colors.white.withOpacity(0.14)),
                            ),
                            child: Text(
                              'Mode gratuit démo : ton code est $demoCode',
                              textAlign: TextAlign.center,
                              style: const TextStyle(fontWeight: FontWeight.w900, color: Colors.white),
                            ),
                          ),
                        ],
                        const SizedBox(height: 16),
                        _PrimaryGradientButton(
                          text: 'Vérifier et entrer',
                          loading: busy,
                          onPressed: busy ? null : verifyCode,
                        ),
                        TextButton(
                          onPressed: busy ? null : requestCode,
                          child: const Text('Renvoyer le code', style: TextStyle(color: Color(0xFFBFC8FF))),
                        ),
                      ],
                      if (error != null) ...[
                        const SizedBox(height: 16),
                        Container(
                          padding: const EdgeInsets.all(13),
                          decoration: BoxDecoration(
                            color: const Color(0xFFFFE4E6).withOpacity(0.95),
                            borderRadius: BorderRadius.circular(16),
                          ),
                          child: Text(
                            error!,
                            textAlign: TextAlign.center,
                            style: const TextStyle(color: Color(0xFFBE123C), fontWeight: FontWeight.w900),
                          ),
                        ),
                      ],
                      const SizedBox(height: 20),
                      const Text(
                        'Mode gratuit : le code est affiché dans l’application au lieu d’être envoyé par SMS.',
                        textAlign: TextAlign.center,
                        style: TextStyle(fontSize: 12, color: Color(0xFFA8B6D3), height: 1.35),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _DarkInput extends StatelessWidget {
  final TextEditingController controller;
  final String label;
  final IconData icon;
  final TextInputType keyboardType;
  final bool obscure;

  const _DarkInput({
    required this.controller,
    required this.label,
    required this.icon,
    this.keyboardType = TextInputType.text,
    this.obscure = false,
  });

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      keyboardType: keyboardType,
      obscureText: obscure,
      style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w700),
      decoration: InputDecoration(
        labelText: label,
        labelStyle: const TextStyle(color: Color(0xFFB7C5DD)),
        prefixIcon: Icon(icon, color: const Color(0xFF39D5FF)),
        filled: true,
        fillColor: Colors.white.withOpacity(0.08),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: Colors.white.withOpacity(0.18)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: const BorderSide(color: Color(0xFF22D3EE), width: 1.5),
        ),
      ),
    );
  }
}

class _PrimaryGradientButton extends StatelessWidget {
  final String text;
  final bool loading;
  final VoidCallback? onPressed;

  const _PrimaryGradientButton({
    required this.text,
    required this.loading,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return Opacity(
      opacity: onPressed == null ? 0.65 : 1,
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: onPressed,
        child: Container(
          height: 54,
          alignment: Alignment.center,
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(18),
            gradient: const LinearGradient(colors: [Color(0xFF00C8FF), Color(0xFF2563EB), Color(0xFF7C3AED)]),
          ),
          child: loading
              ? const SizedBox(width: 22, height: 22, child: CircularProgressIndicator(strokeWidth: 2.2, color: Colors.white))
              : Text(text, style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w900)),
        ),
      ),
    );
  }
}

/// Page principale de Solola.
class HomePage extends StatefulWidget {
  final ApiClient api;
  final Map<String, dynamic> user;
  final String logoUrl;
  final Future<void> Function(String) onLogoChanged;
  final Future<void> Function(Map<String, dynamic>) updateUser;
  final Future<void> Function() logout;
  final bool darkMode;
  final Future<void> Function(bool) onDarkModeChanged;
  final Future<void> Function(Color) onColorChanged;
  final Future<void> Function(String) onApiChanged;

  const HomePage({
    super.key,
    required this.api,
    required this.user,
    required this.logoUrl,
    required this.onLogoChanged,
    required this.updateUser,
    required this.logout,
    required this.darkMode,
    required this.onDarkModeChanged,
    required this.onColorChanged,
    required this.onApiChanged,
  });

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  AppSection section = AppSection.chats;

  List<dynamic> conversations = [];
  List<dynamic> messages = [];
  List<dynamic> statuses = [];

  int? activeConversationId;
  bool groupsOnly = false;

  WebSocketChannel? socket;
  Timer? reconnectTimer;

  final messageCtrl = TextEditingController();
  final searchCtrl = TextEditingController();
  final apiCtrl = TextEditingController();
  final logoCtrl = TextEditingController();

  final Map<int, String> decryptedMessages = {};
  final Map<int, String> securePins = {};
  final Map<int, Map<String, String>> temporarySecurity = {};
  final Map<int, int> unreadCounts = {};

  @override
  void initState() {
    super.initState();
    apiCtrl.text = widget.api.baseUrl;
    logoCtrl.text = widget.logoUrl;
    loadAll();
    connectWebSocket();
  }

  @override
  void dispose() {
    reconnectTimer?.cancel();
    socket?.sink.close();
    messageCtrl.dispose();
    searchCtrl.dispose();
    apiCtrl.dispose();
    logoCtrl.dispose();
    super.dispose();
  }

  Future<void> loadAll() async {
    try {
      conversations = await widget.api.get('/conversations');
      statuses = uniqueStatusList(await widget.api.get('/statuses'));
      if (mounted) setState(() {});
    } catch (e) {
      showToast(e);
    }
  }

  List<dynamic> uniqueStatusList(dynamic rawStatuses) {
    final result = <dynamic>[];
    final seen = <String>{};

    for (final raw in (rawStatuses as List? ?? <dynamic>[])) {
      final status = Map<String, dynamic>.from(raw);
      final key = '${status['id'] ?? status['file']?['download_url'] ?? jsonEncode(status)}';
      if (seen.add(key)) result.add(status);
    }

    return result;
  }

  void upsertStatus(dynamic rawStatus) {
    final status = Map<String, dynamic>.from(rawStatus);
    final id = status['id'];
    final existingIndex = statuses.indexWhere((item) {
      final current = Map<String, dynamic>.from(item);
      return current['id'] == id;
    });

    if (existingIndex >= 0) {
      statuses[existingIndex] = status;
    } else {
      statuses.insert(0, status);
    }
  }

  Future<void> loadMessages(int conversationId) async {
    try {
      messages = await widget.api.get('/conversations/$conversationId/messages');
      unreadCounts[conversationId] = 0;
      if (mounted) setState(() {});
      await markConversationRead(conversationId);
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> refreshConversations() async {
    try {
      conversations = await widget.api.get('/conversations');
      if (mounted) setState(() {});
    } catch (_) {
      // On ignore pour éviter de bloquer l'interface pendant le temps réel.
    }
  }

  Future<void> markConversationRead(int conversationId) async {
    try {
      await widget.api.post('/conversations/$conversationId/read', {});
    } catch (_) {}
  }

  void connectWebSocket() {
    try {
      socket = WebSocketChannel.connect(Uri.parse(widget.api.websocketUrl()));
      socket!.sink.add(jsonEncode({'type': 'ping'}));

      socket!.stream.listen(
        (event) async {
          final data = jsonDecode(event.toString());

          if (data['type'] == 'new_message') {
            final message = data['payload'];
            final conversationId = message['conversation_id'];

            if (conversationId == activeConversationId) {
              if (!messages.any((item) => item['id'] == message['id'])) {
                messages.add(message);
              }
              await markConversationRead(conversationId);
            } else {
              unreadCounts[conversationId] = (unreadCounts[conversationId] ?? 0) + 1;
              showToast('Nouveau message reçu');
            }

            await refreshConversations();
            if (mounted) setState(() {});
          }

          if (data['type'] == 'conversation_created') {
            await refreshConversations();
          }

          if (data['type'] == 'new_status') {
            upsertStatus(data['payload']);
            showToast('Nouveau statut publié');
            if (mounted) setState(() {});
          }

          if (data['type'] == 'status_deleted') {
            final deletedId = data['payload']['id'];
            statuses.removeWhere((item) => item['id'] == deletedId);
            if (mounted) setState(() {});
          }

          if (data['type'] == 'message_deleted') {
            messages.removeWhere((item) => item['id'] == data['payload']['id']);
            await refreshConversations();
            if (mounted) setState(() {});
          }

          if (data['type'] == 'messages_read') {
            await refreshConversations();
          }
        },
        onDone: scheduleReconnect,
        onError: (_) => scheduleReconnect(),
      );
    } catch (_) {
      scheduleReconnect();
    }
  }

  void scheduleReconnect() {
    reconnectTimer?.cancel();
    reconnectTimer = Timer(const Duration(seconds: 3), connectWebSocket);
  }

  bool get wideScreen => MediaQuery.sizeOf(context).width >= 950;

  Map<String, dynamic>? get activeConversation {
    for (final conversation in conversations) {
      final item = Map<String, dynamic>.from(conversation);
      if (item['id'] == activeConversationId) return item;
    }
    return null;
  }

  List<Map<String, dynamic>> get visibleConversations {
    final result = <Map<String, dynamic>>[];
    final q = searchCtrl.text.trim().toLowerCase();

    for (final raw in conversations) {
      final c = Map<String, dynamic>.from(raw);

      if (section == AppSection.secure) {
        if (c['is_secure'] != true) continue;
      } else if (section == AppSection.groups) {
        if (c['type'] != 'group' || c['is_secure'] == true) continue;
      } else if (section == AppSection.chats) {
        if (c['is_secure'] == true) continue;
        if (groupsOnly && c['type'] != 'group') continue;
      }

      final title = '${c['display_title'] ?? c['title'] ?? ''}'.toLowerCase();
      final last = previewMessage(c['last_message']).toLowerCase();
      if (q.isNotEmpty && !title.contains(q) && !last.contains(q)) continue;

      result.add(c);
    }

    return result;
  }

  @override
  Widget build(BuildContext context) {
    final conversationSection =
        section == AppSection.chats || section == AppSection.groups || section == AppSection.secure;

    if (wideScreen) {
      return Scaffold(
        body: appBackground(
          child: Row(
            children: [
              rail(),
              if (conversationSection) ...[
                SizedBox(width: 430, child: sidePanel()),
                VerticalDivider(width: 1, color: Colors.white.withOpacity(0.08)),
              ],
              Expanded(child: mainPanel()),
            ],
          ),
        ),
      );
    }

    return Scaffold(
      body: appBackground(
        child: activeConversationId != null && conversationSection ? mainPanel() : sidePanel(),
      ),
      bottomNavigationBar: mobileNavigation(),
    );
  }

  Widget appBackground({required Widget child}) {
    return Container(
      decoration: const BoxDecoration(
        gradient: RadialGradient(
          center: Alignment(-0.85, -0.95),
          radius: 1.35,
          colors: [
            Color(0xFF033A4C),
            Color(0xFF071B35),
            Color(0xFF150B33),
            Color(0xFF070817),
          ],
          stops: [0.0, 0.34, 0.72, 1.0],
        ),
      ),
      child: Stack(
        children: [
          Positioned(
            top: -180,
            left: -160,
            child: decorativeOrb(const Color(0xFF00C8FF), 420, 0.18),
          ),
          Positioned(
            right: -190,
            bottom: -190,
            child: decorativeOrb(const Color(0xFF7C3AED), 460, 0.22),
          ),
          Positioned(
            top: 120,
            right: 180,
            child: decorativeOrb(const Color(0xFF2563EB), 220, 0.10),
          ),
          child,
        ],
      ),
    );
  }

  Widget decorativeOrb(Color color, double size, double opacity) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: color.withOpacity(opacity),
        boxShadow: [
          BoxShadow(
            color: color.withOpacity(opacity),
            blurRadius: 120,
            spreadRadius: 35,
          ),
        ],
      ),
    );
  }) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFFF8FBFF), Color(0xFFF3F0FF), Color(0xFFEAF7FF)],
        ),
      ),
      child: child,
    );
  }

  Widget glassCard({
    required Widget child,
    EdgeInsetsGeometry padding = const EdgeInsets.all(20),
    EdgeInsetsGeometry margin = EdgeInsets.zero,
  }) {
    return Container(
      margin: margin,
      padding: padding,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(28),
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Colors.white.withOpacity(0.92),
            const Color(0xFFF8F7FF).withOpacity(0.86),
            const Color(0xFFEAF7FF).withOpacity(0.82),
          ],
        ),
        border: Border.all(color: Colors.white.withOpacity(0.88), width: 1.1),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF00C8FF).withOpacity(0.08),
            blurRadius: 36,
            offset: const Offset(-12, 16),
          ),
          BoxShadow(
            color: const Color(0xFF1E1B4B).withOpacity(0.13),
            blurRadius: 42,
            offset: const Offset(0, 20),
          ),
        ],
      ),
      child: child,
    );
  }) {
    return Container(
      margin: margin,
      padding: padding,
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.72),
        borderRadius: BorderRadius.circular(26),
        border: Border.all(color: Colors.white.withOpacity(0.75)),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF1E1B4B).withOpacity(0.08),
            blurRadius: 28,
            offset: const Offset(0, 16),
          ),
        ],
      ),
      child: child,
    );
  }

  Widget gradientTitleCard({
    required String title,
    required String subtitle,
    required IconData icon,
    Widget? action,
  }) {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(32),
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF061126), Color(0xFF042B44), Color(0xFF1238B5), Color(0xFF4C1D95)],
          stops: [0.0, 0.36, 0.70, 1.0],
        ),
        border: Border.all(color: Colors.white.withOpacity(0.12)),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF2563EB).withOpacity(0.28),
            blurRadius: 44,
            offset: const Offset(0, 22),
          ),
        ],
      ),
      child: Stack(
        children: [
          Positioned(right: -80, top: -95, child: decorativeOrb(const Color(0xFF00C8FF), 190, 0.16)),
          Positioned(right: 80, bottom: -115, child: decorativeOrb(const Color(0xFF7C3AED), 220, 0.17)),
          Row(
            children: [
              Container(
                width: 66,
                height: 66,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(22),
                  gradient: const LinearGradient(colors: [Color(0xFF00C8FF), Color(0xFF2563EB), Color(0xFF7C3AED)]),
                  boxShadow: [
                    BoxShadow(color: const Color(0xFF00C8FF).withOpacity(0.30), blurRadius: 28, offset: const Offset(0, 14)),
                  ],
                ),
                child: Icon(icon, color: Colors.white, size: 30),
              ),
              const SizedBox(width: 18),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title, style: const TextStyle(color: Colors.white, fontSize: 32, fontWeight: FontWeight.w900, letterSpacing: -0.8)),
                    const SizedBox(height: 6),
                    Text(subtitle, style: const TextStyle(color: Color(0xFFD7E5F7), fontSize: 15, fontWeight: FontWeight.w600)),
                  ],
                ),
              ),
              if (action != null) action,
            ],
          ),
        ],
      ),
    );
  }) {
    return Container(
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(28),
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF061126), Color(0xFF12395A), Color(0xFF3B1B7A)],
        ),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF2563EB).withOpacity(0.18),
            blurRadius: 32,
            offset: const Offset(0, 18),
          ),
        ],
      ),
      child: Row(
        children: [
          Container(
            width: 54,
            height: 54,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(18),
              gradient: const LinearGradient(colors: [Color(0xFF00C8FF), Color(0xFF7C3AED)]),
            ),
            child: Icon(icon, color: Colors.white),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(title, style: const TextStyle(color: Colors.white, fontSize: 28, fontWeight: FontWeight.w900)),
              const SizedBox(height: 4),
              Text(subtitle, style: const TextStyle(color: Color(0xFFD7E5F7), fontSize: 14)),
            ]),
          ),
          if (action != null) action,
        ],
      ),
    );
  }

  Widget mobileNavigation() {
    final sections = [
      AppSection.chats,
      AppSection.status,
      AppSection.groups,
      AppSection.secure,
      AppSection.settings,
    ];

    return NavigationBar(
      selectedIndex: sections.contains(section) ? sections.indexOf(section) : 0,
      onDestinationSelected: (index) {
        setState(() {
          section = sections[index];
          if (section != AppSection.chats && section != AppSection.groups && section != AppSection.secure) {
            activeConversationId = null;
          }
        });
      },
      destinations: const [
        NavigationDestination(icon: Icon(Icons.chat_bubble_outline), label: 'Chats'),
        NavigationDestination(icon: Icon(Icons.circle_outlined), label: 'Statuts'),
        NavigationDestination(icon: Icon(Icons.groups_outlined), label: 'Groupes'),
        NavigationDestination(icon: Icon(Icons.lock_outline), label: 'Sécurisé'),
        NavigationDestination(icon: Icon(Icons.settings_outlined), label: 'Réglages'),
      ],
    );
  }

  Widget rail() {
    return Container(
      width: 88,
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [Color(0xFF061126), Color(0xFF0A1B35), Color(0xFF140B2E)],
        ),
        border: Border(right: BorderSide(color: Colors.white.withOpacity(0.10))),
        boxShadow: [
          BoxShadow(color: Colors.black.withOpacity(0.22), blurRadius: 28, offset: const Offset(8, 0)),
        ],
      ),
      child: Column(
        children: [
          const SizedBox(height: 18),
          SololaLogo(logoUrl: widget.logoUrl, size: 58),
          const SizedBox(height: 20),
          for (final item in AppSection.values) navRailButton(item),
          IconButton(
            tooltip: 'Avis',
            color: Colors.white.withOpacity(0.82),
            onPressed: () => sendFeedback(),
            icon: const Icon(Icons.mail_outline),
          ),
          const Spacer(),
          IconButton(
            tooltip: 'Déconnexion',
            color: Colors.white.withOpacity(0.82),
            onPressed: () => widget.logout(),
            icon: const Icon(Icons.logout),
          ),
          const SizedBox(height: 16),
        ],
      ),
    );
  }

  Widget navRailButton(AppSection item) {
    final selected = section == item;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
      child: Tooltip(
        message: sectionLabel(item),
        child: InkWell(
          borderRadius: BorderRadius.circular(20),
          onTap: () {
            setState(() {
              section = item;
              if (item != AppSection.chats && item != AppSection.groups && item != AppSection.secure) {
                activeConversationId = null;
              }
            });
          },
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 180),
            width: 54,
            height: 50,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(20),
              gradient: selected
                  ? const LinearGradient(colors: [Color(0xFF00C8FF), Color(0xFF2563EB), Color(0xFF7C3AED)])
                  : null,
              color: selected ? null : Colors.white.withOpacity(0.045),
              border: Border.all(color: selected ? Colors.white.withOpacity(0.20) : Colors.white.withOpacity(0.08)),
              boxShadow: selected
                  ? [BoxShadow(color: const Color(0xFF00C8FF).withOpacity(0.24), blurRadius: 24, offset: const Offset(0, 12))]
                  : [],
            ),
            child: Icon(sectionIcon(item), color: Colors.white, size: 25),
          ),
        ),
      ),
    );
  }

  String sectionLabel(AppSection value) {
    switch (value) {
      case AppSection.chats:
        return 'Discussions';
      case AppSection.status:
        return 'Statuts';
      case AppSection.groups:
        return 'Groupes';
      case AppSection.secure:
        return 'Sécurisé';
      case AppSection.settings:
        return 'Paramètres';
      case AppSection.help:
        return 'Aide';
    }
  }

  IconData sectionIcon(AppSection value) {
    switch (value) {
      case AppSection.chats:
        return Icons.chat_bubble_outline;
      case AppSection.status:
        return Icons.circle_outlined;
      case AppSection.groups:
        return Icons.groups_outlined;
      case AppSection.secure:
        return Icons.lock_outline;
      case AppSection.settings:
        return Icons.settings_outlined;
      case AppSection.help:
        return Icons.help_outline;
    }
  }

  Widget sidePanel() {
    if (section == AppSection.status) return statusPage();
    if (section == AppSection.settings) return settingsPage();
    if (section == AppSection.help) return helpPage();

    final secureSection = section == AppSection.secure;

    return Container(
      margin: const EdgeInsets.fromLTRB(18, 18, 0, 18),
      padding: const EdgeInsets.fromLTRB(22, 22, 22, 20),
      decoration: BoxDecoration(
        borderRadius: const BorderRadius.only(topLeft: Radius.circular(30), bottomLeft: Radius.circular(30)),
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Colors.white.withOpacity(0.86), Colors.white.withOpacity(0.66), const Color(0xFFEAF7FF).withOpacity(0.55)],
        ),
        border: Border.all(color: Colors.white.withOpacity(0.78)),
        boxShadow: [
          BoxShadow(color: const Color(0xFF061126).withOpacity(0.18), blurRadius: 36, offset: const Offset(0, 20)),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          sideHeader(sectionLabel(section)),
          const SizedBox(height: 18),
          Row(
            children: [
              Expanded(
                child: FilledButton.icon(
                  onPressed: secureSection ? () => createSecurePrivate() : () => createPrivate(),
                  icon: Icon(secureSection ? Icons.lock_person : Icons.person_add),
                  label: Text(secureSection ? 'Sécurisée' : 'Conversation'),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: secureSection ? () => createSecureGroup() : () => createGroup(),
                  icon: Icon(secureSection ? Icons.lock : Icons.group_add),
                  label: Text(secureSection ? 'Groupe sécurisé' : 'Groupe'),
                ),
              ),
            ],
          ),
          if (section == AppSection.chats) ...[
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(5),
              decoration: BoxDecoration(
                color: const Color(0xFF061126).withOpacity(0.07),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: Colors.white.withOpacity(0.65)),
              ),
              child: Row(
                children: [
                  Expanded(child: segmentButton('Toutes', !groupsOnly, () => setState(() => groupsOnly = false))),
                  Expanded(child: segmentButton('Groupes', groupsOnly, () => setState(() => groupsOnly = true))),
                ],
              ),
            ),
          ],
          const SizedBox(height: 18),
          Expanded(
            child: visibleConversations.isEmpty
                ? Center(
                    child: glassCard(
                      padding: const EdgeInsets.all(24),
                      child: Column(mainAxisSize: MainAxisSize.min, children: const [
                        Icon(Icons.chat_bubble_outline, size: 54, color: Color(0xFF4F46E5)),
                        SizedBox(height: 12),
                        Text('Aucune conversation ici.', style: TextStyle(fontWeight: FontWeight.w900)),
                        SizedBox(height: 4),
                        Text('Crée une discussion ou un groupe.', textAlign: TextAlign.center),
                      ]),
                    ),
                  )
                : ListView.separated(
                    itemCount: visibleConversations.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 10),
                    itemBuilder: (context, index) => conversationTile(visibleConversations[index]),
                  ),
          ),
        ],
      ),
    );
  }

  Widget segmentButton(String text, bool selected, VoidCallback onTap) {
    return TextButton(
      onPressed: onTap,
      style: TextButton.styleFrom(
        foregroundColor: selected ? Colors.white : const Color(0xFF334155),
        backgroundColor: selected ? const Color(0xFF2563EB) : Colors.transparent,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(15)),
      ),
      child: Text(text, style: const TextStyle(fontWeight: FontWeight.w800)),
    );
  }

  Widget sideHeader(String title) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Container(
              width: 8,
              height: 34,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(10),
                gradient: const LinearGradient(colors: [Color(0xFF00C8FF), Color(0xFF7C3AED)]),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(child: Text(title, style: const TextStyle(fontSize: 32, fontWeight: FontWeight.w900, letterSpacing: -0.9, color: Color(0xFF0F172A)))),
          ],
        ),
        const SizedBox(height: 18),
        TextField(
          controller: searchCtrl,
          onChanged: (_) => setState(() {}),
          decoration: InputDecoration(
            prefixIcon: const Icon(Icons.search, color: Color(0xFF2563EB)),
            hintText: 'Rechercher',
            filled: true,
            fillColor: Colors.white.withOpacity(0.92),
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(22), borderSide: BorderSide.none),
            enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(22), borderSide: BorderSide(color: Colors.white.withOpacity(0.90))),
            focusedBorder: const OutlineInputBorder(borderRadius: BorderRadius.all(Radius.circular(22)), borderSide: BorderSide(color: Color(0xFF00C8FF), width: 1.5)),
          ),
        ),
      ],
    );
  }

  Widget conversationTile(Map<String, dynamic> conversation) {
    final last = conversation['last_message'];
    final count = unreadCounts[conversation['id']] ?? 0;

    return ListTile(
      selected: conversation['id'] == activeConversationId,
      leading: conversationAvatar(conversation),
      title: Text(
        '${conversation['display_title'] ?? 'Conversation'}',
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      subtitle: Text(
        previewMessage(last),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(formatHour(last?['created_at'])),
          if (count > 0)
            CircleAvatar(
              radius: 11,
              child: Text('$count', style: const TextStyle(fontSize: 10)),
            ),
        ],
      ),
      onTap: () async {
        activeConversationId = conversation['id'];
        await loadMessages(conversation['id']);
      },
    );
  }

  Widget conversationAvatar(Map<String, dynamic> conversation, {double radius = 24}) {
    if (conversation['is_secure'] == true) {
      return CircleAvatar(radius: radius, child: const Icon(Icons.lock_outline));
    }

    if (conversation['type'] == 'group') {
      return CircleAvatar(radius: radius, child: const Icon(Icons.groups_outlined));
    }

    final members = (conversation['members'] as List?) ?? [];
    Map<String, dynamic>? other;

    for (final member in members) {
      if (member is Map && member['id'] != widget.user['id']) {
        other = Map<String, dynamic>.from(member);
        break;
      }
    }

    final avatarUrl = other?['avatar_url'];
    if (avatarUrl != null && '$avatarUrl'.isNotEmpty) {
      return CircleAvatar(
        radius: radius,
        backgroundImage: NetworkImage(widget.api.fileUrl(avatarUrl)),
      );
    }

    return CircleAvatar(
      radius: radius,
      child: Text(initials(conversation['display_title'])),
    );
  }

  Widget mainPanel() {
    if (section == AppSection.status) return statusPage();
    if (section == AppSection.settings) return settingsPage();
    if (section == AppSection.help) return helpPage();

    final conversation = activeConversation;
    if (conversation == null) {
      return Center(
        child: Container(
          width: 560,
          margin: const EdgeInsets.all(24),
          padding: const EdgeInsets.fromLTRB(46, 44, 46, 40),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(36),
            gradient: const LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF061126), Color(0xFF092443), Color(0xFF1E1B4B), Color(0xFF3B1B7A)],
            ),
            border: Border.all(color: Colors.white.withOpacity(0.12)),
            boxShadow: [
              BoxShadow(color: const Color(0xFF00C8FF).withOpacity(0.18), blurRadius: 44, offset: const Offset(0, 20)),
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              SololaLogo(logoUrl: widget.logoUrl, size: 110, showText: true),
              const SizedBox(height: 20),
              const Text(
                'Sélectionne une discussion pour commencer.',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800, color: Colors.white),
              ),
              const SizedBox(height: 8),
              const Text(
                'Messages, statuts, fichiers et conversations chiffrées sont regroupés dans un espace propre.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Color(0xFFCFE3FF), height: 1.35),
              ),
            ],
          ),
        ),
      );
    }

    return chatPanel(conversation);
  }

  Widget chatPanel(Map<String, dynamic> conversation) {
    final locked = conversation['is_secure'] == true && !securePins.containsKey(conversation['id']);
    final temporary = temporarySecurity.containsKey(conversation['id']);

    final filteredMessages = searchCtrl.text.trim().isEmpty
        ? messages
        : messages.where((message) {
            final raw = jsonEncode(message).toLowerCase();
            final clear = decryptedMessages[message['id']]?.toLowerCase() ?? '';
            return raw.contains(searchCtrl.text.toLowerCase()) || clear.contains(searchCtrl.text.toLowerCase());
          }).toList();

    return Column(
      children: [
        chatHeader(conversation, locked, temporary),
        if (locked)
          Expanded(child: lockedConversationPanel(conversation))
        else ...[
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 0),
            child: TextField(
              controller: searchCtrl,
              onChanged: (_) => setState(() {}),
              decoration: InputDecoration(
                prefixIcon: const Icon(Icons.search),
                hintText: 'Rechercher dans la conversation',
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(16)),
              ),
            ),
          ),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(18),
              itemCount: filteredMessages.length,
              itemBuilder: (context, index) {
                return messageBubble(Map<String, dynamic>.from(filteredMessages[index]));
              },
            ),
          ),
          composer(conversation),
        ],
      ],
    );
  }

  Widget chatHeader(Map<String, dynamic> conversation, bool locked, bool temporary) {
    return Container(
      color: Theme.of(context).colorScheme.surface,
      padding: const EdgeInsets.all(12),
      child: Row(
        children: [
          if (!wideScreen)
            IconButton(
              onPressed: () => setState(() => activeConversationId = null),
              icon: const Icon(Icons.arrow_back),
            ),
          conversationAvatar(conversation, radius: 25),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '${conversation['display_title'] ?? 'Conversation'}',
                  style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                Text(
                  conversation['is_secure'] == true
                      ? 'Conversation 100 % chiffrée'
                      : temporary
                          ? 'Chiffrement temporaire activé'
                          : 'Temps réel',
                ),
              ],
            ),
          ),
          FilledButton.tonalIcon(
            onPressed: () {
              if (conversation['is_secure'] == true) {
                togglePermanentSecure(conversation);
              } else {
                toggleTemporarySecure(conversation);
              }
            },
            icon: Icon(
              conversation['is_secure'] == true
                  ? locked
                      ? Icons.lock_open
                      : Icons.lock
                  : temporary
                      ? Icons.lock_open
                      : Icons.lock_outline,
            ),
            label: Text(
              conversation['is_secure'] == true
                  ? locked
                      ? 'Déverrouiller'
                      : 'Verrouiller'
                  : temporary
                      ? 'Temporaire ON'
                      : 'Temporaire',
            ),
          ),
          const SizedBox(width: 8),
          if (conversation['type'] == 'private')
            IconButton(
              tooltip: 'Appel',
              onPressed: () => showToast('Module appel prêt. WebRTC complet à finaliser.'),
              icon: const Icon(Icons.call_outlined),
            ),
        ],
      ),
    );
  }

  Widget lockedConversationPanel(Map<String, dynamic> conversation) {
    return Center(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.lock_outline, size: 64),
              const SizedBox(height: 12),
              const Text('Conversation sécurisée', style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
              Text('Indice : ${conversation['security_hint'] ?? 'Aucun'}'),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: () => togglePermanentSecure(conversation),
                child: const Text('Entrer le PIN'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget composer(Map<String, dynamic> conversation) {
    final secure = conversation['is_secure'] == true || temporarySecurity.containsKey(conversation['id']);

    return Container(
      color: Theme.of(context).colorScheme.surface,
      padding: const EdgeInsets.all(12),
      child: Row(
        children: [
          IconButton(
            tooltip: 'Envoyer fichier',
            onPressed: () => uploadFile(conversation, encrypted: false),
            icon: const Icon(Icons.attach_file),
          ),
          IconButton(
            tooltip: 'Envoyer fichier chiffré',
            onPressed: () => uploadFile(conversation, encrypted: true),
            icon: const Icon(Icons.enhanced_encryption_outlined),
          ),
          Expanded(
            child: TextField(
              controller: messageCtrl,
              minLines: 1,
              maxLines: 4,
              decoration: InputDecoration(
                hintText: secure ? 'Message automatiquement chiffré...' : 'Écrire un message...',
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(18)),
              ),
              onSubmitted: (_) => sendMessage(conversation),
            ),
          ),
          const SizedBox(width: 8),
          IconButton.filled(
            onPressed: () => sendMessage(conversation),
            icon: const Icon(Icons.send),
          ),
        ],
      ),
    );
  }

  Widget messageBubble(Map<String, dynamic> message) {
    final mine = message['sender_id'] == widget.user['id'];
    final type = '${message['message_type']}';

    Widget content;

    if (type == 'encrypted_text') {
      content = encryptedMessageWidget(message);
    } else if (message['file'] != null) {
      final file = message['file'];
      content = InkWell(
        onTap: () => launchUrl(Uri.parse(widget.api.fileUrl(file['download_url']))),
        child: Text(
          '📎 ${file['original_filename']}',
          style: const TextStyle(fontWeight: FontWeight.bold, decoration: TextDecoration.underline),
        ),
      );
    } else {
      content = Text('${message['content'] ?? ''}');
    }

    return Align(
      alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 680),
        child: Card(
          color: mine ? Theme.of(context).colorScheme.primaryContainer : null,
          child: Padding(
            padding: const EdgeInsets.all(13),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (!mine)
                  Text(
                    '${message['sender_pseudo'] ?? ''}',
                    style: TextStyle(color: Theme.of(context).colorScheme.primary, fontWeight: FontWeight.bold),
                  ),
                content,
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(formatHour(message['created_at']), style: const TextStyle(fontSize: 11)),
                    if (mine)
                      Padding(
                        padding: const EdgeInsets.only(left: 6),
                        child: Text(messageStatusLabel(message['status']), style: const TextStyle(fontSize: 11)),
                      ),
                    IconButton(
                      iconSize: 18,
                      onPressed: () => forwardMessage(message),
                      icon: const Icon(Icons.forward),
                    ),
                    if (mine)
                      IconButton(
                        iconSize: 18,
                        onPressed: () => deleteMessage(message),
                        icon: const Icon(Icons.delete_outline),
                      ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget encryptedMessageWidget(Map<String, dynamic> message) {
    final id = message['id'] as int;

    if (decryptedMessages[id] != null) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('🔓 Message déchiffré', style: TextStyle(fontWeight: FontWeight.bold)),
          Text(decryptedMessages[id]!),
        ],
      );
    }

    Map<String, dynamic> payload = {};
    try {
      payload = Map<String, dynamic>.from(jsonDecode('${message['content']}'));
    } catch (_) {}

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('🔐 Message chiffré', style: TextStyle(fontWeight: FontWeight.bold)),
        Text('Indice : ${payload['hint'] ?? 'Aucun'}'),
        SelectableText(
          '${payload['ciphertext'] ?? message['content']}',
          style: const TextStyle(fontSize: 11),
        ),
        const SizedBox(height: 8),
        FilledButton.tonal(
          onPressed: () => decryptMessage(message),
          child: const Text('Déchiffrer avec PIN'),
        ),
      ],
    );
  }

  String messageStatusLabel(dynamic status) {
    if (status == 'read') return '✓✓ lu';
    if (status == 'delivered') return '✓✓ reçu';
    return '✓ envoyé';
  }

  Map<String, String>? securityContextFor(Map<String, dynamic> conversation) {
    final id = conversation['id'] as int;

    if (conversation['is_secure'] == true) {
      final pin = securePins[id];
      if (pin == null) {
        showToast('Déverrouille d’abord cette conversation.');
        return null;
      }

      return {
        'pin': pin,
        'hint': '${conversation['security_hint'] ?? ''}',
        'mode': 'permanent_secure',
      };
    }

    if (temporarySecurity.containsKey(id)) {
      return temporarySecurity[id];
    }

    return null;
  }

  Future<void> sendMessage(Map<String, dynamic> conversation) async {
    final text = messageCtrl.text.trim();
    if (text.isEmpty) return;

    messageCtrl.clear();

    try {
      final security = securityContextFor(conversation);

      if (security != null) {
        final encrypted = await PinCrypto.encryptText(
          clearText: text,
          pin: security['pin']!,
          hint: security['hint'] ?? '',
          mode: security['mode'] ?? 'temporary_secure',
        );

        await widget.api.post('/conversations/${conversation['id']}/messages', {
          'content': jsonEncode(encrypted),
          'message_type': 'encrypted_text',
        });
      } else {
        await widget.api.post('/conversations/${conversation['id']}/messages', {
          'content': text,
          'message_type': 'text',
        });
      }
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> decryptMessage(Map<String, dynamic> message, {String? suppliedPin}) async {
    final pin = suppliedPin ??
        await textDialog(
          context,
          title: 'Déchiffrement',
          label: 'PIN',
          obscure: true,
        );

    if (pin == null || pin.isEmpty) return;

    try {
      final payload = Map<String, dynamic>.from(jsonDecode('${message['content']}'));
      decryptedMessages[message['id']] = await PinCrypto.decryptText(payload: payload, pin: pin);
      if (mounted) setState(() {});
    } catch (_) {
      showToast('PIN incorrect ou message impossible à déchiffrer.');
    }
  }

  Future<void> togglePermanentSecure(Map<String, dynamic> conversation) async {
    final id = conversation['id'] as int;

    if (securePins.containsKey(id)) {
      securePins.remove(id);
      decryptedMessages.clear();
      setState(() {});
      return;
    }

    final pin = await textDialog(
      context,
      title: 'Déverrouiller',
      label: 'PIN - indice : ${conversation['security_hint'] ?? 'Aucun'}',
      obscure: true,
    );

    if (pin == null || pin.isEmpty) return;

    securePins[id] = pin;

    for (final rawMessage in messages) {
      final message = Map<String, dynamic>.from(rawMessage);
      if (message['message_type'] == 'encrypted_text') {
        await decryptMessage(message, suppliedPin: pin);
      }
    }

    if (mounted) setState(() {});
  }

  Future<void> toggleTemporarySecure(Map<String, dynamic> conversation) async {
    final id = conversation['id'] as int;

    if (temporarySecurity.containsKey(id)) {
      temporarySecurity.remove(id);
      setState(() {});
      return;
    }

    final result = await temporarySecureDialog(context);
    if (result == null) return;

    temporarySecurity[id] = result;
    setState(() {});
  }

  Future<void> uploadFile(Map<String, dynamic> conversation, {required bool encrypted}) async {
    try {
      final picked = await FilePicker.platform.pickFiles(withData: true);
      if (picked == null) return;

      final file = picked.files.single;

      if (file.size > 10 * 1024 * 1024) {
        showToast('Fichier trop lourd : limite 10 Mo.');
        return;
      }

      if (!encrypted) {
        await widget.api.upload('/conversations/${conversation['id']}/upload', file);
        return;
      }

      final pin = await textDialog(
        context,
        title: 'Fichier chiffré',
        label: 'PIN',
        obscure: true,
      );

      if (pin == null || pin.isEmpty) return;

      final bytes = file.bytes;
      if (bytes == null) {
        showToast('Lecture du fichier impossible.');
        return;
      }

      final encryptedPayload = await PinCrypto.encryptText(
        clearText: base64Encode(bytes),
        pin: pin,
        hint: 'fichier chiffré',
        mode: 'encrypted_file',
      );

      final encoded = Uint8List.fromList(utf8.encode(jsonEncode(encryptedPayload)));

      final encryptedFile = PlatformFile(
        name: '${file.name}.encrypted',
        size: encoded.length,
        bytes: encoded,
      );

      await widget.api.upload('/conversations/${conversation['id']}/upload', encryptedFile);
      showToast('Fichier chiffré envoyé. Tracking garde le hash du fichier chiffré.');
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> createPrivate() async {
    final phone = await textDialog(context, title: 'Nouvelle conversation', label: 'Numéro');
    if (phone == null || phone.isEmpty) return;

    try {
      final conversation = await widget.api.post('/conversations/private', {'phone_number': phone});
      await refreshConversations();
      activeConversationId = conversation['id'];
      section = AppSection.chats;
      await loadMessages(conversation['id']);
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> createSecurePrivate() async {
    final result = await secureConversationDialog(context);
    if (result == null) return;

    try {
      final conversation = await widget.api.post('/conversations/private', {
        'phone_number': result['phone'],
        'is_secure': true,
        'security_hint': result['hint'],
      });

      securePins[conversation['id']] = result['pin']!;
      await refreshConversations();
      activeConversationId = conversation['id'];
      section = AppSection.secure;
      await loadMessages(conversation['id']);
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> createGroup() async {
    final result = await groupDialog(context, secure: false);
    if (result == null) return;

    try {
      final conversation = await widget.api.post('/conversations/group', result);
      await refreshConversations();
      activeConversationId = conversation['id'];
      section = AppSection.groups;
      await loadMessages(conversation['id']);
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> createSecureGroup() async {
    final result = await groupDialog(context, secure: true);
    if (result == null) return;

    final pin = result.remove('pin');

    try {
      final conversation = await widget.api.post('/conversations/group', result);
      securePins[conversation['id']] = '$pin';
      await refreshConversations();
      activeConversationId = conversation['id'];
      section = AppSection.secure;
      await loadMessages(conversation['id']);
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> forwardMessage(Map<String, dynamic> message) async {
    final list = conversations.map((conversation) {
      return '${conversation['id']} - ${conversation['display_title']}';
    }).join('\n');

    final id = await textDialog(context, title: 'Transfert', label: 'ID conversation cible\n$list');
    if (id == null || id.isEmpty) return;

    try {
      await widget.api.post('/messages/${message['id']}/forward', {
        'conversation_id': int.parse(id),
      });
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> deleteMessage(Map<String, dynamic> message) async {
    try {
      await widget.api.delete('/messages/${message['id']}');
      messages.removeWhere((item) => item['id'] == message['id']);
      if (mounted) setState(() {});
    } catch (e) {
      showToast(e);
    }
  }

  Widget statusPage() {
    return ListView(
      padding: const EdgeInsets.fromLTRB(28, 26, 28, 32),
      children: [
        gradientTitleCard(
          title: 'Statuts',
          subtitle: 'Partage une photo. Appuie sur une carte pour l’afficher en plein écran.',
          icon: Icons.photo_library_outlined,
          action: FilledButton.icon(
            style: FilledButton.styleFrom(
              backgroundColor: Colors.white.withOpacity(0.18),
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
            ),
            onPressed: () => publishStatus(),
            icon: const Icon(Icons.add_photo_alternate_outlined),
            label: const Text('Poster'),
          ),
        ),
        const SizedBox(height: 26),
        if (statuses.isEmpty)
          Center(
            child: glassCard(
              padding: const EdgeInsets.all(34),
              child: Column(mainAxisSize: MainAxisSize.min, children: const [
                Icon(Icons.photo_outlined, size: 62, color: Color(0xFF2563EB)),
                SizedBox(height: 14),
                Text('Aucun statut publié.', style: TextStyle(fontWeight: FontWeight.w900, fontSize: 18)),
                SizedBox(height: 6),
                Text('Ajoute une photo pour tester les statuts en temps réel.'),
              ]),
            ),
          )
        else
          GridView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: statuses.length,
            gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
              maxCrossAxisExtent: 285,
              crossAxisSpacing: 22,
              mainAxisSpacing: 22,
              childAspectRatio: 0.78,
            ),
            itemBuilder: (context, index) {
              final status = Map<String, dynamic>.from(statuses[index]);
              final file = status['file'];
              final mine = isMyStatus(status);

              return InkWell(
                borderRadius: BorderRadius.circular(28),
                onTap: () => showStatusViewer(index),
                child: Container(
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(28),
                    gradient: LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [Colors.white.withOpacity(0.94), const Color(0xFFEAF7FF).withOpacity(0.84)],
                    ),
                    border: Border.all(color: Colors.white.withOpacity(0.95)),
                    boxShadow: [
                      BoxShadow(color: const Color(0xFF061126).withOpacity(0.18), blurRadius: 30, offset: const Offset(0, 18)),
                    ],
                  ),
                  clipBehavior: Clip.antiAlias,
                  child: Stack(
                    children: [
                      Positioned.fill(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Expanded(
                              child: Stack(
                                fit: StackFit.expand,
                                children: [
                                  Image.network(
                                    widget.api.fileUrl(file['download_url']),
                                    fit: BoxFit.cover,
                                    width: double.infinity,
                                    errorBuilder: (_, __, ___) => Container(
                                      alignment: Alignment.center,
                                      color: const Color(0xFFEFF4FF),
                                      child: const Icon(Icons.broken_image_outlined, size: 48),
                                    ),
                                  ),
                                  DecoratedBox(
                                    decoration: BoxDecoration(
                                      gradient: LinearGradient(
                                        begin: Alignment.topCenter,
                                        end: Alignment.bottomCenter,
                                        colors: [Colors.black.withOpacity(0.18), Colors.transparent, Colors.black.withOpacity(0.18)],
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            Padding(
                              padding: const EdgeInsets.all(14),
                              child: Row(
                                children: [
                                  CircleAvatar(radius: 18, backgroundColor: const Color(0xFFE0EAFF), child: Text(initials(status['user']?['pseudo']))),
                                  const SizedBox(width: 10),
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment: CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          '${status['user']?['pseudo'] ?? 'Utilisateur'}',
                                          maxLines: 1,
                                          overflow: TextOverflow.ellipsis,
                                          style: const TextStyle(fontWeight: FontWeight.w900, fontSize: 15),
                                        ),
                                        Text(formatHour(status['created_at']), style: const TextStyle(fontSize: 12, color: Color(0xFF64748B))),
                                      ],
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                      if (mine)
                        Positioned(
                          top: 10,
                          right: 10,
                          child: Material(
                            color: Colors.black.withOpacity(0.46),
                            borderRadius: BorderRadius.circular(18),
                            child: IconButton(
                              tooltip: 'Supprimer ce statut',
                              color: Colors.white,
                              icon: const Icon(Icons.delete_outline),
                              onPressed: () => deleteStatus(status),
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              );
            },
          ),
      ],
    );
  }

  bool isMyStatus(Map<String, dynamic> status) {
    final owner = status['user'];
    if (owner is Map) return owner['id'] == widget.user['id'];
    return false;
  }

  Future<void> deleteStatus(Map<String, dynamic> status) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Supprimer le statut ?'),
        content: const Text('Cette photo de statut sera retirée pour tous les utilisateurs.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(dialogContext, false), child: const Text('Annuler')),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Supprimer'),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    try {
      await widget.api.delete('/statuses/${status['id']}');
      statuses.removeWhere((item) => item['id'] == status['id']);
      if (mounted) setState(() {});
      showToast('Statut supprimé.');
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> publishStatus() async {
    try {
      final picked = await FilePicker.platform.pickFiles(type: FileType.image, withData: true);
      if (picked == null) return;

      final caption = await textDialog(
            context,
            title: 'Statut',
            label: 'Légende',
            requiredValue: false,
          ) ??
          '';

      final status = await widget.api.upload(
        '/statuses',
        picked.files.single,
        fields: {'caption': caption},
      );

      upsertStatus(status);
      if (mounted) setState(() {});
    } catch (e) {
      showToast(e);
    }
  }

  void showStatusViewer(int startIndex) {
    int index = startIndex;
    showDialog<void>(
      context: context,
      builder: (dialogContext) {
        return StatefulBuilder(builder: (context, setDialogState) {
          final status = Map<String, dynamic>.from(statuses[index]);
          final file = status['file'];
          final mine = isMyStatus(status);

          return Dialog.fullscreen(
            backgroundColor: Colors.black,
            child: Stack(
              children: [
                Positioned.fill(
                  child: Image.network(
                    widget.api.fileUrl(file['download_url']),
                    fit: BoxFit.contain,
                    errorBuilder: (_, __, ___) => const Center(
                      child: Icon(Icons.broken_image_outlined, color: Colors.white, size: 70),
                    ),
                  ),
                ),
                Positioned(
                  left: 0,
                  right: 0,
                  top: 0,
                  child: SafeArea(
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          begin: Alignment.topCenter,
                          end: Alignment.bottomCenter,
                          colors: [Colors.black.withOpacity(0.75), Colors.transparent],
                        ),
                      ),
                      child: ListTile(
                        textColor: Colors.white,
                        iconColor: Colors.white,
                        leading: CircleAvatar(child: Text(initials(status['user']?['pseudo']))),
                        title: Text('${status['user']?['pseudo'] ?? 'Utilisateur'}'),
                        subtitle: Text(formatHour(status['created_at'])),
                        trailing: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            if (mine)
                              IconButton(
                                tooltip: 'Supprimer',
                                onPressed: () async {
                                  Navigator.pop(dialogContext);
                                  await deleteStatus(status);
                                },
                                icon: const Icon(Icons.delete_outline),
                              ),
                            IconButton(
                              onPressed: () => Navigator.pop(dialogContext),
                              icon: const Icon(Icons.close),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
                Positioned(
                  left: 16,
                  right: 16,
                  bottom: 24,
                  child: SafeArea(
                    child: Row(
                      children: [
                        IconButton.filledTonal(
                          color: Colors.white,
                          onPressed: index > 0 ? () => setDialogState(() => index--) : null,
                          icon: const Icon(Icons.arrow_back),
                        ),
                        Expanded(
                          child: Text(
                            '${status['caption'] ?? ''}',
                            textAlign: TextAlign.center,
                            style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w700),
                          ),
                        ),
                        IconButton.filledTonal(
                          color: Colors.white,
                          onPressed: index < statuses.length - 1 ? () => setDialogState(() => index++) : null,
                          icon: const Icon(Icons.arrow_forward),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          );
        });
      },
    );
  }

  Widget settingsPage() {
    final colors = <Color>[
      const Color(0xFF2563EB),
      const Color(0xFF10B981),
      const Color(0xFF7C3AED),
      const Color(0xFFF97316),
      const Color(0xFFE11D48),
    ];

    final privacy = Map<String, dynamic>.from(widget.user['privacy'] ?? <String, dynamic>{
      'show_online': true,
      'allow_calls': true,
      'allow_group_invites': true,
      'show_avatar': true,
    });

    return ListView(
      padding: const EdgeInsets.all(26),
      children: [
        gradientTitleCard(
          title: 'Paramètres Solola',
          subtitle: 'Profil, apparence, confidentialité et accès tracking.',
          icon: Icons.settings_outlined,
        ),
        const SizedBox(height: 22),
        LayoutBuilder(
          builder: (context, constraints) {
            final twoColumns = constraints.maxWidth > 820;
            final profile = glassCard(
              child: Column(children: [
                profileAvatar(radius: 78),
                const SizedBox(height: 12),
                OutlinedButton.icon(
                  onPressed: () => updateAvatar(),
                  icon: const Icon(Icons.camera_alt_outlined),
                  label: const Text('Modifier photo'),
                ),
                const Divider(height: 34),
                profileLine('About', '${widget.user['info'] ?? 'Disponible'}'),
                profileLine('Nom', '${widget.user['pseudo']}'),
                profileLine('Téléphone', '${widget.user['phone_number']}'),
                const SizedBox(height: 10),
                FilledButton(onPressed: () => editProfile(), child: const Text('Modifier profil')),
              ]),
            );

            final appearance = glassCard(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Text('Couleur et apparence', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900)),
                const SizedBox(height: 14),
                Wrap(spacing: 12, children: [
                  for (final color in colors)
                    InkWell(
                      onTap: () => widget.onColorChanged(color),
                      borderRadius: BorderRadius.circular(50),
                      child: CircleAvatar(backgroundColor: color, radius: 18),
                    ),
                ]),
                const SizedBox(height: 10),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  value: widget.darkMode,
                  onChanged: (value) => widget.onDarkModeChanged(value),
                  title: const Text('Mode sombre'),
                ),
              ]),
            );

            if (!twoColumns) {
              return Column(children: [
                profile,
                const SizedBox(height: 18),
                appearance,
              ]);
            }

            return Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(child: profile),
                const SizedBox(width: 18),
                Expanded(child: appearance),
              ],
            );
          },
        ),
        const SizedBox(height: 18),
        glassCard(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Confidentialité', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900)),
            privacySwitch('Afficher mon statut en ligne', privacy, 'show_online'),
            privacySwitch('Autoriser les appels', privacy, 'allow_calls'),
            privacySwitch('Autoriser les invitations de groupe', privacy, 'allow_group_invites'),
            privacySwitch('Afficher ma photo de profil', privacy, 'show_avatar'),
          ]),
        ),
        const SizedBox(height: 18),
        glassCard(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Connexion serveur', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900)),
            const SizedBox(height: 12),
            TextField(controller: apiCtrl, decoration: const InputDecoration(labelText: 'URL API')),
            const SizedBox(height: 10),
            FilledButton.icon(
              onPressed: () => widget.onApiChanged(apiCtrl.text.trim()),
              icon: const Icon(Icons.save_outlined),
              label: const Text('Enregistrer URL'),
            ),
          ]),
        ),
        const SizedBox(height: 18),
        glassCard(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Logo Solola', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900)),
            const SizedBox(height: 12),
            TextField(controller: logoCtrl, decoration: const InputDecoration(labelText: 'URL du logo Solola')),
            const SizedBox(height: 10),
            FilledButton.icon(
              onPressed: () => widget.onLogoChanged(logoCtrl.text),
              icon: const Icon(Icons.image_outlined),
              label: const Text('Enregistrer logo'),
            ),
          ]),
        ),
        const SizedBox(height: 18),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            OutlinedButton.icon(
              onPressed: () => launchUrl(Uri.parse('${widget.api.baseUrl}/tracking'), mode: LaunchMode.externalApplication),
              icon: const Icon(Icons.admin_panel_settings_outlined),
              label: const Text('Ouvrir Solola Tracking'),
            ),
            OutlinedButton.icon(onPressed: () => sendFeedback(), icon: const Icon(Icons.mail_outline), label: const Text('Envoyer un avis')),
            OutlinedButton.icon(onPressed: () => widget.logout(), icon: const Icon(Icons.logout), label: const Text('Déconnexion')),
          ],
        ),
      ],
    );
  }

  Widget profileLine(String title, String value) {
    return ListTile(
      dense: true,
      title: Text(title, style: const TextStyle(color: Colors.grey)),
      subtitle: Text(value, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
    );
  }

  Widget profileAvatar({double radius = 48}) {
    final avatarUrl = widget.user['avatar_url'];
    if (avatarUrl != null && '$avatarUrl'.isNotEmpty) {
      return CircleAvatar(
        radius: radius,
        backgroundImage: NetworkImage(widget.api.fileUrl(avatarUrl)),
      );
    }

    return CircleAvatar(
      radius: radius,
      child: Text(initials(widget.user['pseudo']), style: TextStyle(fontSize: radius / 1.6)),
    );
  }

  Widget privacySwitch(String title, Map<String, dynamic> privacy, String key) {
    return SwitchListTile(
      contentPadding: EdgeInsets.zero,
      value: privacy[key] == true,
      onChanged: (value) => savePrivacy(key, value),
      title: Text(title),
    );
  }

  Future<void> updateAvatar() async {
    try {
      final picked = await FilePicker.platform.pickFiles(type: FileType.image, withData: true);
      if (picked == null) return;

      final updated = await widget.api.upload('/auth/me/avatar', picked.files.single);
      await widget.updateUser(Map<String, dynamic>.from(updated));
      await refreshConversations();
      if (mounted) setState(() {});
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> editProfile() async {
    final pseudo = await textDialog(context, title: 'Profil', label: 'Nouveau pseudo');
    if (pseudo == null || pseudo.isEmpty) return;

    try {
      final updated = await widget.api.patch('/auth/me/profile', {
        'pseudo': pseudo,
        'info': widget.user['info'] ?? '',
      });

      await widget.updateUser(Map<String, dynamic>.from(updated));
      await refreshConversations();
      if (mounted) setState(() {});
    } catch (e) {
      showToast(e);
    }
  }

  Future<void> savePrivacy(String key, bool value) async {
    final privacy = Map<String, dynamic>.from(widget.user['privacy'] ?? {});
    privacy[key] = value;

    try {
      final updated = await widget.api.patch('/auth/me/privacy', {
        'show_online': privacy['show_online'] ?? true,
        'allow_calls': privacy['allow_calls'] ?? true,
        'allow_group_invites': privacy['allow_group_invites'] ?? true,
        'show_avatar': privacy['show_avatar'] ?? true,
      });

      await widget.updateUser(Map<String, dynamic>.from(updated));
      await refreshConversations();
      if (mounted) setState(() {});
    } catch (e) {
      showToast(e);
    }
  }

  Widget helpPage() {
    return ListView(
      padding: const EdgeInsets.all(22),
      children: const [
        Text('Aide / À propos', style: TextStyle(fontSize: 30, fontWeight: FontWeight.w900)),
        SizedBox(height: 14),
        Card(
          child: Padding(
            padding: EdgeInsets.all(18),
            child: Text(
              'Solola Flutter est un prototype de messagerie sécurisée. '
              'Le PIN reste côté application et n’est jamais envoyé au serveur.',
            ),
          ),
        ),
        Card(
          child: Padding(
            padding: EdgeInsets.all(18),
            child: Text(
              'Solola Tracking est séparé de Solola. '
              'Il conserve les preuves : utilisateurs, heures, fichiers, statuts, SHA-256 et audit.',
            ),
          ),
        ),
      ],
    );
  }

  void sendFeedback() {
    launchUrl(
      Uri.parse('mailto:kalodave708@gmail.com?subject=Avis%20Solola&body=Bonjour,%20voici%20mon%20avis%20sur%20Solola%20:%20'),
    );
  }

  void showToast(Object error) {
    if (!mounted) return;
    final message = '$error'.replaceFirst('Exception: ', '');
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }
}

String initials(dynamic value) {
  final text = '${value ?? '?'}'.trim();
  if (text.isEmpty) return '?';
  return text.substring(0, text.length < 2 ? text.length : 2).toUpperCase();
}

String previewMessage(dynamic message) {
  if (message == null) return 'Aucun message';
  if (message['message_type'] == 'encrypted_text') return '🔐 Message chiffré';
  if (message['file'] != null) return '📎 ${message['file']['original_filename']}';
  return '${message['content'] ?? ''}';
}

String formatHour(dynamic isoValue) {
  try {
    if (isoValue == null) return '';
    return DateTime.parse('$isoValue').toLocal().toString().substring(11, 16);
  } catch (_) {
    return '';
  }
}

Future<String?> textDialog(
  BuildContext context, {
  required String title,
  required String label,
  bool obscure = false,
  bool requiredValue = true,
}) {
  final controller = TextEditingController();

  return showDialog<String>(
    context: context,
    builder: (dialogContext) {
      return AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          obscureText: obscure,
          decoration: InputDecoration(labelText: label),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Annuler'),
          ),
          FilledButton(
            onPressed: () {
              if (requiredValue && controller.text.trim().isEmpty) return;
              Navigator.pop(dialogContext, controller.text.trim());
            },
            child: const Text('OK'),
          ),
        ],
      );
    },
  );
}

Future<Map<String, String>?> temporarySecureDialog(BuildContext context) {
  final pinCtrl = TextEditingController();
  final hintCtrl = TextEditingController();

  return showDialog<Map<String, String>>(
    context: context,
    builder: (dialogContext) {
      return AlertDialog(
        title: const Text('Chiffrement temporaire'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Plusieurs messages seront chiffrés jusqu’à désactivation.'),
            TextField(
              controller: pinCtrl,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'PIN'),
            ),
            TextField(
              controller: hintCtrl,
              decoration: const InputDecoration(labelText: 'Indice'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Annuler'),
          ),
          FilledButton(
            onPressed: () {
              if (pinCtrl.text.isEmpty) return;
              Navigator.pop(dialogContext, {
                'pin': pinCtrl.text,
                'hint': hintCtrl.text.trim(),
                'mode': 'temporary_secure',
              });
            },
            child: const Text('Activer'),
          ),
        ],
      );
    },
  );
}

Future<Map<String, String>?> secureConversationDialog(BuildContext context) {
  final phoneCtrl = TextEditingController();
  final pinCtrl = TextEditingController();
  final hintCtrl = TextEditingController();

  return showDialog<Map<String, String>>(
    context: context,
    builder: (dialogContext) {
      return AlertDialog(
        title: const Text('Conversation sécurisée'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: phoneCtrl,
              decoration: const InputDecoration(labelText: 'Numéro'),
            ),
            TextField(
              controller: pinCtrl,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'PIN'),
            ),
            TextField(
              controller: hintCtrl,
              decoration: const InputDecoration(labelText: 'Indice'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Annuler'),
          ),
          FilledButton(
            onPressed: () {
              if (phoneCtrl.text.trim().isEmpty || pinCtrl.text.isEmpty) return;
              Navigator.pop(dialogContext, {
                'phone': phoneCtrl.text.trim(),
                'pin': pinCtrl.text,
                'hint': hintCtrl.text.trim(),
              });
            },
            child: const Text('Créer'),
          ),
        ],
      );
    },
  );
}

Future<Map<String, dynamic>?> groupDialog(BuildContext context, {required bool secure}) {
  final titleCtrl = TextEditingController();
  final membersCtrl = TextEditingController();
  final pinCtrl = TextEditingController();
  final hintCtrl = TextEditingController();

  return showDialog<Map<String, dynamic>>(
    context: context,
    builder: (dialogContext) {
      return AlertDialog(
        title: Text(secure ? 'Groupe sécurisé' : 'Nouveau groupe'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: titleCtrl,
                decoration: const InputDecoration(labelText: 'Nom du groupe'),
              ),
              TextField(
                controller: membersCtrl,
                decoration: const InputDecoration(labelText: 'Numéros séparés par virgule'),
              ),
              if (secure)
                TextField(
                  controller: pinCtrl,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'PIN'),
                ),
              if (secure)
                TextField(
                  controller: hintCtrl,
                  decoration: const InputDecoration(labelText: 'Indice'),
                ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Annuler'),
          ),
          FilledButton(
            onPressed: () {
              if (titleCtrl.text.trim().isEmpty) return;
              if (secure && pinCtrl.text.isEmpty) return;

              Navigator.pop(dialogContext, {
                'title': titleCtrl.text.trim(),
                'member_phone_numbers': membersCtrl.text
                    .split(',')
                    .map((item) => item.trim())
                    .where((item) => item.isNotEmpty)
                    .toList(),
                if (secure) 'is_secure': true,
                if (secure) 'security_hint': hintCtrl.text.trim(),
                if (secure) 'pin': pinCtrl.text,
              });
            },
            child: const Text('Créer'),
          ),
        ],
      );
    },
  );
}
