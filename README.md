# Solola Flutter Secure V19 - Callbacks Flutter corrigés

Cette version corrige les erreurs restantes probables dans `main.dart`.

## Corrections ajoutées

1. Les callbacks async passés directement à `onPressed` / `onChanged` ont été encapsulés.

Avant :

```dart
onPressed: widget.logout
onChanged: widget.onDarkModeChanged
```

Après :

```dart
onPressed: () { widget.logout(); }
onChanged: (value) { widget.onDarkModeChanged(value); }
```

2. Le logo utilise maintenant correctement le widget `logo` construit dans `SololaLogo`.

3. `pubspec.yaml` est corrigé avec les dépendances et l'asset du logo.

4. Le backend garde la correction OTP `otp_codes`.

## Lancement backend

```bat
cd /d "D:\solola_flutter_secure_v19_compile_callbacks_fixed\backend"
start_backend.bat
```

## Lancement Flutter

```bat
cd /d "D:\solola_flutter_secure_v19_compile_callbacks_fixed\frontend_flutter"
flutter clean
flutter pub get
flutter analyze
flutter run -d edge
```

## Important

Si Flutter affiche :

```txt
Building with plugins requires symlink support
```

ouvre :

```bat
start ms-settings:developers
```

puis active `Mode développeur`.

## Fichier de test rapide

Dans le dossier `frontend_flutter`, tu peux aussi lancer :

```bat
check_flutter.bat
```
