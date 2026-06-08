@echo off
cd /d "%~dp0"
flutter clean
flutter pub get
flutter analyze
flutter run -d edge
