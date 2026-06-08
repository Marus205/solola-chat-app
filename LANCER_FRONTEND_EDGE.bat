@echo off
cd /d "%~dp0frontend_flutter"
flutter clean
flutter pub get
flutter run -d edge
pause
