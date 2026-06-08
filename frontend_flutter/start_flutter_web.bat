@echo off
cd /d "%~dp0"
if not exist web flutter create .
flutter pub get
flutter run -d chrome
