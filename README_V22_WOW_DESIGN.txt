SOLOLA V22 - WOW DESIGN + doublons statuts corrigés

Corrections principales :
- Design global inspiré du logo : fond sombre cyan/bleu/violet, navigation rail premium, cartes glassmorphism.
- Page Statuts retravaillée avec cartes plus propres.
- Correction du doublon des statuts : le statut n'est plus ajouté deux fois quand le WebSocket renvoie le même événement.
- Les pages Statuts / Paramètres / Aide restent affichées une seule fois en grand écran.
- Backend corrigé conservé : suppression de statut, upload avatar Flutter Web, OTP.

Lancement :
1. Backend
cd /d "D:\solola_flutter_secure_v22_wow_design\backend"
start_backend.bat

2. Frontend
cd /d "D:\solola_flutter_secure_v22_wow_design\frontend_flutter"
flutter clean
flutter pub get
flutter run -d edge

Important : ne mélange pas avec V17/V18/V19/V21. Lance backend et frontend depuis ce même dossier V22.
