# AirLevi-NG

Suite d'outils Wi‑Fi (recherche, capture, injection, attaques de test) pour chercheurs en sécurité et pentesters. Objectif: fournir un environnement moderne (C++/CMake/libpcap/OpenSSL) pour analyser, forger et tester des trames IEEE 802.11.

IMPORTANT: Utilisation strictement légale et éthique. Vous êtes seul responsable de l'usage. Ne testez QUE sur des réseaux dont vous êtes propriétaire ou avec autorisation explicite.

## Fonctionnalités clés
- __Monitor/Analyse__: scan d’AP/clients, affichage en temps réel, parsing de trames.
- __Capture Handshake WPA/WPA2__: identification, sauvegarde PCAP, stats.
- __PMKID attack__: collecte PMKID, export Hashcat/CSV, cracking offline (via wordlist).
- __Beacon/Rogue AP__: émission de beacons (evil‑twin, WPS IE, flood), modes karma/captive (selon build).
- __WPS__: scan WPS, ciblage BSSID.
- __Forge__: génération de trames (beacon, probe, deauth) et injection.
- __Lib réseau__: gestion interface, canal, MAC, parsing commun.

## Arborescence du projet
- `include/` headers publics (ex: `common/types.h`, `airlevi-*/...`)
- `src/` implémentations par module
  - `airlevi-monitor/` monitor/scan
  - `airlevi-handshake/` capture handshake
  - `airlevi-pmkid/` PMKID attack
  - `airlevi-beacon/` rogue AP / beacons
  - `airlevi-wps/` WPS
  - `airlevi-forge/` forgeur/injection
  - `common/` utilitaires (interface réseau, parser, logger)
- `CMakeLists.txt` build multi‑binaire

## Prérequis
- Linux (mode moniteur requis)
- Outils/Libs: `gcc/g++` (>= 11 recommandé), `cmake` (>= 3.16), `make`
- Dépendances: `libpcap-dev`, `libssl-dev` (OpenSSL)
- Droits root pour la capture/injection (`sudo`)

Sur Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libssl-dev
```

## Compilation
```bash
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```
Les binaires seront générés sous `build/` (un exécutable par sous‑outil, ex: `airlevi-monitor`, `airlevi-pmkid`, etc.).

## Mise en mode moniteur (exemples)
```bash
# Exemple avec airmon-ng (selon distribution)
sudo airmon-ng start wlan0
# ou via iw
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

## Démarrage rapide
- __Scan/monitoring__:
```bash
sudo ./build/airlevi-monitor -i wlan0mon
```
- __Capture Handshake WPA/WPA2__:
```bash
sudo ./build/airlevi-handshake -i wlan0mon -o handshakes.pcap -d
```
- __PMKID (collecte + export)__:
```bash
sudo ./build/airlevi-pmkid -i wlan0mon -C -d 500 -o results.csv -f csv
```
- __Beacon evil‑twin simple__:
```bash
sudo ./build/airlevi-beacon -i wlan0mon --ssid "CafeFree" --channel 6
```
- __Forge: deauth ciblée__ (exemple générique):
```bash
sudo ./build/airlevi-forge deauth --bssid 00:11:22:33:44:55 --client aa:bb:cc:dd:ee:ff --count 10
```
- __WPS scan__:
```bash
sudo ./build/airlevi-wps -i wlan0mon --scan
```

Plus de détails d’options et d’exemples: voir `USAGE.md`.

## Bonnes pratiques & sécurité
- __Légal__: testez uniquement des réseaux autorisés.
- __Isolation__: utilisez un environnement dédié (VM, adaptateur USB).
- __Journalisation__: consultez la sortie et les logs (`common/logger.h`).
- __Compatibilité__: certaines fonctionnalités dépendent du chipset/driver.

## Dépannage rapide
- "pcap_open_live/create failed": droits root ou interface invalide.
- Aucun paquet vu: l’interface n’est pas en mode moniteur / mauvais canal.
- Injection échoue: driver ou chipset non supporté pour l’injection.
- Erreurs OpenSSL: installez/liez `libssl-dev`.

## Contribution
- Fork, branche feature, PR avec description claire.
- Respecter le style existant C++17, passer `-Wall -Wextra` sans erreurs.

## Licence
Ce projet est sous licence MIT (voir `LICENSE`).
