# USAGE – AirLevi-NG

Ce document décrit l’utilisation des binaires générés par le projet. Tous les outils nécessitent généralement des privilèges root pour la capture/injection.

Note: adaptez l’interface (ex: wlan0mon) à votre système et passez l’interface en mode moniteur si requis.

---

## airlevi-monitor
Scan et monitoring avancé (AP/clients/handshakes) avec mode interactif.

Usage:
```
airlevi-monitor -i <iface> [options]
```
Options clés:
- -i, --interface IFACE
- -c, --channel NUM (désactive le hopping)
- -H, --hop (active channel hopping, défaut)
- -t, --time MS (dwell time, défaut 250)
- -b, --bssid MAC (cible)
- -e, --essid SSID (cible)
- -s, --signal dBm (min)
- -w, --write FILE (sauver session)
- --csv FILE (export CSV)
- --handshakes FILE (sauver handshakes)
- -v, --verbose
- -h, --help

Interactif: n (networks), c (clients), s (channel stats), h (handshakes), r (stats), q (quit)

Exemples:
```
sudo ./build/airlevi-monitor -i wlan0mon
sudo ./build/airlevi-monitor -i wlan0mon -c 6 -b 00:11:22:33:44:55 --csv nets.csv
```

---

## airlevi-handshake
Capture de handshakes WPA/WPA2 avec sauvegarde PCAP.

Usage:
```
airlevi-handshake -i <iface> -o <output.pcap> [options]
```
Options:
- -i IFACE (requis), -o FILE (requis)
- -b BSSID (cible), -e SSID (cible)
- -c CHANNEL (verrouille le canal)
- -d (active un deauth pour accélérer)
- -h help

Exemples:
```
sudo ./build/airlevi-handshake -i wlan0mon -o handshakes.pcap
sudo ./build/airlevi-handshake -i wlan0mon -o out.pcap -b 00:11:22:33:44:55 -c 6 -d
```

---

## airlevi-pmkid
Collecte de PMKID + cracking offline (wordlist) + export CSV/hashcat. Mode interactif intégré.

Usage:
```
airlevi-pmkid -i <iface> [options]
```
Options:
- -i IFACE (requis)
- -b BSSID (cible), -e SSID (cible)
- -c CHANNEL (désactive hopping), -C (active hopping)
- -d MS (dwell time, défaut 250)
- -w FILE (wordlist), -o FILE (export résultats), -f csv|hashcat
- -t SECS (timeout, sinon interactif)
- -h help

Mode interactif (extraits):
- status/s, targets/t, results/r
- channel <ch>, hop <on|off>
- target <bssid>, wordlist <file>, export <file> [csv|hashcat]

Exemples:
```
sudo ./build/airlevi-pmkid -i wlan0mon -C -d 500 -o results.csv -f csv
sudo ./build/airlevi-pmkid -i wlan0mon -b 00:11:22:33:44:55 -w wl.txt -t 60
```

---

## airlevi-beacon
Génère un AP rogue (evil‑twin/karma/captive/wps/honeypot), beacons, flood.

Usage:
```
airlevi-beacon -i <iface> -e <ssid> [options]
```
Options:
- Requis: -i IFACE, -e SSID
- -b BSSID, -c CHANNEL, -E OPEN|WEP|WPA|WPA2, -p PASSWORD
- -m evil-twin|karma|captive|wps|honeypot
- --target-ssid SSID, --target-bssid MAC
- --karma, --captive URL, --beacon-flood N, --fake-ssid SSID (multi), --interval MS
- --hidden, --wps, --wps-locked
- -v, -h

Exemples:
```
sudo ./build/airlevi-beacon -i wlan0mon -e "FreeWiFi" -c 6
sudo ./build/airlevi-beacon -i wlan0mon -e "Cafe" -m evil-twin --target-ssid "Cafe_WiFi"
```

---

## airlevi-wps
Scan WPS et attaques Pixie/Reaver/Brute/Null.

Usage:
```
airlevi-wps -i <iface> [ -S | -b <bssid> ... ] [options]
```
Options:
- Requis pour attaque: -i IFACE et -b BSSID (ou -S pour scan)
- Types: -P (pixie, défaut), -R (reaver), -B (brute), -N (null)
- -c CHANNEL, -p PIN, -w WORDLIST, -d DELAY, -t TIMEOUT, -m MAX_ATTEMPTS
- -o FILE (sauvegarde résultats), -S scan, -v, -h

Exemples:
```
sudo ./build/airlevi-wps -i wlan0mon -S
sudo ./build/airlevi-wps -i wlan0mon -b AA:BB:CC:DD:EE:FF -R -d 2
```

---

## airlevi-forge
Forge et injection de trames (beacon, probe-req, deauth, evil-twin, wps-beacon).

Usage:
```
airlevi-forge -i <iface> [--beacon SSID|--probe-req SSID|--deauth|--evil-twin SSID|--wps-beacon SSID] [options]
```
Options:
- -b BSSID, -c CLIENT, -s SOURCE, -ch CHANNEL, -e WPA|WPA2, -n COUNT, -d DELAY_US, -r REASON, --locked, -v, -h

Exemples:
```
sudo ./build/airlevi-forge -i wlan0mon --beacon "FreeWiFi" -ch 6 -b 00:11:22:33:44:55
sudo ./build/airlevi-forge -i wlan0mon --deauth -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 -n 10 -d 2000
```

---

## airlevi-dump
Capture générique + scanner + affichage stats.

Usage:
```
airlevi-dump [options]
```
Options:
- -i IFACE, -c CHANNEL, -w FILE, -b BSSID, -e ESSID, -t TIMEOUT, -v, -h, --hop, --monitor

Exemples:
```
./build/airlevi-dump -i wlan0 --monitor
./build/airlevi-dump -i wlan0 -c 6 -w capture.cap
```

---

## airlevi-deauth
Envoi de trames deauth (broadcast/target).

Usage:
```
airlevi-deauth -i IFACE -a BSSID [options]
```
Options:
- -a BSSID (requis), -c CLIENT, -n COUNT (0=inf), -d MS, -r REASON, -v, -h, --broadcast, --monitor

Exemples:
```
./build/airlevi-deauth -i wlan0 -a 00:11:22:33:44:55 --monitor
./build/airlevi-deauth -i wlan0 -a 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF -n 50
```

---

## airlevi-replay
Relecture d’un fichier de capture (modes: single, continuous, burst, timed).

Usage:
```
airlevi-replay -i IFACE -r FILE [options]
```
Options:
- -m MODE, -d DELAY_US, -c COUNT, -b BURST, -s SPEED, -t TARGET_MAC, -f FROM_MAC, -v, -h

Exemples:
```
./build/airlevi-replay -i wlan0mon -r capture.cap -m burst -b 50
```

---

## airlevi-mon
Gestion du mode moniteur et des interfaces.

Usage:
```
airlevi-mon [command] [options]
```
Commandes:
- start IFACE, stop IFACE
- check | check kill
- list
- create IFACE
- remove IFACE
- channel IFACE CH
Options: -v, -h

Exemples:
```
./build/airlevi-mon start wlan0
./build/airlevi-mon channel wlan0mon 6
```

---

## airlevi-lib (password database util)
Gestion d’une base de mots de passe/PMK.

Usage:
```
airlevi-lib DB [--create|--import-essid SSID|--import SSID FILE|--compute SSID|--stats|--list-essids|--verify|--vacuum] [-v]
```
Exemples:
```
./build/airlevi-lib mydb.db --create
./build/airlevi-lib mydb.db --import-essid "MyWiFi"
./build/airlevi-lib mydb.db --import "MyWiFi" wordlist.txt
./build/airlevi-lib mydb.db --compute "MyWiFi"
```

---

## airlevi-serv
Petit serveur réseau (télémétrie/contrôle selon impl.).

Usage:
```
airlevi-serv [-p PORT] [-i IFACE] [-v]
```
Exemples:
```
./build/airlevi-serv -p 8080
```

---

## airlevi-suite
Menu interactif regroupant les outils.

Usage:
```
airlevi-suite
```

---

## Notes générales
- Exécuter avec `sudo` lorsque nécessaire.
- Certaines fonctions nécessitent des chipsets/drivers compatibles injection/monitor.
- Formats d’export PMKID: CSV, Hashcat.
- Les adresses MAC doivent être au format `AA:BB:CC:DD:EE:FF`.
