#include "airlevi-beacon/rogue_ap.h"
#include "common/logger.h"
#include <iostream>
#include <getopt.h>
#include <signal.h>
#include <cstdio>
#include <random>

using namespace airlevi;

static bool running = true;
static RogueAP* ap_instance = nullptr;

// Helpers
static bool parseMacString(const std::string& mac_str, MacAddress& out) {
    unsigned int b[6];
    if (std::sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) return false;
    for (int i = 0; i < 6; ++i) out.bytes[i] = static_cast<uint8_t>(b[i] & 0xFF);
    return true;
}

static MacAddress randomMac() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    MacAddress m;
    for (int i = 0; i < 6; ++i) m.bytes[i] = static_cast<uint8_t>(dist(gen));
    // Set locally administered, unicast
    m.bytes[0] = (m.bytes[0] | 0x02) & 0xFE;
    return m;
}

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", stopping AP..." << std::endl;
    running = false;
    if (ap_instance) {
        ap_instance->stopAP();
    }
}

void printUsage(const char* program) {
    std::cout << "AirLevi-NG Rogue AP Tool v1.0\n\n";
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  -i, --interface <iface>    Monitor mode interface\n";
    std::cout << "  -e, --essid <ssid>         AP SSID\n\n";
    std::cout << "Options:\n";
    std::cout << "  -b, --bssid <mac>          AP BSSID (random if not set)\n";
    std::cout << "  -c, --channel <num>        WiFi channel (default: 6)\n";
    std::cout << "  -E, --encryption <type>    Encryption (OPEN/WEP/WPA/WPA2)\n";
    std::cout << "  -p, --password <pass>      Network password\n";
    std::cout << "  -m, --mode <mode>          AP mode (evil-twin/karma/captive/wps/honeypot)\n";
    std::cout << "  --target-ssid <ssid>       Target SSID for evil twin\n";
    std::cout << "  --target-bssid <mac>       Target BSSID for evil twin\n";
    std::cout << "  --karma                    Enable Karma mode\n";
    std::cout << "  --captive <url>            Captive portal redirect URL\n";
    std::cout << "  --beacon-flood <count>     Enable beacon flood with count\n";
    std::cout << "  --fake-ssid <ssid>         Add fake SSID for beacon flood\n";
    std::cout << "  --interval <ms>            Beacon interval (default: 100ms)\n";
    std::cout << "  --hidden                   Hidden SSID\n";
    std::cout << "  --wps                      Enable WPS\n";
    std::cout << "  --wps-locked               WPS locked state\n";
    std::cout << "  -v, --verbose              Enable verbose output\n";
    std::cout << "  -h, --help                 Show this help\n\n";
    std::cout << "Interactive Commands:\n";
    std::cout << "  's' - Show AP status\n";
    std::cout << "  'c' - Show connected clients\n";
    std::cout << "  'k' - Kick all clients\n";
    std::cout << "  'r' - Show real-time stats\n";
    std::cout << "  'q' - Quit\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program << " -i wlan0mon -e \"FreeWiFi\" -c 6\n";
    std::cout << "  " << program << " -i wlan0mon -e \"Starbucks\" -m evil-twin --target-ssid \"Starbucks_WiFi\"\n";
    std::cout << "  " << program << " -i wlan0mon -e \"HoneyPot\" -m karma --beacon-flood 20\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::string interface, ssid, bssid, password, encryption = "OPEN";
    std::string mode_str = "evil-twin", target_ssid, target_bssid, captive_url;
    std::vector<std::string> fake_ssids;
    int channel = 6, beacon_interval = 100, beacon_flood_count = 0;
    bool verbose = false, hidden = false, wps_enabled = false, wps_locked = false;
    bool karma_mode = false;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"essid", required_argument, 0, 'e'},
        {"bssid", required_argument, 0, 'b'},
        {"channel", required_argument, 0, 'c'},
        {"encryption", required_argument, 0, 'E'},
        {"password", required_argument, 0, 'p'},
        {"mode", required_argument, 0, 'm'},
        {"target-ssid", required_argument, 0, 1001},
        {"target-bssid", required_argument, 0, 1002},
        {"karma", no_argument, 0, 1003},
        {"captive", required_argument, 0, 1004},
        {"beacon-flood", required_argument, 0, 1005},
        {"fake-ssid", required_argument, 0, 1006},
        {"interval", required_argument, 0, 1007},
        {"hidden", no_argument, 0, 1008},
        {"wps", no_argument, 0, 1009},
        {"wps-locked", no_argument, 0, 1010},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:e:b:c:E:p:m:vh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'e':
                ssid = optarg;
                break;
            case 'b':
                bssid = optarg;
                break;
            case 'c':
                channel = std::stoi(optarg);
                break;
            case 'E':
                encryption = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'm':
                mode_str = optarg;
                break;
            case 1001:
                target_ssid = optarg;
                break;
            case 1002:
                target_bssid = optarg;
                break;
            case 1003:
                karma_mode = true;
                break;
            case 1004:
                captive_url = optarg;
                break;
            case 1005:
                beacon_flood_count = std::stoi(optarg);
                break;
            case 1006:
                fake_ssids.push_back(optarg);
                break;
            case 1007:
                beacon_interval = std::stoi(optarg);
                break;
            case 1008:
                hidden = true;
                break;
            case 1009:
                wps_enabled = true;
                break;
            case 1010:
                wps_locked = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    if (interface.empty() || ssid.empty()) {
        std::cerr << "Error: Interface and SSID are required\n";
        printUsage(argv[0]);
        return 1;
    }
    
    Logger::getInstance().setVerbose(verbose);
    
    try {
        RogueAP rogue_ap;
        ap_instance = &rogue_ap;
        
        if (!rogue_ap.initialize(interface)) {
            std::cerr << "Failed to initialize interface: " << interface << std::endl;
            return 1;
        }
        
        // Configure AP
        APConfig config;
        config.ssid = ssid;
        if (bssid.empty()) {
            config.bssid = randomMac();
        } else {
            MacAddress mac;
            if (!parseMacString(bssid, mac)) { std::cerr << "Invalid BSSID format\n"; return 1; }
            config.bssid = mac;
        }
        config.channel = channel;
        config.encryption = encryption;
        config.password = password;
        config.beacon_interval = beacon_interval;
        config.hidden = hidden;
        config.wps_enabled = wps_enabled;
        config.wps_locked = wps_locked;
        
        if (!rogue_ap.configure(config)) {
            std::cerr << "Failed to configure AP\n";
            return 1;
        }
        
        // Set mode
        APMode mode = APMode::EVIL_TWIN;
        if (mode_str == "karma") mode = APMode::KARMA;
        else if (mode_str == "captive") mode = APMode::CAPTIVE_PORTAL;
        else if (mode_str == "wps") mode = APMode::WPS_FAKE;
        else if (mode_str == "honeypot") mode = APMode::HONEYPOT;
        
        rogue_ap.setMode(mode);
        
        if (!target_ssid.empty()) {
            rogue_ap.setTargetSSID(target_ssid);
        }
        
        if (!target_bssid.empty()) {
            MacAddress tb;
            if (!parseMacString(target_bssid, tb)) { std::cerr << "Invalid target BSSID format\n"; return 1; }
            rogue_ap.setTargetBSSID(tb);
        }
        
        if (karma_mode) {
            rogue_ap.enableKarmaMode(true);
        }
        
        if (!captive_url.empty()) {
            rogue_ap.setCaptivePortal(captive_url);
        }
        
        if (beacon_flood_count > 0) {
            rogue_ap.enableBeaconFlood(true, beacon_flood_count);
            for (const auto& fake_ssid : fake_ssids) {
                rogue_ap.addFakeSSID(fake_ssid);
            }
        }
        
        std::cout << "\n=== AirLevi-NG Rogue AP ===\n";
        std::cout << "Interface: " << interface << "\n";
        std::cout << "SSID: " << ssid << "\n";
        std::cout << "BSSID: " << config.bssid.toString() << "\n";
        std::cout << "Channel: " << channel << "\n";
        std::cout << "Mode: " << mode_str << "\n";
        std::cout << "Encryption: " << encryption << "\n";
        if (karma_mode) std::cout << "Karma Mode: Enabled\n";
        if (beacon_flood_count > 0) std::cout << "Beacon Flood: " << beacon_flood_count << " SSIDs\n";
        std::cout << "==========================\n\n";
        
        if (!rogue_ap.startAP()) {
            std::cerr << "Failed to start rogue AP\n";
            return 1;
        }
        
        std::cout << "Rogue AP started. Press 's' for status, 'q' to quit.\n";
        
        // Interactive mode
        char cmd;
        while (running && std::cin >> cmd) {
            switch (cmd) {
                case 's':
                    rogue_ap.displayAPStatus();
                    break;
                case 'c':
                    rogue_ap.displayClientTable();
                    break;
                case 'k':
                    rogue_ap.kickAllClients();
                    std::cout << "All clients kicked\n";
                    break;
                case 'r':
                    rogue_ap.displayRealTimeStats();
                    break;
                case 'q':
                    running = false;
                    break;
                default:
                    std::cout << "Unknown command. Press 's' for status, 'q' to quit.\n";
                    break;
            }
        }
        
        rogue_ap.stopAP();
        
        // Print final statistics
        auto stats = rogue_ap.getStats();
        std::cout << "\n=== Final Statistics ===\n";
        std::cout << "Beacons Sent: " << stats.beacons_sent << "\n";
        std::cout << "Auth Requests: " << stats.auth_requests << "\n";
        std::cout << "Clients Connected: " << stats.clients_total << "\n";
        std::cout << "========================\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
