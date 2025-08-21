#include "airlevi-forge/packet_forge.h"
#include "common/logger.h"
#include <iostream>
#include <getopt.h>
#include <signal.h>
#include <cstdio>

using namespace airlevi;

static bool running = true;

// Helper to parse a MAC string like AA:BB:CC:DD:EE:FF into MacAddress
static bool parseMacString(const std::string& mac_str, MacAddress& out) {
    unsigned int b[6];
    if (std::sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; ++i) out.bytes[i] = static_cast<uint8_t>(b[i] & 0xFF);
    return true;
}

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", stopping forge..." << std::endl;
    running = false;
}

void printUsage(const char* program) {
    std::cout << "AirLevi-NG Packet Forge Tool v1.0\n\n";
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  -i, --interface <iface>    Wireless interface for injection\n\n";
    std::cout << "Packet Types:\n";
    std::cout << "  --beacon <ssid>            Create beacon frame\n";
    std::cout << "  --probe-req <ssid>         Create probe request\n";
    std::cout << "  --deauth                   Create deauth frame\n";
    std::cout << "  --evil-twin <ssid>         Create evil twin beacon\n";
    std::cout << "  --wps-beacon <ssid>        Create WPS beacon\n\n";
    std::cout << "Options:\n";
    std::cout << "  -b, --bssid <mac>          Target BSSID\n";
    std::cout << "  -c, --client <mac>         Target client MAC\n";
    std::cout << "  -s, --source <mac>         Source MAC address\n";
    std::cout << "  -ch, --channel <num>       WiFi channel (1-14)\n";
    std::cout << "  -e, --encryption <type>    Encryption (WPA/WPA2)\n";
    std::cout << "  -n, --count <num>          Number of packets to send\n";
    std::cout << "  -d, --delay <us>           Delay between packets (microseconds)\n";
    std::cout << "  -r, --reason <code>        Reason code for deauth/disassoc\n";
    std::cout << "  --locked                   WPS locked state\n";
    std::cout << "  -v, --verbose              Enable verbose output\n";
    std::cout << "  -h, --help                 Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program << " -i wlan0mon --beacon \"FreeWiFi\" -ch 6\n";
    std::cout << "  " << program << " -i wlan0mon --deauth -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66\n";
    std::cout << "  " << program << " -i wlan0mon --evil-twin \"Starbucks\" -ch 11 -n 100\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::string interface, ssid, bssid, client, source, encryption = "WPA2";
    std::string packet_type;
    int channel = 6, count = 1, delay = 1000, reason = 7;
    bool verbose = false, wps_locked = false;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"beacon", required_argument, 0, 1001},
        {"probe-req", required_argument, 0, 1002},
        {"deauth", no_argument, 0, 1003},
        {"evil-twin", required_argument, 0, 1004},
        {"wps-beacon", required_argument, 0, 1005},
        {"bssid", required_argument, 0, 'b'},
        {"client", required_argument, 0, 'c'},
        {"source", required_argument, 0, 's'},
        {"channel", required_argument, 0, 1006},
        {"encryption", required_argument, 0, 'e'},
        {"count", required_argument, 0, 'n'},
        {"delay", required_argument, 0, 'd'},
        {"reason", required_argument, 0, 'r'},
        {"locked", no_argument, 0, 1007},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:b:c:s:e:n:d:r:vh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 1001:
                packet_type = "beacon";
                ssid = optarg;
                break;
            case 1002:
                packet_type = "probe-req";
                ssid = optarg;
                break;
            case 1003:
                packet_type = "deauth";
                break;
            case 1004:
                packet_type = "evil-twin";
                ssid = optarg;
                break;
            case 1005:
                packet_type = "wps-beacon";
                ssid = optarg;
                break;
            case 'b':
                bssid = optarg;
                break;
            case 'c':
                client = optarg;
                break;
            case 's':
                source = optarg;
                break;
            case 1006:
                channel = std::stoi(optarg);
                break;
            case 'e':
                encryption = optarg;
                break;
            case 'n':
                count = std::stoi(optarg);
                break;
            case 'd':
                delay = std::stoi(optarg);
                break;
            case 'r':
                reason = std::stoi(optarg);
                break;
            case 1007:
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
    
    if (interface.empty() || packet_type.empty()) {
        std::cerr << "Error: Interface and packet type are required\n";
        printUsage(argv[0]);
        return 1;
    }
    
    Logger::getInstance().setVerbose(verbose);
    
    try {
        PacketForge forge;
        
        if (!forge.initialize(interface)) {
            std::cerr << "Failed to initialize interface: " << interface << std::endl;
            return 1;
        }
        
        std::vector<uint8_t> packet;
        
        // Create packet based on type
        if (packet_type == "beacon") {
            if (ssid.empty() || bssid.empty()) {
                std::cerr << "Error: SSID and BSSID required for beacon\n";
                return 1;
            }
            MacAddress bssid_mac;
            if (!parseMacString(bssid, bssid_mac)) { std::cerr << "Invalid BSSID format\n"; return 1; }
            packet = forge.createBeacon(ssid, bssid_mac, channel, encryption);
            
        } else if (packet_type == "probe-req") {
            if (ssid.empty() || source.empty()) {
                std::cerr << "Error: SSID and source MAC required for probe request\n";
                return 1;
            }
            MacAddress src_mac;
            if (!parseMacString(source, src_mac)) { std::cerr << "Invalid source MAC format\n"; return 1; }
            packet = forge.createProbeRequest(ssid, src_mac);
            
        } else if (packet_type == "deauth") {
            if (bssid.empty() || client.empty()) {
                std::cerr << "Error: BSSID and client MAC required for deauth\n";
                return 1;
            }
            MacAddress bssid_mac, client_mac;
            if (!parseMacString(bssid, bssid_mac) || !parseMacString(client, client_mac)) { std::cerr << "Invalid MAC format\n"; return 1; }
            packet = forge.createDeauth(bssid_mac, client_mac, reason);
            
        } else if (packet_type == "evil-twin") {
            if (ssid.empty() || bssid.empty()) {
                std::cerr << "Error: SSID and BSSID required for evil twin\n";
                return 1;
            }
            MacAddress bssid_mac;
            if (!parseMacString(bssid, bssid_mac)) { std::cerr << "Invalid BSSID format\n"; return 1; }
            packet = forge.createEvilTwinBeacon(ssid, bssid_mac, channel);
            
        } else if (packet_type == "wps-beacon") {
            if (ssid.empty() || bssid.empty()) {
                std::cerr << "Error: SSID and BSSID required for WPS beacon\n";
                return 1;
            }
            MacAddress bssid_mac;
            if (!parseMacString(bssid, bssid_mac)) { std::cerr << "Invalid BSSID format\n"; return 1; }
            packet = forge.createWPSBeacon(ssid, bssid_mac, channel, wps_locked);
        }
        
        if (packet.empty()) {
            std::cerr << "Failed to create packet\n";
            return 1;
        }
        
        std::cout << "\n=== AirLevi-NG Packet Forge ===\n";
        std::cout << "Interface: " << interface << "\n";
        std::cout << "Packet Type: " << packet_type << "\n";
        if (!ssid.empty()) std::cout << "SSID: " << ssid << "\n";
        if (!bssid.empty()) std::cout << "BSSID: " << bssid << "\n";
        if (!client.empty()) std::cout << "Client: " << client << "\n";
        std::cout << "Channel: " << channel << "\n";
        std::cout << "Count: " << count << "\n";
        std::cout << "Delay: " << delay << " μs\n";
        std::cout << "Packet Size: " << packet.size() << " bytes\n";
        std::cout << "==============================\n\n";
        
        // Inject packets
        std::cout << "Injecting packets";
        for (int i = 0; i < count && running; i++) {
            if (forge.injectPacket(packet)) {
                std::cout << "." << std::flush;
            } else {
                std::cout << "X" << std::flush;
            }
            
            if (delay > 0 && i < count - 1) {
                usleep(delay);
            }
        }
        std::cout << " Done!\n\n";
        
        forge.printStats();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
