#include "airlevi-handshake/handshake_capture.h"
#include <iostream>
#include <string>
#include <unistd.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include <cstdio>

HandshakeCapture* g_capture = nullptr;

static bool parseMacString(const std::string& mac_str, MacAddress& out) {
    unsigned int b[6];
    if (std::sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) return false;
    for (int i = 0; i < 6; ++i) out.bytes[i] = static_cast<uint8_t>(b[i] & 0xFF);
    return true;
}

void signalHandler(int signum) {
    if (g_capture) {
        std::cout << "\n[!] Signal received, stopping capture..." << std::endl;
        g_capture->stopCapture();
    }
    exit(signum);
}

void printUsage(const std::string& app_name) {
    std::cout << "AirLevi-NG Handshake Capture Tool v1.0\n";
    std::cout << "Usage: " << app_name << " -i <interface> -o <output.pcap> [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  -i <interface>      Wireless interface in monitor mode\n";
    std::cout << "  -o <output.pcap>    File to save captured handshakes\n\n";
    std::cout << "Optional:\n";
    std::cout << "  -b <bssid>          Target a specific BSSID\n";
    std::cout << "  -e <ssid>           Target a specific SSID\n";
    std::cout << "  -c <channel>        Lock capture to a specific channel (disables hopping)\n";
    std::cout << "  -d                  Enable deauthentication attack to speed up capture\n";
    std::cout << "  -h                  Show this help message\n";
}

int main(int argc, char* argv[]) {
    if (geteuid() != 0) {
        std::cerr << "[-] This program must be run as root." << std::endl;
        return 1;
    }

    std::string interface, output_file, bssid_str, ssid_str;
    int channel = 0;
    bool deauth_attack = false;

    int opt;
    while ((opt = getopt(argc, argv, "i:o:b:e:c:dh")) != -1) {
        switch (opt) {
            case 'i': interface = optarg; break;
            case 'o': output_file = optarg; break;
            case 'b': bssid_str = optarg; break;
            case 'e': ssid_str = optarg; break;
            case 'c': channel = std::atoi(optarg); break;
            case 'd': deauth_attack = true; break;
            case 'h':
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    if (interface.empty() || output_file.empty()) {
        std::cerr << "[-] Interface and output file are required." << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    HandshakeCapture capture;
    g_capture = &capture;
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    if (!capture.initialize(interface, output_file)) {
        return 1;
    }

    if (!bssid_str.empty()) {
        MacAddress mac;
        if (!parseMacString(bssid_str, mac)) {
            std::cerr << "[-] Invalid BSSID format." << std::endl;
            return 1;
        }
        capture.setTargetBSSID(mac);
    }

    if (!ssid_str.empty()) {
        capture.setTargetSSID(ssid_str);
    }

    if (channel > 0) {
        capture.setChannel(channel);
    }

    if (deauth_attack) {
        capture.setDeauthAttack(true);
    }

    if (!capture.startCapture()) {
        std::cerr << "[-] Failed to start capture." << std::endl;
        return 1;
    }

    // Display loop
    while (g_capture->getStats().runtime_seconds < 3600 * 24) { // 24h timeout
        capture.displayStatus();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    capture.stopCapture();

    std::cout << "\n[+] Final Stats:" << std::endl;
    HandshakeStats final_stats = capture.getStats();
    std::cout << "  - Handshakes captured: " << final_stats.handshakes_captured << std::endl;
    std::cout << "  - APs discovered: " << final_stats.aps_found << std::endl;
    std::cout << "  - Total packets processed: " << final_stats.packets_processed << std::endl;

    return 0;
}
