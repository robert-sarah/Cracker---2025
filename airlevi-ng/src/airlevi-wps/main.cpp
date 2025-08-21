#include "airlevi-wps/wps_attack.h"
#include "common/logger.h"
#include <iostream>
#include <getopt.h>
#include <signal.h>

using namespace airlevi;

static bool running = true;
static WPSAttack* wps_instance = nullptr;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", stopping attack..." << std::endl;
    running = false;
    if (wps_instance) {
        // Stop attack gracefully
    }
}

void printUsage(const char* program) {
    std::cout << "AirLevi-NG WPS Attack Tool v1.0\n\n";
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  -i, --interface <iface>    Monitor mode interface\n";
    std::cout << "  -b, --bssid <mac>          Target BSSID\n\n";
    std::cout << "Attack Types:\n";
    std::cout << "  -P, --pixie-dust           Pixie Dust attack (default)\n";
    std::cout << "  -R, --reaver               Reaver-style attack\n";
    std::cout << "  -B, --brute-force          Brute force attack\n";
    std::cout << "  -N, --null-pin             Null PIN attack\n\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --channel <num>        WiFi channel\n";
    std::cout << "  -p, --pin <pin>            Test specific PIN\n";
    std::cout << "  -w, --wordlist <file>      PIN wordlist file\n";
    std::cout << "  -d, --delay <sec>          Delay between attempts (default: 1)\n";
    std::cout << "  -t, --timeout <sec>        Timeout per attempt (default: 10)\n";
    std::cout << "  -m, --max-attempts <num>   Maximum attempts (default: 11000)\n";
    std::cout << "  -o, --output <file>        Save results to file\n";
    std::cout << "  -S, --scan                 Scan for WPS-enabled networks\n";
    std::cout << "  -v, --verbose              Enable verbose output\n";
    std::cout << "  -h, --help                 Show this help\n\n";
    std::cout << "Interactive Commands:\n";
    std::cout << "  'p' - Show attack progress\n";
    std::cout << "  's' - Show statistics\n";
    std::cout << "  'r' - Show results\n";
    std::cout << "  'q' - Quit\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program << " -i wlan0mon -S\n";
    std::cout << "  " << program << " -i wlan0mon -b AA:BB:CC:DD:EE:FF -P\n";
    std::cout << "  " << program << " -i wlan0mon -b AA:BB:CC:DD:EE:FF -R -d 2\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::string interface, bssid, pin, wordlist, output_file;
    std::string attack_type = "pixie";
    int channel = 0, delay = 1, timeout = 10, max_attempts = 11000;
    bool verbose = false, scan_mode = false;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"bssid", required_argument, 0, 'b'},
        {"pixie-dust", no_argument, 0, 'P'},
        {"reaver", no_argument, 0, 'R'},
        {"brute-force", no_argument, 0, 'B'},
        {"null-pin", no_argument, 0, 'N'},
        {"channel", required_argument, 0, 'c'},
        {"pin", required_argument, 0, 'p'},
        {"wordlist", required_argument, 0, 'w'},
        {"delay", required_argument, 0, 'd'},
        {"timeout", required_argument, 0, 't'},
        {"max-attempts", required_argument, 0, 'm'},
        {"output", required_argument, 0, 'o'},
        {"scan", no_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:b:PRBNc:p:w:d:t:m:o:Svh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'b':
                bssid = optarg;
                break;
            case 'P':
                attack_type = "pixie";
                break;
            case 'R':
                attack_type = "reaver";
                break;
            case 'B':
                attack_type = "brute";
                break;
            case 'N':
                attack_type = "null";
                break;
            case 'c':
                channel = std::stoi(optarg);
                break;
            case 'p':
                pin = optarg;
                break;
            case 'w':
                wordlist = optarg;
                break;
            case 'd':
                delay = std::stoi(optarg);
                break;
            case 't':
                timeout = std::stoi(optarg);
                break;
            case 'm':
                max_attempts = std::stoi(optarg);
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'S':
                scan_mode = true;
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
    
    if (interface.empty()) {
        std::cerr << "Error: Interface is required\n";
        printUsage(argv[0]);
        return 1;
    }
    
    if (!scan_mode && bssid.empty()) {
        std::cerr << "Error: BSSID is required for attacks\n";
        printUsage(argv[0]);
        return 1;
    }
    
    Logger::getInstance().setVerbose(verbose);
    
    try {
        WPSAttack wps_attack;
        wps_instance = &wps_attack;
        
        if (!wps_attack.initialize(interface)) {
            std::cerr << "Failed to initialize interface: " << interface << std::endl;
            return 1;
        }
        
        if (scan_mode) {
            std::cout << "\n=== Scanning for WPS Networks ===\n";
            wps_attack.scanForWPS();
            
            std::this_thread::sleep_for(std::chrono::seconds(10));
            wps_attack.displayWPSTable();
            return 0;
        }
        
        // Configure attack
        wps_attack.setTarget(MacAddress(bssid));
        if (channel > 0) {
            wps_attack.setChannel(channel);
        }
        
        wps_attack.setDelay(delay);
        wps_attack.setTimeout(timeout);
        wps_attack.setMaxAttempts(max_attempts);
        wps_attack.setVerbose(verbose);
        
        if (!pin.empty()) {
            wps_attack.addCustomPin(pin);
        }
        
        if (!wordlist.empty()) {
            wps_attack.loadPinList(wordlist);
        }
        
        std::cout << "\n=== AirLevi-NG WPS Attack ===\n";
        std::cout << "Interface: " << interface << "\n";
        std::cout << "Target: " << bssid << "\n";
        std::cout << "Attack Type: " << attack_type << "\n";
        std::cout << "Delay: " << delay << " seconds\n";
        std::cout << "Timeout: " << timeout << " seconds\n";
        std::cout << "=============================\n\n";
        
        // Start attack
        bool attack_started = false;
        if (attack_type == "pixie") {
            attack_started = wps_attack.startPixieDustAttack();
        } else if (attack_type == "reaver") {
            attack_started = wps_attack.startReaverAttack();
        } else if (attack_type == "brute") {
            attack_started = wps_attack.startBruteForceAttack();
        } else if (attack_type == "null") {
            attack_started = wps_attack.startNullPinAttack();
        }
        
        if (!attack_started) {
            std::cerr << "Failed to start WPS attack\n";
            return 1;
        }
        
        std::cout << "WPS attack started. Press 'p' for progress, 'q' to quit.\n";
        
        // Interactive mode
        char cmd;
        while (running && std::cin >> cmd) {
            switch (cmd) {
                case 'p':
                    wps_attack.displayAttackProgress();
                    break;
                case 's':
                    wps_attack.displayRealTimeStats();
                    break;
                case 'r': {
                    auto results = wps_attack.getResults();
                    if (results.empty()) {
                        std::cout << "No results yet.\n";
                    } else {
                        std::cout << "\n=== Attack Results ===\n";
                        for (const auto& result : results) {
                            std::cout << "BSSID: " << result.bssid.toString() << "\n";
                            std::cout << "SSID: " << result.ssid << "\n";
                            std::cout << "PIN: " << result.pin << "\n";
                            if (!result.psk.empty()) {
                                std::cout << "PSK: " << result.psk << "\n";
                            }
                            std::cout << "Attack: ";
                            switch (result.attack_type) {
                                case WPSAttackType::PIXIE_DUST: std::cout << "Pixie Dust"; break;
                                case WPSAttackType::REAVER: std::cout << "Reaver"; break;
                                default: std::cout << "Unknown"; break;
                            }
                            std::cout << "\n======================\n";
                        }
                    }
                    break;
                }
                case 'q':
                    running = false;
                    break;
                default:
                    std::cout << "Unknown command. Press 'p' for progress, 'q' to quit.\n";
                    break;
            }
        }
        
        // Save results if requested
        if (!output_file.empty()) {
            wps_attack.saveResults(output_file);
            std::cout << "Results saved to: " << output_file << "\n";
        }
        
        // Print final statistics
        auto stats = wps_attack.getStats();
        std::cout << "\n=== Final Statistics ===\n";
        std::cout << "PINs Tested: " << stats.pins_tested << "\n";
        std::cout << "Rate: " << std::fixed << std::setprecision(2) << stats.pins_per_second << " pins/sec\n";
        std::cout << "Timeouts: " << stats.timeouts << "\n";
        std::cout << "========================\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
