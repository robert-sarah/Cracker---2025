#include <iostream>
#include <signal.h>
#include <getopt.h>
#include <thread>
#include <chrono>
#include "airlevi-deauth/deauth_attack.h"
#include "common/logger.h"
#include "common/config.h"

using namespace airlevi;

static bool running = true;
static std::unique_ptr<DeauthAttack> attack;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", shutting down..." << std::endl;
    running = false;
    if (attack) attack->stop();
}

void printUsage(const char* program_name) {
    std::cout << "AirLevi-NG Deauthentication Attack Tool v1.0\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i, --interface IFACE    Wireless interface to use\n";
    std::cout << "  -a, --ap BSSID           Target AP BSSID\n";
    std::cout << "  -c, --client MAC         Target client MAC (optional)\n";
    std::cout << "  -n, --count NUM          Number of deauth packets (0 = unlimited)\n";
    std::cout << "  -d, --delay MS           Delay between packets in milliseconds\n";
    std::cout << "  -r, --reason CODE        Reason code (default: 7)\n";
    std::cout << "  -v, --verbose            Verbose output\n";
    std::cout << "  -h, --help               Show this help\n";
    std::cout << "  --broadcast              Target all clients (broadcast)\n";
    std::cout << "  --monitor                Enable monitor mode\n";
    std::cout << "\nReason Codes:\n";
    std::cout << "  1 = Unspecified reason\n";
    std::cout << "  2 = Previous authentication no longer valid\n";
    std::cout << "  3 = Deauthenticated because sending STA is leaving\n";
    std::cout << "  4 = Disassociated due to inactivity\n";
    std::cout << "  5 = Disassociated because AP is unable to handle all currently associated STAs\n";
    std::cout << "  6 = Class 2 frame received from nonauthenticated STA\n";
    std::cout << "  7 = Class 3 frame received from nonassociated STA (default)\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " -i wlan0 -a 00:11:22:33:44:55 --monitor\n";
    std::cout << "  " << program_name << " -i wlan0 -a 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF\n";
    std::cout << "  " << program_name << " -i wlan0 -a 00:11:22:33:44:55 --broadcast -n 100\n";
}

int main(int argc, char* argv[]) {
    Config config;
    std::string target_ap;
    std::string target_client;
    int packet_count = 0; // 0 = unlimited
    int delay_ms = 100;
    int reason_code = 7;
    bool broadcast = false;
    
    // Default values
    config.interface = "wlan0";
    config.monitor_mode = false;
    config.verbose = false;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"ap", required_argument, 0, 'a'},
        {"client", required_argument, 0, 'c'},
        {"count", required_argument, 0, 'n'},
        {"delay", required_argument, 0, 'd'},
        {"reason", required_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"broadcast", no_argument, 0, 1000},
        {"monitor", no_argument, 0, 1001},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "i:a:c:n:d:r:vh", long_options, nullptr)) != -1) {
        switch (c) {
            case 'i':
                config.interface = optarg;
                break;
            case 'a':
                target_ap = optarg;
                break;
            case 'c':
                target_client = optarg;
                break;
            case 'n':
                packet_count = std::atoi(optarg);
                break;
            case 'd':
                delay_ms = std::atoi(optarg);
                break;
            case 'r':
                reason_code = std::atoi(optarg);
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 1000:
                broadcast = true;
                break;
            case 1001:
                config.monitor_mode = true;
                break;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    if (target_ap.empty()) {
        std::cerr << "Error: Target AP BSSID is required (-a option)" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "AirLevi-NG Deauthentication Attack v1.0\n";
    std::cout << "========================================\n";
    
    try {
        // Initialize logger
        Logger::getInstance().setVerbose(config.verbose);
        
        // Create deauth attack instance
        attack = std::make_unique<DeauthAttack>(config);
        
        // Configure attack parameters
        attack->setTargetAP(target_ap);
        if (!target_client.empty()) {
            attack->setTargetClient(target_client);
        }
        attack->setBroadcast(broadcast);
        attack->setPacketCount(packet_count);
        attack->setDelay(delay_ms);
        attack->setReasonCode(reason_code);
        
        std::cout << "Interface: " << config.interface << std::endl;
        std::cout << "Target AP: " << target_ap << std::endl;
        
        if (broadcast) {
            std::cout << "Mode: Broadcast (all clients)" << std::endl;
        } else if (!target_client.empty()) {
            std::cout << "Target Client: " << target_client << std::endl;
        } else {
            std::cout << "Mode: Auto-discover clients" << std::endl;
        }
        
        std::cout << "Packet count: " << (packet_count == 0 ? "unlimited" : std::to_string(packet_count)) << std::endl;
        std::cout << "Delay: " << delay_ms << "ms" << std::endl;
        std::cout << "Reason code: " << reason_code << std::endl;
        
        // Start attack
        if (!attack->start()) {
            std::cerr << "Failed to start deauth attack" << std::endl;
            return 1;
        }
        
        std::cout << "\nStarting deauth attack... Press Ctrl+C to stop\n" << std::endl;
        
        // Main loop
        while (running && attack->isRunning()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Display statistics
            auto stats = attack->getStatistics();
            std::cout << "\r[" << stats.packets_sent << " sent, " 
                      << stats.clients_deauthed << " clients affected] ";
            std::cout.flush();
        }
        
        attack->stop();
        
        // Final statistics
        auto final_stats = attack->getStatistics();
        std::cout << "\n\nAttack Summary:" << std::endl;
        std::cout << "===============" << std::endl;
        std::cout << "Packets sent: " << final_stats.packets_sent << std::endl;
        std::cout << "Clients affected: " << final_stats.clients_deauthed << std::endl;
        std::cout << "Duration: " << final_stats.duration_seconds << " seconds" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
