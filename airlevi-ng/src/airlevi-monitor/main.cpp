#include "airlevi-monitor/advanced_monitor.h"
#include "common/logger.h"
#include <iostream>
#include <getopt.h>
#include <signal.h>

using namespace airlevi;

static bool running = true;
static AdvancedMonitor* monitor_instance = nullptr;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", stopping monitor..." << std::endl;
    running = false;
    if (monitor_instance) {
        monitor_instance->stopMonitoring();
    }
}

void printUsage(const char* program) {
    std::cout << "AirLevi-NG Advanced Monitor v1.0\n\n";
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  -i, --interface <iface>    Monitor mode interface\n\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --channel <num>        Fixed channel (disables hopping)\n";
    std::cout << "  -H, --hop                  Enable channel hopping (default)\n";
    std::cout << "  -t, --time <ms>            Channel dwell time (default: 250ms)\n";
    std::cout << "  -b, --bssid <mac>          Target specific BSSID\n";
    std::cout << "  -e, --essid <ssid>         Target specific ESSID\n";
    std::cout << "  -s, --signal <dbm>         Minimum signal strength\n";
    std::cout << "  -w, --write <file>         Save session to file\n";
    std::cout << "  --csv <file>               Export to CSV\n";
    std::cout << "  --handshakes <file>        Save handshakes\n";
    std::cout << "  -v, --verbose              Enable verbose output\n";
    std::cout << "  -h, --help                 Show this help\n\n";
    std::cout << "Interactive Commands:\n";
    std::cout << "  'n' - Show networks table\n";
    std::cout << "  'c' - Show clients table\n";
    std::cout << "  's' - Show channel statistics\n";
    std::cout << "  'h' - Show handshakes\n";
    std::cout << "  'r' - Show real-time stats\n";
    std::cout << "  'q' - Quit\n\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::string interface, bssid, essid, output_file, csv_file, handshake_file;
    int channel = 0, dwell_time = 250, signal_threshold = -100;
    bool verbose = false, channel_hopping = true;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"channel", required_argument, 0, 'c'},
        {"hop", no_argument, 0, 'H'},
        {"time", required_argument, 0, 't'},
        {"bssid", required_argument, 0, 'b'},
        {"essid", required_argument, 0, 'e'},
        {"signal", required_argument, 0, 's'},
        {"write", required_argument, 0, 'w'},
        {"csv", required_argument, 0, 1001},
        {"handshakes", required_argument, 0, 1002},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:c:Ht:b:e:s:w:vh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'c':
                channel = std::stoi(optarg);
                channel_hopping = false;
                break;
            case 'H':
                channel_hopping = true;
                break;
            case 't':
                dwell_time = std::stoi(optarg);
                break;
            case 'b':
                bssid = optarg;
                break;
            case 'e':
                essid = optarg;
                break;
            case 's':
                signal_threshold = std::stoi(optarg);
                break;
            case 'w':
                output_file = optarg;
                break;
            case 1001:
                csv_file = optarg;
                break;
            case 1002:
                handshake_file = optarg;
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
    
    Logger::getInstance().setVerbose(verbose);
    
    try {
        AdvancedMonitor monitor;
        monitor_instance = &monitor;
        
        if (!monitor.initialize(interface)) {
            std::cerr << "Failed to initialize interface: " << interface << std::endl;
            return 1;
        }
        
        // Configure monitoring
        if (channel > 0) {
            monitor.setFixedChannel(channel);
        } else {
            monitor.setChannelHopping(true, dwell_time);
        }
        
        if (!bssid.empty()) {
            monitor.setTargetBSSID(MacAddress(bssid));
        }
        
        if (!essid.empty()) {
            monitor.setTargetSSID(essid);
        }
        
        monitor.setSignalThreshold(signal_threshold);
        
        std::cout << "\n=== AirLevi-NG Advanced Monitor ===\n";
        std::cout << "Interface: " << interface << "\n";
        if (channel > 0) {
            std::cout << "Fixed Channel: " << channel << "\n";
        } else {
            std::cout << "Channel Hopping: Enabled (" << dwell_time << "ms dwell)\n";
        }
        if (!bssid.empty()) std::cout << "Target BSSID: " << bssid << "\n";
        if (!essid.empty()) std::cout << "Target ESSID: " << essid << "\n";
        std::cout << "Signal Threshold: " << signal_threshold << " dBm\n";
        std::cout << "==================================\n\n";
        
        if (!monitor.startMonitoring()) {
            std::cerr << "Failed to start monitoring\n";
            return 1;
        }
        
        // Interactive mode
        std::cout << "Monitoring started. Press 'h' for help, 'q' to quit.\n";
        
        char cmd;
        while (running && std::cin >> cmd) {
            switch (cmd) {
                case 'n':
                    monitor.displayNetworksTable();
                    break;
                case 'c':
                    monitor.displayClientsTable();
                    break;
                case 's':
                    monitor.displayChannelStats();
                    break;
                case 'h':
                    monitor.displayHandshakes();
                    break;
                case 'r':
                    monitor.displayRealTimeStats();
                    break;
                case 'q':
                    running = false;
                    break;
                default:
                    std::cout << "Unknown command. Press 'h' for help.\n";
                    break;
            }
        }
        
        monitor.stopMonitoring();
        
        // Export data if requested
        if (!csv_file.empty()) {
            monitor.exportToCSV(csv_file);
            std::cout << "Data exported to: " << csv_file << "\n";
        }
        
        if (!handshake_file.empty()) {
            monitor.exportHandshakes(handshake_file);
            std::cout << "Handshakes saved to: " << handshake_file << "\n";
        }
        
        if (!output_file.empty()) {
            monitor.saveSession(output_file);
            std::cout << "Session saved to: " << output_file << "\n";
        }
        
        // Print final statistics
        auto stats = monitor.getStats();
        std::cout << "\n=== Final Statistics ===\n";
        std::cout << "Total Packets: " << stats.total_packets << "\n";
        std::cout << "Unique APs: " << stats.unique_aps << "\n";
        std::cout << "Unique Clients: " << stats.unique_clients << "\n";
        std::cout << "Handshakes: " << stats.handshakes_captured << "\n";
        std::cout << "========================\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
