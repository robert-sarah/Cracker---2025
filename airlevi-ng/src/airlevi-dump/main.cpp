#include <iostream>
#include <signal.h>
#include <getopt.h>
#include <thread>
#include <chrono>
#include "airlevi-dump/packet_capture.h"
#include "airlevi-dump/wifi_scanner.h"
#include "common/logger.h"
#include "common/config.h"

using namespace airlevi;

static bool running = true;
static std::unique_ptr<PacketCapture> capture;
static std::unique_ptr<WifiScanner> scanner;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", shutting down..." << std::endl;
    running = false;
    if (capture) capture->stop();
    if (scanner) scanner->stop();
}

void printUsage(const char* program_name) {
    std::cout << "AirLevi-NG Packet Capture Tool v1.0\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i, --interface IFACE    Wireless interface to use\n";
    std::cout << "  -c, --channel CHANNEL    Channel to monitor (1-196 for 2.4/5GHz)\n";
    std::cout << "  -w, --write FILE         Write packets to file\n";
    std::cout << "  -b, --bssid BSSID        Target specific BSSID\n";
    std::cout << "  -e, --essid ESSID        Target specific ESSID\n";
    std::cout << "  -t, --timeout SECONDS    Capture timeout\n";
    std::cout << "  -v, --verbose            Verbose output\n";
    std::cout << "  -h, --help               Show this help\n";
    std::cout << "  --hop                    Enable channel hopping\n";
    std::cout << "  --monitor                Enable monitor mode\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " -i wlan0 --monitor\n";
    std::cout << "  " << program_name << " -i wlan0 -c 6 -w capture.cap\n";
    std::cout << "  " << program_name << " -i wlan0 -b 00:11:22:33:44:55\n";
}

void displayStatistics(const Statistics& stats) {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats.start_time);
    
    std::cout << "\r[" << duration.count() << "s] ";
    std::cout << "Packets: " << stats.total_packets << " ";
    std::cout << "Networks: " << stats.networks_found << " ";
    std::cout << "Clients: " << stats.clients_found << " ";
    std::cout << "Handshakes: " << stats.handshakes_captured << " ";
    std::cout << std::flush;
}

int main(int argc, char* argv[]) {
    Config config;
    bool channel_hop = false;
    
    // Default values
    config.interface = "wlan0";
    config.channel = 0;
    config.monitor_mode = false;
    config.verbose = false;
    config.timeout = 0;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"channel", required_argument, 0, 'c'},
        {"write", required_argument, 0, 'w'},
        {"bssid", required_argument, 0, 'b'},
        {"essid", required_argument, 0, 'e'},
        {"timeout", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"hop", no_argument, 0, 1000},
        {"monitor", no_argument, 0, 1001},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "i:c:w:b:e:t:vh", long_options, nullptr)) != -1) {
        switch (c) {
            case 'i':
                config.interface = optarg;
                break;
            case 'c':
                config.channel = std::atoi(optarg);
                break;
            case 'w':
                config.output_file = optarg;
                break;
            case 'b':
                config.target_bssid = optarg;
                break;
            case 'e':
                config.target_essid = optarg;
                break;
            case 't':
                config.timeout = std::atoi(optarg);
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 1000:
                channel_hop = true;
                break;
            case 1001:
                config.monitor_mode = true;
                break;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "AirLevi-NG Packet Capture v1.0\n";
    std::cout << "================================\n";
    
    try {
        // Initialize logger
        Logger::getInstance().setVerbose(config.verbose);
        
        // Create packet capture instance
        capture = std::make_unique<PacketCapture>(config);
        
        // Create WiFi scanner
        scanner = std::make_unique<WifiScanner>(config);
        
        // Start capture
        if (!capture->start()) {
            std::cerr << "Failed to start packet capture" << std::endl;
            return 1;
        }
        
        // Start scanner
        if (!scanner->start()) {
            std::cerr << "Failed to start WiFi scanner" << std::endl;
            return 1;
        }
        
        std::cout << "Interface: " << config.interface << std::endl;
        if (config.channel > 0) {
            std::cout << "Channel: " << config.channel << std::endl;
        } else if (channel_hop) {
            std::cout << "Channel hopping enabled" << std::endl;
        }
        
        if (!config.target_bssid.empty()) {
            std::cout << "Target BSSID: " << config.target_bssid << std::endl;
        }
        
        if (!config.target_essid.empty()) {
            std::cout << "Target ESSID: " << config.target_essid << std::endl;
        }
        
        std::cout << "\nStarting capture... Press Ctrl+C to stop\n" << std::endl;
        
        // Channel hopping thread
        std::thread hop_thread;
        if (channel_hop && config.channel == 0) {
            hop_thread = std::thread([&]() {
                // Full 2.4GHz and 5GHz channel list for hopping
                int channels[] = {
                    // 2.4 GHz
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                    // 5 GHz
                    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 
                    116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 
                    157, 161, 165
                };
                int num_channels = sizeof(channels) / sizeof(channels[0]);
                int channel_index = 0;
                
                while (running) {
                    scanner->setChannel(channels[channel_index]);
                    channel_index = (channel_index + 1) % num_channels;
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
            });
        }
        
        // Statistics display thread
        std::thread stats_thread([&]() {
            while (running) {
                if (!config.verbose) {
                    displayStatistics(scanner->getStatistics());
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        });
        
        // Main capture loop
        auto start_time = std::chrono::steady_clock::now();
        while (running) {
            // Check timeout
            if (config.timeout > 0) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
                if (elapsed.count() >= config.timeout) {
                    std::cout << "\nTimeout reached, stopping capture..." << std::endl;
                    break;
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Cleanup
        running = false;
        
        if (hop_thread.joinable()) {
            hop_thread.join();
        }
        
        if (stats_thread.joinable()) {
            stats_thread.join();
        }
        
        capture->stop();
        scanner->stop();
        
        // Final statistics
        auto final_stats = scanner->getStatistics();
        std::cout << "\n\nCapture Summary:" << std::endl;
        std::cout << "=================" << std::endl;
        std::cout << "Total packets captured: " << final_stats.total_packets << std::endl;
        std::cout << "Networks discovered: " << final_stats.networks_found << std::endl;
        std::cout << "Clients discovered: " << final_stats.clients_found << std::endl;
        std::cout << "Handshakes captured: " << final_stats.handshakes_captured << std::endl;
        
        if (!config.output_file.empty()) {
            std::cout << "Output saved to: " << config.output_file << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
