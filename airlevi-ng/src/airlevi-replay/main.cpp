#include "airlevi-replay/packet_replay.h"
#include "common/logger.h"
#include <iostream>
#include <getopt.h>
#include <signal.h>

using namespace airlevi;

static bool running = true;
static PacketReplay* replay_instance = nullptr;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", stopping replay..." << std::endl;
    running = false;
    if (replay_instance) {
        replay_instance->stopReplay();
    }
}

void printUsage(const char* program) {
    std::cout << "AirLevi-NG Packet Replay Tool v1.0\n\n";
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  -i, --interface <iface>    Wireless interface for injection\n";
    std::cout << "  -r, --read <file>          Capture file to replay\n\n";
    std::cout << "Options:\n";
    std::cout << "  -m, --mode <mode>          Replay mode (single|continuous|burst|timed)\n";
    std::cout << "  -d, --delay <us>           Delay between packets (microseconds)\n";
    std::cout << "  -c, --count <num>          Number of packets to send (timed mode)\n";
    std::cout << "  -b, --burst <size>         Burst size (burst mode)\n";
    std::cout << "  -s, --speed <mult>         Speed multiplier (default: 1.0)\n";
    std::cout << "  -t, --target <mac>         Target MAC address\n";
    std::cout << "  -f, --from <mac>           Source MAC address\n";
    std::cout << "  -v, --verbose              Enable verbose output\n";
    std::cout << "  -h, --help                 Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program << " -i wlan0mon -r capture.cap -m continuous\n";
    std::cout << "  " << program << " -i wlan0mon -r handshake.cap -m burst -b 50\n";
    std::cout << "  " << program << " -i wlan0mon -r deauth.cap -t AA:BB:CC:DD:EE:FF\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::string interface, capture_file, target_mac, source_mac;
    std::string mode_str = "single";
    int delay = 1000, count = 1, burst = 10;
    double speed = 1.0;
    bool verbose = false;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"read", required_argument, 0, 'r'},
        {"mode", required_argument, 0, 'm'},
        {"delay", required_argument, 0, 'd'},
        {"count", required_argument, 0, 'c'},
        {"burst", required_argument, 0, 'b'},
        {"speed", required_argument, 0, 's'},
        {"target", required_argument, 0, 't'},
        {"from", required_argument, 0, 'f'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:r:m:d:c:b:s:t:f:vh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'r':
                capture_file = optarg;
                break;
            case 'm':
                mode_str = optarg;
                break;
            case 'd':
                delay = std::stoi(optarg);
                break;
            case 'c':
                count = std::stoi(optarg);
                break;
            case 'b':
                burst = std::stoi(optarg);
                break;
            case 's':
                speed = std::stod(optarg);
                break;
            case 't':
                target_mac = optarg;
                break;
            case 'f':
                source_mac = optarg;
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
    
    if (interface.empty() || capture_file.empty()) {
        std::cerr << "Error: Interface and capture file are required\n";
        printUsage(argv[0]);
        return 1;
    }
    
    Logger::getInstance().setVerbose(verbose);
    
    try {
        PacketReplay replay;
        replay_instance = &replay;
        
        if (!replay.initialize(interface)) {
            std::cerr << "Failed to initialize interface: " << interface << std::endl;
            return 1;
        }
        
        if (!replay.loadCaptureFile(capture_file)) {
            std::cerr << "Failed to load capture file: " << capture_file << std::endl;
            return 1;
        }
        
        // Set replay mode
        ReplayMode mode = ReplayMode::SINGLE;
        if (mode_str == "continuous") mode = ReplayMode::CONTINUOUS;
        else if (mode_str == "burst") mode = ReplayMode::BURST;
        else if (mode_str == "timed") mode = ReplayMode::TIMED;
        
        replay.setReplayMode(mode);
        replay.setPacketDelay(delay);
        replay.setPacketCount(count);
        replay.setBurstSize(burst);
        replay.setSpeed(speed);
        
        if (!target_mac.empty()) {
            replay.setTargetMAC(target_mac);
        }
        
        if (!source_mac.empty()) {
            replay.setSourceMAC(source_mac);
        }
        
        std::cout << "\n=== AirLevi-NG Packet Replay ===\n";
        std::cout << "Interface: " << interface << "\n";
        std::cout << "Capture File: " << capture_file << "\n";
        std::cout << "Mode: " << mode_str << "\n";
        std::cout << "Delay: " << delay << " μs\n";
        std::cout << "Speed: " << speed << "x\n";
        if (!target_mac.empty()) std::cout << "Target MAC: " << target_mac << "\n";
        if (!source_mac.empty()) std::cout << "Source MAC: " << source_mac << "\n";
        std::cout << "===============================\n\n";
        
        if (!replay.startReplay()) {
            std::cerr << "Failed to start replay\n";
            return 1;
        }
        
        // Real-time stats display
        std::thread stats_thread([&replay]() {
            replay.printRealTimeStats();
        });
        
        while (running && replay.isRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        replay.stopReplay();
        if (stats_thread.joinable()) {
            stats_thread.join();
        }
        
        replay.printStats();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
