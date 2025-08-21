#include <iostream>
#include <signal.h>
#include <getopt.h>
#include <thread>
#include <chrono>
#include "airlevi-serv/network_server.h"
#include "common/logger.h"

using namespace airlevi;

static bool running = true;
static std::unique_ptr<NetworkServer> server;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", shutting down..." << std::endl;
    running = false;
    if (server) {
        server->stop();
    }
}

void printUsage(const char* program_name) {
    std::cout << "AirLevi-NG Network Server v1.0\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -p, --port PORT         Server port (default: 666)\n";
    std::cout << "  -i, --interface IFACE   Bind to specific interface\n";
    std::cout << "  -v, --verbose           Verbose output\n";
    std::cout << "  -h, --help              Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " -p 8080\n";
    std::cout << "  " << program_name << " -i wlan0 -p 666\n";
}

int main(int argc, char* argv[]) {
    uint16_t port = 666;
    std::string interface;
    bool verbose = false;
    
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"interface", required_argument, 0, 'i'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "p:i:vh", long_options, nullptr)) != -1) {
        switch (c) {
            case 'p':
                port = std::atoi(optarg);
                break;
            case 'i':
                interface = optarg;
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
    
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "AirLevi-NG Network Server v1.0\n";
    std::cout << "===============================\n";
    
    try {
        Logger::getInstance().setVerbose(verbose);
        server = std::make_unique<NetworkServer>();
        
        std::cout << "Starting server on port " << port;
        if (!interface.empty()) {
            std::cout << " (interface: " << interface << ")";
        }
        std::cout << "...\n";
        
        if (!server->start(port, interface)) {
            std::cerr << "Failed to start server" << std::endl;
            return 1;
        }
        
        std::cout << "[+] Server started successfully\n";
        std::cout << "Waiting for connections... Press Ctrl+C to stop\n\n";
        
        // Status display loop
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            if (verbose && server->isRunning()) {
                auto clients = server->getConnectedClients();
                std::cout << "\r[" << std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count() << "] ";
                std::cout << "Clients: " << clients.size() << " ";
                std::cout << "Total: " << server->getTotalConnections() << " ";
                std::cout << "Packets: " << server->getPacketsSent() << "    ";
                std::cout << std::flush;
            }
        }
        
        std::cout << "\nShutting down server...\n";
        server->stop();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
