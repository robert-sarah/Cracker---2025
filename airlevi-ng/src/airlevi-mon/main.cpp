#include <iostream>
#include <signal.h>
#include <getopt.h>
#include <string>
#include <vector>
#include "airlevi-mon/interface_manager.h"
#include "common/logger.h"

using namespace airlevi;

static bool running = true;
static std::unique_ptr<InterfaceManager> manager;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", shutting down..." << std::endl;
    running = false;
}

void printUsage(const char* program_name) {
    std::cout << "AirLevi-NG Interface Monitor v1.0\n";
    std::cout << "Usage: " << program_name << " [COMMAND] [OPTIONS]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  start INTERFACE         Enable monitor mode on interface\n";
    std::cout << "  stop INTERFACE          Disable monitor mode on interface\n";
    std::cout << "  check                   Check for conflicting processes\n";
    std::cout << "  check kill              Kill conflicting processes\n";
    std::cout << "  list                    List all wireless interfaces\n";
    std::cout << "  create INTERFACE        Create virtual monitor interface\n";
    std::cout << "  remove INTERFACE        Remove virtual interface\n";
    std::cout << "  channel INTERFACE CH    Set channel on interface\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -v, --verbose           Verbose output\n";
    std::cout << "  -h, --help              Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " start wlan0\n";
    std::cout << "  " << program_name << " check kill\n";
    std::cout << "  " << program_name << " list\n";
    std::cout << "  " << program_name << " channel wlan0mon 6\n";
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    
    static struct option long_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "vh", long_options, nullptr)) != -1) {
        switch (c) {
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
    
    if (optind >= argc) {
        printUsage(argv[0]);
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "AirLevi-NG Interface Monitor v1.0\n";
    std::cout << "==================================\n";
    
    try {
        // Initialize logger
        Logger::getInstance().setVerbose(verbose);
        
        // Create interface manager
        manager = std::make_unique<InterfaceManager>();
        
        std::string command = argv[optind];
        
        if (command == "start") {
            if (optind + 1 >= argc) {
                std::cerr << "Error: Interface name required for start command" << std::endl;
                return 1;
            }
            
            std::string interface = argv[optind + 1];
            
            if (!manager->checkRootPrivileges()) {
                std::cerr << "Error: Root privileges required" << std::endl;
                return 1;
            }
            
            std::cout << "Enabling monitor mode on " << interface << "...\n";
            
            // Check for conflicting processes
            auto conflicts = manager->checkConflictingProcesses();
            if (!conflicts.empty()) {
                std::cout << "\nWarning: Found conflicting processes:\n";
                manager->displayConflictingProcesses();
                std::cout << "\nRun 'airlevi-mon check kill' to terminate them.\n";
            }
            
            if (manager->enableMonitorMode(interface)) {
                std::cout << "\n[+] Monitor mode enabled on " << interface << std::endl;
                
                // Display interface info
                auto info = manager->getInterfaceInfo(interface);
                std::cout << "\nInterface Information:\n";
                std::cout << "  Name: " << info.name << "\n";
                std::cout << "  Driver: " << info.driver << "\n";
                std::cout << "  Chipset: " << info.chipset << "\n";
                std::cout << "  Mode: " << info.mode << "\n";
                std::cout << "  MAC: " << info.mac_address << "\n";
            } else {
                std::cerr << "[-] Failed to enable monitor mode on " << interface << std::endl;
                return 1;
            }
            
        } else if (command == "stop") {
            if (optind + 1 >= argc) {
                std::cerr << "Error: Interface name required for stop command" << std::endl;
                return 1;
            }
            
            std::string interface = argv[optind + 1];
            
            if (!manager->checkRootPrivileges()) {
                std::cerr << "Error: Root privileges required" << std::endl;
                return 1;
            }
            
            std::cout << "Disabling monitor mode on " << interface << "...\n";
            
            if (manager->disableMonitorMode(interface)) {
                std::cout << "[+] Monitor mode disabled on " << interface << std::endl;
            } else {
                std::cerr << "[-] Failed to disable monitor mode on " << interface << std::endl;
                return 1;
            }
            
        } else if (command == "check") {
            if (optind + 1 < argc && std::string(argv[optind + 1]) == "kill") {
                if (!manager->checkRootPrivileges()) {
                    std::cerr << "Error: Root privileges required to kill processes" << std::endl;
                    return 1;
                }
                
                std::cout << "Checking and killing conflicting processes...\n";
                manager->killConflictingProcesses();
                std::cout << "[+] Conflicting processes terminated" << std::endl;
            } else {
                std::cout << "Checking for conflicting processes...\n";
                manager->displayConflictingProcesses();
            }
            
        } else if (command == "list") {
            std::cout << "Scanning wireless interfaces...\n";
            manager->displayInterfaces();
            
        } else if (command == "create") {
            if (optind + 1 >= argc) {
                std::cerr << "Error: Base interface name required for create command" << std::endl;
                return 1;
            }
            
            std::string base_interface = argv[optind + 1];
            
            if (!manager->checkRootPrivileges()) {
                std::cerr << "Error: Root privileges required" << std::endl;
                return 1;
            }
            
            std::cout << "Creating monitor interface from " << base_interface << "...\n";
            
            std::string monitor_interface = manager->createMonitorInterface(base_interface);
            if (!monitor_interface.empty()) {
                std::cout << "[+] Created monitor interface: " << monitor_interface << std::endl;
                
                // Bring up the new interface
                if (manager->bringUp(monitor_interface)) {
                    std::cout << "[+] Interface " << monitor_interface << " is up" << std::endl;
                }
            } else {
                std::cerr << "[-] Failed to create monitor interface" << std::endl;
                return 1;
            }
            
        } else if (command == "remove") {
            if (optind + 1 >= argc) {
                std::cerr << "Error: Interface name required for remove command" << std::endl;
                return 1;
            }
            
            std::string interface = argv[optind + 1];
            
            if (!manager->checkRootPrivileges()) {
                std::cerr << "Error: Root privileges required" << std::endl;
                return 1;
            }
            
            std::cout << "Removing interface " << interface << "...\n";
            
            if (manager->removeInterface(interface)) {
                std::cout << "[+] Interface " << interface << " removed" << std::endl;
            } else {
                std::cerr << "[-] Failed to remove interface " << interface << std::endl;
                return 1;
            }
            
        } else if (command == "channel") {
            if (optind + 2 >= argc) {
                std::cerr << "Error: Interface name and channel required for channel command" << std::endl;
                return 1;
            }
            
            std::string interface = argv[optind + 1];
            int channel = std::atoi(argv[optind + 2]);
            
            if (!manager->checkRootPrivileges()) {
                std::cerr << "Error: Root privileges required" << std::endl;
                return 1;
            }
            
            std::cout << "Setting channel " << channel << " on " << interface << "...\n";
            
            if (manager->setChannel(interface, channel)) {
                std::cout << "[+] Channel set successfully" << std::endl;
            } else {
                std::cerr << "[-] Failed to set channel" << std::endl;
                return 1;
            }
            
        } else {
            std::cerr << "Error: Unknown command '" << command << "'" << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
