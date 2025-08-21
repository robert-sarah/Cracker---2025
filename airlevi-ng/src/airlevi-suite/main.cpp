#include <iostream>
#include <signal.h>
#include "airlevi-suite/interactive_menu.h"
#include "common/logger.h"

using namespace airlevi;

static bool running = true;
static std::unique_ptr<InteractiveMenu> menu;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", shutting down..." << std::endl;
    running = false;
    if (menu) menu->stop();
}

int main(int argc, char* argv[]) {
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << R"(
    ╔═══════════════════════════════════════════════════════════════╗
    ║                        AirLevi-NG Suite                      ║
    ║                   Professional WiFi Auditing                 ║
    ║                         Version 1.0                          ║
    ╚═══════════════════════════════════════════════════════════════╝
    )" << std::endl;
    
    try {
        // Initialize logger
        Logger::getInstance().setVerbose(false);
        
        // Create interactive menu
        menu = std::make_unique<InteractiveMenu>();
        
        // Start menu
        menu->run();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
