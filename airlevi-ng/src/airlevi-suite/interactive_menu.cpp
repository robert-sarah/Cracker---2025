#include "airlevi-suite/interactive_menu.h"
#include "common/logger.h"
#include <iostream>
#include <cstdlib>
#include <limits>

namespace airlevi {

InteractiveMenu::InteractiveMenu() 
    : running_(false), current_state_(MenuState::MAIN) {
    initializeMenus();
}

InteractiveMenu::~InteractiveMenu() {
    stop();
}

void InteractiveMenu::run() {
    running_ = true;
    
    while (running_) {
        switch (current_state_) {
            case MenuState::MAIN:
                showMainMenu();
                break;
            case MenuState::SELECT_INTERFACE:
                showSelectInterfaceMenu();
                break;
            case MenuState::SCANNING:
                showScanningMenu();
                break;
            case MenuState::ATTACK_MENU:
                showAttackMenu();
                break;
            case MenuState::TOOL_MENU:
                showToolMenu();
                break;
        }
        handleInput();
    }
}

void InteractiveMenu::initializeMenus() {
    main_menu_ = {
        {"Select Wireless Interface", [this]() { current_state_ = MenuState::SELECT_INTERFACE; }},
        {"Scan for WiFi Networks", [this]() { launchScanner(); }},
        {"Attack Menu", [this]() { current_state_ = MenuState::ATTACK_MENU; }},
        {"Tool Menu", [this]() { current_state_ = MenuState::TOOL_MENU; }},
        {"Exit", [this]() { stop(); }}
    };
}

void InteractiveMenu::displayMenu(const std::vector<MenuItem>& menu, const std::string& title) {
    clearScreen();
    printHeader(title);
    
    for (size_t i = 0; i < menu.size(); ++i) {
        std::cout << "  " << (i + 1) << ". " << menu[i].title << std::endl;
    }
    
    std::cout << "\nInterface: " << (selected_interface_.empty() ? "Not selected" : selected_interface_) << std::endl;
    std::cout << "--------------------------------------------------\n";
}

void InteractiveMenu::handleInput() {
    // Placeholder for input handling
    // In a real app, this would read user input and call the appropriate action
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void InteractiveMenu::clearScreen() const {
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif
}

void InteractiveMenu::printHeader(const std::string& title) const {
    std::cout << "==================================================\n";
    std::cout << "          AirLevi-NG - " << title << "\n";
    std::cout << "==================================================\n\n";
}

void InteractiveMenu::showMainMenu() {
    displayMenu(main_menu_, "Main Menu");
    
    int choice = 0;
    std::cout << "Enter your choice: ";
    std::cin >> choice;
    
    if (std::cin.fail() || choice < 1 || choice > main_menu_.size()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return;
    }
    
    main_menu_[choice - 1].action();
}

void InteractiveMenu::showSelectInterfaceMenu() {
    clearScreen();
    printHeader("Select Interface");
    
    auto interfaces = NetworkInterface::getWirelessInterfaces();
    if (interfaces.empty()) {
        std::cout << "No wireless interfaces found!" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        current_state_ = MenuState::MAIN;
        return;
    }
    
    for (size_t i = 0; i < interfaces.size(); ++i) {
        std::cout << "  " << (i + 1) << ". " << interfaces[i] << std::endl;
    }
    
    std::cout << "\nEnter choice (0 to go back): ";
    int choice = 0;
    std::cin >> choice;
    
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return;
    }
    
    if (choice > 0 && choice <= interfaces.size()) {
        selected_interface_ = interfaces[choice - 1];
        app_config_.interface = selected_interface_;
        Logger::getInstance().info("Selected interface: " + selected_interface_);
    }
    
    current_state_ = MenuState::MAIN;
}

void InteractiveMenu::showScanningMenu() {
    // This will be implemented with the scanner logic
    Logger::getInstance().info("Scanning not yet implemented.");
    std::this_thread::sleep_for(std::chrono::seconds(2));
    current_state_ = MenuState::MAIN;
}

void InteractiveMenu::showAttackMenu() {
    std::vector<MenuItem> attack_menu = {
        {"Deauthentication Attack", [this]() { launchDeauthAttack(); }},
        {"Password Cracking", [this]() { launchPasswordCrack(); }},
        {"Back to Main Menu", [this]() { current_state_ = MenuState::MAIN; }}
    };
    
    displayMenu(attack_menu, "Attack Menu");
    
    int choice = 0;
    std::cout << "Enter your choice: ";
    std::cin >> choice;
    
    if (std::cin.fail() || choice < 1 || choice > attack_menu.size()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return;
    }
    
    attack_menu[choice - 1].action();
}

void InteractiveMenu::showToolMenu() {
    std::vector<MenuItem> tool_menu = {
        {"Packet Replay (airlevi-replay)", [this]() { launchPacketReplay(); }},
        {"Packet Forging (airlevi-forge)", [this]() { launchPacketForge(); }},
        {"Back to Main Menu", [this]() { current_state_ = MenuState::MAIN; }}
    };
    
    displayMenu(tool_menu, "Tool Menu");
    
    int choice = 0;
    std::cout << "Enter your choice: ";
    std::cin >> choice;
    
    if (std::cin.fail() || choice < 1 || choice > tool_menu.size()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return;
    }
    
    tool_menu[choice - 1].action();
}

void InteractiveMenu::launchScanner() {
    if (selected_interface_.empty()) {
        Logger::getInstance().warning("Please select an interface first.");
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }
    
    Logger::getInstance().info("Scanner functionality to be implemented here.");
    // Example: system("./airlevi-dump -i ...");
    std::this_thread::sleep_for(std::chrono::seconds(2));
}

void InteractiveMenu::launchDeauthAttack() {
    Logger::getInstance().info("Deauth Attack functionality to be implemented here.");
    std::this_thread::sleep_for(std::chrono::seconds(2));
}

void InteractiveMenu::launchPasswordCrack() {
    Logger::getInstance().info("Password Cracking functionality to be implemented here.");
    std::this_thread::sleep_for(std::chrono::seconds(2));
}

void InteractiveMenu::launchPacketReplay() {
    Logger::getInstance().info("Packet Replay functionality to be implemented here.");
    std::this_thread::sleep_for(std::chrono::seconds(2));
}

void InteractiveMenu::launchPacketForge() {
    Logger::getInstance().info("Packet Forging functionality to be implemented here.");
    std::this_thread::sleep_for(std::chrono::seconds(2));
}

std::string InteractiveMenu::getInput(const std::string& prompt) const {
    std::string input;
    std::cout << prompt;
    std::getline(std::cin, input);
    return input;
}

} // namespace airlevi
