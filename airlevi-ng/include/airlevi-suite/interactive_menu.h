#ifndef AIRLEVI_INTERACTIVE_MENU_H
#define AIRLEVI_INTERACTIVE_MENU_H

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include "common/types.h"
#include "common/network_interface.h"
#include "airlevi-dump/wifi_scanner.h"

namespace airlevi {

struct MenuItem {
    std::string title;
    std::function<void()> action;
};

class InteractiveMenu {
public:
    InteractiveMenu();
    ~InteractiveMenu();

    void run();
    void stop() { running_ = false; }

private:
    std::atomic<bool> running_;
    std::vector<MenuItem> main_menu_;
    std::string selected_interface_;
    Config app_config_;

    // Menu states
    enum class MenuState {
        MAIN,
        SELECT_INTERFACE,
        SCANNING,
        ATTACK_MENU,
        TOOL_MENU
    };
    MenuState current_state_;

    // Menu drawing and handling
    void displayMenu(const std::vector<MenuItem>& menu, const std::string& title);
    void handleInput();
    void clearScreen() const;

    // Menu actions
    void showMainMenu();
    void showSelectInterfaceMenu();
    void showScanningMenu();
    void showAttackMenu();
    void showToolMenu();

    // Tool launchers
    void launchScanner();
    void launchDeauthAttack();
    void launchPasswordCrack();
    void launchPacketReplay();
    void launchPacketForge();

    // Helper functions
    void initializeMenus();
    bool selectInterface();
    void printHeader(const std::string& title) const;
    std::string getInput(const std::string& prompt) const;
};

} // namespace airlevi

#endif // AIRLEVI_INTERACTIVE_MENU_H
