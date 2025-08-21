#include "airlevi-mon/interface_manager.h"
#include "common/logger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <dirent.h>
#include <regex>
#include <iomanip>

namespace airlevi {

InterfaceManager::InterfaceManager() {
    updateInterfaceList();
    updateConflictingProcesses();
}

InterfaceManager::~InterfaceManager() = default;

std::vector<WifiInterface> InterfaceManager::scanInterfaces() {
    updateInterfaceList();
    return interfaces_;
}

bool InterfaceManager::executeCommand(const std::string& command, std::string& output) {
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return false;
    
    char buffer[128];
    output.clear();
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int result = pclose(pipe);
    return result == 0;
}

std::vector<std::string> InterfaceManager::parseNetworkInterfaces() {
    std::vector<std::string> interfaces;
    std::string output;
    
    if (executeCommand("ls /sys/class/net/", output)) {
        std::istringstream iss(output);
        std::string interface;
        while (iss >> interface) {
            if (isWirelessInterface(interface)) {
                interfaces.push_back(interface);
            }
        }
    }
    
    return interfaces;
}

bool InterfaceManager::isWirelessInterface(const std::string& interface) {
    std::string path = "/sys/class/net/" + interface + "/wireless";
    return access(path.c_str(), F_OK) == 0;
}

std::string InterfaceManager::getPhyFromInterface(const std::string& interface) {
    std::string output;
    std::string command = "iw dev " + interface + " info | grep wiphy | awk '{print $2}'";
    
    if (executeCommand(command, output)) {
        output.erase(output.find_last_not_of(" \n\r\t") + 1);
        return "phy" + output;
    }
    
    return "";
}

std::string InterfaceManager::detectDriver(const std::string& interface) {
    std::string output;
    std::string command = "ethtool -i " + interface + " 2>/dev/null | grep driver | awk '{print $2}'";
    
    if (executeCommand(command, output)) {
        output.erase(output.find_last_not_of(" \n\r\t") + 1);
        return output;
    }
    
    return "unknown";
}

std::string InterfaceManager::detectChipset(const std::string& interface) {
    std::string output;
    std::string command = "lspci | grep -i wireless";
    
    if (executeCommand(command, output)) {
        // Parse chipset from lspci output
        if (output.find("Intel") != std::string::npos) {
            return "Intel";
        } else if (output.find("Atheros") != std::string::npos) {
            return "Atheros";
        } else if (output.find("Realtek") != std::string::npos) {
            return "Realtek";
        } else if (output.find("Broadcom") != std::string::npos) {
            return "Broadcom";
        }
    }
    
    return "unknown";
}

bool InterfaceManager::supportsMonitorMode(const std::string& driver) {
    // List of drivers known to support monitor mode
    std::vector<std::string> supported_drivers = {
        "ath9k", "ath5k", "ath10k", "ath11k",
        "iwlwifi", "iwlegacy",
        "rt2800usb", "rt2800pci", "rt73usb", "rt61pci",
        "rtl8187", "rtl8192cu", "rtl88xxau",
        "brcmfmac", "b43", "b43legacy"
    };
    
    for (const auto& supported : supported_drivers) {
        if (driver.find(supported) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

WifiInterface InterfaceManager::getInterfaceInfo(const std::string& interface) {
    WifiInterface info;
    info.name = interface;
    info.driver = detectDriver(interface);
    info.chipset = detectChipset(interface);
    info.phy = getPhyFromInterface(interface);
    info.monitor_capable = supportsMonitorMode(info.driver);
    info.monitor_mode = isInMonitorMode(interface);
    
    // Get MAC address
    std::string output;
    if (executeCommand("cat /sys/class/net/" + interface + "/address", output)) {
        output.erase(output.find_last_not_of(" \n\r\t") + 1);
        info.mac_address = output;
    }
    
    // Check if interface is up
    if (executeCommand("ip link show " + interface + " | grep UP", output)) {
        info.up = !output.empty();
    }
    
    // Get current mode
    if (executeCommand("iw dev " + interface + " info | grep type | awk '{print $2}'", output)) {
        output.erase(output.find_last_not_of(" \n\r\t") + 1);
        info.mode = output;
    }
    
    return info;
}

bool InterfaceManager::isInMonitorMode(const std::string& interface) {
    std::string output;
    std::string command = "iw dev " + interface + " info | grep type";
    
    if (executeCommand(command, output)) {
        return output.find("monitor") != std::string::npos;
    }
    
    return false;
}

bool InterfaceManager::enableMonitorMode(const std::string& interface) {
    if (!checkRootPrivileges()) {
        Logger::getInstance().log("Root privileges required for monitor mode", LogLevel::ERROR);
        return false;
    }
    
    // Bring interface down
    if (!bringDown(interface)) {
        Logger::getInstance().log("Failed to bring down interface " + interface, LogLevel::ERROR);
        return false;
    }
    
    // Set monitor mode
    if (!setInterfaceMode(interface, "monitor")) {
        Logger::getInstance().log("Failed to set monitor mode on " + interface, LogLevel::ERROR);
        return false;
    }
    
    // Bring interface up
    if (!bringUp(interface)) {
        Logger::getInstance().log("Failed to bring up interface " + interface, LogLevel::ERROR);
        return false;
    }
    
    Logger::getInstance().log("Successfully enabled monitor mode on " + interface, LogLevel::INFO);
    return true;
}

bool InterfaceManager::disableMonitorMode(const std::string& interface) {
    if (!checkRootPrivileges()) {
        Logger::getInstance().log("Root privileges required", LogLevel::ERROR);
        return false;
    }
    
    // Bring interface down
    if (!bringDown(interface)) {
        return false;
    }
    
    // Set managed mode
    if (!setInterfaceMode(interface, "managed")) {
        return false;
    }
    
    // Bring interface up
    if (!bringUp(interface)) {
        return false;
    }
    
    Logger::getInstance().log("Successfully disabled monitor mode on " + interface, LogLevel::INFO);
    return true;
}

bool InterfaceManager::setInterfaceMode(const std::string& interface, const std::string& mode) {
    std::string output;
    std::string command = "iw dev " + interface + " set type " + mode;
    
    return executeCommand(command, output);
}

bool InterfaceManager::bringUp(const std::string& interface) {
    std::string output;
    std::string command = "ip link set " + interface + " up";
    
    return executeCommand(command, output);
}

bool InterfaceManager::bringDown(const std::string& interface) {
    std::string output;
    std::string command = "ip link set " + interface + " down";
    
    return executeCommand(command, output);
}

bool InterfaceManager::setChannel(const std::string& interface, int channel) {
    if (channel < 1 || channel > 14) {
        Logger::getInstance().log("Invalid channel: " + std::to_string(channel), LogLevel::ERROR);
        return false;
    }
    
    std::string output;
    std::string command = "iw dev " + interface + " set channel " + std::to_string(channel);
    
    bool result = executeCommand(command, output);
    if (result) {
        Logger::getInstance().log("Set channel " + std::to_string(channel) + " on " + interface, LogLevel::INFO);
    }
    
    return result;
}

std::vector<ConflictingProcess> InterfaceManager::checkConflictingProcesses() {
    updateConflictingProcesses();
    return conflicting_processes_;
}

void InterfaceManager::updateConflictingProcesses() {
    conflicting_processes_.clear();
    
    std::vector<std::string> problematic_processes = {
        "NetworkManager", "wpa_supplicant", "dhclient", "dhcpcd",
        "avahi-daemon", "wicd", "connman"
    };
    
    for (const auto& process_name : problematic_processes) {
        auto pids = findProcessesByName(process_name);
        for (int pid : pids) {
            ConflictingProcess proc;
            proc.pid = pid;
            proc.name = process_name;
            proc.description = "May interfere with monitor mode";
            conflicting_processes_.push_back(proc);
        }
    }
}

std::vector<int> InterfaceManager::findProcessesByName(const std::string& name) {
    std::vector<int> pids;
    std::string output;
    std::string command = "pgrep " + name;
    
    if (executeCommand(command, output)) {
        std::istringstream iss(output);
        std::string pid_str;
        while (iss >> pid_str) {
            try {
                int pid = std::stoi(pid_str);
                pids.push_back(pid);
            } catch (const std::exception&) {
                // Ignore invalid PIDs
            }
        }
    }
    
    return pids;
}

bool InterfaceManager::killConflictingProcesses() {
    if (!checkRootPrivileges()) {
        Logger::getInstance().log("Root privileges required to kill processes", LogLevel::ERROR);
        return false;
    }
    
    updateConflictingProcesses();
    
    for (const auto& proc : conflicting_processes_) {
        if (killProcess(proc.pid)) {
            Logger::getInstance().log("Killed process " + proc.name + " (PID: " + std::to_string(proc.pid) + ")", LogLevel::INFO);
        }
    }
    
    return true;
}

bool InterfaceManager::killProcess(int pid) {
    return kill(pid, SIGTERM) == 0;
}

bool InterfaceManager::checkRootPrivileges() {
    return geteuid() == 0;
}

void InterfaceManager::updateInterfaceList() {
    interfaces_.clear();
    auto interface_names = parseNetworkInterfaces();
    
    for (const auto& name : interface_names) {
        interfaces_.push_back(getInterfaceInfo(name));
    }
}

std::string InterfaceManager::createMonitorInterface(const std::string& base_interface) {
    if (!checkRootPrivileges()) {
        Logger::getInstance().log("Root privileges required", LogLevel::ERROR);
        return "";
    }
    
    std::string phy = getPhyFromInterface(base_interface);
    if (phy.empty()) {
        Logger::getInstance().log("Could not determine PHY for " + base_interface, LogLevel::ERROR);
        return "";
    }
    
    std::string monitor_name = base_interface + "mon";
    std::string output;
    std::string command = "iw phy " + phy + " interface add " + monitor_name + " type monitor";
    
    if (executeCommand(command, output)) {
        Logger::getInstance().log("Created monitor interface " + monitor_name, LogLevel::INFO);
        return monitor_name;
    }
    
    return "";
}

bool InterfaceManager::removeInterface(const std::string& interface) {
    if (!checkRootPrivileges()) {
        return false;
    }
    
    std::string output;
    std::string command = "iw dev " + interface + " del";
    
    return executeCommand(command, output);
}

void InterfaceManager::displayInterfaces() {
    updateInterfaceList();
    
    std::cout << "\nWiFi Interfaces:\n";
    std::cout << "================\n";
    std::cout << std::left;
    std::cout << std::setw(12) << "Interface" 
              << std::setw(15) << "Driver" 
              << std::setw(12) << "Chipset"
              << std::setw(8) << "Monitor"
              << std::setw(8) << "Mode"
              << std::setw(6) << "Status"
              << "MAC Address\n";
    std::cout << std::string(80, '-') << "\n";
    
    for (const auto& iface : interfaces_) {
        std::cout << std::setw(12) << iface.name
                  << std::setw(15) << iface.driver
                  << std::setw(12) << iface.chipset
                  << std::setw(8) << (iface.monitor_capable ? "Yes" : "No")
                  << std::setw(8) << iface.mode
                  << std::setw(6) << (iface.up ? "UP" : "DOWN")
                  << iface.mac_address << "\n";
    }
}

void InterfaceManager::displayConflictingProcesses() {
    updateConflictingProcesses();
    
    if (conflicting_processes_.empty()) {
        std::cout << "\nNo conflicting processes found.\n";
        return;
    }
    
    std::cout << "\nConflicting Processes:\n";
    std::cout << "=====================\n";
    std::cout << std::left;
    std::cout << std::setw(8) << "PID" 
              << std::setw(20) << "Process Name" 
              << "Description\n";
    std::cout << std::string(60, '-') << "\n";
    
    for (const auto& proc : conflicting_processes_) {
        std::cout << std::setw(8) << proc.pid
                  << std::setw(20) << proc.name
                  << proc.description << "\n";
    }
}

} // namespace airlevi
