#include "common/network_interface.h"
#include "common/logger.h"
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

namespace airlevi {

NetworkInterface::NetworkInterface(const std::string& interface_name)
    : interface_name_(interface_name), monitor_mode_(false), current_channel_(0) {
}

NetworkInterface::~NetworkInterface() {
    if (monitor_mode_) {
        setMonitorMode(false);
    }
}

bool NetworkInterface::setMonitorMode(bool enable) {
    if (enable == monitor_mode_) return true;
    
    std::string mode = enable ? "monitor" : "managed";
    
    // Bring interface down first
    if (!bringDown()) {
        Logger::getInstance().error("Failed to bring down interface " + interface_name_);
        return false;
    }
    
    // Set mode
    std::string command = "iwconfig " + interface_name_ + " mode " + mode + " 2>/dev/null";
    if (!executeCommand(command)) {
        Logger::getInstance().error("Failed to set " + mode + " mode on " + interface_name_);
        bringUp(); // Try to bring it back up
        return false;
    }
    
    // Bring interface back up
    if (!bringUp()) {
        Logger::getInstance().error("Failed to bring up interface " + interface_name_);
        return false;
    }
    
    monitor_mode_ = enable;
    Logger::getInstance().info("Set " + interface_name_ + " to " + mode + " mode");
    return true;
}

bool NetworkInterface::isMonitorMode() const {
    std::string mode = getInterfaceProperty("mode");
    return mode == "Monitor";
}

bool NetworkInterface::setChannel(int channel) {
    // Allow a wider range of channels for 2.4GHz and 5GHz bands.
    // A more robust implementation would query the device for supported channels.
    if (channel < 1 || channel > 196) { // Covers most 5GHz channels
        Logger::getInstance().warning("Attempting to set an unusual channel: " + std::to_string(channel));
    }
    
    std::string command = "iwconfig " + interface_name_ + " channel " + std::to_string(channel) + " 2>/dev/null";
    if (executeCommand(command)) {
        current_channel_ = channel;
        return true;
    }
    
    return false;
}

int NetworkInterface::getChannel() const {
    std::string channel_str = getInterfaceProperty("channel");
    if (channel_str.empty()) return 0;
    
    try {
        return std::stoi(channel_str);
    } catch (const std::exception&) {
        return 0;
    }
}

bool NetworkInterface::isUp() const {
    std::ifstream file("/sys/class/net/" + interface_name_ + "/operstate");
    if (!file.is_open()) return false;
    
    std::string state;
    std::getline(file, state);
    return state == "up";
}

bool NetworkInterface::bringUp() {
    std::string command = "ip link set " + interface_name_ + " up 2>/dev/null";
    return executeCommand(command);
}

bool NetworkInterface::bringDown() {
    std::string command = "ip link set " + interface_name_ + " down 2>/dev/null";
    return executeCommand(command);
}

MacAddress NetworkInterface::getMacAddress() const {
    std::ifstream file("/sys/class/net/" + interface_name_ + "/address");
    if (!file.is_open()) return MacAddress();
    
    std::string mac_str;
    std::getline(file, mac_str);
    
    MacAddress mac;
    std::istringstream iss(mac_str);
    std::string byte_str;
    int i = 0;
    
    while (std::getline(iss, byte_str, ':') && i < 6) {
        mac.bytes[i++] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
    
    return mac;
}

std::vector<int> NetworkInterface::getSupportedChannels() const {
    // Standard 2.4GHz and 5GHz channels
    return {
        // 2.4 GHz
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        // 5 GHz (U-NII bands)
        36, 40, 44, 48, 52, 56, 60, 64, // U-NII-1 & U-NII-2A
        100, 104, 108, 112, 116, 120, 124, 128, // U-NII-2C
        132, 136, 140, 144, // U-NII-2C (continued)
        149, 153, 157, 161, // U-NII-3
        165 // U-NII-4
    };
}

bool NetworkInterface::supportsMonitorMode() const {
    // Check if interface supports monitor mode
    std::string command = "iw " + interface_name_ + " info 2>/dev/null | grep -q monitor";
    return executeCommand(command);
}

std::vector<std::string> NetworkInterface::getWirelessInterfaces() {
    std::vector<std::string> interfaces;
    
    std::ifstream file("/proc/net/wireless");
    if (!file.is_open()) return interfaces;
    
    std::string line;
    // Skip header lines
    std::getline(file, line);
    std::getline(file, line);
    
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string interface = line.substr(0, colon_pos);
            // Remove leading whitespace
            interface.erase(0, interface.find_first_not_of(" \t"));
            interfaces.push_back(interface);
        }
    }
    
    return interfaces;
}

bool NetworkInterface::interfaceExists(const std::string& interface_name) {
    std::ifstream file("/sys/class/net/" + interface_name + "/operstate");
    return file.is_open();
}

bool NetworkInterface::executeCommand(const std::string& command) const {
    int result = std::system(command.c_str());
    return result == 0;
}

std::string NetworkInterface::getInterfaceProperty(const std::string& property) const {
    std::string command = "iwconfig " + interface_name_ + " 2>/dev/null | grep -i " + property;
    
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return "";
    
    char buffer[256];
    std::string result;
    
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }
    
    pclose(pipe);
    
    // Parse the result to extract the property value
    if (property == "mode") {
        size_t pos = result.find("Mode:");
        if (pos != std::string::npos) {
            pos += 5; // Skip "Mode:"
            size_t end = result.find(' ', pos);
            if (end != std::string::npos) {
                return result.substr(pos, end - pos);
            }
        }
    } else if (property == "channel") {
        size_t pos = result.find("Channel:");
        if (pos != std::string::npos) {
            pos += 8; // Skip "Channel:"
            size_t end = result.find(' ', pos);
            if (end != std::string::npos) {
                return result.substr(pos, end - pos);
            }
        }
    }
    
    return "";
}

bool NetworkInterface::setInterfaceProperty(const std::string& property, const std::string& value) const {
    std::string command = "iwconfig " + interface_name_ + " " + property + " " + value + " 2>/dev/null";
    return executeCommand(command);
}

} // namespace airlevi
