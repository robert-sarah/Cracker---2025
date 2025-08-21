#include "common/config.h"
#include <fstream>
#include <iostream>

namespace airlevi {

ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

bool ConfigManager::loadConfig(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        size_t pos = line.find('=');
        if (pos == std::string::npos) continue;
        
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        
        if (key == "interface") {
            config_.interface = value;
        } else if (key == "channel") {
            config_.channel = std::stoi(value);
        } else if (key == "output_file") {
            config_.output_file = value;
        } else if (key == "wordlist_file") {
            config_.wordlist_file = value;
        } else if (key == "target_bssid") {
            config_.target_bssid = value;
        } else if (key == "target_essid") {
            config_.target_essid = value;
        } else if (key == "verbose") {
            config_.verbose = (value == "true" || value == "1");
        } else if (key == "monitor_mode") {
            config_.monitor_mode = (value == "true" || value == "1");
        } else if (key == "timeout") {
            config_.timeout = std::stoi(value);
        }
    }
    
    return true;
}

bool ConfigManager::saveConfig(const std::string& config_file) const {
    std::ofstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    file << "# AirLevi-NG Configuration File\n";
    file << "interface=" << config_.interface << "\n";
    file << "channel=" << config_.channel << "\n";
    file << "output_file=" << config_.output_file << "\n";
    file << "wordlist_file=" << config_.wordlist_file << "\n";
    file << "target_bssid=" << config_.target_bssid << "\n";
    file << "target_essid=" << config_.target_essid << "\n";
    file << "verbose=" << (config_.verbose ? "true" : "false") << "\n";
    file << "monitor_mode=" << (config_.monitor_mode ? "true" : "false") << "\n";
    file << "timeout=" << config_.timeout << "\n";
    
    return true;
}

} // namespace airlevi
