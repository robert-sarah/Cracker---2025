#ifndef AIRLEVI_CONFIG_H
#define AIRLEVI_CONFIG_H

#include "types.h"
#include <string>

namespace airlevi {

class ConfigManager {
public:
    static ConfigManager& getInstance();
    
    bool loadConfig(const std::string& config_file);
    bool saveConfig(const std::string& config_file) const;
    
    // Getters
    const Config& getConfig() const { return config_; }
    Config& getConfig() { return config_; }
    
    // Setters
    void setInterface(const std::string& interface) { config_.interface = interface; }
    void setChannel(int channel) { config_.channel = channel; }
    void setOutputFile(const std::string& output_file) { config_.output_file = output_file; }
    void setWordlistFile(const std::string& wordlist_file) { config_.wordlist_file = wordlist_file; }
    void setTargetBSSID(const std::string& bssid) { config_.target_bssid = bssid; }
    void setTargetESSID(const std::string& essid) { config_.target_essid = essid; }
    void setVerbose(bool verbose) { config_.verbose = verbose; }
    void setMonitorMode(bool monitor_mode) { config_.monitor_mode = monitor_mode; }
    void setTimeout(int timeout) { config_.timeout = timeout; }

private:
    ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    Config config_;
};

} // namespace airlevi

#endif // AIRLEVI_CONFIG_H
