#ifndef AIRLEVI_NETWORK_INTERFACE_H
#define AIRLEVI_NETWORK_INTERFACE_H

#include "types.h"
#include <string>
#include <vector>

namespace airlevi {

class NetworkInterface {
public:
    NetworkInterface(const std::string& interface_name);
    ~NetworkInterface();

    // Interface management
    bool setMonitorMode(bool enable);
    bool isMonitorMode() const;
    bool setChannel(int channel);
    int getChannel() const;
    bool isUp() const;
    bool bringUp();
    bool bringDown();

    // Information
    std::string getName() const { return interface_name_; }
    MacAddress getMacAddress() const;
    std::vector<int> getSupportedChannels() const;
    bool supportsMonitorMode() const;

    // Static utility functions
    static std::vector<std::string> getWirelessInterfaces();
    static bool interfaceExists(const std::string& interface_name);

private:
    std::string interface_name_;
    bool monitor_mode_;
    int current_channel_;

    // Helper functions
    bool executeCommand(const std::string& command) const;
    std::string getInterfaceProperty(const std::string& property) const;
    bool setInterfaceProperty(const std::string& property, const std::string& value) const;
};

} // namespace airlevi

#endif // AIRLEVI_NETWORK_INTERFACE_H
