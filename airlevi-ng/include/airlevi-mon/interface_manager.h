#ifndef AIRLEVI_INTERFACE_MANAGER_H
#define AIRLEVI_INTERFACE_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include "common/types.h"

namespace airlevi {

struct WifiInterface {
    std::string name;
    std::string driver;
    std::string chipset;
    std::string phy;
    bool monitor_capable;
    bool monitor_mode;
    bool up;
    std::string mac_address;
    int channel;
    std::string mode;
};

struct ConflictingProcess {
    int pid;
    std::string name;
    std::string description;
};

class InterfaceManager {
public:
    InterfaceManager();
    ~InterfaceManager();

    // Interface discovery and management
    std::vector<WifiInterface> scanInterfaces();
    bool enableMonitorMode(const std::string& interface);
    bool disableMonitorMode(const std::string& interface);
    bool setChannel(const std::string& interface, int channel);
    bool bringUp(const std::string& interface);
    bool bringDown(const std::string& interface);
    
    // Process management
    std::vector<ConflictingProcess> checkConflictingProcesses();
    bool killConflictingProcesses();
    bool killProcess(int pid);
    
    // Interface information
    WifiInterface getInterfaceInfo(const std::string& interface);
    bool isMonitorCapable(const std::string& interface);
    bool isInMonitorMode(const std::string& interface);
    std::string getDriver(const std::string& interface);
    std::string getChipset(const std::string& interface);
    
    // Virtual interface management
    std::string createMonitorInterface(const std::string& base_interface);
    bool removeInterface(const std::string& interface);
    
    // System checks
    bool checkRootPrivileges();
    bool checkKernelModules();
    std::vector<std::string> getRequiredModules();
    
    // Display functions
    void displayInterfaces();
    void displayConflictingProcesses();
    
private:
    std::vector<WifiInterface> interfaces_;
    std::vector<ConflictingProcess> conflicting_processes_;
    
    // Helper functions
    bool executeCommand(const std::string& command, std::string& output);
    bool isWirelessInterface(const std::string& interface);
    std::string getPhyFromInterface(const std::string& interface);
    bool setInterfaceMode(const std::string& interface, const std::string& mode);
    std::vector<std::string> parseNetworkInterfaces();
    std::map<std::string, std::string> getInterfaceDetails(const std::string& interface);
    
    // Process detection
    std::vector<int> findProcessesByName(const std::string& name);
    bool isProcessRunning(int pid);
    std::string getProcessName(int pid);
    
    // Driver and chipset detection
    std::string detectDriver(const std::string& interface);
    std::string detectChipset(const std::string& interface);
    bool supportsMonitorMode(const std::string& driver);
    
    // Network manager interaction
    bool stopNetworkManager();
    bool startNetworkManager();
    bool isNetworkManagerRunning();
    
    // Interface state management
    void updateInterfaceList();
    void updateConflictingProcesses();
};

} // namespace airlevi

#endif // AIRLEVI_INTERFACE_MANAGER_H
