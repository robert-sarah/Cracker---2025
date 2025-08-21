#ifndef AIRLEVI_WIFI_SCANNER_H
#define AIRLEVI_WIFI_SCANNER_H

#include "common/types.h"
#include <map>
#include <mutex>
#include <thread>
#include <atomic>

namespace airlevi {

class WifiScanner {
public:
    explicit WifiScanner(const Config& config);
    ~WifiScanner();

    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Channel management
    void setChannel(int channel);
    int getCurrentChannel() const { return current_channel_; }

    // Network management
    void addNetwork(const WifiNetwork& network);
    void addClient(const WifiClient& client);
    void addSAEHandshake(const SAEHandshakePacket& sae_packet);
    void updateNetworkHandshake(const MacAddress& bssid, bool has_handshake);

    // Data access
    std::vector<WifiNetwork> getNetworks() const;
    std::vector<WifiClient> getClients() const;
    std::vector<SAEHandshakePacket> getSAEHandshakes() const;
    Statistics getStatistics() const;

    // Display functions
    void displayNetworks() const;
    void displayClients() const;
    void displayStatistics() const;

private:
    Config config_;
    std::atomic<bool> running_;
    std::atomic<int> current_channel_;
    
    // Data storage
    mutable std::mutex networks_mutex_;
    mutable std::mutex clients_mutex_;
    mutable std::mutex sae_handshakes_mutex_;
    std::map<MacAddress, WifiNetwork> networks_;
    std::map<MacAddress, WifiClient> clients_;
    std::vector<SAEHandshakePacket> sae_handshakes_;
    
    // Statistics
    Statistics stats_;
    mutable std::mutex stats_mutex_;
    
    // Background threads
    std::thread cleanup_thread_;
    
    // Background tasks
    void cleanupTask();
    void updateStatistics();
    
    // Helper functions
    void removeOldEntries();
    bool isNetworkActive(const WifiNetwork& network) const;
    bool isClientActive(const WifiClient& client) const;
    
    // Channel switching (requires root/monitor mode)
    bool switchToChannel(int channel);
};

} // namespace airlevi

#endif // AIRLEVI_WIFI_SCANNER_H
