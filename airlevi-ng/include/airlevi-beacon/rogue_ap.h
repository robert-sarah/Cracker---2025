#ifndef AIRLEVI_ROGUE_AP_H
#define AIRLEVI_ROGUE_AP_H

#include "common/types.h"
#include "common/logger.h"
#include <pcap.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace airlevi {

enum class APMode {
    EVIL_TWIN,      // Clone existing AP
    KARMA,          // Respond to all probe requests
    CAPTIVE_PORTAL, // Redirect to captive portal
    WPS_FAKE,       // Fake WPS-enabled AP
    HONEYPOT        // Advanced honeypot mode
};

struct ClientConnection {
    MacAddress mac;
    std::string hostname;
    std::chrono::steady_clock::time_point connected_time;
    uint64_t packets_sent;
    uint64_t packets_received;
    bool authenticated;
    bool associated;
};

struct APConfig {
    std::string ssid;
    MacAddress bssid;
    uint8_t channel;
    std::string encryption;
    std::string password;
    uint16_t beacon_interval;
    bool hidden;
    bool wps_enabled;
    bool wps_locked;
    std::string country_code;
    int tx_power;
};

class RogueAP {
public:
    RogueAP();
    ~RogueAP();

    bool initialize(const std::string& interface);
    bool configure(const APConfig& config);
    bool startAP();
    void stopAP();
    
    // Mode configuration
    void setMode(APMode mode);
    void setTargetSSID(const std::string& ssid);
    void setTargetBSSID(const MacAddress& bssid);
    void enableKarmaMode(bool enabled);
    void setCaptivePortal(const std::string& redirect_url);
    
    // Client management
    std::vector<ClientConnection> getConnectedClients() const;
    bool deauthClient(const MacAddress& client);
    bool kickAllClients();
    
    // Beacon management
    void setBeaconInterval(uint16_t interval);
    void enableBeaconFlood(bool enabled, int count = 10);
    void addFakeSSID(const std::string& ssid);
    void removeFakeSSID(const std::string& ssid);
    
    // Monitoring
    void displayClientTable();
    void displayAPStatus();
    void displayRealTimeStats();
    
    // Statistics
    struct APStats {
        uint64_t beacons_sent;
        uint64_t probe_responses_sent;
        uint64_t auth_requests;
        uint64_t assoc_requests;
        uint64_t data_packets;
        uint64_t clients_connected;
        uint64_t clients_total;
        std::chrono::steady_clock::time_point start_time;
    };
    
    APStats getStats() const { return stats_; }
    void resetStats();
    
    // Export functions
    bool exportClientList(const std::string& filename) const;
    bool saveAPConfig(const std::string& filename) const;

private:
    void beaconThread();
    void monitoringThread();
    void clientManagementThread();
    void packetHandler(const struct pcap_pkthdr* header, const u_char* packet);
    
    // Packet creation
    std::vector<uint8_t> createBeacon();
    std::vector<uint8_t> createProbeResponse(const MacAddress& dst, const std::string& ssid);
    std::vector<uint8_t> createAuthResponse(const MacAddress& client);
    std::vector<uint8_t> createAssocResponse(const MacAddress& client);
    std::vector<uint8_t> createDeauthFrame(const MacAddress& client, uint16_t reason = 7);
    
    // Packet analysis
    void handleProbeRequest(const u_char* packet, int length);
    void handleAuthRequest(const u_char* packet, int length);
    void handleAssocRequest(const u_char* packet, int length);
    void handleDataFrame(const u_char* packet, int length);
    
    // Client management
    void addClient(const MacAddress& mac);
    void removeClient(const MacAddress& mac);
    void updateClientActivity(const MacAddress& mac);
    
    // Karma mode
    void handleKarmaProbe(const std::string& ssid, const MacAddress& client);
    void addKarmaSSID(const std::string& ssid);
    
    // Display helpers
    void clearScreen();
    void printHeader(const std::string& title);
    std::string formatUptime();
    std::string formatBytes(uint64_t bytes);
    
    pcap_t* pcap_handle_;
    std::string interface_;
    APConfig config_;
    APMode mode_;
    
    // Threading
    std::atomic<bool> running_;
    std::thread beacon_thread_;
    std::thread monitoring_thread_;
    std::thread client_mgmt_thread_;
    
    // Client management
    mutable std::mutex clients_mutex_;
    std::unordered_map<std::string, ClientConnection> clients_;
    
    // Karma mode
    std::atomic<bool> karma_enabled_;
    std::vector<std::string> karma_ssids_;
    std::mutex karma_mutex_;
    
    // Beacon flood
    std::atomic<bool> beacon_flood_enabled_;
    std::atomic<int> beacon_flood_count_;
    std::vector<std::string> fake_ssids_;
    std::mutex fake_ssids_mutex_;
    
    // Captive portal
    std::string captive_url_;
    std::atomic<bool> captive_enabled_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    APStats stats_;
    
    // Sequence numbers
    std::atomic<uint16_t> sequence_number_;
};

} // namespace airlevi

#endif // AIRLEVI_ROGUE_AP_H
