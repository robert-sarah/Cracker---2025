#ifndef AIRLEVI_ADVANCED_MONITOR_H
#define AIRLEVI_ADVANCED_MONITOR_H

#include "common/types.h"
#include "common/logger.h"
#include <pcap.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>

namespace airlevi {

struct ClientInfo {
    MacAddress mac;
    std::string vendor;
    int signal_strength;
    std::chrono::steady_clock::time_point last_seen;
    uint64_t packets_count;
    uint64_t data_bytes;
    std::vector<std::string> probed_ssids;
    bool is_associated;
    MacAddress associated_bssid;
};

struct AccessPointInfo {
    MacAddress bssid;
    std::string ssid;
    uint8_t channel;
    std::string encryption;
    std::string cipher;
    std::string auth;
    int signal_strength;
    uint16_t beacon_interval;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    uint64_t beacon_count;
    uint64_t data_packets;
    std::vector<MacAddress> clients;
    bool wps_enabled;
    bool wps_locked;
    std::string vendor;
    uint32_t uptime_estimate;
};

struct ChannelStats {
    uint8_t channel;
    uint64_t total_packets;
    uint64_t beacon_packets;
    uint64_t data_packets;
    uint64_t mgmt_packets;
    uint64_t ctrl_packets;
    double utilization;
    int noise_level;
    std::vector<MacAddress> active_aps;
};

struct HandshakeInfo {
    MacAddress ap_bssid;
    MacAddress client_mac;
    std::string ssid;
    std::chrono::steady_clock::time_point captured_time;
    bool is_complete;
    uint8_t message_flags; // Bitmask: 1=M1, 2=M2, 4=M3, 8=M4
    std::vector<uint8_t> anonce;
    std::vector<uint8_t> snonce;
    std::vector<uint8_t> mic;
};

class AdvancedMonitor {
public:
    AdvancedMonitor();
    ~AdvancedMonitor();

    bool initialize(const std::string& interface);
    bool startMonitoring();
    void stopMonitoring();
    
    // Channel management
    void setChannelHopping(bool enabled, int dwell_time_ms = 250);
    void setFixedChannel(uint8_t channel);
    void setChannelList(const std::vector<uint8_t>& channels);
    
    // Filtering
    void setTargetBSSID(const MacAddress& bssid);
    void setTargetSSID(const std::string& ssid);
    void setSignalThreshold(int min_signal);
    
    // Data access
    std::vector<AccessPointInfo> getAccessPoints() const;
    std::vector<ClientInfo> getClients() const;
    std::vector<HandshakeInfo> getHandshakes() const;
    std::vector<ChannelStats> getChannelStats() const;
    
    // Real-time display
    void displayNetworksTable();
    void displayClientsTable();
    void displayChannelStats();
    void displayHandshakes();
    void displayRealTimeStats();
    
    // Export functions
    bool exportToCSV(const std::string& filename) const;
    bool exportHandshakes(const std::string& filename) const;
    bool saveSession(const std::string& filename) const;
    
    // Statistics
    struct MonitorStats {
        uint64_t total_packets;
        uint64_t beacon_frames;
        uint64_t probe_requests;
        uint64_t probe_responses;
        uint64_t auth_frames;
        uint64_t assoc_frames;
        uint64_t data_frames;
        uint64_t deauth_frames;
        uint64_t disassoc_frames;
        uint64_t handshakes_captured;
        uint64_t unique_aps;
        uint64_t unique_clients;
        std::chrono::steady_clock::time_point start_time;
    };
    
    MonitorStats getStats() const { return stats_; }
    void resetStats();

private:
    void monitoringThread();
    void channelHoppingThread();
    void cleanupThread();
    void packetHandler(const struct pcap_pkthdr* header, const u_char* packet);
    
    // Packet analysis
    void analyzeBeacon(const u_char* packet, int length);
    void analyzeProbeRequest(const u_char* packet, int length);
    void analyzeProbeResponse(const u_char* packet, int length);
    void analyzeAuthFrame(const u_char* packet, int length);
    void analyzeAssocFrame(const u_char* packet, int length);
    void analyzeDataFrame(const u_char* packet, int length);
    void analyzeDeauthFrame(const u_char* packet, int length);
    void analyzeEAPOLFrame(const u_char* packet, int length);
    
    // Information extraction
    std::string extractSSID(const u_char* packet, int length);
    std::string extractEncryption(const u_char* packet, int length);
    uint8_t extractChannel(const u_char* packet, int length);
    int extractSignalStrength(const u_char* packet);
    std::string getVendorFromMAC(const MacAddress& mac);
    
    // Handshake detection
    void detectHandshake(const u_char* packet, int length);
    bool isEAPOLKey(const u_char* packet, int length);
    uint8_t getEAPOLKeyType(const u_char* packet, int length);
    
    // Display helpers
    void clearScreen();
    void printHeader(const std::string& title);
    void printTableHeader(const std::vector<std::string>& headers, const std::vector<int>& widths);
    void printTableRow(const std::vector<std::string>& data, const std::vector<int>& widths);
    std::string formatTime(const std::chrono::steady_clock::time_point& time);
    std::string formatDuration(const std::chrono::steady_clock::time_point& start);
    
    pcap_t* pcap_handle_;
    std::string interface_;
    
    // Threading
    std::atomic<bool> running_;
    std::thread monitoring_thread_;
    std::thread channel_hopping_thread_;
    std::thread cleanup_thread_;
    
    // Channel management
    std::atomic<bool> channel_hopping_enabled_;
    std::atomic<uint8_t> current_channel_;
    std::vector<uint8_t> channel_list_;
    int channel_dwell_time_;
    
    // Filtering
    MacAddress target_bssid_;
    std::string target_ssid_;
    int signal_threshold_;
    
    // Data storage
    mutable std::mutex data_mutex_;
    std::unordered_map<std::string, AccessPointInfo> access_points_;
    std::unordered_map<std::string, ClientInfo> clients_;
    std::vector<HandshakeInfo> handshakes_;
    std::map<uint8_t, ChannelStats> channel_stats_;
    
    // Statistics
    MonitorStats stats_;
    
    // OUI database for vendor lookup
    std::unordered_map<std::string, std::string> oui_database_;
    void loadOUIDatabase();
};

} // namespace airlevi

#endif // AIRLEVI_ADVANCED_MONITOR_H
