#ifndef AIRLEVI_PMKID_ATTACK_H
#define AIRLEVI_PMKID_ATTACK_H

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

struct PMKIDInfo {
    MacAddress ap_bssid;
    MacAddress client_mac;
    std::string ssid;
    std::vector<uint8_t> pmkid;
    std::vector<uint8_t> eapol_frame;
    std::chrono::steady_clock::time_point captured_time;
    bool cracked;
    std::string password;
};

struct TargetAP {
    MacAddress bssid;
    std::string ssid;
    uint8_t channel;
    int signal_strength;
    bool pmkid_support;
    std::chrono::steady_clock::time_point last_seen;
};

class PMKIDAttack {
public:
    PMKIDAttack();
    ~PMKIDAttack();

    bool initialize(const std::string& interface);
    bool startAttack();
    void stopAttack();
    
    // Configuration
    void setTargetBSSID(const MacAddress& bssid);
    void setTargetSSID(const std::string& ssid);
    void setChannel(uint8_t channel);
    void setChannelHopping(bool enabled, int dwell_time_ms = 250);
    void setWordlist(const std::string& filename);
    void setTimeout(int seconds);
    
    // Discovery
    void scanForTargets();
    std::vector<TargetAP> getTargets() const;
    void displayTargetsTable();
    
    // Cracking
    bool crackPMKID(PMKIDInfo& pmkid_info);
    void crackAllPMKIDs();
    
    // Results
    std::vector<PMKIDInfo> getCapturedPMKIDs() const;
    void displayPMKIDTable();
    bool savePMKIDs(const std::string& filename, bool hashcat_format = true) const;
    
    // Statistics
    struct PMKIDStats {
        uint64_t assoc_requests_sent;
        uint64_t eapol_starts_sent;
        uint64_t pmkids_captured;
        uint64_t pmkids_cracked;
        uint64_t targets_found;
        std::chrono::steady_clock::time_point start_time;
        double keys_per_second;
    };
    
    PMKIDStats getStats() const { return stats_; }
    void resetStats();

private:
    void attackThread();
    void monitoringThread();
    void channelHoppingThread();
    void packetHandler(const struct pcap_pkthdr* header, const u_char* packet);
    
    // Attack logic
    bool associateToAP(const TargetAP& target);
    bool sendEAPOLStart(const TargetAP& target);
    void handleEAPOL(const u_char* packet, int length);
    std::vector<uint8_t> extractPMKID(const u_char* packet, int length);
    
    // Packet creation
    std::vector<uint8_t> createAssocRequest(const MacAddress& bssid, const std::string& ssid);
    std::vector<uint8_t> createEAPOLStartFrame(const MacAddress& bssid);
    
    // Cracking logic
    bool tryPassword(const PMKIDInfo& pmkid_info, const std::string& password);
    void loadWordlist();
    
    // Display helpers
    void clearScreen();
    void printHeader(const std::string& title);
    std::string formatBytes(const std::vector<uint8_t>& data) const;
    
    pcap_t* pcap_handle_;
    std::string interface_;
    MacAddress local_mac_;
    
    // Threading
    std::atomic<bool> running_;
    std::thread attack_thread_;
    std::thread monitoring_thread_;
    std::thread channel_hopping_thread_;
    
    // Configuration
    MacAddress target_bssid_;
    std::string target_ssid_;
    std::atomic<uint8_t> current_channel_;
    bool channel_hopping_enabled_;
    int channel_dwell_time_;
    int timeout_seconds_;
    
    // Data storage
    mutable std::mutex data_mutex_;
    std::unordered_map<std::string, TargetAP> targets_;
    std::vector<PMKIDInfo> captured_pmkids_;
    
    // Cracking
    std::string wordlist_file_;
    std::vector<std::string> wordlist_;
    std::atomic<bool> cracking_active_;
    
    // Statistics
    PMKIDStats stats_;
};

} // namespace airlevi

#endif // AIRLEVI_PMKID_ATTACK_H
