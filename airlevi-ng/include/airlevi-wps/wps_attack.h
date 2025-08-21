#ifndef AIRLEVI_WPS_ATTACK_H
#define AIRLEVI_WPS_ATTACK_H

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

enum class WPSAttackType {
    PIXIE_DUST,
    REAVER,
    BRUTE_FORCE,
    NULL_PIN,
    CHECKSUM_BYPASS
};

struct WPSInfo {
    MacAddress bssid;
    std::string ssid;
    uint8_t channel;
    std::string manufacturer;
    std::string model;
    std::string version;
    bool locked;
    bool configured;
    uint32_t uuid_e[4];
    uint8_t pke[192];
    uint8_t pkr[192];
    uint8_t auth_key[32];
    uint8_t key_wrap_key[16];
    uint8_t emsk[32];
    std::chrono::steady_clock::time_point last_seen;
};

struct WPSPin {
    std::string pin;
    uint32_t checksum;
    bool tested;
    std::chrono::steady_clock::time_point test_time;
};

class WPSAttack {
public:
    WPSAttack();
    ~WPSAttack();

    bool initialize(const std::string& interface);
    bool setTarget(const MacAddress& bssid);
    bool setChannel(uint8_t channel);
    
    // Attack methods
    bool startPixieDustAttack();
    bool startReaverAttack();
    bool startBruteForceAttack();
    bool startNullPinAttack();
    
    // WPS discovery
    bool scanForWPS();
    std::vector<WPSInfo> getWPSNetworks() const;
    void displayWPSTable();
    
    // Pin management
    void addCustomPin(const std::string& pin);
    void loadPinList(const std::string& filename);
    void generateCommonPins();
    std::vector<WPSPin> getPinQueue() const;
    
    // Attack configuration
    void setDelay(int seconds);
    void setMaxAttempts(int attempts);
    void setTimeout(int seconds);
    void setVerbose(bool enabled);
    
    // Monitoring
    void displayAttackProgress();
    void displayRealTimeStats();
    
    // Results
    struct AttackResult {
        bool success;
        std::string pin;
        std::string psk;
        std::string ssid;
        MacAddress bssid;
        std::chrono::steady_clock::time_point found_time;
        WPSAttackType attack_type;
    };
    
    std::vector<AttackResult> getResults() const;
    bool saveResults(const std::string& filename) const;
    
    // Statistics
    struct WPSStats {
        uint64_t pins_tested;
        uint64_t m1_sent;
        uint64_t m2_received;
        uint64_t m3_sent;
        uint64_t m4_received;
        uint64_t m5_sent;
        uint64_t m6_received;
        uint64_t m7_sent;
        uint64_t m8_received;
        uint64_t nacks_received;
        uint64_t timeouts;
        uint64_t lockouts;
        std::chrono::steady_clock::time_point start_time;
        double pins_per_second;
    };
    
    WPSStats getStats() const { return stats_; }
    void resetStats();

private:
    void attackThread();
    void monitoringThread();
    void packetHandler(const struct pcap_pkthdr* header, const u_char* packet);
    
    // WPS protocol
    bool sendM1();
    bool sendM3();
    bool sendM5();
    bool sendM7();
    void handleM2(const u_char* packet, int length);
    void handleM4(const u_char* packet, int length);
    void handleM6(const u_char* packet, int length);
    void handleM8(const u_char* packet, int length);
    void handleNack(const u_char* packet, int length);
    
    // Pixie Dust specific
    bool performPixieDustAttack();
    bool extractPixieDustData();
    uint32_t calculatePixiePin();
    
    // Pin generation
    std::vector<std::string> generateDefaultPins();
    std::vector<std::string> generateManufacturerPins();
    uint32_t calculateChecksum(const std::string& pin);
    bool validatePin(const std::string& pin);
    
    // Packet creation
    std::vector<uint8_t> createEAPOLStart();
    std::vector<uint8_t> createM1Packet();
    std::vector<uint8_t> createM3Packet(const std::string& pin);
    std::vector<uint8_t> createM5Packet();
    std::vector<uint8_t> createM7Packet();
    
    // Crypto operations
    void deriveKeys(const std::string& pin);
    bool verifyAuthenticator(const u_char* packet, int length);
    void decryptSettings(const u_char* encrypted, int length);
    
    // Display helpers
    void clearScreen();
    void printHeader(const std::string& title);
    void printProgress(int current, int total);
    std::string formatDuration(const std::chrono::steady_clock::time_point& start);
    
    pcap_t* pcap_handle_;
    std::string interface_;
    MacAddress target_bssid_;
    uint8_t target_channel_;
    WPSAttackType current_attack_;
    
    // Threading
    std::atomic<bool> running_;
    std::atomic<bool> attack_active_;
    std::thread attack_thread_;
    std::thread monitoring_thread_;
    
    // WPS data
    mutable std::mutex wps_mutex_;
    std::unordered_map<std::string, WPSInfo> wps_networks_;
    WPSInfo current_target_;
    
    // Pin management
    std::vector<WPSPin> pin_queue_;
    std::atomic<size_t> current_pin_index_;
    std::mutex pin_mutex_;
    
    // Attack configuration
    int delay_seconds_;
    int max_attempts_;
    int timeout_seconds_;
    bool verbose_;
    
    // Results
    std::vector<AttackResult> results_;
    std::mutex results_mutex_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    WPSStats stats_;
    
    // WPS protocol state
    enum class WPSState {
        IDLE,
        ASSOCIATING,
        M1_SENT,
        M2_RECEIVED,
        M3_SENT,
        M4_RECEIVED,
        M5_SENT,
        M6_RECEIVED,
        M7_SENT,
        M8_RECEIVED,
        DONE,
        LOCKED
    };
    
    std::atomic<WPSState> wps_state_;
    
    // Pixie Dust data
    struct PixieData {
        uint8_t pke[192];
        uint8_t pkr[192];
        uint8_t e_hash1[32];
        uint8_t e_hash2[32];
        uint8_t authkey[32];
        uint8_t e_nonce[16];
        uint8_t r_nonce[16];
        bool valid;
    };
    
    PixieData pixie_data_;
};

} // namespace airlevi

#endif // AIRLEVI_WPS_ATTACK_H
