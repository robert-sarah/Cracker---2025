#ifndef AIRLEVI_DEAUTH_ATTACK_H
#define AIRLEVI_DEAUTH_ATTACK_H

#include "common/types.h"
#include "common/network_interface.h"
#include <thread>
#include <atomic>
#include <vector>
#include <set>
#include <mutex>
#include <chrono>

namespace airlevi {

struct DeauthStatistics {
    uint64_t packets_sent = 0;
    uint64_t clients_deauthed = 0;
    uint64_t duration_seconds = 0;
    std::chrono::steady_clock::time_point start_time;
};

class DeauthAttack {
public:
    explicit DeauthAttack(const Config& config);
    ~DeauthAttack();

    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Configuration
    void setTargetAP(const std::string& bssid);
    void setTargetClient(const std::string& mac);
    void setBroadcast(bool broadcast) { broadcast_mode_ = broadcast; }
    void setPacketCount(int count) { packet_count_ = count; }
    void setDelay(int delay_ms) { delay_ms_ = delay_ms; }
    void setReasonCode(int code) { reason_code_ = code; }

    // Statistics
    DeauthStatistics getStatistics() const;

private:
    Config config_;
    std::unique_ptr<NetworkInterface> interface_;
    
    // Attack parameters
    MacAddress target_ap_;
    MacAddress target_client_;
    bool broadcast_mode_;
    int packet_count_;
    int delay_ms_;
    int reason_code_;
    
    // Runtime state
    std::atomic<bool> running_;
    std::thread attack_thread_;
    std::thread discovery_thread_;
    
    // Client discovery
    std::set<MacAddress> discovered_clients_;
    std::mutex clients_mutex_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    DeauthStatistics stats_;
    
    // Attack methods
    void attackLoop();
    void clientDiscoveryLoop();
    
    // Packet crafting and sending
    bool sendDeauthPacket(const MacAddress& ap, const MacAddress& client);
    std::vector<uint8_t> craftDeauthFrame(const MacAddress& src, const MacAddress& dst, uint16_t reason);
    bool injectPacket(const std::vector<uint8_t>& packet);
    
    // Client discovery
    void discoverClients();
    void addDiscoveredClient(const MacAddress& client);
    std::vector<MacAddress> getTargetClients();
    
    // Utility functions
    bool setupInterface();
    void updateStatistics();
};

} // namespace airlevi

#endif // AIRLEVI_DEAUTH_ATTACK_H
