#ifndef AIRLEVI_PACKET_REPLAY_H
#define AIRLEVI_PACKET_REPLAY_H

#include "common/types.h"
#include "common/logger.h"
#include <pcap.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>

namespace airlevi {

enum class ReplayMode {
    SINGLE,
    CONTINUOUS,
    BURST,
    TIMED
};

struct ReplayStats {
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t errors;
    std::chrono::steady_clock::time_point start_time;
    double packets_per_second;
};

class PacketReplay {
public:
    PacketReplay();
    ~PacketReplay();

    bool initialize(const std::string& interface);
    bool loadCaptureFile(const std::string& filename);
    bool setTargetMAC(const std::string& mac);
    bool setSourceMAC(const std::string& mac);
    
    void setReplayMode(ReplayMode mode);
    void setPacketDelay(int microseconds);
    void setPacketCount(int count);
    void setBurstSize(int size);
    void setSpeed(double multiplier);
    
    bool startReplay();
    void stopReplay();
    bool isRunning() const { return running_; }
    
    ReplayStats getStats() const;
    void printStats() const;
    void printRealTimeStats();
    
private:
    void replayThread();
    bool injectPacket(const u_char* packet, int length);
    void modifyPacket(u_char* packet, int length);
    void updateStats();
    
    pcap_t* pcap_handle_;
    pcap_t* inject_handle_;
    std::string interface_;
    std::string capture_file_;
    
    std::vector<std::pair<std::vector<u_char>, int>> packets_;
    
    ReplayMode mode_;
    int packet_delay_;
    int packet_count_;
    int burst_size_;
    double speed_multiplier_;
    
    MacAddress target_mac_;
    MacAddress source_mac_;
    bool modify_mac_;
    
    std::atomic<bool> running_;
    std::thread replay_thread_;
    
    mutable std::mutex stats_mutex_;
    ReplayStats stats_;
};

} // namespace airlevi

#endif // AIRLEVI_PACKET_REPLAY_H
