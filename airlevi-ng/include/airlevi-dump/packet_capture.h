#ifndef AIRLEVI_PACKET_CAPTURE_H
#define AIRLEVI_PACKET_CAPTURE_H

#include "common/types.h"
#include "common/packet_parser.h"
#include <pcap.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>

namespace airlevi {

class PacketCapture {
public:
    explicit PacketCapture(const Config& config);
    ~PacketCapture();

    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Packet handlers
    void onPacketReceived(const uint8_t* packet, int length);
    void onBeaconFrame(const WifiNetwork& network);
    void onDataFrame(const MacAddress& src, const MacAddress& dst);
    void onHandshakePacket(const HandshakePacket& handshake);
    void onSAEHandshakePacket(const SAEHandshakePacket& sae_packet);

    // Statistics
    uint64_t getTotalPackets() const { return total_packets_; }
    uint64_t getHandshakeCount() const { return handshake_count_; }

private:
    Config config_;
    pcap_t* pcap_handle_;
    std::thread capture_thread_;
    std::atomic<bool> running_;
    PacketParser parser_;
    
    // Statistics
    std::atomic<uint64_t> total_packets_;
    std::atomic<uint64_t> handshake_count_;
    
    // Output file
    std::ofstream output_file_;
    std::mutex file_mutex_;
    
    // Packet capture loop
    void captureLoop();
    
    // Packet processing
    void processPacket(const struct pcap_pkthdr* header, const uint8_t* packet);
    
    // File operations
    bool openOutputFile();
    void writePacketToFile(const struct pcap_pkthdr* header, const uint8_t* packet);
    
    // Filter functions
    bool shouldCapturePacket(const uint8_t* packet, int length);
    bool matchesTargetBSSID(const MacAddress& bssid);
    bool matchesTargetESSID(const std::string& essid);
    
    // Static callback for pcap
    static void packetCallback(uint8_t* user_data, const struct pcap_pkthdr* header, const uint8_t* packet);
};

} // namespace airlevi

#endif // AIRLEVI_PACKET_CAPTURE_H
