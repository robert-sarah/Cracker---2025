#ifndef AIRLEVI_PACKET_FORGE_H
#define AIRLEVI_PACKET_FORGE_H

#include "common/types.h"
#include "common/logger.h"
#include <pcap.h>
#include <string>
#include <vector>
#include <map>

namespace airlevi {

enum class PacketType {
    BEACON,
    PROBE_REQUEST,
    PROBE_RESPONSE,
    DEAUTH,
    DISASSOC,
    AUTH,
    ASSOC_REQUEST,
    ASSOC_RESPONSE,
    DATA,
    QOS_DATA,
    RTS,
    CTS,
    ACK
};

struct IEEE80211Header {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];  // Destination
    uint8_t addr2[6];  // Source
    uint8_t addr3[6];  // BSSID
    uint16_t seq_ctrl;
} __attribute__((packed));

struct BeaconFrame {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;
} __attribute__((packed));

class PacketForge {
public:
    PacketForge();
    ~PacketForge();

    bool initialize(const std::string& interface);
    
    // Packet creation methods
    std::vector<uint8_t> createBeacon(const std::string& ssid, const MacAddress& bssid, 
                                     uint8_t channel, const std::string& encryption = "");
    std::vector<uint8_t> createProbeRequest(const std::string& ssid, const MacAddress& src_mac);
    std::vector<uint8_t> createProbeResponse(const std::string& ssid, const MacAddress& bssid,
                                           const MacAddress& dst_mac, uint8_t channel);
    std::vector<uint8_t> createDeauth(const MacAddress& bssid, const MacAddress& client,
                                     uint16_t reason = 7);
    std::vector<uint8_t> createDisassoc(const MacAddress& bssid, const MacAddress& client,
                                       uint16_t reason = 8);
    std::vector<uint8_t> createAuth(const MacAddress& bssid, const MacAddress& client,
                                   uint16_t auth_algo = 0, uint16_t auth_seq = 1);
    std::vector<uint8_t> createAssocRequest(const std::string& ssid, const MacAddress& bssid,
                                          const MacAddress& client);
    std::vector<uint8_t> createDataFrame(const MacAddress& dst, const MacAddress& src,
                                        const MacAddress& bssid, const std::vector<uint8_t>& payload);
    
    // Advanced packet crafting
    std::vector<uint8_t> createEvilTwinBeacon(const std::string& target_ssid, 
                                             const MacAddress& fake_bssid, uint8_t channel);
    std::vector<uint8_t> createKarmaBeacon(const std::string& ssid);
    std::vector<uint8_t> createWPSBeacon(const std::string& ssid, const MacAddress& bssid,
                                        uint8_t channel, bool locked = false);
    
    // Injection methods
    bool injectPacket(const std::vector<uint8_t>& packet);
    bool injectPacketBurst(const std::vector<uint8_t>& packet, int count, int delay_us = 1000);
    
    // Template management
    bool saveTemplate(const std::string& name, const std::vector<uint8_t>& packet);
    std::vector<uint8_t> loadTemplate(const std::string& name);
    std::vector<std::string> listTemplates() const;
    
    // Utility methods
    void setRadiotapHeader(std::vector<uint8_t>& packet, uint8_t channel, int8_t power = 20);
    void addInformationElement(std::vector<uint8_t>& packet, uint8_t type, 
                              const std::vector<uint8_t>& data);
    void calculateChecksum(std::vector<uint8_t>& packet);
    
    // Statistics
    struct ForgeStats {
        uint64_t packets_created;
        uint64_t packets_injected;
        uint64_t injection_errors;
        std::map<PacketType, uint64_t> type_counts;
    };
    
    ForgeStats getStats() const { return stats_; }
    void printStats() const;
    void resetStats();

private:
    void addRadiotapHeader(std::vector<uint8_t>& packet, uint8_t channel, int8_t power);
    void add80211Header(std::vector<uint8_t>& packet, PacketType type,
                       const MacAddress& dst, const MacAddress& src, const MacAddress& bssid);
    void addSSIDElement(std::vector<uint8_t>& packet, const std::string& ssid);
    void addChannelElement(std::vector<uint8_t>& packet, uint8_t channel);
    void addRatesElement(std::vector<uint8_t>& packet);
    void addWPAElement(std::vector<uint8_t>& packet);
    void addWPA2Element(std::vector<uint8_t>& packet);
    void addWPSElement(std::vector<uint8_t>& packet, bool locked);
    
    pcap_t* pcap_handle_;
    std::string interface_;
    std::map<std::string, std::vector<uint8_t>> templates_;
    ForgeStats stats_;
    uint16_t sequence_number_;
};

} // namespace airlevi

#endif // AIRLEVI_PACKET_FORGE_H
