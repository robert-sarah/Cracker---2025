#ifndef AIRLEVI_TYPES_H
#define AIRLEVI_TYPES_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <cstring>

namespace airlevi {

// Network types
struct MacAddress {
    uint8_t bytes[6];
    
    MacAddress() { memset(bytes, 0, 6); }
    MacAddress(const uint8_t* addr) { memcpy(bytes, addr, 6); }
    
    std::string toString() const;
    bool operator==(const MacAddress& other) const;
    bool operator<(const MacAddress& other) const;
};

struct WifiNetwork {
    MacAddress bssid;
    std::string essid;
    int channel;
    int signal_strength;
    std::string encryption;
    uint64_t packets_captured;
    std::chrono::steady_clock::time_point last_seen;
    bool has_handshake;
    std::vector<MacAddress> clients;
};

struct WifiClient {
    MacAddress mac;
    MacAddress associated_ap;
    int signal_strength;
    uint64_t packets_sent;
    uint64_t packets_received;
    std::chrono::steady_clock::time_point last_seen;
};

// Packet structures
struct IEEE80211Header {
    uint16_t frame_control;
    uint16_t duration;
    MacAddress addr1;
    MacAddress addr2;
    MacAddress addr3;
    uint16_t seq_ctrl;
} __attribute__((packed));

struct BeaconFrame {
    IEEE80211Header header;
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;
    // Variable length information elements follow
} __attribute__((packed));

struct HandshakePacket {
    MacAddress ap_mac;
    MacAddress client_mac;
    std::vector<uint8_t> anonce;
    std::vector<uint8_t> snonce;
    std::vector<uint8_t> mic;
    std::vector<uint8_t> eapol_data;
    std::string essid;
    int message_number; // 1-4 for 4-way handshake
};

struct SAEHandshakePacket {
    MacAddress ap_mac;
    MacAddress client_mac;
    std::string essid;
    int message_number; // 1 for Commit, 2 for Confirm
    uint16_t finite_field_group;
    std::vector<uint8_t> scalar;
    std::vector<uint8_t> element;
    std::vector<uint8_t> confirm;
    std::vector<uint8_t> raw_data;
};

// Attack types
enum class AttackType {
    WEP_CRACK,
    WPA_DICTIONARY,
    WPA_BRUTE_FORCE,
    DEAUTH,
    EVIL_TWIN,
    PMKID
};

enum class EncryptionType {
    OPEN,
    WEP,
    WPA,
    WPA2,
    WPA3,
    UNKNOWN
};

// Configuration
struct Config {
    std::string interface;
    std::string output_file;
    std::string wordlist_file;
    int channel;
    bool monitor_mode;
    bool verbose;
    int timeout;
    std::string target_bssid;
    std::string target_essid;
};

// Statistics
struct Statistics {
    uint64_t total_packets;
    uint64_t beacon_frames;
    uint64_t data_frames;
    uint64_t management_frames;
    uint64_t control_frames;
    uint64_t networks_found;
    uint64_t clients_found;
    uint64_t handshakes_captured;
    std::chrono::steady_clock::time_point start_time;
};

} // namespace airlevi

#endif // AIRLEVI_TYPES_H
