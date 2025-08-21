#include "airlevi-forge/packet_forge.h"
#include "common/network_interface.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <iomanip>

namespace airlevi {

PacketForge::PacketForge() 
    : pcap_handle_(nullptr), sequence_number_(0) {
    memset(&stats_, 0, sizeof(stats_));
}

PacketForge::~PacketForge() {
    if (pcap_handle_) pcap_close(pcap_handle_);
}

bool PacketForge::initialize(const std::string& interface) {
    interface_ = interface;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (!pcap_handle_) {
        Logger::getInstance().error("Failed to open interface for injection: " + std::string(errbuf));
        return false;
    }
    
    Logger::getInstance().info("Initialized packet forge on interface: " + interface);
    return true;
}

std::vector<uint8_t> PacketForge::createBeacon(const std::string& ssid, const MacAddress& bssid, 
                                              uint8_t channel, const std::string& encryption) {
    std::vector<uint8_t> packet;
    
    // Add radiotap header
    addRadiotapHeader(packet, channel, 20);
    
    // Add 802.11 header
    add80211Header(packet, PacketType::BEACON, MacAddress::broadcast(), bssid, bssid);
    
    // Add beacon frame body
    BeaconFrame beacon = {};
    beacon.timestamp = 0; // Will be filled by hardware
    beacon.beacon_interval = htole16(100); // 100 TU
    beacon.capabilities = htole16(0x0401); // ESS + Privacy
    
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&beacon), 
                  reinterpret_cast<uint8_t*>(&beacon) + sizeof(beacon));
    
    // Add information elements
    addSSIDElement(packet, ssid);
    addRatesElement(packet);
    addChannelElement(packet, channel);
    
    if (encryption == "WPA") {
        addWPAElement(packet);
    } else if (encryption == "WPA2") {
        addWPA2Element(packet);
    }
    
    stats_.packets_created++;
    stats_.type_counts[PacketType::BEACON]++;
    
    return packet;
}

std::vector<uint8_t> PacketForge::createProbeRequest(const std::string& ssid, const MacAddress& src_mac) {
    std::vector<uint8_t> packet;
    
    addRadiotapHeader(packet, 6, 20);
    add80211Header(packet, PacketType::PROBE_REQUEST, MacAddress::broadcast(), src_mac, MacAddress::broadcast());
    
    addSSIDElement(packet, ssid);
    addRatesElement(packet);
    
    stats_.packets_created++;
    stats_.type_counts[PacketType::PROBE_REQUEST]++;
    
    return packet;
}

std::vector<uint8_t> PacketForge::createDeauth(const MacAddress& bssid, const MacAddress& client, uint16_t reason) {
    std::vector<uint8_t> packet;
    
    addRadiotapHeader(packet, 6, 20);
    add80211Header(packet, PacketType::DEAUTH, client, bssid, bssid);
    
    // Add reason code
    uint16_t reason_le = htole16(reason);
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&reason_le), 
                  reinterpret_cast<uint8_t*>(&reason_le) + 2);
    
    stats_.packets_created++;
    stats_.type_counts[PacketType::DEAUTH]++;
    
    return packet;
}

std::vector<uint8_t> PacketForge::createEvilTwinBeacon(const std::string& target_ssid, 
                                                      const MacAddress& fake_bssid, uint8_t channel) {
    std::vector<uint8_t> packet = createBeacon(target_ssid, fake_bssid, channel, "WPA2");
    
    // Modify capabilities to appear more attractive
    size_t beacon_offset = 8 + 24; // Radiotap + 802.11 header
    if (packet.size() > beacon_offset + 10) {
        uint16_t* capabilities = reinterpret_cast<uint16_t*>(&packet[beacon_offset + 10]);
        *capabilities = htole16(0x1411); // ESS + Privacy + Short Preamble + PBCC
    }
    
    return packet;
}

std::vector<uint8_t> PacketForge::createWPSBeacon(const std::string& ssid, const MacAddress& bssid,
                                                  uint8_t channel, bool locked) {
    std::vector<uint8_t> packet = createBeacon(ssid, bssid, channel, "WPA2");
    
    // Add WPS information element
    addWPSElement(packet, locked);
    
    return packet;
}

bool PacketForge::injectPacket(const std::vector<uint8_t>& packet) {
    if (!pcap_handle_ || packet.empty()) {
        stats_.injection_errors++;
        return false;
    }
    
    if (pcap_inject(pcap_handle_, packet.data(), packet.size()) == -1) {
        stats_.injection_errors++;
        Logger::getInstance().error("Failed to inject packet: " + std::string(pcap_geterr(pcap_handle_)));
        return false;
    }
    
    stats_.packets_injected++;
    return true;
}

bool PacketForge::injectPacketBurst(const std::vector<uint8_t>& packet, int count, int delay_us) {
    bool success = true;
    
    for (int i = 0; i < count; i++) {
        if (!injectPacket(packet)) {
            success = false;
        }
        if (delay_us > 0 && i < count - 1) {
            usleep(delay_us);
        }
    }
    
    return success;
}

void PacketForge::addRadiotapHeader(std::vector<uint8_t>& packet, uint8_t channel, int8_t power) {
    // Basic radiotap header
    uint8_t radiotap[] = {
        0x00, 0x00, // Version
        0x08, 0x00, // Length (8 bytes)
        0x00, 0x00, 0x00, 0x00  // Present flags
    };
    
    packet.insert(packet.end(), radiotap, radiotap + sizeof(radiotap));
}

void PacketForge::add80211Header(std::vector<uint8_t>& packet, PacketType type,
                                const MacAddress& dst, const MacAddress& src, const MacAddress& bssid) {
    IEEE80211Header header = {};
    
    // Set frame control based on packet type
    switch (type) {
        case PacketType::BEACON:
            header.frame_control = htole16(0x0080); // Management, Beacon
            break;
        case PacketType::PROBE_REQUEST:
            header.frame_control = htole16(0x0040); // Management, Probe Request
            break;
        case PacketType::DEAUTH:
            header.frame_control = htole16(0x00C0); // Management, Deauth
            break;
        case PacketType::DATA:
            header.frame_control = htole16(0x0008); // Data
            break;
        default:
            header.frame_control = htole16(0x0080);
            break;
    }
    
    header.duration = htole16(0);
    memcpy(header.addr1, dst.bytes, 6);
    memcpy(header.addr2, src.bytes, 6);
    memcpy(header.addr3, bssid.bytes, 6);
    header.seq_ctrl = htole16(sequence_number_++ << 4);
    
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&header), 
                  reinterpret_cast<uint8_t*>(&header) + sizeof(header));
}

void PacketForge::addSSIDElement(std::vector<uint8_t>& packet, const std::string& ssid) {
    packet.push_back(0x00); // SSID element ID
    packet.push_back(ssid.length()); // Length
    packet.insert(packet.end(), ssid.begin(), ssid.end());
}

void PacketForge::addChannelElement(std::vector<uint8_t>& packet, uint8_t channel) {
    packet.push_back(0x03); // DS Parameter Set
    packet.push_back(0x01); // Length
    packet.push_back(channel);
}

void PacketForge::addRatesElement(std::vector<uint8_t>& packet) {
    uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    packet.insert(packet.end(), rates, rates + sizeof(rates));
}

void PacketForge::addWPA2Element(std::vector<uint8_t>& packet) {
    uint8_t wpa2[] = {
        0x30, 0x14, // RSN IE, Length
        0x01, 0x00, // Version
        0x00, 0x0f, 0xac, 0x04, // Group cipher (CCMP)
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // Pairwise cipher (CCMP)
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, // AKM (PSK)
        0x00, 0x00  // RSN capabilities
    };
    packet.insert(packet.end(), wpa2, wpa2 + sizeof(wpa2));
}

void PacketForge::addWPSElement(std::vector<uint8_t>& packet, bool locked) {
    uint8_t wps_base[] = {
        0xdd, 0x18, // Vendor specific IE, Length
        0x00, 0x50, 0xf2, 0x04, // WPS OUI
        0x10, 0x4a, 0x00, 0x01, 0x10, // Version
        0x10, 0x44, 0x00, 0x01, 0x02, // State (configured)
        0x10, 0x57, 0x00, 0x01, locked ? 0x01 : 0x00, // AP Setup Locked
        0x10, 0x3c, 0x00, 0x01, 0x03  // RF Bands
    };
    packet.insert(packet.end(), wps_base, wps_base + sizeof(wps_base));
}

void PacketForge::printStats() const {
    std::cout << "\n=== Packet Forge Statistics ===\n";
    std::cout << "Packets Created: " << stats_.packets_created << "\n";
    std::cout << "Packets Injected: " << stats_.packets_injected << "\n";
    std::cout << "Injection Errors: " << stats_.injection_errors << "\n";
    std::cout << "\nPacket Types:\n";
    
    const char* type_names[] = {
        "Beacon", "Probe Request", "Probe Response", "Deauth", "Disassoc",
        "Auth", "Assoc Request", "Assoc Response", "Data", "QoS Data", "RTS", "CTS", "ACK"
    };
    
    for (const auto& [type, count] : stats_.type_counts) {
        if (count > 0) {
            std::cout << "  " << type_names[static_cast<int>(type)] << ": " << count << "\n";
        }
    }
    std::cout << "===============================\n";
}

} // namespace airlevi
