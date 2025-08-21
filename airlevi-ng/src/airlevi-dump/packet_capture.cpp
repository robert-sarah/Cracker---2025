#include "airlevi-dump/packet_capture.h"
#include "common/logger.h"
#include <iostream>
#include <cstring>
#include <iomanip>

namespace airlevi {

PacketCapture::PacketCapture(const Config& config)
    : config_(config), pcap_handle_(nullptr), running_(false), 
      total_packets_(0), handshake_count_(0) {
}

PacketCapture::~PacketCapture() {
    stop();
}

bool PacketCapture::start() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open network interface
    pcap_handle_ = pcap_open_live(config_.interface.c_str(), 65536, 1, 1000, errbuf);
    if (!pcap_handle_) {
        Logger::getInstance().error("Failed to open interface " + config_.interface + ": " + errbuf);
        return false;
    }
    
    // Check if interface supports monitor mode
    if (pcap_can_set_rfmon(pcap_handle_) == 1 && config_.monitor_mode) {
        pcap_close(pcap_handle_);
        pcap_handle_ = pcap_create(config_.interface.c_str(), errbuf);
        if (!pcap_handle_) {
            Logger::getInstance().error("Failed to create pcap handle: " + std::string(errbuf));
            return false;
        }
        
        if (pcap_set_rfmon(pcap_handle_, 1) != 0) {
            Logger::getInstance().error("Failed to set monitor mode");
            pcap_close(pcap_handle_);
            return false;
        }
        
        if (pcap_set_snaplen(pcap_handle_, 65536) != 0 ||
            pcap_set_promisc(pcap_handle_, 1) != 0 ||
            pcap_set_timeout(pcap_handle_, 1000) != 0) {
            Logger::getInstance().error("Failed to set pcap parameters");
            pcap_close(pcap_handle_);
            return false;
        }
        
        if (pcap_activate(pcap_handle_) != 0) {
            Logger::getInstance().error("Failed to activate pcap handle");
            pcap_close(pcap_handle_);
            return false;
        }
    }
    
    // Set filter for 802.11 frames
    struct bpf_program filter;
    std::string filter_exp = "type mgt or type ctl or type data";
    
    if (pcap_compile(pcap_handle_, &filter, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        Logger::getInstance().error("Failed to compile filter: " + std::string(pcap_geterr(pcap_handle_)));
        pcap_close(pcap_handle_);
        return false;
    }
    
    if (pcap_setfilter(pcap_handle_, &filter) == -1) {
        Logger::getInstance().error("Failed to set filter: " + std::string(pcap_geterr(pcap_handle_)));
        pcap_freecode(&filter);
        pcap_close(pcap_handle_);
        return false;
    }
    
    pcap_freecode(&filter);
    
    // Open output file if specified
    if (!config_.output_file.empty() && !openOutputFile()) {
        pcap_close(pcap_handle_);
        return false;
    }
    
    // Start capture thread
    running_ = true;
    capture_thread_ = std::thread(&PacketCapture::captureLoop, this);
    
    Logger::getInstance().info("Packet capture started on interface " + config_.interface);
    return true;
}

void PacketCapture::stop() {
    if (running_) {
        running_ = false;
        
        if (pcap_handle_) {
            pcap_breakloop(pcap_handle_);
        }
        
        if (capture_thread_.joinable()) {
            capture_thread_.join();
        }
        
        if (pcap_handle_) {
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
        }
        
        if (output_file_.is_open()) {
            output_file_.close();
        }
        
        Logger::getInstance().info("Packet capture stopped");
    }
}

void PacketCapture::captureLoop() {
    while (running_) {
        int result = pcap_dispatch(pcap_handle_, -1, packetCallback, reinterpret_cast<uint8_t*>(this));
        
        if (result == -1) {
            Logger::getInstance().error("Error in pcap_dispatch: " + std::string(pcap_geterr(pcap_handle_)));
            break;
        } else if (result == -2) {
            // pcap_breakloop was called
            break;
        }
    }
}

void PacketCapture::packetCallback(uint8_t* user_data, const struct pcap_pkthdr* header, const uint8_t* packet) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(user_data);
    capture->processPacket(header, packet);
}

void PacketCapture::processPacket(const struct pcap_pkthdr* header, const uint8_t* packet) {
    if (!shouldCapturePacket(packet, header->caplen)) {
        return;
    }
    
    total_packets_++;
    
    // Write to file if enabled
    if (output_file_.is_open()) {
        writePacketToFile(header, packet);
    }
    
    // Process packet based on type
    onPacketReceived(packet, header->caplen);
    
    // Parse different frame types
    if (parser_.isBeaconFrame(packet)) {
        WifiNetwork network;
        if (parser_.parseBeaconFrame(packet, header->caplen, network)) {
            onBeaconFrame(network);
        }
    } else if (parser_.isDataFrame(packet)) {
        MacAddress src, dst;
        if (parser_.parseDataFrame(packet, header->caplen, src, dst)) {
            onDataFrame(src, dst);
        }
    } else if (parser_.isEAPOLFrame(packet)) {
        HandshakePacket handshake;
        if (parser_.parseEAPOLFrame(packet, header->caplen, handshake)) {
            handshake_count_++;
            onHandshakePacket(handshake);
        }
    } else if (parser_.isSAEFrame(packet)) {
        SAEHandshakePacket sae_packet;
        if (parser_.parseSAEFrame(packet, header->caplen, sae_packet)) {
            // Compter également les handshakes SAE
            handshake_count_++;
            onSAEHandshakePacket(sae_packet);
        }
    }
}

void PacketCapture::onPacketReceived(const uint8_t* packet, int length) {
    if (config_.verbose) {
        Logger::getInstance().debug("Captured packet of " + std::to_string(length) + " bytes");
    }
}

void PacketCapture::onBeaconFrame(const WifiNetwork& network) {
    if (config_.verbose) {
        std::string msg = "Beacon: " + network.essid + " (" + network.bssid.toString() + 
                         ") Channel: " + std::to_string(network.channel);
        Logger::getInstance().info(msg);
    }
}

void PacketCapture::onDataFrame(const MacAddress& src, const MacAddress& dst) {
    if (config_.verbose) {
        std::string msg = "Data: " + src.toString() + " -> " + dst.toString();
        Logger::getInstance().debug(msg);
    }
}

void PacketCapture::onHandshakePacket(const HandshakePacket& handshake) {
    std::string msg = "Handshake captured! AP: " + handshake.ap_mac.toString() + 
                     " Client: " + handshake.client_mac.toString() +
                     " Message: " + std::to_string(handshake.message_number);
    Logger::getInstance().info(msg);
}

void PacketCapture::onSAEHandshakePacket(const SAEHandshakePacket& sae_packet) {
    std::string msg = "WPA3-SAE handshake captured! AP: " + sae_packet.ap_mac.toString() +
                     " Client: " + sae_packet.client_mac.toString() +
                     " Seq: " + std::to_string(sae_packet.message_number) +
                     " Group: " + std::to_string(sae_packet.finite_field_group);
    Logger::getInstance().info(msg);
}

bool PacketCapture::openOutputFile() {
    output_file_.open(config_.output_file, std::ios::binary);
    if (!output_file_.is_open()) {
        Logger::getInstance().error("Failed to open output file: " + config_.output_file);
        return false;
    }
    
    // Write pcap file header
    struct {
        uint32_t magic_number = 0xa1b2c3d4;
        uint16_t version_major = 2;
        uint16_t version_minor = 4;
        int32_t thiszone = 0;
        uint32_t sigfigs = 0;
        uint32_t snaplen = 65535;
        uint32_t network = 127; // IEEE 802.11 + radiotap header
    } pcap_header;
    
    output_file_.write(reinterpret_cast<const char*>(&pcap_header), sizeof(pcap_header));
    
    Logger::getInstance().info("Output file opened: " + config_.output_file);
    return true;
}

void PacketCapture::writePacketToFile(const struct pcap_pkthdr* header, const uint8_t* packet) {
    std::lock_guard<std::mutex> lock(file_mutex_);
    
    // Write packet header
    struct PacketHeader {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t caplen;
        uint32_t len;
    } packet_header;

    packet_header.ts_sec = static_cast<uint32_t>(header->ts.tv_sec);
    packet_header.ts_usec = static_cast<uint32_t>(header->ts.tv_usec);
    packet_header.caplen = header->caplen;
    packet_header.len = header->len;

    output_file_.write(reinterpret_cast<const char*>(&packet_header), sizeof(packet_header));
    output_file_.write(reinterpret_cast<const char*>(packet), header->caplen);
}

bool PacketCapture::shouldCapturePacket(const uint8_t* packet, int length) {
    if (length < sizeof(IEEE80211Header)) {
        return false;
    }
    
    // Check target BSSID filter
    if (!config_.target_bssid.empty()) {
        const IEEE80211Header* header = reinterpret_cast<const IEEE80211Header*>(packet);
        
        // Check all address fields for BSSID match
        if (!matchesTargetBSSID(header->addr1) && 
            !matchesTargetBSSID(header->addr2) && 
            !matchesTargetBSSID(header->addr3)) {
            return false;
        }
    }
    
    return true;
}

bool PacketCapture::matchesTargetBSSID(const MacAddress& bssid) {
    if (config_.target_bssid.empty()) return true;
    
    // Convert target BSSID string to MacAddress for comparison
    // Simple implementation - in production would need proper MAC parsing
    return config_.target_bssid == bssid.toString();
}

bool PacketCapture::matchesTargetESSID(const std::string& essid) {
    if (config_.target_essid.empty()) return true;
    return config_.target_essid == essid;
}

} // namespace airlevi
