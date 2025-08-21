#include "airlevi-beacon/rogue_ap.h"
#include "common/network_interface.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <unistd.h>

namespace airlevi {

RogueAP::RogueAP() 
    : pcap_handle_(nullptr), mode_(APMode::EVIL_TWIN), running_(false),
      karma_enabled_(false), beacon_flood_enabled_(false), beacon_flood_count_(10),
      captive_enabled_(false), sequence_number_(0) {
    memset(&stats_, 0, sizeof(stats_));
}

RogueAP::~RogueAP() {
    stopAP();
    if (pcap_handle_) pcap_close(pcap_handle_);
}

bool RogueAP::initialize(const std::string& interface) {
    interface_ = interface;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (!pcap_handle_) {
        Logger::getInstance().error("Failed to open interface: " + std::string(errbuf));
        return false;
    }
    
    Logger::getInstance().info("Initialized rogue AP on: " + interface);
    return true;
}

bool RogueAP::configure(const APConfig& config) {
    config_ = config;
    
    // Set interface channel
    NetworkInterface ni(interface_);
    if (!ni.setChannel(config.channel)) {
        Logger::getInstance().error("Failed to set channel " + std::to_string(config.channel));
        return false;
    }
    
    Logger::getInstance().info("Configured AP: " + config.ssid + " on channel " + std::to_string(config.channel));
    return true;
}

bool RogueAP::startAP() {
    if (running_ || !pcap_handle_) return false;
    
    running_ = true;
    stats_.start_time = std::chrono::steady_clock::now();
    
    beacon_thread_ = std::thread(&RogueAP::beaconThread, this);
    monitoring_thread_ = std::thread(&RogueAP::monitoringThread, this);
    client_mgmt_thread_ = std::thread(&RogueAP::clientManagementThread, this);
    
    Logger::getInstance().info("Started rogue AP: " + config_.ssid);
    return true;
}

void RogueAP::stopAP() {
    running_ = false;
    
    if (beacon_thread_.joinable()) beacon_thread_.join();
    if (monitoring_thread_.joinable()) monitoring_thread_.join();
    if (client_mgmt_thread_.joinable()) client_mgmt_thread_.join();
    
    Logger::getInstance().info("Stopped rogue AP");
}

void RogueAP::beaconThread() {
    while (running_) {
        // Send main beacon
        auto beacon = createBeacon();
        if (!beacon.empty()) {
            pcap_inject(pcap_handle_, beacon.data(), beacon.size());
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.beacons_sent++;
        }
        
        // Send beacon flood if enabled
        if (beacon_flood_enabled_) {
            std::lock_guard<std::mutex> lock(fake_ssids_mutex_);
            for (const auto& ssid : fake_ssids_) {
                APConfig fake_config = config_;
                fake_config.ssid = ssid;
                fake_config.bssid = MacAddress::random();
                
                // Create and send fake beacon
                auto fake_beacon = createBeacon();
                if (!fake_beacon.empty()) {
                    pcap_inject(pcap_handle_, fake_beacon.data(), fake_beacon.size());
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.beacon_interval));
    }
}

void RogueAP::monitoringThread() {
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    while (running_) {
        int result = pcap_next_ex(pcap_handle_, &header, &packet);
        
        if (result == 1) {
            packetHandler(header, packet);
        } else if (result == -1) {
            Logger::getInstance().error("Error reading packet: " + std::string(pcap_geterr(pcap_handle_)));
            break;
        }
    }
}

void RogueAP::clientManagementThread() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        
        // Clean up inactive clients
        std::lock_guard<std::mutex> lock(clients_mutex_);
        auto now = std::chrono::steady_clock::now();
        
        for (auto it = clients_.begin(); it != clients_.end();) {
            auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.connected_time);
            if (duration.count() > 10) { // Remove clients inactive for 10+ minutes
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

std::vector<uint8_t> RogueAP::createBeacon() {
    std::vector<uint8_t> packet;
    
    // Radiotap header (8 bytes)
    uint8_t radiotap[] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
    packet.insert(packet.end(), radiotap, radiotap + 8);
    
    // 802.11 header (24 bytes)
    uint8_t header[] = {
        0x80, 0x00,                    // Frame control (beacon)
        0x00, 0x00,                    // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination (broadcast)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (BSSID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00                     // Sequence control
    };
    
    // Set BSSID
    memcpy(header + 10, config_.bssid.bytes, 6);
    memcpy(header + 16, config_.bssid.bytes, 6);
    
    // Set sequence number
    uint16_t seq = sequence_number_++ << 4;
    memcpy(header + 22, &seq, 2);
    
    packet.insert(packet.end(), header, header + 24);
    
    // Beacon frame body
    uint64_t timestamp = 0;
    uint16_t interval = htole16(config_.beacon_interval);
    uint16_t capabilities = htole16(0x0401); // ESS + Privacy
    
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&timestamp), 
                  reinterpret_cast<uint8_t*>(&timestamp) + 8);
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&interval), 
                  reinterpret_cast<uint8_t*>(&interval) + 2);
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&capabilities), 
                  reinterpret_cast<uint8_t*>(&capabilities) + 2);
    
    // SSID element
    packet.push_back(0x00); // SSID element ID
    packet.push_back(config_.ssid.length());
    packet.insert(packet.end(), config_.ssid.begin(), config_.ssid.end());
    
    // Supported rates
    uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    packet.insert(packet.end(), rates, rates + sizeof(rates));
    
    // DS Parameter Set (channel)
    packet.push_back(0x03);
    packet.push_back(0x01);
    packet.push_back(config_.channel);
    
    return packet;
}

void RogueAP::displayAPStatus() {
    clearScreen();
    printHeader("Rogue AP Status");
    
    std::cout << "SSID: " << config_.ssid << "\n";
    std::cout << "BSSID: " << config_.bssid.toString() << "\n";
    std::cout << "Channel: " << static_cast<int>(config_.channel) << "\n";
    std::cout << "Encryption: " << config_.encryption << "\n";
    std::cout << "Mode: ";
    
    switch (mode_) {
        case APMode::EVIL_TWIN: std::cout << "Evil Twin"; break;
        case APMode::KARMA: std::cout << "Karma"; break;
        case APMode::CAPTIVE_PORTAL: std::cout << "Captive Portal"; break;
        case APMode::WPS_FAKE: std::cout << "Fake WPS"; break;
        case APMode::HONEYPOT: std::cout << "Honeypot"; break;
    }
    std::cout << "\n";
    
    std::cout << "Uptime: " << formatUptime() << "\n";
    std::cout << "Connected Clients: " << clients_.size() << "\n";
    std::cout << "Beacons Sent: " << stats_.beacons_sent << "\n";
    std::cout << "Auth Requests: " << stats_.auth_requests << "\n";
    std::cout << "Assoc Requests: " << stats_.assoc_requests << "\n";
}

void RogueAP::clearScreen() {
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif
}

void RogueAP::printHeader(const std::string& title) {
    std::cout << "==================================================\n";
    std::cout << "          AirLevi-NG - " << title << "\n";
    std::cout << "==================================================\n\n";
}

std::string RogueAP::formatUptime() {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.start_time);
    
    int hours = duration.count() / 3600;
    int minutes = (duration.count() % 3600) / 60;
    int seconds = duration.count() % 60;
    
    return std::to_string(hours) + "h " + std::to_string(minutes) + "m " + std::to_string(seconds) + "s";
}

} // namespace airlevi
