#include "airlevi-monitor/advanced_monitor.h"
#include "common/network_interface.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

namespace airlevi {

AdvancedMonitor::AdvancedMonitor() 
    : pcap_handle_(nullptr), running_(false), channel_hopping_enabled_(true),
      current_channel_(1), channel_dwell_time_(250), signal_threshold_(-100) {
    
    // Initialize default channel list (2.4GHz)
    channel_list_ = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    
    memset(&stats_, 0, sizeof(stats_));
    loadOUIDatabase();
}

AdvancedMonitor::~AdvancedMonitor() {
    stopMonitoring();
    if (pcap_handle_) pcap_close(pcap_handle_);
}

bool AdvancedMonitor::initialize(const std::string& interface) {
    interface_ = interface;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (!pcap_handle_) {
        Logger::getInstance().error("Failed to open interface: " + std::string(errbuf));
        return false;
    }
    
    // Set monitor mode filter for 802.11 frames
    struct bpf_program fp;
    if (pcap_compile(pcap_handle_, &fp, "type mgt or type ctl or type data", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        Logger::getInstance().error("Failed to compile filter");
        return false;
    }
    
    if (pcap_setfilter(pcap_handle_, &fp) == -1) {
        Logger::getInstance().error("Failed to set filter");
        return false;
    }
    
    Logger::getInstance().info("Initialized advanced monitor on: " + interface);
    return true;
}

bool AdvancedMonitor::startMonitoring() {
    if (running_ || !pcap_handle_) return false;
    
    running_ = true;
    stats_.start_time = std::chrono::steady_clock::now();
    
    monitoring_thread_ = std::thread(&AdvancedMonitor::monitoringThread, this);
    
    if (channel_hopping_enabled_) {
        channel_hopping_thread_ = std::thread(&AdvancedMonitor::channelHoppingThread, this);
    }
    
    cleanup_thread_ = std::thread(&AdvancedMonitor::cleanupThread, this);
    
    Logger::getInstance().info("Started advanced monitoring");
    return true;
}

void AdvancedMonitor::stopMonitoring() {
    running_ = false;
    
    if (monitoring_thread_.joinable()) monitoring_thread_.join();
    if (channel_hopping_thread_.joinable()) channel_hopping_thread_.join();
    if (cleanup_thread_.joinable()) cleanup_thread_.join();
    
    Logger::getInstance().info("Stopped advanced monitoring");
}

void AdvancedMonitor::monitoringThread() {
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

void AdvancedMonitor::channelHoppingThread() {
    size_t channel_index = 0;
    
    while (running_) {
        if (channel_hopping_enabled_ && !channel_list_.empty()) {
            uint8_t channel = channel_list_[channel_index];
            current_channel_ = channel;
            
            NetworkInterface ni(interface_);
            ni.setChannel(channel);
            
            channel_index = (channel_index + 1) % channel_list_.size();
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(channel_dwell_time_));
    }
}

void AdvancedMonitor::displayNetworksTable() {
    clearScreen();
    printHeader("WiFi Networks");
    
    std::vector<std::string> headers = {"BSSID", "SSID", "CH", "ENC", "PWR", "Beacons", "Clients"};
    std::vector<int> widths = {18, 20, 3, 8, 4, 8, 7};
    
    printTableHeader(headers, widths);
    
    std::lock_guard<std::mutex> lock(data_mutex_);
    for (const auto& [key, ap] : access_points_) {
        std::vector<std::string> row = {
            ap.bssid.toString(),
            ap.ssid.empty() ? "<hidden>" : ap.ssid,
            std::to_string(ap.channel),
            ap.encryption,
            std::to_string(ap.signal_strength),
            std::to_string(ap.beacon_count),
            std::to_string(ap.clients.size())
        };
        printTableRow(row, widths);
    }
}

void AdvancedMonitor::loadOUIDatabase() {
    // Basic OUI mappings - in real implementation, load from file
    oui_database_["00:50:F2"] = "Microsoft";
    oui_database_["00:0C:29"] = "VMware";
    oui_database_["08:00:27"] = "VirtualBox";
    // Add more as needed
}

} // namespace airlevi
