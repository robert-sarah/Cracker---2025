#include "airlevi-replay/packet_replay.h"
#include "common/network_interface.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>

namespace airlevi {

PacketReplay::PacketReplay() 
    : pcap_handle_(nullptr), inject_handle_(nullptr), mode_(ReplayMode::SINGLE),
      packet_delay_(1000), packet_count_(1), burst_size_(10), speed_multiplier_(1.0),
      modify_mac_(false), running_(false) {
    memset(&stats_, 0, sizeof(stats_));
}

PacketReplay::~PacketReplay() {
    stopReplay();
    if (pcap_handle_) pcap_close(pcap_handle_);
    if (inject_handle_) pcap_close(inject_handle_);
}

bool PacketReplay::initialize(const std::string& interface) {
    interface_ = interface;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    inject_handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (!inject_handle_) {
        Logger::getInstance().error("Failed to open interface for injection: " + std::string(errbuf));
        return false;
    }
    
    Logger::getInstance().info("Initialized packet replay on interface: " + interface);
    return true;
}

bool PacketReplay::loadCaptureFile(const std::string& filename) {
    capture_file_ = filename;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_ = pcap_open_offline(filename.c_str(), errbuf);
    
    if (!pcap_handle_) {
        Logger::getInstance().error("Failed to open capture file: " + std::string(errbuf));
        return false;
    }
    
    // Load all packets into memory
    packets_.clear();
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    while (pcap_next_ex(pcap_handle_, &header, &packet) >= 0) {
        std::vector<u_char> packet_data(packet, packet + header->caplen);
        packets_.emplace_back(packet_data, header->caplen);
    }
    
    Logger::getInstance().info("Loaded " + std::to_string(packets_.size()) + " packets from " + filename);
    return true;
}

bool PacketReplay::setTargetMAC(const std::string& mac) {
    target_mac_ = MacAddress(mac);
    modify_mac_ = true;
    return true;
}

bool PacketReplay::setSourceMAC(const std::string& mac) {
    source_mac_ = MacAddress(mac);
    modify_mac_ = true;
    return true;
}

void PacketReplay::setReplayMode(ReplayMode mode) {
    mode_ = mode;
}

void PacketReplay::setPacketDelay(int microseconds) {
    packet_delay_ = microseconds;
}

void PacketReplay::setPacketCount(int count) {
    packet_count_ = count;
}

void PacketReplay::setBurstSize(int size) {
    burst_size_ = size;
}

void PacketReplay::setSpeed(double multiplier) {
    speed_multiplier_ = multiplier;
}

bool PacketReplay::startReplay() {
    if (running_ || packets_.empty() || !inject_handle_) {
        return false;
    }
    
    running_ = true;
    stats_.start_time = std::chrono::steady_clock::now();
    stats_.packets_sent = 0;
    stats_.bytes_sent = 0;
    stats_.errors = 0;
    
    replay_thread_ = std::thread(&PacketReplay::replayThread, this);
    
    Logger::getInstance().info("Started packet replay");
    return true;
}

void PacketReplay::stopReplay() {
    running_ = false;
    if (replay_thread_.joinable()) {
        replay_thread_.join();
    }
    Logger::getInstance().info("Stopped packet replay");
}

void PacketReplay::replayThread() {
    int packets_sent = 0;
    
    while (running_) {
        switch (mode_) {
            case ReplayMode::SINGLE:
                for (const auto& [packet_data, length] : packets_) {
                    if (!running_) break;
                    
                    std::vector<u_char> modified_packet = packet_data;
                    if (modify_mac_) {
                        modifyPacket(modified_packet.data(), length);
                    }
                    
                    if (injectPacket(modified_packet.data(), length)) {
                        std::lock_guard<std::mutex> lock(stats_mutex_);
                        stats_.packets_sent++;
                        stats_.bytes_sent += length;
                    }
                    
                    usleep(packet_delay_ / speed_multiplier_);
                }
                running_ = false;
                break;
                
            case ReplayMode::CONTINUOUS:
                for (const auto& [packet_data, length] : packets_) {
                    if (!running_) break;
                    
                    std::vector<u_char> modified_packet = packet_data;
                    if (modify_mac_) {
                        modifyPacket(modified_packet.data(), length);
                    }
                    
                    if (injectPacket(modified_packet.data(), length)) {
                        std::lock_guard<std::mutex> lock(stats_mutex_);
                        stats_.packets_sent++;
                        stats_.bytes_sent += length;
                    }
                    
                    usleep(packet_delay_ / speed_multiplier_);
                }
                break;
                
            case ReplayMode::BURST:
                for (int burst = 0; burst < burst_size_ && running_; burst++) {
                    for (const auto& [packet_data, length] : packets_) {
                        if (!running_) break;
                        
                        std::vector<u_char> modified_packet = packet_data;
                        if (modify_mac_) {
                            modifyPacket(modified_packet.data(), length);
                        }
                        
                        if (injectPacket(modified_packet.data(), length)) {
                            std::lock_guard<std::mutex> lock(stats_mutex_);
                            stats_.packets_sent++;
                            stats_.bytes_sent += length;
                        }
                    }
                    usleep(packet_delay_ / speed_multiplier_);
                }
                running_ = false;
                break;
                
            case ReplayMode::TIMED:
                if (packets_sent >= packet_count_) {
                    running_ = false;
                    break;
                }
                
                for (const auto& [packet_data, length] : packets_) {
                    if (!running_ || packets_sent >= packet_count_) break;
                    
                    std::vector<u_char> modified_packet = packet_data;
                    if (modify_mac_) {
                        modifyPacket(modified_packet.data(), length);
                    }
                    
                    if (injectPacket(modified_packet.data(), length)) {
                        std::lock_guard<std::mutex> lock(stats_mutex_);
                        stats_.packets_sent++;
                        stats_.bytes_sent += length;
                        packets_sent++;
                    }
                    
                    usleep(packet_delay_ / speed_multiplier_);
                }
                break;
        }
    }
}

bool PacketReplay::injectPacket(const u_char* packet, int length) {
    if (pcap_inject(inject_handle_, packet, length) == -1) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.errors++;
        return false;
    }
    return true;
}

void PacketReplay::modifyPacket(u_char* packet, int length) {
    if (length < 24) return; // Too short for 802.11 header
    
    // Modify destination MAC (offset 4-9)
    if (!target_mac_.isNull()) {
        memcpy(packet + 4, target_mac_.bytes, 6);
    }
    
    // Modify source MAC (offset 10-15)
    if (!source_mac_.isNull()) {
        memcpy(packet + 10, source_mac_.bytes, 6);
    }
}

ReplayStats PacketReplay::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ReplayStats current_stats = stats_;
    
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.start_time).count();
    
    if (duration > 0) {
        current_stats.packets_per_second = static_cast<double>(stats_.packets_sent) / duration;
    }
    
    return current_stats;
}

void PacketReplay::printStats() const {
    auto stats = getStats();
    
    std::cout << "\n=== Packet Replay Statistics ===\n";
    std::cout << "Packets Sent: " << stats.packets_sent << "\n";
    std::cout << "Bytes Sent: " << stats.bytes_sent << "\n";
    std::cout << "Errors: " << stats.errors << "\n";
    std::cout << "Rate: " << std::fixed << std::setprecision(2) << stats.packets_per_second << " pps\n";
    std::cout << "================================\n";
}

void PacketReplay::printRealTimeStats() {
    while (running_) {
        auto stats = getStats();
        
        std::cout << "\r[REPLAY] Sent: " << stats.packets_sent 
                  << " | Rate: " << std::fixed << std::setprecision(1) << stats.packets_per_second 
                  << " pps | Errors: " << stats.errors << std::flush;
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << std::endl;
}

} // namespace airlevi
