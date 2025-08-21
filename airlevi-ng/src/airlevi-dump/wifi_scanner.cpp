#include "airlevi-dump/wifi_scanner.h"
#include "common/logger.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <cstdlib>

namespace airlevi {

WifiScanner::WifiScanner(const Config& config)
    : config_(config), running_(false), current_channel_(0) {
    stats_.start_time = std::chrono::steady_clock::now();
}

WifiScanner::~WifiScanner() {
    stop();
}

bool WifiScanner::start() {
    running_ = true;
    
    // Start cleanup thread
    cleanup_thread_ = std::thread(&WifiScanner::cleanupTask, this);
    
    Logger::getInstance().info("WiFi scanner started");
    return true;
}

void WifiScanner::stop() {
    if (running_) {
        running_ = false;
        
        if (cleanup_thread_.joinable()) {
            cleanup_thread_.join();
        }
        
        Logger::getInstance().info("WiFi scanner stopped");
    }
}

void WifiScanner::setChannel(int channel) {
    if (channel < 1 || channel > 196) { // Covers most 5GHz channels
        Logger::getInstance().warning("Attempting to set an unusual channel in scanner: " + std::to_string(channel));
        return;
    }
    
    current_channel_ = channel;
    
    if (config_.monitor_mode) {
        switchToChannel(channel);
    }
}

void WifiScanner::addNetwork(const WifiNetwork& network) {
    std::lock_guard<std::mutex> lock(networks_mutex_);
    
    auto it = networks_.find(network.bssid);
    if (it != networks_.end()) {
        // Update existing network
        it->second.last_seen = network.last_seen;
        it->second.packets_captured++;
        it->second.signal_strength = network.signal_strength;
        
        // Update ESSID if it was hidden before
        if (it->second.essid == "<hidden>" && !network.essid.empty() && network.essid != "<hidden>") {
            it->second.essid = network.essid;
        }
    } else {
        // Add new network
        networks_[network.bssid] = network;
        updateStatistics();
    }
}

void WifiScanner::addSAEHandshake(const SAEHandshakePacket& sae_packet) {
    std::lock_guard<std::mutex> lock(sae_handshakes_mutex_);
    sae_handshakes_.push_back(sae_packet);
    // Optionally, update stats or log the capture
    Logger::getInstance().info("Captured a WPA3-SAE handshake frame.");
}

void WifiScanner::addClient(const WifiClient& client) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    auto it = clients_.find(client.mac);
    if (it != clients_.end()) {
        // Update existing client
        it->second.last_seen = client.last_seen;
        it->second.packets_sent++;
        it->second.signal_strength = client.signal_strength;
        it->second.associated_ap = client.associated_ap;
    } else {
        // Add new client
        clients_[client.mac] = client;
        updateStatistics();
    }
}

void WifiScanner::updateNetworkHandshake(const MacAddress& bssid, bool has_handshake) {
    std::lock_guard<std::mutex> lock(networks_mutex_);
    
    auto it = networks_.find(bssid);
    if (it != networks_.end()) {
        it->second.has_handshake = has_handshake;
        if (has_handshake) {
            updateStatistics();
        }
    }
}

std::vector<WifiNetwork> WifiScanner::getNetworks() const {
    std::lock_guard<std::mutex> lock(networks_mutex_);
    
    std::vector<WifiNetwork> result;
    result.reserve(networks_.size());
    
    for (const auto& pair : networks_) {
        result.push_back(pair.second);
    }
    
    // Sort by signal strength (descending)
    std::sort(result.begin(), result.end(), 
              [](const WifiNetwork& a, const WifiNetwork& b) {
                  return a.signal_strength > b.signal_strength;
              });
    
    return result;
}

std::vector<WifiClient> WifiScanner::getClients() const {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    std::vector<WifiClient> result;
    result.reserve(clients_.size());
    
    for (const auto& pair : clients_) {
        result.push_back(pair.second);
    }
    
    return result;
}

std::vector<SAEHandshakePacket> WifiScanner::getSAEHandshakes() const {
    std::lock_guard<std::mutex> lock(sae_handshakes_mutex_);
    return sae_handshakes_;
}

Statistics WifiScanner::getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void WifiScanner::displayNetworks() const {
    auto networks = getNetworks();
    
    std::cout << "\n┌─────────────────────────────────────────────────────────────────────────────┐" << std::endl;
    std::cout << "│                              WiFi Networks                                  │" << std::endl;
    std::cout << "├─────────────────┬────────────────────────┬─────┬──────┬─────────┬─────────┤" << std::endl;
    std::cout << "│      BSSID      │         ESSID          │ CH  │ PWR  │  ENC    │   HS    │" << std::endl;
    std::cout << "├─────────────────┼────────────────────────┼─────┼──────┼─────────┼─────────┤" << std::endl;
    
    for (const auto& network : networks) {
        std::cout << "│ " << std::setw(15) << std::left << network.bssid.toString() 
                  << " │ " << std::setw(22) << std::left << network.essid.substr(0, 22)
                  << " │ " << std::setw(3) << std::right << network.channel
                  << " │ " << std::setw(4) << std::right << network.signal_strength
                  << " │ " << std::setw(7) << std::left << network.encryption
                  << " │ " << std::setw(7) << std::left << (network.has_handshake ? "YES" : "NO")
                  << " │" << std::endl;
    }
    
    std::cout << "└─────────────────┴────────────────────────┴─────┴──────┴─────────┴─────────┘" << std::endl;
}

void WifiScanner::displayClients() const {
    auto clients = getClients();
    
    std::cout << "\n┌─────────────────────────────────────────────────────────────────────────────┐" << std::endl;
    std::cout << "│                              WiFi Clients                                   │" << std::endl;
    std::cout << "├─────────────────┬─────────────────┬──────┬─────────┬─────────────────────┤" << std::endl;
    std::cout << "│   Client MAC    │   Associated AP │ PWR  │  Packets│     Last Seen       │" << std::endl;
    std::cout << "├─────────────────┼─────────────────┼──────┼─────────┼─────────────────────┤" << std::endl;
    
    for (const auto& client : clients) {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - client.last_seen);
        
        std::cout << "│ " << std::setw(15) << std::left << client.mac.toString()
                  << " │ " << std::setw(15) << std::left << client.associated_ap.toString()
                  << " │ " << std::setw(4) << std::right << client.signal_strength
                  << " │ " << std::setw(7) << std::right << (client.packets_sent + client.packets_received)
                  << " │ " << std::setw(19) << std::right << (std::to_string(duration.count()) + "s ago")
                  << " │" << std::endl;
    }
    
    std::cout << "└─────────────────┴─────────────────┴──────┴─────────┴─────────────────────┘" << std::endl;
}

void WifiScanner::displayStatistics() const {
    auto stats = getStatistics();
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats.start_time);
    
    std::cout << "\n┌─────────────────────────────────────────────────────────────────────────────┐" << std::endl;
    std::cout << "│                               Statistics                                    │" << std::endl;
    std::cout << "├─────────────────────────────────────────────────────────────────────────────┤" << std::endl;
    std::cout << "│ Runtime: " << std::setw(10) << std::right << duration.count() << "s"
              << "                                                    │" << std::endl;
    std::cout << "│ Total Packets: " << std::setw(10) << std::right << stats.total_packets
              << "                                               │" << std::endl;
    std::cout << "│ Networks Found: " << std::setw(10) << std::right << stats.networks_found
              << "                                              │" << std::endl;
    std::cout << "│ Clients Found: " << std::setw(10) << std::right << stats.clients_found
              << "                                               │" << std::endl;
    std::cout << "│ Handshakes: " << std::setw(10) << std::right << stats.handshakes_captured
              << "                                                  │" << std::endl;
    std::cout << "│ Beacon Frames: " << std::setw(10) << std::right << stats.beacon_frames
              << "                                               │" << std::endl;
    std::cout << "│ Data Frames: " << std::setw(10) << std::right << stats.data_frames
              << "                                                 │" << std::endl;
    std::cout << "└─────────────────────────────────────────────────────────────────────────────┘" << std::endl;
}

void WifiScanner::cleanupTask() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        
        if (running_) {
            removeOldEntries();
        }
    }
}

void WifiScanner::updateStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.networks_found = networks_.size();
    stats_.clients_found = clients_.size();
    
    // Count handshakes
    stats_.handshakes_captured = 0;
    for (const auto& pair : networks_) {
        if (pair.second.has_handshake) {
            stats_.handshakes_captured++;
        }
    }
}

void WifiScanner::removeOldEntries() {
    const auto timeout = std::chrono::minutes(5); // Remove entries older than 5 minutes
    
    // Clean up networks
    {
        std::lock_guard<std::mutex> lock(networks_mutex_);
        auto it = networks_.begin();
        while (it != networks_.end()) {
            if (!isNetworkActive(it->second)) {
                it = networks_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // Clean up clients
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        auto it = clients_.begin();
        while (it != clients_.end()) {
            if (!isClientActive(it->second)) {
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    updateStatistics();
}

bool WifiScanner::isNetworkActive(const WifiNetwork& network) const {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - network.last_seen);
    return duration.count() < 5; // Consider active if seen within 5 minutes
}

bool WifiScanner::isClientActive(const WifiClient& client) const {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - client.last_seen);
    return duration.count() < 5; // Consider active if seen within 5 minutes
}

bool WifiScanner::switchToChannel(int channel) {
    if (!config_.monitor_mode) return false;
    
    // Use iwconfig to switch channel (requires root privileges)
    std::string command = "iwconfig " + config_.interface + " channel " + std::to_string(channel) + " 2>/dev/null";
    int result = std::system(command.c_str());
    
    if (result == 0 && config_.verbose) {
        Logger::getInstance().debug("Switched to channel " + std::to_string(channel));
    }
    
    return result == 0;
}

} // namespace airlevi
