#include "airlevi-wps/wps_attack.h"
#include "common/network_interface.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <random>

namespace airlevi {

WPSAttack::WPSAttack() 
    : pcap_handle_(nullptr), target_channel_(6), current_attack_(WPSAttackType::REAVER),
      running_(false), attack_active_(false), current_pin_index_(0),
      delay_seconds_(1), max_attempts_(11000), timeout_seconds_(10), verbose_(false),
      wps_state_(WPSState::IDLE) {
    memset(&stats_, 0, sizeof(stats_));
    memset(&pixie_data_, 0, sizeof(pixie_data_));
}

WPSAttack::~WPSAttack() {
    running_ = false;
    if (attack_thread_.joinable()) attack_thread_.join();
    if (monitoring_thread_.joinable()) monitoring_thread_.join();
    if (pcap_handle_) pcap_close(pcap_handle_);
}

bool WPSAttack::initialize(const std::string& interface) {
    interface_ = interface;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (!pcap_handle_) {
        Logger::getInstance().error("Failed to open interface: " + std::string(errbuf));
        return false;
    }
    
    Logger::getInstance().info("Initialized WPS attack on: " + interface);
    return true;
}

bool WPSAttack::setTarget(const MacAddress& bssid) {
    target_bssid_ = bssid;
    
    std::lock_guard<std::mutex> lock(wps_mutex_);
    auto it = wps_networks_.find(bssid.toString());
    if (it != wps_networks_.end()) {
        current_target_ = it->second;
        target_channel_ = current_target_.channel;
        return true;
    }
    
    Logger::getInstance().warning("Target BSSID not found in WPS networks");
    return false;
}

bool WPSAttack::startReaverAttack() {
    if (attack_active_ || target_bssid_.isNull()) return false;
    
    current_attack_ = WPSAttackType::REAVER;
    generateCommonPins();
    
    attack_active_ = true;
    stats_.start_time = std::chrono::steady_clock::now();
    
    attack_thread_ = std::thread(&WPSAttack::attackThread, this);
    monitoring_thread_ = std::thread(&WPSAttack::monitoringThread, this);
    
    Logger::getInstance().info("Started Reaver attack on " + target_bssid_.toString());
    return true;
}

bool WPSAttack::startPixieDustAttack() {
    if (attack_active_ || target_bssid_.isNull()) return false;
    
    current_attack_ = WPSAttackType::PIXIE_DUST;
    
    attack_active_ = true;
    stats_.start_time = std::chrono::steady_clock::now();
    
    attack_thread_ = std::thread(&WPSAttack::attackThread, this);
    monitoring_thread_ = std::thread(&WPSAttack::monitoringThread, this);
    
    Logger::getInstance().info("Started Pixie Dust attack on " + target_bssid_.toString());
    return true;
}

void WPSAttack::attackThread() {
    NetworkInterface ni(interface_);
    ni.setChannel(target_channel_);
    
    while (attack_active_) {
        switch (current_attack_) {
            case WPSAttackType::PIXIE_DUST:
                if (performPixieDustAttack()) {
                    attack_active_ = false;
                }
                break;
                
            case WPSAttackType::REAVER:
                if (current_pin_index_ < pin_queue_.size()) {
                    std::string pin = pin_queue_[current_pin_index_].pin;
                    
                    if (verbose_) {
                        std::cout << "[+] Testing PIN: " << pin << std::endl;
                    }
                    
                    // Reset WPS state
                    wps_state_ = WPSState::IDLE;
                    
                    // Send M1
                    if (sendM1()) {
                        wps_state_ = WPSState::M1_SENT;
                        
                        // Wait for M2 or timeout
                        auto start = std::chrono::steady_clock::now();
                        while (wps_state_ == WPSState::M1_SENT) {
                            auto now = std::chrono::steady_clock::now();
                            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start);
                            
                            if (duration.count() > timeout_seconds_) {
                                stats_.timeouts++;
                                break;
                            }
                            
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        }
                    }
                    
                    current_pin_index_++;
                    stats_.pins_tested++;
                    
                    // Calculate pins per second
                    auto now = std::chrono::steady_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.start_time);
                    if (duration.count() > 0) {
                        stats_.pins_per_second = static_cast<double>(stats_.pins_tested) / duration.count();
                    }
                }
                
                if (current_pin_index_ >= pin_queue_.size()) {
                    attack_active_ = false;
                }
                break;
                
            default:
                attack_active_ = false;
                break;
        }
        
        if (attack_active_) {
            std::this_thread::sleep_for(std::chrono::seconds(delay_seconds_));
        }
    }
}

void WPSAttack::monitoringThread() {
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    while (attack_active_) {
        int result = pcap_next_ex(pcap_handle_, &header, &packet);
        
        if (result == 1) {
            packetHandler(header, packet);
        } else if (result == -1) {
            Logger::getInstance().error("Error reading packet: " + std::string(pcap_geterr(pcap_handle_)));
            break;
        }
    }
}

bool WPSAttack::performPixieDustAttack() {
    // Send M1 and wait for M2
    if (!sendM1()) return false;
    
    // Wait for M2 with Pixie Dust data
    auto start = std::chrono::steady_clock::now();
    while (!pixie_data_.valid) {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start);
        
        if (duration.count() > timeout_seconds_) {
            Logger::getInstance().error("Timeout waiting for M2 in Pixie Dust attack");
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Calculate PIN using Pixie Dust algorithm
    uint32_t pin = calculatePixiePin();
    if (pin > 0) {
        AttackResult result;
        result.success = true;
        result.pin = std::to_string(pin);
        result.bssid = target_bssid_;
        result.ssid = current_target_.ssid;
        result.attack_type = WPSAttackType::PIXIE_DUST;
        result.found_time = std::chrono::steady_clock::now();
        
        std::lock_guard<std::mutex> lock(results_mutex_);
        results_.push_back(result);
        
        Logger::getInstance().info("Pixie Dust attack successful! PIN: " + result.pin);
        return true;
    }
    
    return false;
}

uint32_t WPSAttack::calculatePixiePin() {
    // Simplified Pixie Dust calculation
    // In real implementation, this would use proper cryptographic operations
    
    if (!pixie_data_.valid) return 0;
    
    // Mock calculation for demonstration
    uint32_t pin = 0;
    for (int i = 0; i < 16; i++) {
        pin ^= pixie_data_.e_nonce[i] << (i % 24);
        pin ^= pixie_data_.r_nonce[i] << ((i + 8) % 24);
    }
    
    // Ensure PIN is 8 digits
    pin = pin % 100000000;
    if (pin < 10000000) pin += 10000000;
    
    return pin;
}

void WPSAttack::generateCommonPins() {
    pin_queue_.clear();
    
    // Common default PINs
    std::vector<std::string> common_pins = {
        "12345670", "00000000", "11111111", "22222222", "33333333",
        "44444444", "55555555", "66666666", "77777777", "88888888",
        "99999999", "12345678", "87654321", "11223344", "55667788"
    };
    
    for (const auto& pin : common_pins) {
        WPSPin wps_pin;
        wps_pin.pin = pin;
        wps_pin.checksum = calculateChecksum(pin);
        wps_pin.tested = false;
        pin_queue_.push_back(wps_pin);
    }
    
    // Generate manufacturer-specific PINs
    auto manufacturer_pins = generateManufacturerPins();
    for (const auto& pin : manufacturer_pins) {
        WPSPin wps_pin;
        wps_pin.pin = pin;
        wps_pin.checksum = calculateChecksum(pin);
        wps_pin.tested = false;
        pin_queue_.push_back(wps_pin);
    }
    
    Logger::getInstance().info("Generated " + std::to_string(pin_queue_.size()) + " PINs for testing");
}

std::vector<std::string> WPSAttack::generateManufacturerPins() {
    std::vector<std::string> pins;
    
    // Generate PINs based on MAC address patterns
    std::string mac_str = target_bssid_.toString();
    std::replace(mac_str.begin(), mac_str.end(), ':', ' ');
    
    // Simple algorithm based on MAC
    uint32_t mac_sum = 0;
    for (int i = 0; i < 6; i++) {
        mac_sum += target_bssid_.bytes[i];
    }
    
    // Generate variations
    for (int i = 0; i < 100; i++) {
        uint32_t pin = (mac_sum + i) % 100000000;
        if (pin < 10000000) pin += 10000000;
        
        std::string pin_str = std::to_string(pin);
        if (validatePin(pin_str)) {
            pins.push_back(pin_str);
        }
    }
    
    return pins;
}

uint32_t WPSAttack::calculateChecksum(const std::string& pin) {
    if (pin.length() != 8) return 0;
    
    uint32_t accum = 0;
    for (int i = 0; i < 7; i++) {
        accum += (pin[i] - '0') * (3 - (i % 2) * 2);
    }
    
    return (10 - (accum % 10)) % 10;
}

bool WPSAttack::validatePin(const std::string& pin) {
    if (pin.length() != 8) return false;
    
    for (char c : pin) {
        if (c < '0' || c > '9') return false;
    }
    
    uint32_t expected_checksum = calculateChecksum(pin);
    uint32_t actual_checksum = pin[7] - '0';
    
    return expected_checksum == actual_checksum;
}

void WPSAttack::displayAttackProgress() {
    clearScreen();
    printHeader("WPS Attack Progress");
    
    std::cout << "Target: " << target_bssid_.toString() << " (" << current_target_.ssid << ")\n";
    std::cout << "Attack Type: ";
    
    switch (current_attack_) {
        case WPSAttackType::PIXIE_DUST: std::cout << "Pixie Dust"; break;
        case WPSAttackType::REAVER: std::cout << "Reaver"; break;
        case WPSAttackType::BRUTE_FORCE: std::cout << "Brute Force"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << "\n";
    
    std::cout << "PINs Tested: " << stats_.pins_tested << " / " << pin_queue_.size() << "\n";
    std::cout << "Rate: " << std::fixed << std::setprecision(2) << stats_.pins_per_second << " pins/sec\n";
    std::cout << "Timeouts: " << stats_.timeouts << "\n";
    std::cout << "Runtime: " << formatDuration(stats_.start_time) << "\n";
    
    if (!pin_queue_.empty() && current_pin_index_ < pin_queue_.size()) {
        std::cout << "Current PIN: " << pin_queue_[current_pin_index_].pin << "\n";
        
        int progress = (current_pin_index_ * 100) / pin_queue_.size();
        printProgress(progress, 100);
    }
}

void WPSAttack::clearScreen() {
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif
}

void WPSAttack::printHeader(const std::string& title) {
    std::cout << "==================================================\n";
    std::cout << "          AirLevi-NG - " << title << "\n";
    std::cout << "==================================================\n\n";
}

std::string WPSAttack::formatDuration(const std::chrono::steady_clock::time_point& start) {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start);
    
    int hours = duration.count() / 3600;
    int minutes = (duration.count() % 3600) / 60;
    int seconds = duration.count() % 60;
    
    return std::to_string(hours) + "h " + std::to_string(minutes) + "m " + std::to_string(seconds) + "s";
}

} // namespace airlevi
