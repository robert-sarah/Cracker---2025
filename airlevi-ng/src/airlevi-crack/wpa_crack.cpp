#include "airlevi-crack/wpa_crack.h"
#include "common/logger.h"
#include "common/packet_parser.h"
#include <fstream>
#include <algorithm>
#include <map>

namespace airlevi {

WPACrack::WPACrack(const Config& config) : config_(config) {}

WPACrack::~WPACrack() {}

bool WPACrack::crack(std::string& found_password) {
    Logger::getInstance().info("Starting WPA/WPA2 crack attack");
    
    if (!loadCaptureFile()) {
        Logger::getInstance().error("Failed to load capture file");
        return false;
    }
    
    if (!extractHandshakes() && !extractPMKIDs()) {
        Logger::getInstance().error("No WPA handshakes or PMKIDs found in capture file");
        return false;
    }
    
    Logger::getInstance().info("Found " + std::to_string(handshakes_.size()) + " handshakes and " + 
                             std::to_string(pmkids_.size()) + " PMKIDs");
    
    // Try PMKID attack first (faster)
    if (!pmkids_.empty() && pmkidAttack(found_password)) {
        return true;
    }
    
    // Try handshake attack
    if (!handshakes_.empty() && handshakeAttack(found_password)) {
        return true;
    }
    
    return false;
}

bool WPACrack::handshakeAttack(std::string& found_password) {
    Logger::getInstance().info("Attempting handshake attack");
    
    auto best_handshake = findBestHandshake();
    if (best_handshake.essid.empty()) {
        Logger::getInstance().error("No valid handshake found");
        return false;
    }
    
    Logger::getInstance().info("Using handshake for ESSID: " + best_handshake.essid);
    
    if (!config_.wordlist_file.empty()) {
        std::ifstream wordlist(config_.wordlist_file);
        if (!wordlist.is_open()) {
            Logger::getInstance().error("Cannot open wordlist file: " + config_.wordlist_file);
            return false;
        }
        
        std::string password;
        int attempts = 0;
        
        while (std::getline(wordlist, password) && attempts < 10000000) {
            attempts++;
            
            if (attempts % 1000 == 0) {
                Logger::getInstance().info("Tried " + std::to_string(attempts) + " passwords");
            }
            
            if (testPassword(password, best_handshake)) {
                found_password = password;
                Logger::getInstance().info("Password found: " + found_password);
                return true;
            }
        }
        
        Logger::getInstance().info("Handshake attack completed. Tried " + std::to_string(attempts) + " passwords");
    }
    
    return false;
}

bool WPACrack::pmkidAttack(std::string& found_password) {
    Logger::getInstance().info("Attempting PMKID attack");
    
    if (pmkids_.empty()) return false;
    
    if (!config_.wordlist_file.empty()) {
        std::ifstream wordlist(config_.wordlist_file);
        if (!wordlist.is_open()) {
            Logger::getInstance().error("Cannot open wordlist file: " + config_.wordlist_file);
            return false;
        }
        
        std::string password;
        int attempts = 0;
        
        while (std::getline(wordlist, password) && attempts < 10000000) {
            attempts++;
            
            if (attempts % 1000 == 0) {
                Logger::getInstance().info("Tried " + std::to_string(attempts) + " passwords");
            }
            
            for (const auto& pmkid : pmkids_) {
                if (testPasswordPMKID(password, pmkid)) {
                    found_password = password;
                    Logger::getInstance().info("Password found via PMKID: " + found_password);
                    return true;
                }
            }
        }
        
        Logger::getInstance().info("PMKID attack completed. Tried " + std::to_string(attempts) + " passwords");
    }
    
    return false;
}

bool WPACrack::validateHandshake(const HandshakePacket& handshake) {
    // Check if handshake has required fields
    if (handshake.essid.empty() || handshake.anonce.empty() || handshake.snonce.empty()) {
        return false;
    }
    
    if (handshake.mic.empty() || handshake.eapol_data.empty()) {
        return false;
    }
    
    // Check message number
    if (handshake.message_number < 1 || handshake.message_number > 4) {
        return false;
    }
    
    return verifyHandshakeIntegrity(handshake);
}

bool WPACrack::isCompleteHandshake(const std::vector<HandshakePacket>& packets) {
    if (packets.size() < 2) return false;
    
    bool has_msg1 = false, has_msg2 = false, has_msg3 = false, has_msg4 = false;
    
    for (const auto& pkt : packets) {
        switch (pkt.message_number) {
            case 1: has_msg1 = true; break;
            case 2: has_msg2 = true; break;
            case 3: has_msg3 = true; break;
            case 4: has_msg4 = true; break;
        }
    }
    
    // Need at least messages 2 and 3 for cracking
    return has_msg2 && has_msg3;
}

bool WPACrack::loadCaptureFile() {
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
        
        // Check if it's an EAPOL frame
        if (parser.isEAPOLFrame(packet.data())) {
            HandshakePacket handshake;
            if (parser.parseEAPOLFrame(packet.data(), pkt_hdr.caplen, handshake)) {
                handshakes_.push_back(handshake);
            }
        }
    }
    
    return !handshakes_.empty();
}

bool WPACrack::extractHandshakes() {
    if (handshakes_.empty()) return false;
    
    // Filter by target BSSID/ESSID if specified
    if (!config_.target_bssid.empty() || !config_.target_essid.empty()) {
        auto it = std::remove_if(handshakes_.begin(), handshakes_.end(),
            [this](const HandshakePacket& hs) {
                if (!config_.target_bssid.empty() && hs.ap_mac.toString() != config_.target_bssid) {
                    return true;
                }
                if (!config_.target_essid.empty() && hs.essid != config_.target_essid) {
                    return true;
                }
                return false;
            });
        
        handshakes_.erase(it, handshakes_.end());
    }
    
    // Remove invalid handshakes
    auto it = std::remove_if(handshakes_.begin(), handshakes_.end(),
        [this](const HandshakePacket& hs) {
            return !validateHandshake(hs);
        });
    
    handshakes_.erase(it, handshakes_.end());
    
    return !handshakes_.empty();
}

bool WPACrack::extractPMKIDs() {
    // PMKID extraction would be implemented here
    // PMKIDs are found in the first message of RSN authentication
    // This is a simplified placeholder
    return false;
}

bool WPACrack::testPassword(const std::string& password, const HandshakePacket& handshake) {
    if (password.length() < 8 || password.length() > 63) {
        return false; // Invalid WPA password length
    }
    
    try {
        // Generate PMK from password and ESSID
        auto pmk = CryptoUtils::generatePMK(password, handshake.essid);
        
        // Generate PTK
        auto ptk = CryptoUtils::generatePTK(pmk, handshake.ap_mac, handshake.client_mac,
                                           handshake.anonce, handshake.snonce);
        
        // Verify MIC
        return CryptoUtils::verifyMIC(handshake, ptk);
        
    } catch (const std::exception& e) {
        Logger::getInstance().debug("Error testing password '" + password + "': " + e.what());
        return false;
    }
}

bool WPACrack::testPasswordPMKID(const std::string& password, const std::vector<uint8_t>& pmkid) {
    // PMKID verification would be implemented here
    // PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)
    return false;
}

HandshakePacket WPACrack::findBestHandshake() {
    if (handshakes_.empty()) {
        return HandshakePacket();
    }
    
    // Group handshakes by AP
    std::map<MacAddress, std::vector<HandshakePacket>> grouped;
    for (const auto& hs : handshakes_) {
        grouped[hs.ap_mac].push_back(hs);
    }
    
    // Find the most complete handshake
    HandshakePacket best;
    int best_score = 0;
    
    for (const auto& pair : grouped) {
        const auto& packets = pair.second;
        
        if (isCompleteHandshake(packets)) {
            // Find message 2 or 3 (both contain MIC and nonces)
            for (const auto& pkt : packets) {
                if (pkt.message_number == 2 || pkt.message_number == 3) {
                    int score = 0;
                    
                    // Score based on completeness
                    if (!pkt.anonce.empty()) score += 10;
                    if (!pkt.snonce.empty()) score += 10;
                    if (!pkt.mic.empty()) score += 20;
                    if (!pkt.essid.empty()) score += 5;
                    
                    if (score > best_score) {
                        best = pkt;
                        best_score = score;
                        
                        // Fill in missing nonces from other messages
                        for (const auto& other : packets) {
                            if (best.anonce.empty() && !other.anonce.empty()) {
                                best.anonce = other.anonce;
                            }
                            if (best.snonce.empty() && !other.snonce.empty()) {
                                best.snonce = other.snonce;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return best;
}

bool WPACrack::verifyHandshakeIntegrity(const HandshakePacket& handshake) {
    // Basic integrity checks
    if (handshake.anonce.size() != 32 || handshake.snonce.size() != 32) {
        return false;
    }
    
    if (handshake.mic.size() != 16) {
        return false;
    }
    
    if (handshake.eapol_data.size() < 95) { // Minimum EAPOL key frame size
        return false;
    }
    
    return true;
}

} // namespace airlevi
