#ifndef AIRLEVI_WPA_CRACK_H
#define AIRLEVI_WPA_CRACK_H

#include "common/types.h"
#include "common/crypto_utils.h"
#include <vector>
#include <string>

namespace airlevi {

class WPACrack {
public:
    explicit WPACrack(const Config& config);
    ~WPACrack();

    bool crack(std::string& found_password);
    
    // Attack methods
    bool handshakeAttack(std::string& found_password);
    bool pmkidAttack(std::string& found_password);
    
    // Handshake validation
    bool validateHandshake(const HandshakePacket& handshake);
    bool isCompleteHandshake(const std::vector<HandshakePacket>& packets);

private:
    Config config_;
    std::vector<HandshakePacket> handshakes_;
    std::vector<std::vector<uint8_t>> pmkids_;
    
    // Load data from capture file
    bool loadCaptureFile();
    bool extractHandshakes();
    bool extractPMKIDs();
    
    // Password testing
    bool testPassword(const std::string& password, const HandshakePacket& handshake);
    bool testPasswordPMKID(const std::string& password, const std::vector<uint8_t>& pmkid);
    
    // Handshake processing
    HandshakePacket findBestHandshake();
    bool verifyHandshakeIntegrity(const HandshakePacket& handshake);
};

} // namespace airlevi

#endif // AIRLEVI_WPA_CRACK_H
