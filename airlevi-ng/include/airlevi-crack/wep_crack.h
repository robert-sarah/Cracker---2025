#ifndef AIRLEVI_WEP_CRACK_H
#define AIRLEVI_WEP_CRACK_H

#include "common/types.h"
#include "common/crypto_utils.h"
#include <vector>
#include <string>

namespace airlevi {

class WEPCrack {
public:
    explicit WEPCrack(const Config& config);
    ~WEPCrack();

    bool crack(std::string& found_key);
    
    // Statistical attack methods
    bool statisticalAttack(std::string& found_key);
    bool fmsAttack(std::string& found_key);
    bool koreKAttack(std::string& found_key);
    
    // Dictionary attack for WEP
    bool dictionaryAttack(std::string& found_key);

private:
    Config config_;
    std::vector<std::vector<uint8_t>> captured_packets_;
    std::vector<std::vector<uint8_t>> weak_ivs_;
    
    // Load packets from capture file
    bool loadCaptureFile();
    
    // Extract IVs and encrypted data
    bool extractWEPData();
    
    // Key recovery algorithms
    std::vector<uint8_t> recoverKey(int key_length);
    bool testKey(const std::vector<uint8_t>& key);
    
    // Statistical analysis
    void analyzeIVs();
    double calculateKeyProbability(const std::vector<uint8_t>& key);
    
    // Weak IV detection
    bool isWeakIV(const std::vector<uint8_t>& iv);
    void collectWeakIVs();
};

} // namespace airlevi

#endif // AIRLEVI_WEP_CRACK_H
