#ifndef AIRLEVI_CRYPTO_UTILS_H
#define AIRLEVI_CRYPTO_UTILS_H

#include "types.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace airlevi {

class CryptoUtils {
public:
    CryptoUtils();
    ~CryptoUtils();

    // WEP cracking utilities
    static std::vector<uint8_t> wepDecrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    static bool testWEPKey(const std::vector<uint8_t>& encrypted_data, const std::vector<uint8_t>& key);
    static std::vector<uint8_t> generateWEPKeyFromPassphrase(const std::string& passphrase, int key_length);

    // WPA/WPA2 utilities
    static std::vector<uint8_t> pbkdf2(const std::string& passphrase, const std::string& ssid, int iterations = 4096);
    static std::vector<uint8_t> generatePMK(const std::string& passphrase, const std::string& ssid);
    static std::vector<uint8_t> generatePTK(const std::vector<uint8_t>& pmk, 
                                           const MacAddress& ap_mac, 
                                           const MacAddress& client_mac,
                                           const std::vector<uint8_t>& anonce,
                                           const std::vector<uint8_t>& snonce);
    
    // MIC verification
    static bool verifyMIC(const HandshakePacket& handshake, const std::vector<uint8_t>& ptk);
    static std::vector<uint8_t> calculateMIC(const std::vector<uint8_t>& kck, 
                                            const std::vector<uint8_t>& eapol_data);

    // Hash functions
    static std::vector<uint8_t> md5Hash(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> sha1Hash(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> sha256Hash(const std::vector<uint8_t>& data);

    // Random generation
    static std::vector<uint8_t> generateRandomBytes(size_t length);
    static std::string generateRandomString(size_t length);

    // Utility functions
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> hexToBytes(const std::string& hex);
    static void xorBytes(std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

private:
    // PRF (Pseudo-Random Function) for WPA
    static std::vector<uint8_t> prf(const std::vector<uint8_t>& key,
                                   const std::string& label,
                                   const std::vector<uint8_t>& data,
                                   size_t output_length);
    
    // HMAC-SHA1
    static std::vector<uint8_t> hmacSha1(const std::vector<uint8_t>& key, 
                                        const std::vector<uint8_t>& data);
};

} // namespace airlevi

#endif // AIRLEVI_CRYPTO_UTILS_H
