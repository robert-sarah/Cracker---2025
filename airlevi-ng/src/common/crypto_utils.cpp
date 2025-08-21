#include "common/crypto_utils.h"
#include <openssl/rand.h>
#include <openssl/rc4.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace airlevi {

CryptoUtils::CryptoUtils() {}

CryptoUtils::~CryptoUtils() {}

std::vector<uint8_t> CryptoUtils::wepDecrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    if (data.size() < 4) return {}; // Need at least IV
    
    // Extract IV from first 3 bytes
    std::vector<uint8_t> full_key;
    full_key.insert(full_key.end(), data.begin(), data.begin() + 3);
    full_key.insert(full_key.end(), key.begin(), key.end());
    
    // RC4 decryption
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, full_key.size(), full_key.data());
    
    std::vector<uint8_t> decrypted(data.size() - 4);
    RC4(&rc4_key, data.size() - 4, data.data() + 4, decrypted.data());
    
    return decrypted;
}

bool CryptoUtils::testWEPKey(const std::vector<uint8_t>& encrypted_data, const std::vector<uint8_t>& key) {
    auto decrypted = wepDecrypt(encrypted_data, key);
    if (decrypted.empty()) return false;
    
    // Check for valid LLC/SNAP header
    if (decrypted.size() >= 8) {
        return (decrypted[0] == 0xaa && decrypted[1] == 0xaa && decrypted[2] == 0x03);
    }
    
    return false;
}

std::vector<uint8_t> CryptoUtils::generateWEPKeyFromPassphrase(const std::string& passphrase, int key_length) {
    std::vector<uint8_t> key(key_length);
    
    // Simple key derivation (MD5 based)
    auto hash = md5Hash(std::vector<uint8_t>(passphrase.begin(), passphrase.end()));
    
    for (int i = 0; i < key_length; ++i) {
        key[i] = hash[i % hash.size()];
    }
    
    return key;
}

std::vector<uint8_t> CryptoUtils::pbkdf2(const std::string& passphrase, const std::string& ssid, int iterations) {
    std::vector<uint8_t> pmk(32);
    
    PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(),
                      reinterpret_cast<const unsigned char*>(ssid.c_str()), ssid.length(),
                      iterations, EVP_sha1(), 32, pmk.data());
    
    return pmk;
}

std::vector<uint8_t> CryptoUtils::generatePMK(const std::string& passphrase, const std::string& ssid) {
    return pbkdf2(passphrase, ssid, 4096);
}

std::vector<uint8_t> CryptoUtils::generatePTK(const std::vector<uint8_t>& pmk,
                                             const MacAddress& ap_mac,
                                             const MacAddress& client_mac,
                                             const std::vector<uint8_t>& anonce,
                                             const std::vector<uint8_t>& snonce) {
    
    // Create data for PRF
    std::vector<uint8_t> prf_data;
    
    // Min(AP MAC, Client MAC) || Max(AP MAC, Client MAC)
    if (ap_mac < client_mac) {
        prf_data.insert(prf_data.end(), ap_mac.bytes, ap_mac.bytes + 6);
        prf_data.insert(prf_data.end(), client_mac.bytes, client_mac.bytes + 6);
    } else {
        prf_data.insert(prf_data.end(), client_mac.bytes, client_mac.bytes + 6);
        prf_data.insert(prf_data.end(), ap_mac.bytes, ap_mac.bytes + 6);
    }
    
    // Min(ANonce, SNonce) || Max(ANonce, SNonce)
    if (anonce < snonce) {
        prf_data.insert(prf_data.end(), anonce.begin(), anonce.end());
        prf_data.insert(prf_data.end(), snonce.begin(), snonce.end());
    } else {
        prf_data.insert(prf_data.end(), snonce.begin(), snonce.end());
        prf_data.insert(prf_data.end(), anonce.begin(), anonce.end());
    }
    
    // Generate 64-byte PTK using PRF
    return prf(pmk, "Pairwise key expansion", prf_data, 64);
}

bool CryptoUtils::verifyMIC(const HandshakePacket& handshake, const std::vector<uint8_t>& ptk) {
    if (ptk.size() < 16) return false;
    
    // Extract KCK (first 16 bytes of PTK)
    std::vector<uint8_t> kck(ptk.begin(), ptk.begin() + 16);
    
    // Calculate MIC
    auto calculated_mic = calculateMIC(kck, handshake.eapol_data);
    
    // Compare with stored MIC
    return std::equal(calculated_mic.begin(), calculated_mic.end(), handshake.mic.begin());
}

std::vector<uint8_t> CryptoUtils::calculateMIC(const std::vector<uint8_t>& kck,
                                              const std::vector<uint8_t>& eapol_data) {
    // Create EAPOL data with zeroed MIC field
    std::vector<uint8_t> data = eapol_data;
    
    // Zero out MIC field (bytes 77-92 in EAPOL key frame)
    if (data.size() >= 93) {
        std::fill(data.begin() + 77, data.begin() + 93, 0);
    }
    
    // Calculate HMAC-MD5
    unsigned char mic[16];
    unsigned int mic_len;
    
    HMAC(EVP_md5(), kck.data(), kck.size(), data.data(), data.size(), mic, &mic_len);
    
    return std::vector<uint8_t>(mic, mic + 16);
}

std::vector<uint8_t> CryptoUtils::md5Hash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(MD5_DIGEST_LENGTH);
    MD5(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> CryptoUtils::sha1Hash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA_DIGEST_LENGTH);
    SHA1(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> CryptoUtils::sha256Hash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> CryptoUtils::generateRandomBytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    RAND_bytes(bytes.data(), length);
    return bytes;
}

std::string CryptoUtils::generateRandomString(size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.reserve(length);
    
    auto random_bytes = generateRandomBytes(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[random_bytes[i] % (sizeof(charset) - 1)];
    }
    
    return result;
}

std::string CryptoUtils::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> CryptoUtils::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void CryptoUtils::xorBytes(std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    size_t min_size = std::min(a.size(), b.size());
    for (size_t i = 0; i < min_size; ++i) {
        a[i] ^= b[i];
    }
}

std::vector<uint8_t> CryptoUtils::prf(const std::vector<uint8_t>& key,
                                     const std::string& label,
                                     const std::vector<uint8_t>& data,
                                     size_t output_length) {
    std::vector<uint8_t> result;
    result.reserve(output_length);
    
    // Create input for HMAC: label + 0x00 + data + counter
    std::vector<uint8_t> hmac_input;
    hmac_input.insert(hmac_input.end(), label.begin(), label.end());
    hmac_input.push_back(0x00);
    hmac_input.insert(hmac_input.end(), data.begin(), data.end());
    
    uint8_t counter = 0;
    while (result.size() < output_length) {
        hmac_input.push_back(counter++);
        
        auto hash = hmacSha1(key, hmac_input);
        
        size_t bytes_to_copy = std::min(hash.size(), output_length - result.size());
        result.insert(result.end(), hash.begin(), hash.begin() + bytes_to_copy);
        
        hmac_input.pop_back(); // Remove counter for next iteration
    }
    
    result.resize(output_length);
    return result;
}

std::vector<uint8_t> CryptoUtils::hmacSha1(const std::vector<uint8_t>& key,
                                          const std::vector<uint8_t>& data) {
    unsigned char result[SHA_DIGEST_LENGTH];
    unsigned int result_len;
    
    HMAC(EVP_sha1(), key.data(), key.size(), data.data(), data.size(), result, &result_len);
    
    return std::vector<uint8_t>(result, result + result_len);
}

} // namespace airlevi
