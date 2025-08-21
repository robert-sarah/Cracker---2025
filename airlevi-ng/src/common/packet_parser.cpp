#include "common/packet_parser.h"
#include <cstring>
#include <iostream>
#include <iomanip>
#include <arpa/inet.h> // For ntohs

namespace airlevi {

PacketParser::PacketParser() {}

PacketParser::~PacketParser() {}

bool PacketParser::parseBeaconFrame(const uint8_t* packet, int length, WifiNetwork& network) {
    if (length < sizeof(BeaconFrame)) return false;
    
    const BeaconFrame* beacon = reinterpret_cast<const BeaconFrame*>(packet);
    
    // Extract BSSID (AP MAC address)
    network.bssid = MacAddress(beacon->header.addr3.bytes);
    
    // Parse information elements
    const uint8_t* ie_start = packet + sizeof(BeaconFrame);
    int ie_length = length - sizeof(BeaconFrame);
    
    network.essid = extractSSID(ie_start, ie_length);
    network.channel = extractChannel(ie_start, ie_length);
    EncryptionType enc_type = extractEncryption(ie_start, ie_length);
    switch (enc_type) {
        case EncryptionType::OPEN:
            network.encryption = "Open";
            break;
        case EncryptionType::WEP:
            network.encryption = "WEP";
            break;
        case EncryptionType::WPA:
            network.encryption = "WPA";
            break;
        case EncryptionType::WPA2:
            network.encryption = "WPA2";
            break;
        case EncryptionType::WPA3:
            network.encryption = "WPA3";
            break;
        default:
            network.encryption = "Unknown";
            break;
    }
    network.last_seen = std::chrono::steady_clock::now();
    
    return true;
}

bool PacketParser::parseDataFrame(const uint8_t* packet, int length, MacAddress& src, MacAddress& dst) {
    if (length < sizeof(IEEE80211Header)) return false;
    
    const IEEE80211Header* header = reinterpret_cast<const IEEE80211Header*>(packet);
    
    // Extract source and destination based on DS bits
    if (isFromDS(packet) && !isToDS(packet)) {
        // From AP to STA
        src = MacAddress(header->addr3.bytes); // BSSID
        dst = MacAddress(header->addr1.bytes); // DA
    } else if (!isFromDS(packet) && isToDS(packet)) {
        // From STA to AP
        src = MacAddress(header->addr2.bytes); // SA
        dst = MacAddress(header->addr3.bytes); // BSSID
    } else {
        // Other cases
        src = MacAddress(header->addr2.bytes);
        dst = MacAddress(header->addr1.bytes);
    }
    
    return true;
}

bool PacketParser::parseEAPOLFrame(const uint8_t* packet, int length, HandshakePacket& handshake) {
    if (length < sizeof(IEEE80211Header) + 8) return false; // Minimum EAPOL size
    
    const IEEE80211Header* header = reinterpret_cast<const IEEE80211Header*>(packet);
    const uint8_t* eapol_start = packet + sizeof(IEEE80211Header);
    
    // Check for LLC/SNAP header and EAPOL
    if (eapol_start[6] != 0x88 || eapol_start[7] != 0x8e) return false; // EAPOL ethertype
    
    const uint8_t* eapol_packet = eapol_start + 8; // Skip LLC/SNAP
    
    // EAPOL header: version(1) + type(1) + length(2)
    if (eapol_packet[1] != 0x03) return false; // Key type
    
    // Extract MAC addresses
    handshake.ap_mac = MacAddress(header->addr1.bytes);
    handshake.client_mac = MacAddress(header->addr2.bytes);
    
    // Parse key information
    const uint8_t* key_info = eapol_packet + 4;
    uint16_t key_info_flags = (key_info[1] << 8) | key_info[0];
    
    // Determine message number based on key info flags
    bool install = (key_info_flags & 0x0040) != 0;
    bool ack = (key_info_flags & 0x0080) != 0;
    bool mic = (key_info_flags & 0x0100) != 0;
    
    if (ack && !install && !mic) {
        handshake.message_number = 1;
    } else if (!ack && !install && mic) {
        handshake.message_number = 2;
    } else if (ack && install && mic) {
        handshake.message_number = 3;
    } else if (!ack && !install && mic) {
        handshake.message_number = 4;
    }
    
    // Extract nonces and MIC
    if (handshake.message_number == 1 || handshake.message_number == 3) {
        // ANonce is at offset 13 in key data
        handshake.anonce.assign(key_info + 13, key_info + 13 + 32);
    }
    
    if (handshake.message_number == 2 || handshake.message_number == 4) {
        // SNonce is at offset 13 in key data
        handshake.snonce.assign(key_info + 13, key_info + 13 + 32);
    }
    
    // Extract MIC (16 bytes at offset 77)
    if (mic) {
        handshake.mic.assign(key_info + 77, key_info + 77 + 16);
    }
    
    // Store complete EAPOL data
    int eapol_length = (eapol_packet[2] << 8) | eapol_packet[3];
    handshake.eapol_data.assign(eapol_packet, eapol_packet + eapol_length + 4);
    
    return true;
}

bool PacketParser::parseDeauthFrame(const uint8_t* packet, int length, MacAddress& src, MacAddress& dst) {
    if (length < sizeof(IEEE80211Header) + 2) return false; // Deauth has 2-byte reason code
    
    const IEEE80211Header* header = reinterpret_cast<const IEEE80211Header*>(packet);
    
    src = MacAddress(header->addr2.bytes);
    dst = MacAddress(header->addr1.bytes);
    
    return true;
}

std::string PacketParser::extractSSID(const uint8_t* ie_data, int ie_length) {
    const uint8_t* ssid_ie = findInformationElement(ie_data, ie_length, 0); // SSID IE
    if (!ssid_ie) return "";
    
    int ssid_len = ssid_ie[1];
    if (ssid_len == 0) return "<hidden>";
    
    return std::string(reinterpret_cast<const char*>(ssid_ie + 2), ssid_len);
}

int PacketParser::extractChannel(const uint8_t* ie_data, int ie_length) {
    const uint8_t* channel_ie = findInformationElement(ie_data, ie_length, 3); // DS Parameter Set
    if (!channel_ie || channel_ie[1] != 1) return 0;
    
    return channel_ie[2];
}

EncryptionType PacketParser::extractEncryption(const uint8_t* ie_data, int ie_length) {
    // Check for RSN (WPA2/WPA3)
    const uint8_t* rsn_ie = findInformationElement(ie_data, ie_length, 48);
    if (rsn_ie) {
        EncryptionType type;
        if (parseRSNInformation(rsn_ie + 2, rsn_ie[1], type)) {
            return type;
        }
    }
    
    // Check for WPA
    const uint8_t* wpa_ie = findInformationElement(ie_data, ie_length, 221); // Vendor specific
    if (wpa_ie && wpa_ie[1] >= 4) {
        // Check for Microsoft WPA OUI
        if (wpa_ie[2] == 0x00 && wpa_ie[3] == 0x50 && wpa_ie[4] == 0xf2 && wpa_ie[5] == 0x01) {
            EncryptionType type;
            if (parseWPAInformation(wpa_ie + 6, wpa_ie[1] - 4, type)) {
                return type;
            }
        }
    }
    
    // Check for WEP (Privacy bit in capabilities)
    return EncryptionType::OPEN; // Simplified for now
}

bool PacketParser::isBeaconFrame(const uint8_t* packet) {
    if (!packet) return false;
    return (packet[0] & 0xfc) == 0x80; // Type: Management, Subtype: Beacon
}

bool PacketParser::isDataFrame(const uint8_t* packet) {
    if (!packet) return false;
    return (packet[0] & 0x0c) == 0x08; // Type: Data
}

bool PacketParser::isEAPOLFrame(const uint8_t* packet) {
    if (!packet) return false;
    // Check if it's a data frame first
    if (!isDataFrame(packet)) return false;
    
    // Check for EAPOL ethertype in LLC/SNAP header
    const uint8_t* llc_start = packet + sizeof(IEEE80211Header);
    return (llc_start[6] == 0x88 && llc_start[7] == 0x8e);
}

bool PacketParser::isDeauthFrame(const uint8_t* packet) {
    if (!packet) return false;
    return (packet[0] & 0xfc) == 0xc0; // Type: Management, Subtype: Deauthentication
}

bool PacketParser::isSAEFrame(const uint8_t* packet) {
    if (!packet) return false;
    // Type: Management (00), Subtype: Authentication (1011) -> 0xb0
    if ((packet[0] & 0xfc) != 0xb0) return false;

    // Check auth algorithm inside the frame body
    const uint16_t* auth_algo = reinterpret_cast<const uint16_t*>(packet + sizeof(IEEE80211Header));
    if (ntohs(*auth_algo) != 3) return false; // 3 = SAE

    return true;
}

bool PacketParser::isFromDS(const uint8_t* packet) {
    return (packet[1] & 0x02) != 0;
}

bool PacketParser::isToDS(const uint8_t* packet) {
    return (packet[1] & 0x01) != 0;
}

const uint8_t* PacketParser::findInformationElement(const uint8_t* ie_data, int ie_length, uint8_t element_id) {
    const uint8_t* current = ie_data;
    const uint8_t* end = ie_data + ie_length;
    
    while (current + 2 <= end) {
        uint8_t id = current[0];
        uint8_t len = current[1];
        
        if (current + 2 + len > end) break;
        
        if (id == element_id) {
            return current;
        }
        
        current += 2 + len;
    }
    
    return nullptr;
}

bool PacketParser::parseRSNInformation(const uint8_t* rsn_data, int rsn_length, EncryptionType& encryption) {
    if (rsn_length < 8) return false; // Version(2) + GroupCipher(4) + PairwiseCount(2)

    // RSN Version
    if (rsn_data[0] != 0x01 || rsn_data[1] != 0x00) return false;

    const uint8_t* current = rsn_data + 2; // Skip version
    int remaining_length = rsn_length - 2;

    // Group Data Cipher Suite (4 bytes)
    current += 4;
    remaining_length -= 4;
    if (remaining_length < 2) return false;

    // Pairwise Cipher Suite Count (2 bytes)
    uint16_t pairwise_count = (current[1] << 8) | current[0];
    current += 2;
    remaining_length -= 2;
    if (remaining_length < pairwise_count * 4) return false;

    // Skip Pairwise Cipher Suite List
    current += pairwise_count * 4;
    remaining_length -= pairwise_count * 4;
    if (remaining_length < 2) return false;

    // AKM Suite Count (2 bytes)
    uint16_t akm_count = (current[1] << 8) | current[0];
    current += 2;
    remaining_length -= 2;
    if (remaining_length < akm_count * 4) return false;

    // AKM Suite List
    bool is_wpa3 = false;
    for (int i = 0; i < akm_count; ++i) {
        // Check for WPA3-SAE (00-0F-AC:8)
        if (current[0] == 0x00 && current[1] == 0x0F && current[2] == 0xAC && current[3] == 0x08) {
            is_wpa3 = true;
            break;
        }
        current += 4;
    }

    if (is_wpa3) {
        encryption = EncryptionType::WPA3;
    } else {
        encryption = EncryptionType::WPA2;
    }

    return true;
}

bool PacketParser::parseWPAInformation(const uint8_t* wpa_data, int wpa_length, EncryptionType& encryption) {
    if (wpa_length < 2) return false;
    
    encryption = EncryptionType::WPA;
    return true;
}

bool PacketParser::validateFrameChecksum(const uint8_t* packet, int length) {
    // FCS validation would require CRC32 calculation
    // Simplified implementation
    return length >= sizeof(IEEE80211Header);
}

bool PacketParser::parseSAEFrame(const uint8_t* packet, int length, SAEHandshakePacket& sae_packet) {
    struct AuthenticationFrame {
        IEEE80211Header header;
        uint16_t auth_algorithm;
        uint16_t auth_seq;
        uint16_t status_code;
    } __attribute__((packed));

    if (length < sizeof(AuthenticationFrame)) return false;

    const AuthenticationFrame* auth_frame = reinterpret_cast<const AuthenticationFrame*>(packet);

    if (ntohs(auth_frame->auth_algorithm) != 3) return false; // SAE

    sae_packet.ap_mac = MacAddress(auth_frame->header.addr1.bytes);
    sae_packet.client_mac = MacAddress(auth_frame->header.addr2.bytes);
    
    uint16_t seq_num = ntohs(auth_frame->auth_seq);
    const uint8_t* sae_data = packet + sizeof(AuthenticationFrame);
    int sae_data_len = length - sizeof(AuthenticationFrame);

    if (seq_num == 1) { // Commit Message
        sae_packet.message_number = 1;
        if (sae_data_len < 2) return false; // Must have at least group ID
        sae_packet.finite_field_group = sae_data[0] | (sae_data[1] << 8);
        // Simplified parsing: copy the rest of the data
        sae_packet.raw_data.assign(sae_data, sae_data + sae_data_len);
    } else if (seq_num == 2) { // Confirm Message
        sae_packet.message_number = 2;
        // Simplified parsing: copy the confirm data
        sae_packet.raw_data.assign(sae_data, sae_data + sae_data_len);
    } else {
        return false; // Other sequence numbers are not part of the handshake
    }

    return true;
}

} // namespace airlevi
