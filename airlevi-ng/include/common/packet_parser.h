#ifndef AIRLEVI_PACKET_PARSER_H
#define AIRLEVI_PACKET_PARSER_H

#include "types.h"
#include <pcap.h>

namespace airlevi {

class PacketParser {
public:
    PacketParser();
    ~PacketParser();

    // Parse different types of 802.11 frames
    bool parseBeaconFrame(const uint8_t* packet, int length, WifiNetwork& network);
    bool parseDataFrame(const uint8_t* packet, int length, MacAddress& src, MacAddress& dst);
    bool parseEAPOLFrame(const uint8_t* packet, int length, HandshakePacket& handshake);
    bool parseDeauthFrame(const uint8_t* packet, int length, MacAddress& src, MacAddress& dst);
    bool parseSAEFrame(const uint8_t* packet, int length, SAEHandshakePacket& sae_packet);
    
    // Extract information elements from beacon frames
    std::string extractSSID(const uint8_t* ie_data, int ie_length);
    int extractChannel(const uint8_t* ie_data, int ie_length);
    EncryptionType extractEncryption(const uint8_t* ie_data, int ie_length);
    
    // Utility functions
    bool isBeaconFrame(const uint8_t* packet);
    bool isDataFrame(const uint8_t* packet);
    bool isEAPOLFrame(const uint8_t* packet);
    bool isDeauthFrame(const uint8_t* packet);
    bool isSAEFrame(const uint8_t* packet);
    
    // Frame validation
    bool validateFrameChecksum(const uint8_t* packet, int length);
    bool isFromDS(const uint8_t* packet);
    bool isToDS(const uint8_t* packet);

private:
    // Helper functions for parsing information elements
    const uint8_t* findInformationElement(const uint8_t* ie_data, int ie_length, uint8_t element_id);
    bool parseRSNInformation(const uint8_t* rsn_data, int rsn_length, EncryptionType& encryption);
    bool parseWPAInformation(const uint8_t* wpa_data, int wpa_length, EncryptionType& encryption);
};

} // namespace airlevi

#endif // AIRLEVI_PACKET_PARSER_H
