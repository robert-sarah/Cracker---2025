#ifndef HANDSHAKE_CAPTURE_H
#define HANDSHAKE_CAPTURE_H

#include "common/mac_address.h"
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <pcap.h>
#include <chrono>
#include <map>

// Structure pour représenter un point d'accès (AP)
struct AccessPoint {
    MacAddress bssid;
    std::string ssid;
    uint8_t channel;
    int signal_strength;
    bool has_handshake = false;
    std::chrono::steady_clock::time_point last_seen;
};

// Structure pour représenter un client connecté
struct ClientStation {
    MacAddress mac;
    MacAddress ap_bssid; // BSSID de l'AP auquel il est associé
    int signal_strength;
    bool is_associated = false;
    std::chrono::steady_clock::time_point last_seen;
};

// Structure pour stocker un handshake capturé
struct Handshake {
    MacAddress ap_bssid;
    MacAddress client_mac;
    std::string ssid;
    std::vector<uint8_t> eapol_frames[4]; // Stocke les 4 trames EAPOL
    bool complete = false;
    std::chrono::steady_clock::time_point timestamp;
};

// Statistiques de la capture
struct HandshakeStats {
    uint64_t packets_processed = 0;
    uint32_t handshakes_captured = 0;
    uint32_t deauth_sent = 0;
    uint32_t aps_found = 0;
    uint32_t clients_found = 0;
    uint32_t runtime_seconds = 0;
    uint8_t current_channel = 1;
};

class HandshakeCapture {
public:
    HandshakeCapture();
    ~HandshakeCapture();

    bool initialize(const std::string& interface, const std::string& output_file);
    bool startCapture();
    void stopCapture();

    // Configuration
    void setTargetBSSID(const MacAddress& bssid);
    void setTargetSSID(const std::string& ssid);
    void setChannel(uint8_t channel);
    void setChannelHopping(bool enabled, int dwell_time_ms = 250);
    void setDeauthAttack(bool enabled, int packets_per_burst = 5, int burst_interval_ms = 2000);

    // Accesseurs
    std::vector<AccessPoint> getAccessPoints() const;
    std::vector<ClientStation> getClients() const;
    std::vector<Handshake> getHandshakes() const;
    HandshakeStats getStats() const;

    void displayStatus() const;

private:
    void captureLoop();
    void channelHoppingLoop();
    void deauthLoop();
    void processPacket(const struct pcap_pkthdr* header, const u_char* packet);
    void parseBeaconFrame(const u_char* packet, int length);
    void parseEAPOL(const u_char* packet, int length);
    void sendDeauthPacket(const MacAddress& ap_bssid, const MacAddress& client_mac);
    void saveHandshake(const Handshake& handshake);
    bool setWifiChannel(const std::string& interface, uint8_t channel);

    std::string interface;
    std::string output_file;
    pcap_t* pcap_handle = nullptr;
    pcap_dumper_t* pcap_dumper = nullptr;

    std::atomic<bool> running;
    std::thread capture_thread;
    std::thread hopping_thread;
    std::thread deauth_thread;

    // Données partagées
    mutable std::mutex data_mutex;
    std::map<MacAddress, AccessPoint> access_points;
    std::map<MacAddress, ClientStation> clients;
    std::map<MacAddress, Handshake> handshakes; // Clé: BSSID de l'AP

    // Configuration
    MacAddress target_bssid;
    std::string target_ssid;
    bool channel_hopping_enabled = true;
    int dwell_time_ms = 250;
    bool deauth_attack_enabled = false;
    int deauth_packets_per_burst = 5;
    int deauth_burst_interval_ms = 2000;
    uint8_t current_channel = 1;
    std::vector<uint8_t> channels;

    // Statistiques
    std::atomic<uint64_t> packets_processed;
    std::atomic<uint32_t> deauth_sent;
    std::chrono::steady_clock::time_point start_time;
};

#endif // HANDSHAKE_CAPTURE_H
