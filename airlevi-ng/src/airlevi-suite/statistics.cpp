#include "airlevi-suite/statistics.h"
#include <iostream>
#include <iomanip>

namespace airlevi {

Statistics::Statistics()
    : start_time_(std::chrono::steady_clock::now()),
      packets_captured_(0),
      bytes_captured_(0),
      handshakes_captured_(0),
      networks_discovered_(0) {}

void Statistics::packetCaptured(size_t bytes) {
    packets_captured_++;
    bytes_captured_ += bytes;
}

void Statistics::handshakeCaptured() {
    handshakes_captured_++;
}

void Statistics::networkDiscovered() {
    networks_discovered_++;
}

void Statistics::printSummary() const {
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time_).count();

    std::cout << "\n--- Session Statistics ---\n";
    std::cout << "Duration: " << duration << " seconds\n";
    std::cout << "Packets Captured: " << packets_captured_ << "\n";
    std::cout << "Bytes Captured: " << bytes_captured_ << "\n";
    std::cout << "Handshakes Captured: " << handshakes_captured_ << "\n";
    std::cout << "Networks Discovered: " << networks_discovered_ << "\n";
    std::cout << "--------------------------\n";
}

} // namespace airlevi
