#ifndef AIRLEVI_STATISTICS_H
#define AIRLEVI_STATISTICS_H

#include <chrono>
#include <cstddef>

namespace airlevi {

class Statistics {
public:
    Statistics();

    void packetCaptured(size_t bytes);
    void handshakeCaptured();
    void networkDiscovered();

    void printSummary() const;

private:
    std::chrono::steady_clock::time_point start_time_;
    size_t packets_captured_;
    size_t bytes_captured_;
    size_t handshakes_captured_;
    size_t networks_discovered_;
};

} // namespace airlevi

#endif // AIRLEVI_STATISTICS_H
