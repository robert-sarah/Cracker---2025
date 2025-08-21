#ifndef AIRLEVI_BRUTE_FORCE_H
#define AIRLEVI_BRUTE_FORCE_H

#include "common/types.h"
#include "wpa_crack.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <string>

namespace airlevi {

class BruteForce {
public:
    BruteForce(const Config& config, int num_threads = 0);
    ~BruteForce();

    bool crack(std::string& found_password);
    
    void setCharset(const std::string& charset) { charset_ = charset; }
    void setLengthRange(int min_len, int max_len) { 
        min_length_ = min_len; 
        max_length_ = max_len; 
    }
    
    void stop() { running_ = false; }
    bool isRunning() const { return running_; }
    
    uint64_t getAttempts() const { return attempts_; }
    double getRate() const;

private:
    Config config_;
    int num_threads_;
    std::string charset_;
    int min_length_;
    int max_length_;
    
    std::atomic<bool> running_;
    std::atomic<bool> found_;
    std::atomic<uint64_t> attempts_;
    std::atomic<uint64_t> current_index_;
    std::string result_password_;
    
    std::vector<std::thread> worker_threads_;
    std::mutex result_mutex_;
    
    std::unique_ptr<WPACrack> wpa_cracker_;
    
    void workerThread();
    std::string generatePassword(uint64_t index, int length);
    uint64_t calculateTotalCombinations();
    bool testPasswordWorker(const std::string& password);
};

} // namespace airlevi

#endif // AIRLEVI_BRUTE_FORCE_H
