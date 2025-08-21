#ifndef AIRLEVI_DICTIONARY_ATTACK_H
#define AIRLEVI_DICTIONARY_ATTACK_H

#include "common/types.h"
#include "wpa_crack.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>

namespace airlevi {

class DictionaryAttack {
public:
    DictionaryAttack(const Config& config, int num_threads = 0);
    ~DictionaryAttack();

    bool crack(std::string& found_password);
    
    void stop() { running_ = false; }
    bool isRunning() const { return running_; }
    
    // Statistics
    uint64_t getAttempts() const { return attempts_; }
    double getRate() const; // passwords per second

private:
    Config config_;
    int num_threads_;
    std::atomic<bool> running_;
    std::atomic<bool> found_;
    std::atomic<uint64_t> attempts_;
    std::string result_password_;
    
    // Threading
    std::vector<std::thread> worker_threads_;
    std::queue<std::string> password_queue_;
    std::mutex queue_mutex_;
    std::mutex result_mutex_;
    
    // WPA cracker instance
    std::unique_ptr<WPACrack> wpa_cracker_;
    HandshakePacket target_handshake_;
    
    // Worker functions
    void workerThread();
    void loadPasswords();
    bool testPasswordWorker(const std::string& password);
    
    // Queue management
    void addPasswordToQueue(const std::string& password);
    bool getPasswordFromQueue(std::string& password);
};

} // namespace airlevi

#endif // AIRLEVI_DICTIONARY_ATTACK_H
