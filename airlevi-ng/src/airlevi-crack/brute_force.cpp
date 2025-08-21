#include "airlevi-crack/brute_force.h"
#include "common/logger.h"
#include <chrono>
#include <cmath>

namespace airlevi {

BruteForce::BruteForce(const Config& config, int num_threads)
    : config_(config), num_threads_(num_threads > 0 ? num_threads : std::thread::hardware_concurrency()),
      charset_("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
      min_length_(8), max_length_(12), running_(false), found_(false), 
      attempts_(0), current_index_(0) {
    
    wpa_cracker_ = std::make_unique<WPACrack>(config);
}

BruteForce::~BruteForce() {
    stop();
}

bool BruteForce::crack(std::string& found_password) {
    Logger::getInstance().info("Starting brute force attack with " + std::to_string(num_threads_) + " threads");
    Logger::getInstance().info("Charset: " + charset_);
    Logger::getInstance().info("Length range: " + std::to_string(min_length_) + "-" + std::to_string(max_length_));
    
    uint64_t total_combinations = calculateTotalCombinations();
    Logger::getInstance().info("Total combinations to test: " + std::to_string(total_combinations));
    
    running_ = true;
    found_ = false;
    attempts_ = 0;
    current_index_ = 0;
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Start worker threads
    worker_threads_.reserve(num_threads_);
    for (int i = 0; i < num_threads_; ++i) {
        worker_threads_.emplace_back(&BruteForce::workerThread, this);
    }
    
    // Wait for completion
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    Logger::getInstance().info("Brute force attack completed in " + std::to_string(duration.count()) + 
                             " seconds. Tested " + std::to_string(attempts_) + " passwords");
    
    if (found_) {
        std::lock_guard<std::mutex> lock(result_mutex_);
        found_password = result_password_;
        return true;
    }
    
    return false;
}

double BruteForce::getRate() const {
    static auto start_time = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
    
    if (duration.count() > 0) {
        return static_cast<double>(attempts_) / duration.count();
    }
    
    return 0.0;
}

void BruteForce::workerThread() {
    while (running_ && !found_) {
        // Get next password to test
        uint64_t index = current_index_++;
        
        // Try all lengths
        for (int length = min_length_; length <= max_length_ && running_ && !found_; ++length) {
            uint64_t combinations_for_length = static_cast<uint64_t>(std::pow(charset_.size(), length));
            
            if (index >= combinations_for_length) {
                index -= combinations_for_length;
                continue;
            }
            
            std::string password = generatePassword(index, length);
            
            if (testPasswordWorker(password)) {
                std::lock_guard<std::mutex> lock(result_mutex_);
                if (!found_) {
                    found_ = true;
                    result_password_ = password;
                    Logger::getInstance().info("Password found by brute force: " + password);
                }
                return;
            }
            
            attempts_++;
            
            if (attempts_ % 10000 == 0) {
                Logger::getInstance().info("Tested " + std::to_string(attempts_) + 
                                         " passwords (" + std::to_string(static_cast<int>(getRate())) + " p/s)");
            }
            
            break; // Found the right length for this index
        }
    }
}

std::string BruteForce::generatePassword(uint64_t index, int length) {
    std::string password;
    password.reserve(length);
    
    uint64_t charset_size = charset_.size();
    
    for (int i = 0; i < length; ++i) {
        password += charset_[index % charset_size];
        index /= charset_size;
    }
    
    return password;
}

uint64_t BruteForce::calculateTotalCombinations() {
    uint64_t total = 0;
    uint64_t charset_size = charset_.size();
    
    for (int length = min_length_; length <= max_length_; ++length) {
        total += static_cast<uint64_t>(std::pow(charset_size, length));
    }
    
    return total;
}

bool BruteForce::testPasswordWorker(const std::string& password) {
    // Create a local WPA cracker instance for this thread
    WPACrack local_cracker(config_);
    
    // Test the password
    std::string temp_result;
    
    // Placeholder - actual implementation would test against handshake
    return false;
}

} // namespace airlevi
