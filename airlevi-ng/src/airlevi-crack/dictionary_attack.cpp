#include "airlevi-crack/dictionary_attack.h"
#include "common/logger.h"
#include <fstream>
#include <chrono>
#include <algorithm>

namespace airlevi {

DictionaryAttack::DictionaryAttack(const Config& config, int num_threads)
    : config_(config), num_threads_(num_threads > 0 ? num_threads : std::thread::hardware_concurrency()),
      running_(false), found_(false), attempts_(0) {
    
    wpa_cracker_ = std::make_unique<WPACrack>(config);
}

DictionaryAttack::~DictionaryAttack() {
    stop();
}

bool DictionaryAttack::crack(std::string& found_password) {
    Logger::getInstance().info("Starting multi-threaded dictionary attack with " + 
                             std::to_string(num_threads_) + " threads");
    
    // Load and prepare handshake
    std::string temp;
    if (!wpa_cracker_->crack(temp)) {
        // This call is just to load the handshake data
    }
    
    running_ = true;
    found_ = false;
    attempts_ = 0;
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Start worker threads
    worker_threads_.reserve(num_threads_);
    for (int i = 0; i < num_threads_; ++i) {
        worker_threads_.emplace_back(&DictionaryAttack::workerThread, this);
    }
    
    // Load passwords into queue
    loadPasswords();
    
    // Wait for completion or password found
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    Logger::getInstance().info("Dictionary attack completed in " + std::to_string(duration.count()) + 
                             " seconds. Tested " + std::to_string(attempts_) + " passwords");
    
    if (found_) {
        std::lock_guard<std::mutex> lock(result_mutex_);
        found_password = result_password_;
        return true;
    }
    
    return false;
}

double DictionaryAttack::getRate() const {
    // Calculate passwords per second
    static auto start_time = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
    
    if (duration.count() > 0) {
        return static_cast<double>(attempts_) / duration.count();
    }
    
    return 0.0;
}

void DictionaryAttack::workerThread() {
    std::string password;
    
    while (running_ && !found_ && getPasswordFromQueue(password)) {
        if (testPasswordWorker(password)) {
            std::lock_guard<std::mutex> lock(result_mutex_);
            if (!found_) {
                found_ = true;
                result_password_ = password;
                Logger::getInstance().info("Password found by worker thread: " + password);
            }
            break;
        }
        
        attempts_++;
        
        // Progress reporting
        if (attempts_ % 1000 == 0) {
            Logger::getInstance().info("Tested " + std::to_string(attempts_) + 
                                     " passwords (" + std::to_string(static_cast<int>(getRate())) + " p/s)");
        }
    }
}

void DictionaryAttack::loadPasswords() {
    if (config_.wordlist_file.empty()) {
        Logger::getInstance().error("No wordlist file specified");
        running_ = false;
        return;
    }
    
    std::ifstream wordlist(config_.wordlist_file);
    if (!wordlist.is_open()) {
        Logger::getInstance().error("Cannot open wordlist file: " + config_.wordlist_file);
        running_ = false;
        return;
    }
    
    std::string password;
    int loaded = 0;
    
    while (std::getline(wordlist, password) && running_) {
        // Trim whitespace
        password.erase(0, password.find_first_not_of(" \t\r\n"));
        password.erase(password.find_last_not_of(" \t\r\n") + 1);
        
        // Skip empty lines and comments
        if (password.empty() || password[0] == '#') continue;
        
        // WPA password length validation
        if (password.length() >= 8 && password.length() <= 63) {
            addPasswordToQueue(password);
            loaded++;
        }
        
        if (loaded % 100000 == 0) {
            Logger::getInstance().info("Loaded " + std::to_string(loaded) + " passwords");
        }
    }
    
    Logger::getInstance().info("Loaded " + std::to_string(loaded) + " valid passwords from wordlist");
}

bool DictionaryAttack::testPasswordWorker(const std::string& password) {
    // Create a local WPA cracker instance for this thread
    WPACrack local_cracker(config_);
    
    // Test the password (this would need access to the handshake)
    std::string temp_result;
    
    // For now, we'll use a simplified approach
    // In a real implementation, we'd need to share the handshake data
    // between threads more efficiently
    
    return false; // Placeholder - actual implementation would test against handshake
}

void DictionaryAttack::addPasswordToQueue(const std::string& password) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    password_queue_.push(password);
}

bool DictionaryAttack::getPasswordFromQueue(std::string& password) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    
    if (password_queue_.empty()) {
        return false;
    }
    
    password = password_queue_.front();
    password_queue_.pop();
    return true;
}

} // namespace airlevi
