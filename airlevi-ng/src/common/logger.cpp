#include "common/logger.h"
#include <iostream>
#include <iomanip>
#include <chrono>

namespace airlevi {

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() : verbose_(false) {}

void Logger::setVerbose(bool verbose) {
    verbose_ = verbose;
}

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::WARNING, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

void Logger::debug(const std::string& message) {
    if (verbose_) {
        log(LogLevel::DEBUG, message);
    }
}

void Logger::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::string level_str;
    switch (level) {
        case LogLevel::INFO:    level_str = "INFO"; break;
        case LogLevel::WARNING: level_str = "WARN"; break;
        case LogLevel::ERROR:   level_str = "ERROR"; break;
        case LogLevel::DEBUG:   level_str = "DEBUG"; break;
    }
    
    std::cout << "[" << std::put_time(&tm, "%H:%M:%S") << "] "
              << "[" << level_str << "] " << message << std::endl;
}

} // namespace airlevi
