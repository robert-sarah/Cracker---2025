#ifndef AIRLEVI_LOGGER_H
#define AIRLEVI_LOGGER_H

#include <string>
#include <mutex>

namespace airlevi {

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

class Logger {
public:
    static Logger& getInstance();
    
    void setVerbose(bool verbose);
    
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void debug(const std::string& message);

private:
    Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    void log(LogLevel level, const std::string& message);
    
    bool verbose_;
    std::mutex mutex_;
};

} // namespace airlevi

#endif // AIRLEVI_LOGGER_H
