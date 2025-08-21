#ifndef AIRLEVI_PASSWORD_DATABASE_H
#define AIRLEVI_PASSWORD_DATABASE_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <sqlite3.h>
#include "common/types.h"

namespace airlevi {

struct PMKEntry {
    std::string essid;
    std::string password;
    std::vector<uint8_t> pmk;
    uint64_t created_at;
};

struct ESSIDEntry {
    std::string essid;
    uint64_t password_count;
    uint64_t created_at;
    uint64_t updated_at;
};

class PasswordDatabase {
public:
    PasswordDatabase();
    ~PasswordDatabase();

    // Database management
    bool create(const std::string& db_path);
    bool open(const std::string& db_path);
    bool close();
    bool vacuum();
    bool verify();
    
    // ESSID management
    bool importESSID(const std::string& essid);
    bool removeESSID(const std::string& essid);
    std::vector<ESSIDEntry> listESSIDs();
    bool essidExists(const std::string& essid);
    
    // Password management
    bool importWordlist(const std::string& essid, const std::string& wordlist_path);
    bool addPassword(const std::string& essid, const std::string& password);
    bool removePassword(const std::string& essid, const std::string& password);
    std::vector<std::string> getPasswords(const std::string& essid);
    uint64_t getPasswordCount(const std::string& essid);
    
    // PMK computation and storage
    bool computePMKs(const std::string& essid);
    bool computePMK(const std::string& essid, const std::string& password);
    std::vector<uint8_t> getPMK(const std::string& essid, const std::string& password);
    bool pmkExists(const std::string& essid, const std::string& password);
    
    // Batch operations
    bool batchImport(const std::string& essid, const std::vector<std::string>& passwords);
    bool batchComputePMKs(const std::string& essid, int thread_count = 0);
    
    // Statistics and info
    uint64_t getTotalESSIDs();
    uint64_t getTotalPasswords();
    uint64_t getTotalPMKs();
    uint64_t getDatabaseSize();
    void displayStatistics();
    void displayESSIDInfo(const std::string& essid);
    
    // Export/Import
    bool exportToFile(const std::string& essid, const std::string& output_path);
    bool importFromFile(const std::string& essid, const std::string& input_path);
    
    // Cleanup
    bool cleanupOrphaned();
    bool optimizeDatabase();
    
private:
    sqlite3* db_;
    std::string db_path_;
    bool is_open_;
    
    // Database initialization
    bool createTables();
    bool createIndexes();
    
    // PMK computation
    std::vector<uint8_t> computePMKFromPassword(const std::string& essid, const std::string& password);
    
    // Helper functions
    bool executeSQL(const std::string& sql);
    bool prepareStatement(const std::string& sql, sqlite3_stmt** stmt);
    std::string getLastError();
    bool beginTransaction();
    bool commitTransaction();
    bool rollbackTransaction();
    
    // Progress callback for long operations
    static int progressCallback(void* data);
    void updateProgress(int current, int total, const std::string& operation);
};

} // namespace airlevi

#endif // AIRLEVI_PASSWORD_DATABASE_H
