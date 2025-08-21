#include "airlevi-lib/password_database.h"
#include "common/logger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace airlevi {

PasswordDatabase::PasswordDatabase() : db_(nullptr), is_open_(false) {}

PasswordDatabase::~PasswordDatabase() {
    if (is_open_) {
        close();
    }
}

bool PasswordDatabase::create(const std::string& db_path) {
    db_path_ = db_path;
    
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        Logger::getInstance().log("Cannot create database: " + std::string(sqlite3_errmsg(db_)), LogLevel::ERROR);
        return false;
    }
    
    is_open_ = true;
    
    if (!createTables() || !createIndexes()) {
        close();
        return false;
    }
    
    Logger::getInstance().log("Database created: " + db_path, LogLevel::INFO);
    return true;
}

bool PasswordDatabase::open(const std::string& db_path) {
    db_path_ = db_path;
    
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        Logger::getInstance().log("Cannot open database: " + std::string(sqlite3_errmsg(db_)), LogLevel::ERROR);
        return false;
    }
    
    is_open_ = true;
    Logger::getInstance().log("Database opened: " + db_path, LogLevel::INFO);
    return true;
}

bool PasswordDatabase::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    is_open_ = false;
    return true;
}

bool PasswordDatabase::createTables() {
    std::vector<std::string> create_queries = {
        "CREATE TABLE IF NOT EXISTS essids ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "essid TEXT UNIQUE NOT NULL,"
        "created_at INTEGER DEFAULT (strftime('%s','now')),"
        "updated_at INTEGER DEFAULT (strftime('%s','now'))"
        ");",
        
        "CREATE TABLE IF NOT EXISTS passwords ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "essid_id INTEGER,"
        "password TEXT NOT NULL,"
        "created_at INTEGER DEFAULT (strftime('%s','now')),"
        "FOREIGN KEY(essid_id) REFERENCES essids(id) ON DELETE CASCADE,"
        "UNIQUE(essid_id, password)"
        ");",
        
        "CREATE TABLE IF NOT EXISTS pmks ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "password_id INTEGER,"
        "pmk BLOB NOT NULL,"
        "created_at INTEGER DEFAULT (strftime('%s','now')),"
        "FOREIGN KEY(password_id) REFERENCES passwords(id) ON DELETE CASCADE"
        ");"
    };
    
    for (const auto& query : create_queries) {
        if (!executeSQL(query)) {
            return false;
        }
    }
    
    return true;
}

bool PasswordDatabase::createIndexes() {
    std::vector<std::string> index_queries = {
        "CREATE INDEX IF NOT EXISTS idx_essids_essid ON essids(essid);",
        "CREATE INDEX IF NOT EXISTS idx_passwords_essid_id ON passwords(essid_id);",
        "CREATE INDEX IF NOT EXISTS idx_passwords_password ON passwords(password);",
        "CREATE INDEX IF NOT EXISTS idx_pmks_password_id ON pmks(password_id);"
    };
    
    for (const auto& query : index_queries) {
        if (!executeSQL(query)) {
            return false;
        }
    }
    
    return true;
}

bool PasswordDatabase::executeSQL(const std::string& sql) {
    char* error_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &error_msg);
    
    if (rc != SQLITE_OK) {
        std::string error = error_msg ? error_msg : "Unknown error";
        Logger::getInstance().log("SQL error: " + error, LogLevel::ERROR);
        if (error_msg) sqlite3_free(error_msg);
        return false;
    }
    
    return true;
}

bool PasswordDatabase::importESSID(const std::string& essid) {
    std::string sql = "INSERT OR IGNORE INTO essids (essid) VALUES (?);";
    sqlite3_stmt* stmt;
    
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, essid.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        Logger::getInstance().log("Failed to import ESSID: " + essid, LogLevel::ERROR);
        return false;
    }
    
    Logger::getInstance().log("Imported ESSID: " + essid, LogLevel::INFO);
    return true;
}

bool PasswordDatabase::importWordlist(const std::string& essid, const std::string& wordlist_path) {
    if (!importESSID(essid)) {
        return false;
    }
    
    std::ifstream file(wordlist_path);
    if (!file.is_open()) {
        Logger::getInstance().log("Cannot open wordlist: " + wordlist_path, LogLevel::ERROR);
        return false;
    }
    
    beginTransaction();
    
    std::string password;
    int count = 0;
    
    while (std::getline(file, password)) {
        if (!password.empty()) {
            addPassword(essid, password);
            count++;
            
            if (count % 1000 == 0) {
                std::cout << "\rImported " << count << " passwords..." << std::flush;
            }
        }
    }
    
    commitTransaction();
    file.close();
    
    std::cout << "\nImported " << count << " passwords for ESSID: " << essid << std::endl;
    return true;
}

bool PasswordDatabase::addPassword(const std::string& essid, const std::string& password) {
    std::string sql = "INSERT OR IGNORE INTO passwords (essid_id, password) "
                     "SELECT id, ? FROM essids WHERE essid = ?;";
    sqlite3_stmt* stmt;
    
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, password.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, essid.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

std::vector<uint8_t> PasswordDatabase::computePMKFromPassword(const std::string& essid, const std::string& password) {
    std::vector<uint8_t> pmk(32);
    
    // Use PBKDF2 to compute PMK
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                         (const unsigned char*)essid.c_str(), essid.length(),
                         4096, EVP_sha1(),
                         32, pmk.data()) != 1) {
        pmk.clear();
    }
    
    return pmk;
}

bool PasswordDatabase::computePMKs(const std::string& essid) {
    auto passwords = getPasswords(essid);
    
    beginTransaction();
    
    int count = 0;
    for (const auto& password : passwords) {
        if (!pmkExists(essid, password)) {
            computePMK(essid, password);
            count++;
            
            if (count % 100 == 0) {
                std::cout << "\rComputed " << count << " PMKs..." << std::flush;
            }
        }
    }
    
    commitTransaction();
    
    std::cout << "\nComputed " << count << " PMKs for ESSID: " << essid << std::endl;
    return true;
}

bool PasswordDatabase::computePMK(const std::string& essid, const std::string& password) {
    auto pmk = computePMKFromPassword(essid, password);
    if (pmk.empty()) {
        return false;
    }
    
    std::string sql = "INSERT INTO pmks (password_id, pmk) "
                     "SELECT p.id, ? FROM passwords p "
                     "JOIN essids e ON p.essid_id = e.id "
                     "WHERE e.essid = ? AND p.password = ?;";
    sqlite3_stmt* stmt;
    
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }
    
    sqlite3_bind_blob(stmt, 1, pmk.data(), pmk.size(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, essid.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, password.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

bool PasswordDatabase::prepareStatement(const std::string& sql, sqlite3_stmt** stmt) {
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, stmt, nullptr);
    if (rc != SQLITE_OK) {
        Logger::getInstance().log("Failed to prepare statement: " + getLastError(), LogLevel::ERROR);
        return false;
    }
    return true;
}

std::string PasswordDatabase::getLastError() {
    return std::string(sqlite3_errmsg(db_));
}

bool PasswordDatabase::beginTransaction() {
    return executeSQL("BEGIN TRANSACTION;");
}

bool PasswordDatabase::commitTransaction() {
    return executeSQL("COMMIT;");
}

bool PasswordDatabase::rollbackTransaction() {
    return executeSQL("ROLLBACK;");
}

std::vector<std::string> PasswordDatabase::getPasswords(const std::string& essid) {
    std::vector<std::string> passwords;
    
    std::string sql = "SELECT p.password FROM passwords p "
                     "JOIN essids e ON p.essid_id = e.id "
                     "WHERE e.essid = ?;";
    sqlite3_stmt* stmt;
    
    if (!prepareStatement(sql, &stmt)) {
        return passwords;
    }
    
    sqlite3_bind_text(stmt, 1, essid.c_str(), -1, SQLITE_STATIC);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* password = (const char*)sqlite3_column_text(stmt, 0);
        if (password) {
            passwords.push_back(password);
        }
    }
    
    sqlite3_finalize(stmt);
    return passwords;
}

uint64_t PasswordDatabase::getTotalESSIDs() {
    std::string sql = "SELECT COUNT(*) FROM essids;";
    sqlite3_stmt* stmt;
    
    if (!prepareStatement(sql, &stmt)) {
        return 0;
    }
    
    uint64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return count;
}

uint64_t PasswordDatabase::getTotalPasswords() {
    std::string sql = "SELECT COUNT(*) FROM passwords;";
    sqlite3_stmt* stmt;
    
    if (!prepareStatement(sql, &stmt)) {
        return 0;
    }
    
    uint64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return count;
}

uint64_t PasswordDatabase::getTotalPMKs() {
    std::string sql = "SELECT COUNT(*) FROM pmks;";
    sqlite3_stmt* stmt;
    
    if (!prepareStatement(sql, &stmt)) {
        return 0;
    }
    
    uint64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return count;
}

void PasswordDatabase::displayStatistics() {
    std::cout << "\nDatabase Statistics:\n";
    std::cout << "===================\n";
    std::cout << "ESSIDs: " << getTotalESSIDs() << "\n";
    std::cout << "Passwords: " << getTotalPasswords() << "\n";
    std::cout << "PMKs: " << getTotalPMKs() << "\n";
    std::cout << "Database file: " << db_path_ << "\n";
}

bool PasswordDatabase::pmkExists(const std::string& essid, const std::string& password) {
    std::string sql = "SELECT COUNT(*) FROM pmks pk "
                     "JOIN passwords p ON pk.password_id = p.id "
                     "JOIN essids e ON p.essid_id = e.id "
                     "WHERE e.essid = ? AND p.password = ?;";
    sqlite3_stmt* stmt;
    
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, essid.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);
    
    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = sqlite3_column_int(stmt, 0) > 0;
    }
    
    sqlite3_finalize(stmt);
    return exists;
}

bool PasswordDatabase::vacuum() {
    if (!is_open_) {
        Logger::getInstance().log("Database is not open.", LogLevel::ERROR);
        return false;
    }
    Logger::getInstance().log("Running VACUUM on the database...", LogLevel::INFO);
    if (executeSQL("VACUUM;")) {
        Logger::getInstance().log("Database vacuumed successfully.", LogLevel::INFO);
        return true;
    } else {
        Logger::getInstance().log("Failed to vacuum database.", LogLevel::ERROR);
        return false;
    }
}

bool PasswordDatabase::verify() {
    if (!is_open_) {
        Logger::getInstance().log("Database is not open.", LogLevel::ERROR);
        return false;
    }
    
    Logger::getInstance().log("Verifying database integrity...", LogLevel::INFO);
    
    sqlite3_stmt* stmt;
    std::string sql = "PRAGMA integrity_check;";
    
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        Logger::getInstance().log("Failed to prepare integrity_check statement: " + getLastError(), LogLevel::ERROR);
        return false;
    }
    
    bool ok = false;
    int rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_ROW) {
        const char* result = (const char*)sqlite3_column_text(stmt, 0);
        if (result && std::string(result) == "ok") {
            Logger::getInstance().log("Database integrity check passed.", LogLevel::INFO);
            ok = true;
        } else {
            Logger::getInstance().log("Database integrity check failed: " + std::string(result ? result : ""), LogLevel::ERROR);
            // Read all error messages
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                 const char* error_msg = (const char*)sqlite3_column_text(stmt, 0);
                 if (error_msg) {
                     Logger::getInstance().log("Details: " + std::string(error_msg), LogLevel::ERROR);
                 }
            }
        }
    } else {
        Logger::getInstance().log("Failed to execute integrity_check: " + getLastError(), LogLevel::ERROR);
    }
    
    sqlite3_finalize(stmt);
    return ok;
}

} // namespace airlevi
