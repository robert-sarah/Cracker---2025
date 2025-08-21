#include <iostream>
#include <signal.h>
#include <getopt.h>
#include <string>
#include "airlevi-lib/password_database.h"
#include "common/logger.h"

using namespace airlevi;

static bool running = true;
static std::unique_ptr<PasswordDatabase> db;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", shutting down..." << std::endl;
    running = false;
}

void printUsage(const char* program_name) {
    std::cout << "AirLevi-NG Password Database v1.0\n";
    std::cout << "Usage: " << program_name << " [OPTIONS] DATABASE COMMAND\n\n";
    std::cout << "Commands:\n";
    std::cout << "  --create                Create new database\n";
    std::cout << "  --import-essid ESSID   Import ESSID\n";
    std::cout << "  --import ESSID FILE    Import wordlist for ESSID\n";
    std::cout << "  --compute ESSID        Compute PMKs for ESSID\n";
    std::cout << "  --stats                Show database statistics\n";
    std::cout << "  --list-essids          List all ESSIDs\n";
    std::cout << "  --verify               Verify database integrity\n";
    std::cout << "  --vacuum               Optimize database\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -v, --verbose          Verbose output\n";
    std::cout << "  -h, --help             Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " mydb.db --create\n";
    std::cout << "  " << program_name << " mydb.db --import-essid \"MyWiFi\"\n";
    std::cout << "  " << program_name << " mydb.db --import \"MyWiFi\" wordlist.txt\n";
    std::cout << "  " << program_name << " mydb.db --compute \"MyWiFi\"\n";
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    bool create_db = false;
    bool show_stats = false;
    bool list_essids = false;
    bool verify_db = false;
    bool vacuum_db = false;
    std::string import_essid;
    std::string import_wordlist_essid;
    std::string import_wordlist_file;
    std::string compute_essid;
    
    static struct option long_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"create", no_argument, 0, 1000},
        {"import-essid", required_argument, 0, 1001},
        {"import", required_argument, 0, 1002},
        {"compute", required_argument, 0, 1003},
        {"stats", no_argument, 0, 1004},
        {"list-essids", no_argument, 0, 1005},
        {"verify", no_argument, 0, 1006},
        {"vacuum", no_argument, 0, 1007},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "vh", long_options, nullptr)) != -1) {
        switch (c) {
            case 'v':
                verbose = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 1000:
                create_db = true;
                break;
            case 1001:
                import_essid = optarg;
                break;
            case 1002:
                import_wordlist_essid = optarg;
                break;
            case 1003:
                compute_essid = optarg;
                break;
            case 1004:
                show_stats = true;
                break;
            case 1005:
                list_essids = true;
                break;
            case 1006:
                verify_db = true;
                break;
            case 1007:
                vacuum_db = true;
                break;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    if (optind >= argc) {
        std::cerr << "Error: Database path required" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    std::string db_path = argv[optind];
    
    // Handle import command with wordlist file
    if (!import_wordlist_essid.empty()) {
        if (optind + 1 >= argc) {
            std::cerr << "Error: Wordlist file required for import command" << std::endl;
            return 1;
        }
        import_wordlist_file = argv[optind + 1];
    }
    
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "AirLevi-NG Password Database v1.0\n";
    std::cout << "==================================\n";
    
    try {
        Logger::getInstance().setVerbose(verbose);
        db = std::make_unique<PasswordDatabase>();
        
        if (create_db) {
            std::cout << "Creating database: " << db_path << "\n";
            if (!db->create(db_path)) {
                std::cerr << "Failed to create database" << std::endl;
                return 1;
            }
            std::cout << "[+] Database created successfully" << std::endl;
            
        } else {
            if (!db->open(db_path)) {
                std::cerr << "Failed to open database: " << db_path << std::endl;
                return 1;
            }
        }
        
        if (!import_essid.empty()) {
            std::cout << "Importing ESSID: " << import_essid << "\n";
            if (db->importESSID(import_essid)) {
                std::cout << "[+] ESSID imported successfully" << std::endl;
            } else {
                std::cerr << "[-] Failed to import ESSID" << std::endl;
                return 1;
            }
        }
        
        if (!import_wordlist_essid.empty() && !import_wordlist_file.empty()) {
            std::cout << "Importing wordlist for ESSID: " << import_wordlist_essid << "\n";
            std::cout << "Wordlist file: " << import_wordlist_file << "\n";
            
            if (db->importWordlist(import_wordlist_essid, import_wordlist_file)) {
                std::cout << "[+] Wordlist imported successfully" << std::endl;
            } else {
                std::cerr << "[-] Failed to import wordlist" << std::endl;
                return 1;
            }
        }
        
        if (!compute_essid.empty()) {
            std::cout << "Computing PMKs for ESSID: " << compute_essid << "\n";
            
            auto start = std::chrono::high_resolution_clock::now();
            if (db->computePMKs(compute_essid)) {
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
                std::cout << "[+] PMK computation completed in " << duration.count() << " seconds" << std::endl;
            } else {
                std::cerr << "[-] Failed to compute PMKs" << std::endl;
                return 1;
            }
        }
        
        if (show_stats) {
            db->displayStatistics();
        }
        
        if (verify_db) {
            std::cout << "Verifying database integrity...\n";
            if (db->verify()) {
                std::cout << "[+] Database verification passed" << std::endl;
            } else {
                std::cerr << "[-] Database verification failed" << std::endl;
                return 1;
            }
        }
        
        if (vacuum_db) {
            std::cout << "Optimizing database...\n";
            if (db->vacuum()) {
                std::cout << "[+] Database optimized successfully" << std::endl;
            } else {
                std::cerr << "[-] Database optimization failed" << std::endl;
                return 1;
            }
        }
        
        db->close();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
