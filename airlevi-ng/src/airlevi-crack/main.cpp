#include <iostream>
#include <signal.h>
#include <getopt.h>
#include <thread>
#include <chrono>
#include "airlevi-crack/wep_crack.h"
#include "airlevi-crack/wpa_crack.h"
#include "airlevi-crack/dictionary_attack.h"
#include "airlevi-crack/brute_force.h"
#include "common/logger.h"
#include "common/config.h"

using namespace airlevi;

static bool running = true;

void signalHandler(int signal) {
    std::cout << "\n[!] Received signal " << signal << ", shutting down..." << std::endl;
    running = false;
}

void printUsage(const char* program_name) {
    std::cout << "AirLevi-NG Password Cracking Tool v1.0\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -f, --file FILE          Capture file to crack\n";
    std::cout << "  -w, --wordlist FILE      Wordlist file for dictionary attack\n";
    std::cout << "  -b, --bssid BSSID        Target BSSID\n";
    std::cout << "  -e, --essid ESSID        Target ESSID\n";
    std::cout << "  -t, --type TYPE          Attack type (wep, wpa, wpa2)\n";
    std::cout << "  -j, --threads NUM        Number of threads (default: CPU cores)\n";
    std::cout << "  -v, --verbose            Verbose output\n";
    std::cout << "  -h, --help               Show this help\n";
    std::cout << "  --brute-force            Enable brute force attack\n";
    std::cout << "  --min-length NUM         Minimum password length for brute force\n";
    std::cout << "  --max-length NUM         Maximum password length for brute force\n";
    std::cout << "  --charset CHARSET        Character set for brute force\n";
    std::cout << "\nAttack Types:\n";
    std::cout << "  wep                      WEP key recovery\n";
    std::cout << "  wpa                      WPA/WPA2 dictionary attack\n";
    std::cout << "  wpa2                     WPA2 dictionary attack\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " -f capture.cap -t wep\n";
    std::cout << "  " << program_name << " -f capture.cap -t wpa -w wordlist.txt\n";
    std::cout << "  " << program_name << " -f capture.cap -t wpa --brute-force --min-length 8\n";
}

int main(int argc, char* argv[]) {
    Config config;
    std::string attack_type = "wpa";
    bool brute_force = false;
    int min_length = 8;
    int max_length = 12;
    std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int num_threads = std::thread::hardware_concurrency();
    
    // Default values
    config.verbose = false;
    
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"wordlist", required_argument, 0, 'w'},
        {"bssid", required_argument, 0, 'b'},
        {"essid", required_argument, 0, 'e'},
        {"type", required_argument, 0, 't'},
        {"threads", required_argument, 0, 'j'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"brute-force", no_argument, 0, 1000},
        {"min-length", required_argument, 0, 1001},
        {"max-length", required_argument, 0, 1002},
        {"charset", required_argument, 0, 1003},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "f:w:b:e:t:j:vh", long_options, nullptr)) != -1) {
        switch (c) {
            case 'f':
                config.output_file = optarg; // Using output_file as input file
                break;
            case 'w':
                config.wordlist_file = optarg;
                break;
            case 'b':
                config.target_bssid = optarg;
                break;
            case 'e':
                config.target_essid = optarg;
                break;
            case 't':
                attack_type = optarg;
                break;
            case 'j':
                num_threads = std::atoi(optarg);
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 1000:
                brute_force = true;
                break;
            case 1001:
                min_length = std::atoi(optarg);
                break;
            case 1002:
                max_length = std::atoi(optarg);
                break;
            case 1003:
                charset = optarg;
                break;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    if (config.output_file.empty()) {
        std::cerr << "Error: Capture file is required (-f option)" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "AirLevi-NG Password Cracking v1.0\n";
    std::cout << "==================================\n";
    
    try {
        // Initialize logger
        Logger::getInstance().setVerbose(config.verbose);
        
        std::cout << "Capture file: " << config.output_file << std::endl;
        std::cout << "Attack type: " << attack_type << std::endl;
        std::cout << "Threads: " << num_threads << std::endl;
        
        if (!config.target_bssid.empty()) {
            std::cout << "Target BSSID: " << config.target_bssid << std::endl;
        }
        
        if (!config.target_essid.empty()) {
            std::cout << "Target ESSID: " << config.target_essid << std::endl;
        }
        
        std::cout << "\nStarting attack... Press Ctrl+C to stop\n" << std::endl;
        
        bool success = false;
        std::string found_password;
        
        if (attack_type == "wep") {
            WEPCrack wep_cracker(config);
            success = wep_cracker.crack(found_password);
        } else if (attack_type == "wpa" || attack_type == "wpa2") {
            if (brute_force) {
                BruteForce brute_forcer(config, num_threads);
                brute_forcer.setCharset(charset);
                brute_forcer.setLengthRange(min_length, max_length);
                success = brute_forcer.crack(found_password);
            } else if (!config.wordlist_file.empty()) {
                DictionaryAttack dict_attack(config, num_threads);
                success = dict_attack.crack(found_password);
            } else {
                WPACrack wpa_cracker(config);
                success = wpa_cracker.crack(found_password);
            }
        } else {
            std::cerr << "Error: Unknown attack type '" << attack_type << "'" << std::endl;
            return 1;
        }
        
        if (success) {
            std::cout << "\n[+] SUCCESS! Password found: " << found_password << std::endl;
        } else {
            std::cout << "\n[-] Attack failed. Password not found." << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
