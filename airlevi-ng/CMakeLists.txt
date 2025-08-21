cmake_minimum_required(VERSION 3.16)
project(airlevi-ng VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3 -march=native")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -DDEBUG")

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${PCAP_INCLUDE_DIRS})

# Source files
set(COMMON_SOURCES
    src/common/packet_parser.cpp
    src/common/crypto_utils.cpp
    src/common/network_interface.cpp
    src/common/logger.cpp
    src/common/config.cpp
    src/common/types.cpp
)

set(AIRLEVI_DUMP_SOURCES
    src/airlevi-dump/main.cpp
    src/airlevi-dump/packet_capture.cpp
    src/airlevi-dump/wifi_scanner.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_CRACK_SOURCES
    src/airlevi-crack/main.cpp
    src/airlevi-crack/wep_crack.cpp
    src/airlevi-crack/wpa_crack.cpp
    src/airlevi-crack/dictionary_attack.cpp
    src/airlevi-crack/brute_force.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_DEAUTH_SOURCES
    src/airlevi-deauth/main.cpp
    src/airlevi-deauth/deauth_attack.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_SUITE_SOURCES
    src/airlevi-suite/main.cpp
    src/airlevi-suite/interactive_menu.cpp
    src/airlevi-suite/statistics.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_REPLAY_SOURCES
    src/airlevi-replay/main.cpp
    src/airlevi-replay/packet_replay.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_FORGE_SOURCES
    src/airlevi-forge/main.cpp
    src/airlevi-forge/packet_forge.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_MONITOR_SOURCES
    src/airlevi-monitor/main.cpp
    src/airlevi-monitor/advanced_monitor.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_BEACON_SOURCES
    src/airlevi-beacon/main.cpp
    src/airlevi-beacon/rogue_ap.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_WPS_SOURCES
    src/airlevi-wps/main.cpp
    src/airlevi-wps/wps_attack.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_PMKID_SOURCES
    src/airlevi-pmkid/main.cpp
    src/airlevi-pmkid/pmkid_attack.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_HANDSHAKE_SOURCES
    src/airlevi-handshake/main.cpp
    src/airlevi-handshake/handshake_capture.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_MON_SOURCES
    src/airlevi-mon/main.cpp
    src/airlevi-mon/interface_manager.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_LIB_SOURCES
    src/airlevi-lib/main.cpp
    src/airlevi-lib/password_database.cpp
    ${COMMON_SOURCES}
)

set(AIRLEVI_SERV_SOURCES
    src/airlevi-serv/main.cpp
    src/airlevi-serv/network_server.cpp
    ${COMMON_SOURCES}
)

# Executables
add_executable(airlevi-dump ${AIRLEVI_DUMP_SOURCES})
add_executable(airlevi-crack ${AIRLEVI_CRACK_SOURCES})
add_executable(airlevi-deauth ${AIRLEVI_DEAUTH_SOURCES})
add_executable(airlevi-suite ${AIRLEVI_SUITE_SOURCES})
add_executable(airlevi-replay ${AIRLEVI_REPLAY_SOURCES})
add_executable(airlevi-forge ${AIRLEVI_FORGE_SOURCES})
add_executable(airlevi-monitor ${AIRLEVI_MONITOR_SOURCES})
add_executable(airlevi-beacon ${AIRLEVI_BEACON_SOURCES})
add_executable(airlevi-wps ${AIRLEVI_WPS_SOURCES})
add_executable(airlevi-pmkid ${AIRLEVI_PMKID_SOURCES})
add_executable(airlevi-handshake ${AIRLEVI_HANDSHAKE_SOURCES})
add_executable(airlevi-mon ${AIRLEVI_MON_SOURCES})
add_executable(airlevi-lib ${AIRLEVI_LIB_SOURCES})
add_executable(airlevi-serv ${AIRLEVI_SERV_SOURCES})

# Link libraries
target_link_libraries(airlevi-dump ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-crack ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-deauth ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-suite ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-replay ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-forge ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-monitor ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-beacon ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-wps ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-pmkid ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-handshake ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-mon ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(airlevi-lib ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto sqlite3)
target_link_libraries(airlevi-serv ${PCAP_LIBRARIES} Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

# Installation
install(TARGETS airlevi-dump airlevi-crack airlevi-deauth airlevi-suite 
                airlevi-replay airlevi-forge airlevi-monitor airlevi-beacon
                airlevi-wps airlevi-pmkid airlevi-handshake airlevi-mon
                airlevi-lib airlevi-serv
        DESTINATION bin)

install(DIRECTORY wordlists/
        DESTINATION share/airlevi-ng/wordlists)
