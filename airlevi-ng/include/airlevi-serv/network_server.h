#ifndef AIRLEVI_NETWORK_SERVER_H
#define AIRLEVI_NETWORK_SERVER_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include "common/types.h"

namespace airlevi {

struct ClientConnection {
    int socket_fd;
    std::string ip_address;
    uint16_t port;
    std::chrono::steady_clock::time_point connected_at;
    bool authenticated;
    std::string username;
};

class NetworkServer {
public:
    NetworkServer();
    ~NetworkServer();

    bool start(uint16_t port, const std::string& interface = "");
    void stop();
    bool isRunning() const { return running_; }
    
    // Client management
    std::vector<ClientConnection> getConnectedClients();
    bool disconnectClient(int client_id);
    void broadcastMessage(const std::string& message);
    
    // Packet distribution
    void distributePacket(const uint8_t* packet, int length);
    void setPacketFilter(const std::string& filter);
    
    // Statistics
    uint64_t getTotalConnections() const { return total_connections_; }
    uint64_t getActiveConnections() const { return active_connections_; }
    uint64_t getPacketsSent() const { return packets_sent_; }
    
private:
    std::atomic<bool> running_;
    int server_socket_;
    uint16_t port_;
    std::string interface_;
    
    std::thread accept_thread_;
    std::vector<std::thread> client_threads_;
    
    std::mutex clients_mutex_;
    std::map<int, ClientConnection> clients_;
    
    std::atomic<uint64_t> total_connections_;
    std::atomic<uint64_t> active_connections_;
    std::atomic<uint64_t> packets_sent_;
    
    std::string packet_filter_;
    std::mutex filter_mutex_;
    
    void acceptConnections();
    void handleClient(int client_socket);
    bool authenticateClient(int client_socket);
    void sendToClient(int client_socket, const std::string& data);
    void removeClient(int client_socket);
    bool matchesFilter(const uint8_t* packet, int length);
};

} // namespace airlevi

#endif // AIRLEVI_NETWORK_SERVER_H
