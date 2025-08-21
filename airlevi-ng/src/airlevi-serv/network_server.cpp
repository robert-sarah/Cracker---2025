#include "airlevi-serv/network_server.h"
#include "common/logger.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

namespace airlevi {

NetworkServer::NetworkServer() 
    : running_(false), server_socket_(-1), port_(0), 
      total_connections_(0), active_connections_(0), packets_sent_(0) {}

NetworkServer::~NetworkServer() {
    stop();
}

bool NetworkServer::start(uint16_t port, const std::string& interface) {
    port_ = port;
    interface_ = interface;
    
    server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_ < 0) {
        Logger::getInstance().log("Failed to create socket", LogLevel::ERROR);
        return false;
    }
    
    int opt = 1;
    setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        Logger::getInstance().log("Failed to bind socket", LogLevel::ERROR);
        close(server_socket_);
        return false;
    }
    
    if (listen(server_socket_, 10) < 0) {
        Logger::getInstance().log("Failed to listen on socket", LogLevel::ERROR);
        close(server_socket_);
        return false;
    }
    
    running_ = true;
    accept_thread_ = std::thread(&NetworkServer::acceptConnections, this);
    
    Logger::getInstance().log("Server started on port " + std::to_string(port), LogLevel::INFO);
    return true;
}

void NetworkServer::stop() {
    if (!running_) return;
    
    running_ = false;
    
    if (server_socket_ >= 0) {
        close(server_socket_);
        server_socket_ = -1;
    }
    
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    
    for (auto& thread : client_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    client_threads_.clear();
    clients_.clear();
}

void NetworkServer::acceptConnections() {
    while (running_) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket_, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (running_) {
                Logger::getInstance().log("Failed to accept connection", LogLevel::ERROR);
            }
            continue;
        }
        
        ClientConnection conn;
        conn.socket_fd = client_socket;
        conn.ip_address = inet_ntoa(client_addr.sin_addr);
        conn.port = ntohs(client_addr.sin_port);
        conn.connected_at = std::chrono::steady_clock::now();
        conn.authenticated = false;
        
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            clients_[client_socket] = conn;
        }
        
        total_connections_++;
        active_connections_++;
        
        client_threads_.emplace_back(&NetworkServer::handleClient, this, client_socket);
        
        Logger::getInstance().log("Client connected: " + conn.ip_address + ":" + std::to_string(conn.port), LogLevel::INFO);
    }
}

void NetworkServer::handleClient(int client_socket) {
    char buffer[4096];
    
    while (running_) {
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            break;
        }
        
        buffer[bytes_received] = '\0';
        std::string message(buffer);
        
        // Handle client commands
        if (message.find("AUTH") == 0) {
            // Simple authentication
            sendToClient(client_socket, "AUTH_OK\n");
            std::lock_guard<std::mutex> lock(clients_mutex_);
            if (clients_.find(client_socket) != clients_.end()) {
                clients_[client_socket].authenticated = true;
            }
        } else if (message.find("FILTER") == 0) {
            std::string filter = message.substr(7);
            setPacketFilter(filter);
            sendToClient(client_socket, "FILTER_SET\n");
        }
    }
    
    removeClient(client_socket);
}

void NetworkServer::removeClient(int client_socket) {
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_.erase(client_socket);
    }
    
    close(client_socket);
    active_connections_--;
}

void NetworkServer::sendToClient(int client_socket, const std::string& data) {
    send(client_socket, data.c_str(), data.length(), 0);
}

void NetworkServer::distributePacket(const uint8_t* packet, int length) {
    if (!matchesFilter(packet, length)) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(clients_mutex_);
    for (auto& [socket, client] : clients_) {
        if (client.authenticated) {
            send(socket, packet, length, MSG_NOSIGNAL);
            packets_sent_++;
        }
    }
}

bool NetworkServer::matchesFilter(const uint8_t* packet, int length) {
    std::lock_guard<std::mutex> lock(filter_mutex_);
    if (packet_filter_.empty()) {
        return true;
    }
    
    // Simple filter matching - can be enhanced
    return true;
}

void NetworkServer::setPacketFilter(const std::string& filter) {
    std::lock_guard<std::mutex> lock(filter_mutex_);
    packet_filter_ = filter;
}

std::vector<ClientConnection> NetworkServer::getConnectedClients() {
    std::vector<ClientConnection> clients;
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    for (const auto& [socket, client] : clients_) {
        clients.push_back(client);
    }
    
    return clients;
}

} // namespace airlevi
