#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <thread>
#include <unordered_map>

struct Client_Info {
  bool active = true;
};

void logger(std::atomic<bool> &server_alive,
            std::unordered_map<int, Client_Info> &clients,
            std::mutex &clients_mutex,
            std::atomic<size_t> &live_connections,
            std::atomic<size_t> &total_connections);
