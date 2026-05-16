#include "../../include/server_logger.h"

void logger(std::atomic<bool> &server_alive,
            std::unordered_map<int, Client_Info> &clients,
            std::mutex &clients_mutex,
            std::atomic<size_t> &live_connections,
            std::atomic<size_t> &total_connections) {

  auto start_time = std::chrono::steady_clock::now();

  while (server_alive) {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::steady_clock::now() - start_time)
                      .count();

    std::cerr << "\033[H";
    std::cerr << "=== MEFS Server Dashboard ===\n";
    std::cerr << "Uptime: " << uptime << "s\n";
    std::cerr << "Total connections: " << total_connections << "\n";
    std::cerr << "Live connections: " << live_connections << "\n";
    std::cerr << "Client FDs: ";
    {
      std::lock_guard<std::mutex> lock(clients_mutex);
      for (auto &kv : clients) {
        std::cerr << kv.first << " ";
      }
    }
    std::cerr << "\n";

    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}
