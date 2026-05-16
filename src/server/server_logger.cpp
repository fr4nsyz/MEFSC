#include "../../include/server_logger.h"

void print_conns(std::unordered_map<int, Client_Info> &map) {
  std::cerr << "file descriptors:\n";
  for (const auto &pair : map) {
    std::cerr << pair.first << "    ";
  }
  std::cerr << "\n";
}

void logger(std::atomic<bool> &server_alive,
            std::unordered_map<int, Client_Info> &clients,
            std::atomic<size_t> &live_connections, std::atomic<size_t> &total_connections) {
  while (server_alive) {

    std::cerr << "--------------------------------\n";

    std::cerr << green << "TOTAL CONNECTIONS     => " << live_connections << norm
              << "\n";
    std::cerr << mustard << "CURRENT CONNECTIONS => " << live_connections
              << norm << "\n";
    std::cerr << cyan << "CLIENTS                => " << clients.size() << norm
              << "\n";
    print_conns(clients);
    std::this_thread::sleep_for(std::chrono::seconds(2));
  }
}
