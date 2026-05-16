#include <atomic>
#include <iostream>
#include <thread>
#include <unordered_map>

// term colors

inline const char *green = "\033[38;5;10m";
inline const char *mustard = "\e[0;33m";
inline const char *cyan = "\e[0;36m";
inline const char *red = "\e[0;31m";
inline const char *kuku = "\e[0;35m";
inline const char *norm = "\033[0m";

struct Client_Info {
  bool active = true;
};

void logger(std::atomic<bool> &server_alive,
            std::unordered_map<int, Client_Info> &clients,
            std::atomic<size_t> &live_connections, std::atomic<size_t> &total_connections);
