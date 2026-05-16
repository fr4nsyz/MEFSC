#include "../../include/auth.h"
#include "../../include/common/constants.h"
#include "../../include/read_write_handlers.h"
#include "../../include/server_logger.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <queue>
#include <signal.h>

const int ACK_SUC = 0;
const int ACK_FAIL = -1;

const int CONFUSION = -420;
const int READ_FROM_FILESYSTEM = 1;
const int WRITE_TO_FILESYSTEM = 2;

std::atomic<size_t> total_connections{0};
std::atomic<size_t> live_connections{0};
std::unordered_map<int, Client_Info> clients;
std::mutex clients_mutex;

const int POOL_SIZE = 8;
std::queue<int> client_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;

std::atomic<bool> server_alive{true};
int server_sock_fd = -1;

void handle_signal(int) {
  server_alive = false;
  queue_cv.notify_all();
  if (server_sock_fd >= 0) shutdown(server_sock_fd, SHUT_RDWR);
}

void worker(sqlite3 *DB, std::atomic<bool> &server_alive);

void clean_all(std::thread &log_thread, std::thread &kill_server_listener,
               std::vector<std::thread> &pool) {
  std::cerr << "starting clean_all\n";

  for (auto &t : pool) {
    if (t.joinable()) t.join();
  }

  if (log_thread.joinable()) {
    log_thread.join();
    std::cerr << "completed log_thread\n";
  }
  if (kill_server_listener.joinable()) {
    kill_server_listener.join();
    std::cerr << "completed kill_server_listener\n";
  }
}

int verify_credentials(sqlite3 *DB, std::string &username, int client_sock,
                       unsigned char *server_rx) {

  unsigned char decrypted_username[FILE_ENCRYPTED_CHUNK_SIZE];
  unsigned char decrypted_password[FILE_ENCRYPTED_CHUNK_SIZE];

  unsigned long long decrypted_username_len;
  unsigned long long decrypted_password_len;

  SessionEncWrapper username_wrapper = SessionEncWrapper(client_sock);
  username_wrapper.unwrap(server_rx, FILE_ENCRYPTED_CHUNK_SIZE,
                          decrypted_username, &decrypted_username_len);

  username = reinterpret_cast<char *>(decrypted_username);
  SessionEncWrapper password_wrapper = SessionEncWrapper(client_sock);
  password_wrapper.unwrap(server_rx, FILE_ENCRYPTED_CHUNK_SIZE,
                          decrypted_password, &decrypted_password_len);

  if (login(DB, reinterpret_cast<char *>(decrypted_username),
            decrypted_username_len,
            reinterpret_cast<char *>(decrypted_password),
            decrypted_password_len)) { // login implicitly zeroes out my
                                       // decrypted_username and
                                       // decrypted_password with sodium_memzero
    std::cerr << "returned 1 from login\n";
    return 1;
  }

  std::cerr << "made past login\n";

  return 0;
}

void handle_conn(sqlite3 *DB, int client_sock) {

  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES],
      server_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char server_rx[crypto_kx_SESSIONKEYBYTES],
      server_tx[crypto_kx_SESSIONKEYBYTES];

  if (server_crypt_gen(client_sock, server_pk, server_sk, server_rx,
                       server_tx)) {
    std::cerr << "couldn't gen keys :c" << std::endl;
    return;
  }

  // make sure the last character the 4095th index is not overwritten
  // cuz this is the null pointer for you cstring
  std::string username;

  if (verify_credentials(DB, username, client_sock, server_rx)) {
    std::cerr << "couldn't verify creds, ignoring";
    send(client_sock, &ACK_FAIL, sizeof(int), MSG_NOSIGNAL);
    --live_connections;
    return;
  } else {
    send(client_sock, &ACK_SUC, sizeof(int), MSG_NOSIGNAL); // successful login
  }

  FS_Operator OP = FS_Operator(client_sock, username, server_rx,
                               server_tx); // creates it's own nonce within

  bool perform_next = false;

  do {

    std::cerr << "asking for notice of new action\n";
    if (OP.receive_notice_of_new_action()) {
      std::cerr << "did not receive a notice of new action\n";
      perform_next = false;
      break;
    } else {
      perform_next = true;
    }

    int intent = OP.read_intent();

    if (intent == INVALID_READ_INTENT) {
      continue;
    }

    if (intent == READ_FROM_FILESYSTEM) {
      OP.RFFS_Handler__Server();
      std::cerr << "after RFFS_Handler\n";
    } else if (intent == WRITE_TO_FILESYSTEM) {
      OP.WTFS_Handler__Server();
      std::cerr << "after WTFS_Handler\n";
    } else if (intent == LIST_FILES) {
      OP.LFFS_Handler__Server();
      std::cerr << "after LFFS_Handler\n";
    } else if (intent == DELETE_FILE) {
      OP.DFFS_Handler__Server();
      std::cerr << "after DFFS_Handler\n";
    } else {
      std::cerr << "invalid intention\n";
    }
  } while (perform_next);

  {
    std::lock_guard<std::mutex> lock(clients_mutex);
    clients.erase(client_sock);
  }
  close(client_sock);
  --live_connections;
}

void kill_server(std::atomic<bool> &server_alive, int server_sock_fd) {
  std::cout << red << "kill the server by typing (q)\n" << norm;
  char switch_char;
  if (std::cin >> switch_char && switch_char == 'q') {
    server_alive = false;
    shutdown(server_sock_fd, SHUT_RDWR);
  }
}

void worker(sqlite3 *DB, std::atomic<bool> &server_alive) {
  while (server_alive) {
    int client_sock;
    {
      std::unique_lock<std::mutex> lock(queue_mutex);
      queue_cv.wait(lock, [&] {
        return !client_queue.empty() || !server_alive;
      });
      if (!server_alive) return;
      client_sock = client_queue.front();
      client_queue.pop();
    }
    handle_conn(DB, client_sock);
  }
}

int main() {

  sqlite3 *DB;

  signal(SIGTERM, handle_signal);
  signal(SIGINT, handle_signal);

  if (initialize_server(&DB)) {
    std::cerr << "couldn't open db" << std::endl;
    return 1;
  }

  server_sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (server_sock_fd == -1) {
    std::cout << "Failed to create socket descriptor. " << strerror(errno)
              << "\n";
    return 1;
  } else {
    std::cout << "success making server_sock_fd\n";
  }
  sockaddr_in server_address;

  server_address.sin_family = AF_INET;

  server_address.sin_port = htons(8080);

  server_address.sin_addr.s_addr = INADDR_ANY; // 127.0.0.1
  std::cout << "starting bind\n";

  int opt = 1;
  if (setsockopt(server_sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) <
      0) {
    std::cerr << "setsockopt failed: " << strerror(errno) << std::endl;
    close(server_sock_fd);
    return 1;
  }

  int bind_stat = bind(server_sock_fd, (struct sockaddr *)&server_address,
                       sizeof(server_address));

  if (bind_stat == -1) {
    std::cout << "Failed to bind socket. " << strerror(errno) << std::endl;
    close(server_sock_fd);
    return 1;
  }

  if (listen(server_sock_fd, 5) < 0) {
    std::cout << "server could not listen" << std::endl;
    close(server_sock_fd);
  }

  std::cout << "accepting\n";

  std::thread kill_server_listener =
      std::thread(kill_server, std::ref(server_alive), server_sock_fd);

  std::thread log_thread =
      std::thread(logger, std::ref(server_alive), std::ref(clients),
                  std::ref(live_connections), std::ref(total_connections));

  std::vector<std::thread> pool;
  for (int i = 0; i < POOL_SIZE; ++i) {
    pool.emplace_back(worker, DB, std::ref(server_alive));
  }

  while (server_alive) {

    int client_sock = accept(server_sock_fd, nullptr, nullptr);

    if (server_alive == false) {
      close(client_sock);
      break;
    }

    if (client_sock < 0) {
      std::cerr << "Failed to accept connection" << std::endl;
      continue;
    }

    std::cout << "loopy" << std::endl;

    {
      std::lock_guard<std::mutex> client_lock(clients_mutex);
      clients[client_sock] = Client_Info{};
    }

    {
      std::lock_guard<std::mutex> lock(queue_mutex);
      client_queue.push(client_sock);
    }
    queue_cv.notify_one();

    ++total_connections;
    ++live_connections;
  }

  std::cerr << "stopped accepting clients\n";

  queue_cv.notify_all();
  clean_all(log_thread, kill_server_listener, pool);
  sqlite3_close(DB);
}
