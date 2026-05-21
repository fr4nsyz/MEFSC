#include "../../include/authed_entry.h"
#include "../../include/common/SessionEnc.h"
#include "../../include/common/constants.h"
#include "../../include/common/encryption_utils.h"
#include "../../include/tui_menu.h"
#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/utils.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

void disable_echo() {
  termios oldt;
  tcgetattr(STDIN_FILENO, &oldt);
  termios newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
}

void enable_echo() {
  termios oldt;
  tcgetattr(STDIN_FILENO, &oldt);
  oldt.c_lflag |= ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

template <typename T> void get_stuff(T &stuff_holder) {
  while (!(std::cin >> stuff_holder)) {
    std::cin.clear();  // clear error flags
    std::cin.ignore(); // ignore rest of line
    std::cerr << "Invalid input, please try again (failed in get_stuff): ";
  }
}

int send_credentials(
    int client_sock, unsigned char *client_tx, std::string &username,
    std::string &password,
    unsigned char original_nonce[crypto_aead_chacha20poly1305_NPUBBYTES]) {

  std::cout << "enter username: " << std::flush;
  get_stuff(username);
  std::cout << "enter password: " << std::flush;
  disable_echo();
  get_stuff(password);
  std::cout << "\n";
  enable_echo();
  // encrypt the username and password and send it over to the server and wait
  //
  // for a response

  SessionEncWrapper username_wrapper =
      SessionEncWrapper(reinterpret_cast<unsigned char *>(username.data()),
                        username.length() + 1, client_tx, original_nonce);

  username_wrapper.send_all(client_sock);

  SessionEncWrapper password_wrapper =
      SessionEncWrapper(reinterpret_cast<unsigned char *>(password.data()),
                        password.length(), client_tx, original_nonce);

  password_wrapper.send_all(client_sock);

  int auth_stat = -1;

  recv(client_sock, &auth_stat, sizeof(auth_stat), 0);

  if (auth_stat == -1) {
    std::cout << "you sir/madam are not authenticated." << std::endl;
    exit(-1);
  }

  sodium_memzero(username.data(), username.size());

  return 0;
}

int send_intention(
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES], int client_sock,
    int intent,
    unsigned char original_nonce[crypto_aead_chacha20poly1305_NPUBBYTES]) {

  SessionEncWrapper intent_wrap =
      SessionEncWrapper(reinterpret_cast<unsigned char *>(&intent),
                        sizeof(intent), client_tx, original_nonce);

  intent_wrap.send_all(client_sock);

  return 0;
}

int RFFS_Handler(Comms_Agent *CA, Receiver_Agent &RA, int client_sock,
                  std::string &password, const std::string &file_name) {

    SessionEncWrapper file_name_wrapper = SessionEncWrapper(
        reinterpret_cast<unsigned char *>(const_cast<char *>(file_name.data())),
        file_name.length() + 1, CA->get_client_tx(), RA.get_nonce());

    file_name_wrapper.send_all(client_sock);

    std::string out_name = file_name;
    out_name.resize(out_name.length() - 4);
    std::ofstream file(out_name, std::ios::binary);

    RA.decrypt_and_read_from_server(file, password);

    return 0;
}

int WTFS_Handler(Comms_Agent *CA, Sender_Agent &SA, int client_sock,
                  std::string &password, const std::string &file_name) {
    std::string fn = file_name;
    if (SA.encrypt_and_send_to_server(fn, password) != 0) {
        std::cerr << "error in encrypt_and_send_to_server\n";
        return 1;
    }

    return 0;
}

int LFFS_Handler(Comms_Agent *CA, int client_sock,
                  std::vector<std::string> &out_files) {
    int file_count;
    unsigned long long decrypted_len;

    SessionEncWrapper count_wrap = SessionEncWrapper(client_sock);
    if (count_wrap.is_corrupted()) return 1;
    if (count_wrap.unwrap(CA->get_client_rx(), sizeof(file_count),
                          reinterpret_cast<unsigned char *>(&file_count),
                          &decrypted_len))
        return 1;

    std::ostringstream oss;
    oss << "--- Stored Files (" << file_count << ") ---";
    out_files.push_back(oss.str());
    for (int i = 0; i < file_count; ++i) {
        SessionEncWrapper name_wrap = SessionEncWrapper(client_sock);
        if (name_wrap.is_corrupted()) return 1;

        unsigned char filename[MAX_FILE_NAME_LENGTH] = {0};
        if (name_wrap.unwrap(CA->get_client_rx(), MAX_FILE_NAME_LENGTH - 1,
                             filename, &decrypted_len))
            return 1;

        out_files.push_back(
            std::string("  ") + reinterpret_cast<char *>(filename));
    }
    out_files.push_back("--------------------------");
    return 0;
}

int DFFS_Handler(Comms_Agent *CA, int client_sock,
                  const std::string &file_name) {

  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

SessionEncWrapper name_wrap = SessionEncWrapper(
        reinterpret_cast<unsigned char *>(const_cast<char *>(file_name.data())),
        file_name.length() + 1, CA->get_client_tx(), nonce);
  name_wrap.send_all(client_sock);

  int result;
  unsigned long long decrypted_len;
  SessionEncWrapper result_wrap = SessionEncWrapper(client_sock);
  if (result_wrap.is_corrupted()) return 1;
  if (result_wrap.unwrap(CA->get_client_rx(), sizeof(result),
                         reinterpret_cast<unsigned char *>(&result),
                         &decrypted_len))
    return 1;

  if (result == ACK_SUC) {
    std::cout << "deleted successfully\n";
  } else {
    std::cout << "failed to delete (file may not exist)\n";
  }
  return 0;
}

static std::string capture_call(std::function<void()> fn) {
    std::stringstream ss;
    auto old_cout = std::cout.rdbuf(ss.rdbuf());
    auto old_cerr = std::cerr.rdbuf(ss.rdbuf());
    fn();
    std::cout.rdbuf(old_cout);
    std::cerr.rdbuf(old_cerr);
    return ss.str();
}

static void split_lines(const std::string &out,
                        std::vector<std::string> &dest) {
    if (out.empty()) return;
    std::string line;
    std::istringstream lines(out);
    while (std::getline(lines, line)) {
        if (!line.empty()) dest.push_back(line);
    }
}

int authed_comms(
    int client_sock, unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
    unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], std::string &username,
    std::string &password,
    unsigned char original_nonce[crypto_aead_chacha20poly1305_NPUBBYTES]) {

    Comms_Agent CA = Comms_Agent(client_tx, client_rx, client_sock);
    std::vector<std::string> output_log;
    std::vector<std::string> known_files;

    do {
        MenuResult result = show_menu(output_log, known_files);
        Action action = result.action;

        if (action == Action::CONFUSION) break;

        if (CA.notify_server_of_action(NEW_ACTION, original_nonce)) {
            output_log.emplace_back("couldn't notify server of new user action");
            break;
        };

        send_intention(CA.get_client_tx(), client_sock, static_cast<int>(action),
                       original_nonce);

        Sender_Agent SA = Sender_Agent(&CA, password);
        Receiver_Agent RA = Receiver_Agent(&CA);

        output_log.clear();

        switch (action) {
        case Action::READ_FROM_FILESYSTEM: {
            std::string fn = result.input;
            if (fn.empty()) {
                output_log.emplace_back("no file name provided");
                break;
            }
            auto out = capture_call([&] {
                if (RFFS_Handler(&CA, RA, client_sock, password, fn))
                    std::cout << "failed reading from file system\n";
            });
            split_lines(out, output_log);
            break;
        }
        case Action::WRITE_TO_FILESYSTEM: {
            std::string fn = result.input;
            if (fn.empty()) {
                output_log.emplace_back("no file name provided");
                break;
            }
            auto out = capture_call([&] {
                if (WTFS_Handler(&CA, SA, client_sock, password, fn))
                    std::cout << "failed writing to file system\n";
            });
            split_lines(out, output_log);
            if (out.find("error") == std::string::npos) {
                known_files.push_back(fn + ".enc");
            }
            break;
        }
        case Action::LIST_FILES: {
            std::vector<std::string> files;
            if (LFFS_Handler(&CA, client_sock, files)) {
                output_log.emplace_back("failed listing files");
            } else {
                output_log = files;
                known_files.clear();
                for (auto &f : files) {
                    if (f.find("---") == std::string::npos &&
                        f.find("----") == std::string::npos &&
                        !f.empty()) {
                        size_t pos = f.find_first_not_of(" \t");
                        if (pos != std::string::npos)
                            known_files.push_back(f.substr(pos));
                    }
                }
            }
            break;
        }
        case Action::DELETE_FILE: {
            std::string fn = result.input;
            if (fn.empty()) {
                output_log.emplace_back("no file name provided");
                break;
            }
            auto out = capture_call([&] {
                if (DFFS_Handler(&CA, client_sock, fn))
                    std::cout << "failed deleting file\n";
            });
            split_lines(out, output_log);
            known_files.erase(
                std::remove(known_files.begin(), known_files.end(), fn),
                known_files.end());
            break;
        }
        default:
            output_log.emplace_back("invalid intention");
            break;
        }
    } while (true);

    CA.notify_server_of_action(NO_ACTION, original_nonce);

    sodium_memzero(password.data(), password.size());
    return 0;
}

int main() {

  int client_sock = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(8080);
  server_address.sin_addr.s_addr = INADDR_ANY;

  int conn_stat = connect(client_sock, (struct sockaddr *)&server_address,
                          sizeof(server_address));

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES],
      client_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
      client_tx[crypto_kx_SESSIONKEYBYTES];

  if (client_crypt_gen(client_sock, client_pk, client_sk, client_rx,
                       client_tx)) {
    std::cerr << "error generating keys :(" << std::endl;
    return 1;
  }

  std::cerr << std::endl;

  std::string username;
  std::string password;

  unsigned char original_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

  randombytes_buf(original_nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  if (send_credentials(client_sock, client_tx, username, password,
                       original_nonce)) {
    std::cerr << "exiting login_handle" << std::endl;
    return 2;
  }

  authed_comms(client_sock, client_tx, client_rx, username, password,
               original_nonce);

} // this will contain the rest of the follwoing after
// no signup, this is only done by the admin of the server who can add
// themselves to the sql db
