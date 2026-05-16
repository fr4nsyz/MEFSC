#include "../../include/authed_entry.h"
#include "../../include/common/SessionEnc.h"
#include "../../include/common/constants.h"
#include "../../include/common/encryption_utils.h"
#include <cassert>
#include <iostream>
#include <netinet/in.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/utils.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

// intentions
const int ACK_SUC = 0;
const int ACK_FAIL = -1;

const int CONFUSION = -420;
const int READ_FROM_FILESYSTEM = 1;
const int WRITE_TO_FILESYSTEM = 2;

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
                        password.length() + 1, client_tx, original_nonce);

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
                 std::string &password) {

  std::string file_name;
  std::cout << "enter file name to grab from server (ends in .enc extension): ";

  std::cin >> file_name;

  std::cout << "\n";

  SessionEncWrapper file_name_wrapper = SessionEncWrapper(
      reinterpret_cast<unsigned char *>(file_name.data()),
      file_name.length() + 1, CA->get_client_tx(), RA.get_nonce());

  file_name_wrapper.send_all(client_sock);

  file_name.resize(file_name.length() -
                   4); // REMOVE LAST 4 BECAUSE THIS IS .enc
  std::ofstream file(file_name, std::ios::binary);

  RA.decrypt_and_read_from_server(file, password);

  return 0;
}

int WTFS_Handler(Comms_Agent *CA, Sender_Agent &SA, int client_sock,
                 std::string &password) {
  std::cout << "enter file name to send to server:\n";

  std::string file_name;

  get_stuff(file_name);

  if (SA.encrypt_and_send_to_server(file_name, password) != 0) {
    std::cerr << "error in encrypt_and_send_to_server\n";
    return 1;
  }

  return 0;
}

int LFFS_Handler(Comms_Agent *CA, int client_sock) {
  int file_count;
  unsigned long long decrypted_len;

  SessionEncWrapper count_wrap = SessionEncWrapper(client_sock);
  if (count_wrap.is_corrupted()) return 1;
  if (count_wrap.unwrap(CA->get_client_rx(), sizeof(file_count),
                        reinterpret_cast<unsigned char *>(&file_count),
                        &decrypted_len))
    return 1;

  std::cout << "\n--- Stored Files (" << file_count << ") ---\n";
  for (int i = 0; i < file_count; ++i) {
    SessionEncWrapper name_wrap = SessionEncWrapper(client_sock);
    if (name_wrap.is_corrupted()) return 1;

    unsigned char filename[MAX_FILE_NAME_LENGTH] = {0};
    if (name_wrap.unwrap(CA->get_client_rx(), MAX_FILE_NAME_LENGTH - 1, filename,
                         &decrypted_len))
      return 1;

    std::cout << "  " << reinterpret_cast<char *>(filename) << "\n";
  }
  std::cout << "--------------------------\n";
  return 0;
}

int DFFS_Handler(Comms_Agent *CA, int client_sock) {
  std::string file_name;
  std::cout << "enter file name to delete (ends in .enc): ";
  std::cin >> file_name;

  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  SessionEncWrapper name_wrap = SessionEncWrapper(
      reinterpret_cast<unsigned char *>(file_name.data()),
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

int authed_comms(
    int client_sock, unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
    unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], std::string &username,
    std::string &password,
    unsigned char original_nonce[crypto_aead_chacha20poly1305_NPUBBYTES]) {

  Comms_Agent CA = Comms_Agent(client_tx, client_rx, client_sock);
  /// loop from here to the end of the function depending on what the user
  /// syas they want to do. aka if they wish to complete another action, don't
  /// deconstruct the CA, save it for future. REMEMBER in creating CA you
  /// destroyed the original keys. you have no way of communication without
  /// them.

  char perform_next = 'n';

  do {
    if (CA.notify_server_of_action(NEW_ACTION, original_nonce)) {
      std::cerr << "couldn't notify server of new user action\n";
      break;
    };

    std::cout << "enter your intention (1 == read || 2 == write || 3 == list files || 4 == delete file)" << std::endl;

    int intention = CONFUSION;

    get_stuff(intention);

    // when we eventually make the program capable of handling multiple files
    // concurrently, we will need to spawn threads that create their own SA or
    // RA
    Sender_Agent SA = Sender_Agent(&CA, password);
    Receiver_Agent RA = Receiver_Agent(&CA);

    if (intention == CONFUSION) {
      return -1;
    }

    if (intention == READ_FROM_FILESYSTEM) {
      send_intention(CA.get_client_tx(), client_sock, intention,
                     original_nonce);
      if (RFFS_Handler(&CA, RA, client_sock, password)) {
        std::cerr << "failed reading from file system\n";
      }
    } else if (intention == WRITE_TO_FILESYSTEM) {
      send_intention(CA.get_client_tx(), client_sock, intention,
                     original_nonce);
      if (WTFS_Handler(&CA, SA, client_sock, password)) {
        std::cerr << "failed writing to file system\n";
      };
    } else if (intention == LIST_FILES) {
      send_intention(CA.get_client_tx(), client_sock, intention,
                     original_nonce);
      if (LFFS_Handler(&CA, client_sock)) {
        std::cerr << "failed listing files\n";
      }
    } else if (intention == DELETE_FILE) {
      send_intention(CA.get_client_tx(), client_sock, intention,
                     original_nonce);
      if (DFFS_Handler(&CA, client_sock)) {
        std::cerr << "failed deleting file\n";
      }
    } else {
      std::cerr << "invalid intention\n";
    }

    std::cout << "perform another action? " << std::flush;
    std::cin >> perform_next;
  } while (perform_next == 'y' || perform_next == 'Y');

  CA.notify_server_of_action(NO_ACTION, original_nonce);

  // already memzeroed the username during send_credentials
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
