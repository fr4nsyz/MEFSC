#include "../include/common/SessionEnc.h"
#include "../include/common/encryption_utils.h"
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <string>

class FS_Operator {
  int client_sock;
  std::string user_dir;
  unsigned char server_rx[crypto_kx_SESSIONKEYBYTES];
  unsigned char server_tx[crypto_kx_SESSIONKEYBYTES];
  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

private:
  int init_read(
      int client_sock, char file_name_buf[250],
      unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
      unsigned char salt[crypto_pwhash_SALTBYTES]);

public:
  int receive_notice_of_new_action();

  int read_intent();

  int WTFS_Handler__Server(); // Write To File System Handler

  int RFFS_Handler__Server(); // Read From File System Handler

  void rotate_keys();

  FS_Operator(int client_sock, std::string username,
              unsigned char server_rx[crypto_kx_SESSIONKEYBYTES],
              unsigned char server_tx[crypto_kx_SESSIONKEYBYTES]);
  ;
  ~FS_Operator();
};
