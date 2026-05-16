#include "../../include/common/encryption_utils.h"
#include <cstring>
#include <sodium/crypto_kx.h>
#include <sodium/utils.h>

int encrypt_stream_buffer(
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES],
    const unsigned char *message, unsigned long long message_len,
    unsigned char *ciphertext, unsigned long long *ciphertext_len) {

  sodium_increment(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  if (crypto_aead_chacha20poly1305_encrypt(ciphertext, ciphertext_len, message,
                                           message_len, NULL, 0, NULL, nonce,
                                           client_tx)) {
    std::cerr << "encryption failed" << std::endl;

    return 1;
  }

  return 0;
}

int server_crypt_gen(int client_sock, unsigned char *server_pk,
                     unsigned char *server_sk, unsigned char *server_rx,
                     unsigned char *server_tx) {

  crypto_kx_keypair(server_pk, server_sk);

  std::cout << std::endl;

  send(client_sock, server_pk, crypto_kx_PUBLICKEYBYTES, MSG_NOSIGNAL);

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];

  if (!recv_fully(client_sock, client_pk, crypto_kx_PUBLICKEYBYTES)) {
    return 2;
  }

  if (crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk,
                                    client_pk) != 0) {
    std::cerr << "imposta client pub key" << std::endl;
    /* Suspicious client public key, bail out */
    return 1;
  }

  std::cerr << "SUCCESSFUL SERVER KEY GENERATION" << std::endl;

  return 0;
}

int client_crypt_gen(int client_sock, unsigned char *client_pk,
                     unsigned char *client_sk, unsigned char *client_rx,
                     unsigned char *client_tx) {

  /* Generate the client's key pair */
  crypto_kx_keypair(client_pk, client_sk);

  std::cout << std::endl;

  send(client_sock, client_pk, crypto_kx_PUBLICKEYBYTES, MSG_NOSIGNAL);

  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];

  if (!recv_fully(client_sock, server_pk, crypto_kx_PUBLICKEYBYTES)) {
    return 2;
  }

  std::cout << std::endl;

  if (crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk,
                                    server_pk) != 0) {
    std::cerr << "BAILED SUS KEYS" << std::endl;
    return 1;
    /* Suspicious server public key, bail out */
  }

  std::cerr << "SUCCESSFUL CLIENT KEY GENERATION" << std::endl;
  return 0;
}
