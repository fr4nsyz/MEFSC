#include "./constants.h"
#include "encryption_utils.h"
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/randombytes.h>

#ifndef MFSC_SESSION_ENC
#define MFSC_SESSION_ENC

enum wrap_types { READER, SENDER };

class SessionEncWrapper {
  // data under two layers of encryption. first by file encryption means, and
  // the next by session
  bool corrupted = true;
  unsigned char session_encrypted_data[stream_chunk_size];
  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  unsigned long long session_encrypted_data_length;
  int enc_wrap_type;

public:
  unsigned long long get_data_length();

  SessionEncWrapper(int client_sock); // for readers
  SessionEncWrapper(
      const unsigned char *data, unsigned long long data_length,
      unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
      unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES]);
  // for writers
  // both of these constructors will use the encrypt_stream_buffer function in
  // encryption_utils.
  ~SessionEncWrapper(); // zeroes out it's array
  int unwrap(unsigned char rx[crypto_kx_SESSIONKEYBYTES],
             unsigned long long decrypted_data_capacity,
             unsigned char *decrypted_data,
             unsigned long long *decrypted_data_len); // decrypts and
                                                      // returns another
                                                      // type, EncWrapper
  int send_data_length(int client_sock);
  int send_nonce(int client_sock);
  int send_data(int client_sock);
  int send_all(int client_sock);

  bool is_corrupted();
};

#endif
