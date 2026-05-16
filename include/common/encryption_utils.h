#include <cerrno>
#include <cstdint>
#include <iostream>
#include <netinet/in.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <sys/socket.h>

#ifndef MFSC_ENCRYPTION_UTILS
#define MFSC_ENCRYPTION_UTILS

bool recv_fully(int fd, void *buf, size_t len);

int encrypt_stream_buffer(
    unsigned char tx[crypto_kx_SESSIONKEYBYTES],
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES],
    const unsigned char *message, unsigned long long message_len,
    unsigned char *ciphertext, unsigned long long *ciphertext_len);

int server_crypt_gen(int client_sock, unsigned char *server_pk,
                     unsigned char *server_sk, unsigned char *server_rx,
                     unsigned char *server_tx);

int client_crypt_gen(int client_sock, unsigned char *client_pk,
                     unsigned char *client_sk, unsigned char *client_rx,
                     unsigned char *client_tx);

#endif
