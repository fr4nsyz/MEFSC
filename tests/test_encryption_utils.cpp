#include "../include/common/encryption_utils.h"
#include <cstring>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

TEST(EncryptionUtilsTest, EncryptStreamBufferRoundTrip) {
  unsigned char key[crypto_kx_SESSIONKEYBYTES];
  unsigned char pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char sk[crypto_kx_SECRETKEYBYTES];
  crypto_kx_keypair(pk, sk);

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
  crypto_kx_keypair(client_pk, client_sk);

  unsigned char rx[crypto_kx_SESSIONKEYBYTES];
  unsigned char tx[crypto_kx_SESSIONKEYBYTES];
  (void)crypto_kx_server_session_keys(rx, tx, pk, sk, client_pk);

  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  const char *msg = "encrypt me please!";
  unsigned long long msg_len = std::strlen(msg) + 1;

  unsigned char ciphertext[1024];
  unsigned long long ciphertext_len;
  ASSERT_EQ(encrypt_stream_buffer(tx, nonce,
                                  reinterpret_cast<const unsigned char *>(msg),
                                  msg_len, ciphertext, &ciphertext_len), 0);
  EXPECT_GT(ciphertext_len, msg_len);

  unsigned char decrypted[1024];
  unsigned long long decrypted_len;

  unsigned char saved_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  std::memcpy(saved_nonce, nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  ASSERT_EQ(crypto_aead_chacha20poly1305_decrypt(
                decrypted, &decrypted_len, nullptr, ciphertext, ciphertext_len,
                nullptr, 0, saved_nonce, tx),
            0);
  EXPECT_STREQ(reinterpret_cast<char *>(decrypted), msg);
}

TEST(EncryptionUtilsTest, NonceAdvancesOnEncrypt) {
  unsigned char key[crypto_kx_SESSIONKEYBYTES];
  unsigned char pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char sk[crypto_kx_SECRETKEYBYTES];
  crypto_kx_keypair(pk, sk);
  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
  crypto_kx_keypair(client_pk, client_sk);
  unsigned char rx[crypto_kx_SESSIONKEYBYTES];
  unsigned char tx[crypto_kx_SESSIONKEYBYTES];
  (void)crypto_kx_server_session_keys(rx, tx, pk, sk, client_pk);

  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
  unsigned char nonce_copy[crypto_aead_chacha20poly1305_NPUBBYTES];
  std::memcpy(nonce_copy, nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  unsigned char ciphertext[1024];
  unsigned long long ciphertext_len;
  encrypt_stream_buffer(tx, nonce,
                        reinterpret_cast<const unsigned char *>("x"), 2,
                        ciphertext, &ciphertext_len);

  EXPECT_NE(std::memcmp(nonce_copy, nonce,
                        crypto_aead_chacha20poly1305_NPUBBYTES), 0);
}

TEST(EncryptionUtilsTest, RecvFullyRoundTrip) {
  int fds[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

  const char *test_data = "recv_fully test data!";
  size_t len = std::strlen(test_data) + 1;
  ASSERT_EQ(send(fds[0], test_data, len, MSG_NOSIGNAL), (ssize_t)len);

  char buf[256] = {};
  ASSERT_TRUE(recv_fully(fds[1], buf, len));
  EXPECT_STREQ(buf, test_data);

  close(fds[0]);
  close(fds[1]);
}

TEST(EncryptionUtilsTest, RecvFullyPartialDelivery) {
  int fds[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

  const char *msg = "hello from partial!";
  size_t len = std::strlen(msg) + 1;
  size_t half = len / 2;

  send(fds[0], msg, half, MSG_NOSIGNAL);
  usleep(1000);
  send(fds[0], msg + half, len - half, MSG_NOSIGNAL);

  char buf[256] = {};
  ASSERT_TRUE(recv_fully(fds[1], buf, len));
  EXPECT_STREQ(buf, msg);

  close(fds[0]);
  close(fds[1]);
}
