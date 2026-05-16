#include "../include/common/SessionEnc.h"
#include "../include/common/constants.h"
#include "../include/common/encryption_utils.h"
#include <cstring>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

class SessionEncTest : public ::testing::Test {
protected:
  int fds[2] = {-1, -1};
  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char server_rx[crypto_kx_SESSIONKEYBYTES];
  unsigned char server_tx[crypto_kx_SESSIONKEYBYTES];
  unsigned char client_rx[crypto_kx_SESSIONKEYBYTES];
  unsigned char client_tx[crypto_kx_SESSIONKEYBYTES];
  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

  void SetUp() override {
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    crypto_kx_keypair(server_pk, server_sk);
    crypto_kx_keypair(client_pk, client_sk);
    (void)crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk,
                                        client_pk);
    (void)crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk,
                                        server_pk);
    randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
  }

  void TearDown() override {
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
  }
};

TEST_F(SessionEncTest, SendAllRoundTrip) {
  const char *message = "hello session enc!";
  unsigned long long msg_len = std::strlen(message) + 1;

  SessionEncWrapper sender_wrap(
      reinterpret_cast<const unsigned char *>(message), msg_len, client_tx,
      nonce);
  ASSERT_FALSE(sender_wrap.is_corrupted());
  ASSERT_GT(sender_wrap.send_all(fds[0]), 0);

  SessionEncWrapper reader_wrap(fds[1]);
  ASSERT_FALSE(reader_wrap.is_corrupted());

  unsigned char decrypted[256];
  unsigned long long decrypted_len;
  ASSERT_EQ(reader_wrap.unwrap(server_rx, sizeof(decrypted), decrypted,
                               &decrypted_len), 0);
  EXPECT_STREQ(reinterpret_cast<char *>(decrypted), message);
  EXPECT_EQ(decrypted_len, msg_len);
}

TEST_F(SessionEncTest, SendAllPairsAreIndependent) {
  const char *msg1 = "first message";
  const char *msg2 = "second!";

  SessionEncWrapper s1(reinterpret_cast<const unsigned char *>(msg1),
                        std::strlen(msg1) + 1, client_tx, nonce);
  s1.send_all(fds[0]);

  SessionEncWrapper s2(reinterpret_cast<const unsigned char *>(msg2),
                        std::strlen(msg2) + 1, client_tx, nonce);
  s2.send_all(fds[0]);

  SessionEncWrapper r1(fds[1]);
  unsigned char buf1[256];
  unsigned long long len1;
  ASSERT_EQ(r1.unwrap(server_rx, sizeof(buf1), buf1, &len1), 0);
  EXPECT_STREQ(reinterpret_cast<char *>(buf1), msg1);

  SessionEncWrapper r2(fds[1]);
  unsigned char buf2[256];
  unsigned long long len2;
  ASSERT_EQ(r2.unwrap(server_rx, sizeof(buf2), buf2, &len2), 0);
  EXPECT_STREQ(reinterpret_cast<char *>(buf2), msg2);
}

TEST_F(SessionEncTest, ReceiverDetectsCorruptedLength) {
  unsigned long long bad = stream_chunk_size + 1;
  send(fds[0], &bad, sizeof(bad), MSG_NOSIGNAL);

  SessionEncWrapper reader(fds[1]);
  EXPECT_TRUE(reader.is_corrupted());
}

TEST_F(SessionEncTest, NonceAdvancesBetweenMessages) {
  unsigned char n1[crypto_aead_chacha20poly1305_NPUBBYTES];
  std::memcpy(n1, nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  SessionEncWrapper s1(reinterpret_cast<const unsigned char *>("a"), 2,
                        client_tx, nonce);
  s1.send_all(fds[0]);

  EXPECT_NE(std::memcmp(n1, nonce, crypto_aead_chacha20poly1305_NPUBBYTES), 0);
}

TEST_F(SessionEncTest, UnwrapRequiresReader) {
  SessionEncWrapper sender(reinterpret_cast<const unsigned char *>("x"), 2,
                            client_tx, nonce);
  unsigned char buf[64];
  unsigned long long len;
  EXPECT_EQ(sender.unwrap(client_rx, sizeof(buf), buf, &len), -1);
}
