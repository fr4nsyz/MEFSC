#include "../include/common/SessionEnc.h"
#include "../include/common/constants.h"
#include "../include/common/encryption_utils.h"
#include "../include/read_write_handlers.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

class FSTest : public ::testing::Test {
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
  std::string orig_cwd;
  std::string tmpdir;

  void SetUp() override {
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    crypto_kx_keypair(server_pk, server_sk);
    crypto_kx_keypair(client_pk, client_sk);
    (void)crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk,
                                        client_pk);
    (void)crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk,
                                        server_pk);

    orig_cwd = std::filesystem::current_path().string();
    tmpdir = std::filesystem::temp_directory_path() / "mefsc_test_XXXXXX";
    char tmpl[512];
    std::strncpy(tmpl, tmpdir.c_str(), sizeof(tmpl) - 1);
    ASSERT_NE(mkdtemp(tmpl), nullptr);
    tmpdir = tmpl;
    std::filesystem::current_path(tmpdir);
    ASSERT_EQ(std::filesystem::current_path().string(), tmpdir);
  }

  void TearDown() override {
    std::filesystem::current_path(orig_cwd);
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    if (!tmpdir.empty())
      std::filesystem::remove_all(tmpdir);
  }

  void create_user_file(const std::string &user, const std::string &fname) {
    auto dir = std::filesystem::path("MEF_S") / user;
    std::filesystem::create_directories(dir);
    std::ofstream(dir / fname) << "test content";
  }
};

TEST_F(FSTest, ListFilesReturnsCorrectFilenames) {
  std::string user = "testuser";
  create_user_file(user, "a.enc");
  create_user_file(user, "b.enc");
  create_user_file(user, "subdir.enc");

  FS_Operator op(fds[0], user, server_rx, server_tx);

  std::thread driver([&] {
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

    int action = NEW_ACTION;
    SessionEncWrapper notif(reinterpret_cast<const unsigned char *>(&action),
                            sizeof(action), client_tx, nonce);
    notif.send_all(fds[1]);

    int intent = static_cast<int>(Action::LIST_FILES);
    SessionEncWrapper intent_wrap(
        reinterpret_cast<const unsigned char *>(&intent), sizeof(intent),
        client_tx, nonce);
    intent_wrap.send_all(fds[1]);
  });

  ASSERT_EQ(op.receive_notice_of_new_action(), 0);
  ASSERT_EQ(op.read_intent(), static_cast<int>(Action::LIST_FILES));

  ASSERT_EQ(op.LFFS_Handler__Server(), 0);

  driver.join();

  SessionEncWrapper count_wrap(fds[1]);
  ASSERT_FALSE(count_wrap.is_corrupted());
  int file_count;
  unsigned long long decrypted_len;
  ASSERT_EQ(count_wrap.unwrap(client_rx, sizeof(file_count),
                              reinterpret_cast<unsigned char *>(&file_count),
                              &decrypted_len), 0);
  EXPECT_EQ(file_count, 3);

  std::vector<std::string> names;
  for (int i = 0; i < file_count; ++i) {
    SessionEncWrapper name_wrap(fds[1]);
    ASSERT_FALSE(name_wrap.is_corrupted());
    char fname[256] = {};
    ASSERT_EQ(name_wrap.unwrap(client_rx, sizeof(fname) - 1,
                               reinterpret_cast<unsigned char *>(fname),
                               &decrypted_len), 0);
    names.emplace_back(fname);
  }

  EXPECT_NE(std::find(names.begin(), names.end(), "a.enc"), names.end());
  EXPECT_NE(std::find(names.begin(), names.end(), "b.enc"), names.end());
  EXPECT_NE(std::find(names.begin(), names.end(), "subdir.enc"), names.end());
}

TEST_F(FSTest, ListFilesEmptyDirectory) {
  std::string user = "emptyuser";

  FS_Operator op(fds[0], user, server_rx, server_tx);

  std::thread driver([&] {
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

    int action = NEW_ACTION;
    SessionEncWrapper notif(reinterpret_cast<const unsigned char *>(&action),
                            sizeof(action), client_tx, nonce);
    notif.send_all(fds[1]);

    int intent = static_cast<int>(Action::LIST_FILES);
    SessionEncWrapper intent_wrap(
        reinterpret_cast<const unsigned char *>(&intent), sizeof(intent),
        client_tx, nonce);
    intent_wrap.send_all(fds[1]);
  });

  ASSERT_EQ(op.receive_notice_of_new_action(), 0);
  ASSERT_EQ(op.read_intent(), static_cast<int>(Action::LIST_FILES));
  ASSERT_EQ(op.LFFS_Handler__Server(), 0);
  driver.join();

  SessionEncWrapper count_wrap(fds[1]);
  ASSERT_FALSE(count_wrap.is_corrupted());
  int file_count;
  unsigned long long decrypted_len;
  ASSERT_EQ(count_wrap.unwrap(client_rx, sizeof(file_count),
                              reinterpret_cast<unsigned char *>(&file_count),
                              &decrypted_len), 0);
  EXPECT_EQ(file_count, 0);
}
