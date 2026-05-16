#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <signal.h>
#include <sqlite3.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

// --- subprocess helper ---

struct Subprocess {
  pid_t pid;
  int stdin_fd;
  int stdout_fd;
};

static Subprocess spawn(const char *argv[], int stdin_fd, int stdout_fd) {
  pid_t pid = fork();
  if (pid == 0) {
    if (stdin_fd >= 0)
      dup2(stdin_fd, STDIN_FILENO);
    if (stdout_fd >= 0)
      dup2(stdout_fd, STDOUT_FILENO);
    for (int i = 3; i < 256; ++i)
      if (i != stdin_fd && i != stdout_fd)
        close(i);
    execvp(argv[0], const_cast<char *const *>(argv));
    _exit(127);
  }
  return {pid, stdin_fd, stdout_fd};
}

static std::string read_all(int fd) {
  std::string out;
  char buf[4096];
  while (true) {
    auto n = read(fd, buf, sizeof(buf));
    if (n <= 0)
      break;
    out.append(buf, n);
  }
  return out;
}

// --- Integration test environment ---

class IntegEnv : public ::testing::Environment {
public:
  pid_t server_pid = -1;
  int devnull = -1;
  std::string db_path;
  std::string server_path;
  std::string client_path;
  std::string gen_hash_path;

  void SetUp() override {
    devnull = open("/dev/null", O_RDWR);

    auto build_dir = std::filesystem::current_path();
    server_path = (build_dir / "server").string();
    client_path = (build_dir / "client_fs" / "client").string();
    gen_hash_path = (build_dir / "tests" / "gen_hash").string();
    db_path = (build_dir / "MEFSC_DB.db").string();

    ASSERT_TRUE(std::filesystem::exists(server_path)) << server_path;
    ASSERT_TRUE(std::filesystem::exists(client_path)) << client_path;
    ASSERT_TRUE(std::filesystem::exists(gen_hash_path)) << gen_hash_path;

    // Create test user in a clean DB (use sqlite3 API to avoid shell escaping issues with $ in hash)
    std::filesystem::remove(db_path);
    std::string hash = get_hash("swabber");
    {
      sqlite3 *db;
      ASSERT_EQ(sqlite3_open(db_path.c_str(), &db), SQLITE_OK);
      char *err;
      ASSERT_EQ(sqlite3_exec(db, "CREATE TABLE users(username TEXT PRIMARY KEY, hashed_pswd TEXT);", nullptr, nullptr, &err), SQLITE_OK);
      sqlite3_stmt *stmt;
      ASSERT_EQ(sqlite3_prepare_v2(db, "INSERT INTO users VALUES(?, ?);", -1, &stmt, nullptr), SQLITE_OK);
      ASSERT_EQ(sqlite3_bind_text(stmt, 1, "henry", -1, SQLITE_STATIC), SQLITE_OK);
      ASSERT_EQ(sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_STATIC), SQLITE_OK);
      ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
      sqlite3_finalize(stmt);
      sqlite3_close(db);
    }

    // Remove any stale MEF_S dir, create fresh
    std::filesystem::remove_all("MEF_S");

    // Start server
    int pipe_fds[2];
    ASSERT_EQ(pipe(pipe_fds), 0);
    const char *srv_argv[] = {server_path.c_str(), nullptr};
    auto sp = spawn(srv_argv, -1, pipe_fds[1]);
    server_pid = sp.pid;
    close(pipe_fds[1]);
    close(sp.stdin_fd);

    // Wait until server prints "accepting" or 5s timeout
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool ready = false;
    while (std::chrono::steady_clock::now() < deadline) {
      std::string line;
      char c;
      while (read(pipe_fds[0], &c, 1) == 1) {
        line += c;
        if (c == '\n')
          break;
      }
      if (line.find("accepting") != std::string::npos) {
        ready = true;
        break;
      }
    }
    ASSERT_TRUE(ready) << "server failed to start within 5s";
    close(pipe_fds[0]);
  }

  void TearDown() override {
    if (server_pid > 0) {
      kill(server_pid, SIGTERM);
      int status;
      waitpid(server_pid, &status, 0);
    }
    if (devnull >= 0)
      close(devnull);
    std::filesystem::remove_all("MEF_S");
  }

  std::string run_client(const std::string &input) {
    int in_fds[2], out_fds[2];
    EXPECT_EQ(pipe(in_fds), 0);
    EXPECT_EQ(pipe(out_fds), 0);

    const char *cli_argv[] = {client_path.c_str(), nullptr};
    auto sp = spawn(cli_argv, in_fds[0], out_fds[1]);
    close(in_fds[0]);
    close(out_fds[1]);

    write(in_fds[1], input.data(), input.size());
    close(in_fds[1]);

    std::string output = read_all(out_fds[0]);
    close(out_fds[0]);

    int status;
    waitpid(sp.pid, &status, 0);
    return output;
  }

private:
  std::string get_hash(const std::string &pw) {
    int in_fds[2], out_fds[2];
    EXPECT_EQ(pipe(in_fds), 0);
    EXPECT_EQ(pipe(out_fds), 0);

    const char *argv[] = {gen_hash_path.c_str(), pw.c_str(), nullptr};
    auto sp = spawn(argv, -1, out_fds[1]);
    close(out_fds[1]);

    std::string hash = read_all(out_fds[0]);
    close(out_fds[0]);

    int status;
    waitpid(sp.pid, &status, 0);
    EXPECT_EQ(status, 0);

    if (!hash.empty() && hash.back() == '\n')
      hash.pop_back();
    return hash;
  }
};

IntegEnv *env;

// --- test cases ---

TEST(Integ, UploadFile) {
  std::string test_file = "gummy_bear";
  std::ofstream(test_file) << "test content for upload";
  std::string input = "henry\nswabber\n2\n" + test_file + "\n5\n";
  auto out = env->run_client(input);
  EXPECT_TRUE(out.find("failed") == std::string::npos ||
              out.find("failed") == out.size())
      << "upload failed, output:\n" << out;
  EXPECT_TRUE(std::filesystem::exists("MEF_S/henry/" + test_file + ".enc"));
  std::filesystem::remove(test_file);
}

TEST(Integ, ListFiles) {
  // Upload first so there's something to list
  std::string test_file = "gummy_bear";
  std::ofstream(test_file) << "test content for upload";
  env->run_client("henry\nswabber\n2\n" + test_file + "\n5\n");
  std::filesystem::remove(test_file);

  auto out = env->run_client("henry\nswabber\n3\n5\n");
  EXPECT_NE(out.find("gummy_bear.enc"), std::string::npos)
      << "expected gummy_bear.enc in list, output:\n" << out;
  EXPECT_NE(out.find("Stored Files"), std::string::npos);
}

TEST(Integ, DeleteFile) {
  // Upload first
  std::string test_file = "gummy_bear";
  std::ofstream(test_file) << "test content for upload";
  env->run_client("henry\nswabber\n2\n" + test_file + "\n5\n");
  std::filesystem::remove(test_file);
  ASSERT_TRUE(std::filesystem::exists("MEF_S/henry/" + test_file + ".enc"));

  auto out = env->run_client("henry\nswabber\n4\ngummy_bear.enc\n5\n");
  EXPECT_FALSE(std::filesystem::exists("MEF_S/henry/gummy_bear.enc"))
      << "file should have been deleted";

  out = env->run_client("henry\nswabber\n3\n5\n");
  EXPECT_EQ(out.find("gummy_bear.enc"), std::string::npos)
      << "file should be gone, output:\n" << out;
}

TEST(Integ, BadAuth) {
  auto out = env->run_client("henry\nwrongpassword\n3\n5\n");
  EXPECT_NE(out.find("not authenticated"), std::string::npos)
      << "expected auth failure, output:\n" << out;
}

int main(int argc, char **argv) {
  env = new IntegEnv;
  ::testing::AddGlobalTestEnvironment(env);
  ::testing::InitGoogleTest(&argc, argv);
  // Mark bad_auth as expected to fail
  return RUN_ALL_TESTS() == 0 ? 0 : 1;
}
