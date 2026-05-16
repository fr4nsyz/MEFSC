#include "../../include/read_write_handlers.h"
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/utils.h>

const char *ext = ".enc";
const unsigned char ext_len = strlen(ext);

const char *base_dir = "MEF_S/";
const int ACK_SUC = 0;
const int ACK_FAIL = -1; //  to be appended to later

FS_Operator::FS_Operator(int client_sock, std::string username,
                         unsigned char server_rx[crypto_kx_SESSIONKEYBYTES],
                         unsigned char server_tx[crypto_kx_SESSIONKEYBYTES])
    : client_sock(client_sock) {

  this->user_dir = base_dir + username + "/"; // need to make this directory
  if (!std::filesystem::create_directories(this->user_dir)) {
    std::cerr << "couldn't create user_dir: " << this->user_dir << std::endl;
  };

  randombytes_buf(this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  std::memcpy(this->server_tx, server_tx, crypto_kx_SESSIONKEYBYTES);
  std::memcpy(this->server_rx, server_rx, crypto_kx_SESSIONKEYBYTES);

  sodium_memzero(server_tx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(server_rx, crypto_kx_SESSIONKEYBYTES);
}

FS_Operator::~FS_Operator() {
  this->client_sock = -420;
  sodium_memzero(this->user_dir.data(), this->user_dir.size());
  sodium_memzero(this->server_tx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(this->server_rx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
}

int FS_Operator::init_read(
    int client_sock, char file_name_buf[250],
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES]) {

  SessionEncWrapper confirm_client_side_file_exists_wrapper =
      SessionEncWrapper(client_sock);

  bool confirm_file_exists = false;
  unsigned long long confirm_file_exists_bytes;

  if (confirm_client_side_file_exists_wrapper.unwrap(
          this->server_rx, sizeof(confirm_file_exists),
          reinterpret_cast<unsigned char *>(&confirm_file_exists),
          &confirm_file_exists_bytes)) {
    std::cerr << "confirm_client_side_file_exists_wrapper failed in unwrap\n";
    return 6;
  }

  if (!confirm_file_exists) {
    std::cerr << "file " << file_name_buf << " does not exist\n";
    return 5;
  }

  SessionEncWrapper file_name_wrap = SessionEncWrapper(client_sock);
  if (file_name_wrap.is_corrupted()) {
    std::cerr << "file_name_wrap in init_read was corrupted\n";
    return 9;
  }

  unsigned long long decrypted_file_name_length;

  if (file_name_wrap.unwrap(this->server_rx, PRE_EXT_FILE_NAME_LEN,
                            reinterpret_cast<unsigned char *>(file_name_buf),
                            &decrypted_file_name_length) == 2) {
    std::cerr << "couldn't read file name, ABORT\n";
    return 8;
  }

  // decrypted file length will be NOT null terminated. so i need to null
  // terminate it before it leaves int_read

  if (decrypted_file_name_length + strlen(ext) > MAX_FILE_NAME_LENGTH) {
    return 7;
  }

  file_name_buf[decrypted_file_name_length] = '\0';

  SessionEncWrapper header_wrap = SessionEncWrapper(client_sock);

  if (header_wrap.is_corrupted()) {
    std::cerr << "header was corrupted\n";
    return 4;
  }

  unsigned long long decrypted_header_length;

  if (header_wrap.unwrap(this->server_rx,
                         crypto_secretstream_xchacha20poly1305_HEADERBYTES,
                         header, &decrypted_header_length)) {
    if (header_wrap.is_corrupted()) {
      std::cerr << "header was corrupted (discovered in unwrap)\n";
      return 3;
    }
  };

  SessionEncWrapper salt_wrap = SessionEncWrapper(client_sock);
  if (salt_wrap.is_corrupted()) {
    std::cerr << "salt_wrap was corrupted\n";
    return 2;
  }
  unsigned long long decrypted_salt_length;
  if (salt_wrap.unwrap(this->server_rx, crypto_pwhash_SALTBYTES, salt,
                       &decrypted_salt_length)) {

    std::cerr << "salt_wrap was corrupted (discovered in unwrap)\n";
    return 1;
  };

  return 0;
}

int FS_Operator::WTFS_Handler__Server() {

  // when doing multiple files and directories, this function could be called in
  // a separate thread perhaps for each file

  char file_name_buf[FILE_ENCRYPTED_CHUNK_SIZE];

  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];

  if (init_read(this->client_sock, file_name_buf, header, salt)) {
    std::cerr << "error with init_read\n";
    return 1;
  }

  std::string file_name = this->user_dir + file_name_buf;

  file_name.append(".enc");

  std::cerr << "THIS IS FILENAME " << file_name << std::endl;
  std::cerr << "THIS IS FILENAME " << file_name << std::endl;
  std::cerr << "THIS IS FILENAME " << file_name << std::endl;
  std::cerr << "THIS IS FILENAME " << file_name << std::endl;
  std::cerr << "THIS IS FILENAME " << file_name << std::endl;
  std::cerr << "THIS IS FILENAME " << file_name << std::endl;
  std::cerr << "THIS IS FILENAME " << file_name << std::endl;

  std::cerr << "this is file_name now after adding ext: " << file_name << "\n";

  std::ofstream file(file_name, std::ios::binary);

  file.write(reinterpret_cast<const char *>(header),
             crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  file.write(reinterpret_cast<const char *>(salt), crypto_pwhash_SALTBYTES);

  unsigned char decrypted_file_chunk[FILE_ENCRYPTED_CHUNK_SIZE];
  size_t read_bytes;

  int prefix = END_CHUNK;
  do {
    SessionEncWrapper prefix_wrap = SessionEncWrapper(client_sock);
    unsigned long long decrypted_prefix_len;

    if (prefix_wrap.is_corrupted()) {
      std::cerr << "prefix was corrupted\n";
      break;
    }

    if (prefix_wrap.unwrap(this->server_rx, sizeof(prefix),
                           reinterpret_cast<unsigned char *>(&prefix),
                           &decrypted_prefix_len)) {
      std::cerr << "prefix was corrupted (discovered in unwrap)\n";
      break;
    };

    SessionEncWrapper encrypted_data_wrap = SessionEncWrapper(client_sock);
    unsigned long long decrypted_file_chunk_len;

    if (encrypted_data_wrap.is_corrupted()) {
      std::cerr << "encrypted chunk data was corrupted\n";
      break;
    }

    if (encrypted_data_wrap.unwrap(this->server_rx, FILE_ENCRYPTED_CHUNK_SIZE,
                                   decrypted_file_chunk,
                                   &decrypted_file_chunk_len)) {
      std::cerr
          << "encrypted chunk data was corrupted (discovered in unwrap)\n";
      break;
    };

    file.write(reinterpret_cast<char *>(decrypted_file_chunk),
               decrypted_file_chunk_len);

    if (prefix == END_CHUNK) {
      std::cerr << "found last chunk\n";
      break;
    }

  } while (prefix ==
           MEAT_CHUNK); // changing this to MEAT_CHUNK not != END_CHUNK
                        // explicitness or whatever the word is

  return 0;
}

int FS_Operator::RFFS_Handler__Server() {

  randombytes_buf(this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
  char file_name_buf[MAX_FILE_NAME_LENGTH];

  unsigned long long decrypted_file_name_length;

  SessionEncWrapper encrypted_file_name = SessionEncWrapper(client_sock);

  if (encrypted_file_name.is_corrupted()) {
    std::cerr << "file_name was corrupted\n";
    return 3;
  }

  if (encrypted_file_name.unwrap(
          this->server_rx, PRE_EXT_FILE_NAME_LEN,
          reinterpret_cast<unsigned char *>(file_name_buf),
          &decrypted_file_name_length)) {
    std::cerr << "file_name was corrupted (discovered in unwrap)\n";
    return 2;
  };

  std::string file_name = this->user_dir + file_name_buf;

  std::ifstream file(file_name, std::ios::binary);

  if (!file) {
    std::cerr << "couldn't open the file\n";
    return 1;
  }

  unsigned char file_chunk[FILE_ENCRYPTED_CHUNK_SIZE];

  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];

  int tag = 0;

  file.read(reinterpret_cast<char *>(header),
            crypto_secretstream_xchacha20poly1305_HEADERBYTES);

  SessionEncWrapper header_wrap = SessionEncWrapper(
      header, crypto_secretstream_xchacha20poly1305_HEADERBYTES,
      this->server_tx, this->nonce);

  header_wrap.send_all(this->client_sock);

  file.read(reinterpret_cast<char *>(salt), crypto_pwhash_SALTBYTES);

  SessionEncWrapper salt_wrap = SessionEncWrapper(salt, crypto_pwhash_SALTBYTES,
                                                  this->server_tx, this->nonce);

  salt_wrap.send_all(this->client_sock);

  if (!file) {
    std::cerr << "file not valid\n";
  } else if (file.eof()) {
    std::cerr << "eof\n";
  }

  do {

    file.read(reinterpret_cast<char *>(file_chunk), FILE_ENCRYPTED_CHUNK_SIZE);

    unsigned long long file_chunk_len = file.gcount();

    std::cerr << "read file_chunk_len " << file_chunk_len << "\n";

    SessionEncWrapper prefix_wrap =
        file.eof() ? SessionEncWrapper(
                         reinterpret_cast<const unsigned char *>(&END_CHUNK),
                         sizeof(END_CHUNK), this->server_tx, this->nonce)
                   : SessionEncWrapper(
                         reinterpret_cast<const unsigned char *>(&MEAT_CHUNK),
                         sizeof(MEAT_CHUNK), this->server_tx, this->nonce);

    prefix_wrap.send_all(this->client_sock);

    SessionEncWrapper file_chunk_wrap = SessionEncWrapper(
        file_chunk, file_chunk_len, this->server_tx, this->nonce);

    file_chunk_wrap.send_all(this->client_sock);

  } while (!file.eof());

  return 0;
}

int FS_Operator::LFFS_Handler__Server() {
  int file_count = 0;
  for (auto &entry : std::filesystem::directory_iterator(user_dir)) {
    (void)entry;
    ++file_count;
  }

  randombytes_buf(this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
  SessionEncWrapper count_wrap = SessionEncWrapper(
      reinterpret_cast<const unsigned char *>(&file_count), sizeof(file_count),
      this->server_tx, this->nonce);
  count_wrap.send_all(this->client_sock);

  for (auto &entry : std::filesystem::directory_iterator(user_dir)) {
    std::string filename = entry.path().filename().string();
    randombytes_buf(this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
    SessionEncWrapper name_wrap = SessionEncWrapper(
        reinterpret_cast<const unsigned char *>(filename.data()),
        filename.size() + 1, this->server_tx, this->nonce);
    name_wrap.send_all(this->client_sock);
  }

  return 0;
}

int FS_Operator::DFFS_Handler__Server() {
  randombytes_buf(this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  SessionEncWrapper name_wrap = SessionEncWrapper(this->client_sock);
  if (name_wrap.is_corrupted()) {
    return 2;
  }

  char file_name_buf[MAX_FILE_NAME_LENGTH] = {0};
  unsigned long long decrypted_len;

  if (name_wrap.unwrap(this->server_rx, PRE_EXT_FILE_NAME_LEN,
                       reinterpret_cast<unsigned char *>(file_name_buf),
                       &decrypted_len)) {
    return 1;
  }

  std::string file_path = this->user_dir + file_name_buf;
  int result = std::filesystem::remove(file_path) ? ACK_SUC : ACK_FAIL;

  randombytes_buf(this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
  SessionEncWrapper result_wrap = SessionEncWrapper(
      reinterpret_cast<const unsigned char *>(&result), sizeof(result),
      this->server_tx, this->nonce);
  result_wrap.send_all(this->client_sock);

  return 0;
}

int FS_Operator::receive_notice_of_new_action() {
  int notice;
  SessionEncWrapper notice_wrap = SessionEncWrapper(this->client_sock);
  if (notice_wrap.is_corrupted()) {
    return 3;
  }

  unsigned long long decrypted_notice_length;

  if (notice_wrap.unwrap(this->server_rx, sizeof(notice),
                         reinterpret_cast<unsigned char *>(&notice),
                         &decrypted_notice_length)) {
    return 2;
  };

  if (notice != NEW_ACTION) {
    std::cerr << "RETURNED ONE FROM NEWACTION NOOOOOOOOOOOOOO\n";
    return 1;
  } else {
    std::cerr << "NEW ACTION INISIATED\n";
    return 0;
  }
}

int FS_Operator::read_intent() {

  int intent;

  unsigned long long decrypted_data_length;

  SessionEncWrapper intent_wrap = SessionEncWrapper(client_sock);
  if (intent_wrap.is_corrupted()) {
    return INVALID_READ_INTENT;
  }

  if (intent_wrap.unwrap(server_rx, sizeof(intent),
                         reinterpret_cast<unsigned char *>(&intent),
                         &decrypted_data_length)) {
    return INVALID_READ_INTENT;
  };

  return intent;
}
