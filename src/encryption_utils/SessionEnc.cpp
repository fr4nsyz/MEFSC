#include "../../include/common/SessionEnc.h"
#include "../../include/common/constants.h"
#include "../../include/common/encryption_utils.h"
#include <cstring>
#include <sodium/crypto_kx.h>
#include <sodium/utils.h>

bool recv_fully(int fd, void *buf, size_t len) {
  uint8_t *dest = reinterpret_cast<uint8_t *>(buf);
  while (len > 0) {
    ssize_t received = recv(fd, dest, len, MSG_WAITALL);
    if (received <= 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    dest += received;
    len -= received;
  }
  return true;
}

SessionEncWrapper::SessionEncWrapper(
    const unsigned char *data, unsigned long long data_length,
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES])
    : session_encrypted_data_length(0) { // for writers

  this->enc_wrap_type = SENDER;

  // IMPORTANT the nonce used by encrypt_stream_buffer is the one that gets
  // incremented. this should be accessible past the lifetime of this

  if (encrypt_stream_buffer(client_tx, nonce, data, data_length,
                            this->session_encrypted_data,
                            &this->session_encrypted_data_length)) {
    std::cerr << "encryption inside SessionEncWrapper <for writers> "
                 "construction failed\n";
    return;
  };

  std::memcpy(this->nonce, nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  this->corrupted = false;
};

SessionEncWrapper::SessionEncWrapper(int client_sock) { // for readers
  // 1. Receive data length (using recv_fully)
  this->enc_wrap_type = READER;
  if (!recv_fully(client_sock, &this->session_encrypted_data_length,
                  sizeof(this->session_encrypted_data_length))) {
    std::cerr << "Failed to receive data length\n";
    this->corrupted = true;
    return;
  }

  // 2. Validate length
  if (session_encrypted_data_length > stream_chunk_size) {
    std::cerr << "Data length exceeds stream_chunk_size: "
              << session_encrypted_data_length << " > " << stream_chunk_size
              << "\n";
    this->corrupted = true;
    return;
  }

  // 3. Receive nonce (using recv_fully)
  if (!recv_fully(client_sock, this->nonce,
                  crypto_aead_chacha20poly1305_NPUBBYTES)) {
    std::cerr << "Failed to receive nonce\n";
    this->corrupted = true;
    return;
  }

  // 4. Receive encrypted data (using recv_fully)
  if (!recv_fully(client_sock, this->session_encrypted_data,
                  this->session_encrypted_data_length)) {
    std::cerr << "Failed to receive encrypted data ("
              << this->session_encrypted_data_length << " bytes)\n";
    this->corrupted = true;
    return;
  }

  this->corrupted = false;
}

int SessionEncWrapper::unwrap(unsigned char rx[crypto_kx_SESSIONKEYBYTES],
                              unsigned long long decrypted_data_capacity,
                              unsigned char *decrypted_data,
                              unsigned long long *decrypted_data_len) {
  // the data returned within here is up to the caller's interpretation. if the
  // underlying data is encrypted aka was file encrypted or something of the
  // sort, it is the caller's responsibility to decrypt that.

  if (this->enc_wrap_type != READER) {
    return -1;
  }

  if (this->corrupted) {
    std::cerr << "this wrapper already contains corrupted data\n";
    return 4;
  }

  if (this->session_encrypted_data_length -
          crypto_aead_chacha20poly1305_ABYTES >
      stream_chunk_size) {
    std::cerr << "invalid size, it is larger than stream_chunk_size\n";
    return 3;
  }

  if (this->session_encrypted_data_length -
          crypto_aead_chacha20poly1305_ABYTES >
      decrypted_data_capacity) {
    std::cerr << "WARNING COULD OVERFLOW | TRYING TO PUT "
              << this->session_encrypted_data_length << " BYTES INTO "
              << decrypted_data_capacity << "\n";
    this->corrupted = true;
    return 2;
  }

  if (crypto_aead_chacha20poly1305_decrypt(decrypted_data, decrypted_data_len,
                                           NULL, this->session_encrypted_data,
                                           this->session_encrypted_data_length,
                                           NULL, 0, this->nonce, rx) != 0) {

    std::cerr << "failed\n" << std::endl;

    std::cerr << this->session_encrypted_data_length << "\n\n";

    std::cerr << "error decrypting in unwrap" << std::endl;
    this->corrupted = true;
    return 1;
  }
  return 0;
};

SessionEncWrapper::~SessionEncWrapper() {
  // maybe just zero everything regardless of whether it's corrupt or not
  this->session_encrypted_data_length = 0;

  sodium_memzero(this->session_encrypted_data, stream_chunk_size);
  sodium_memzero(this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
}

int SessionEncWrapper::send_data(int client_sock) {
  if (this->enc_wrap_type != SENDER) {
    return -1;
  }
  return send(client_sock, this->session_encrypted_data,
              this->session_encrypted_data_length, MSG_NOSIGNAL);
}
int SessionEncWrapper::send_nonce(int client_sock) {
  if (this->enc_wrap_type != SENDER) {
    return -1;
  }
  return send(client_sock, this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES,
              MSG_NOSIGNAL);
}

int SessionEncWrapper::send_data_length(int client_sock) {
  if (this->enc_wrap_type != SENDER) {
    return -1;
  }
  return send(client_sock, &this->session_encrypted_data_length,
              sizeof(this->session_encrypted_data_length), MSG_NOSIGNAL);
}

unsigned long long SessionEncWrapper::get_data_length() {
  // this one is universal to both SENDER and READER
  return this->session_encrypted_data_length;
};

int SessionEncWrapper::send_all(int client_sock) {
  if (this->enc_wrap_type != SENDER) {
    return -1;
  }
  unsigned char buf[sizeof(unsigned long long) +
                    crypto_aead_chacha20poly1305_NPUBBYTES + stream_chunk_size];
  unsigned char *ptr = buf;

  std::memcpy(ptr, &this->session_encrypted_data_length,
              sizeof(this->session_encrypted_data_length));
  ptr += sizeof(this->session_encrypted_data_length);

  std::memcpy(ptr, this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
  ptr += crypto_aead_chacha20poly1305_NPUBBYTES;

  std::memcpy(ptr, this->session_encrypted_data,
              this->session_encrypted_data_length);
  ptr += this->session_encrypted_data_length;

  size_t total = ptr - buf;
  return send(client_sock, buf, total, MSG_NOSIGNAL);
}

bool SessionEncWrapper::is_corrupted() { return this->corrupted; }
