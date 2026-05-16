#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <unistd.h>

#ifndef MFSC_CONSTANTS
#define MFSC_CONSTANTS

const int INVALID_READ_INTENT = -45;
const int NO_ACTION = 99;
const int NEW_ACTION = 88;
const int END_CHUNK = 77;
const int MEAT_CHUNK = 66;
const size_t CHUNK_SIZE = 4096;
const size_t FILE_ENCRYPTED_CHUNK_SIZE =
    CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
// IMPORTANT: use FILE_ENCRYPTED_CHUNK_SIZE for capacity whenver you decrypt from session.
const size_t stream_chunk_size = 4096 +
                                 crypto_secretstream_xchacha20poly1305_ABYTES +
                                 crypto_aead_chacha20poly1305_ABYTES;
const unsigned char MAX_FILE_NAME_LENGTH = 255;

const unsigned char PRE_EXT_FILE_NAME_LEN =
    250; // remove 5 from 255 because that is reserved for the .enc extension
         // (null byte included)

const int LIST_FILES = 3;
const int DELETE_FILE = 4;

#endif
